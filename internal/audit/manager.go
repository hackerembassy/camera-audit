package audit

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"xkem.am/camera-audit/internal/config"
	"xkem.am/camera-audit/internal/go2rtc"
	"xkem.am/camera-audit/internal/model"
	"xkem.am/camera-audit/internal/store"
)

type compiledRule struct {
	config.Rule
	cidr *netip.Prefix
	ua   *regexp.Regexp
}

type signal struct {
	camera, actor, actorType, confidence, remote, userAgent string
	at                                                      time.Time
}

type liveHTTP struct {
	camera     string
	suppressed bool
}

type activityLease struct {
	eventID    int64
	camera     string
	suppressed bool
	privacy    bool
	expires    time.Time
}

type birdseyeControl struct {
	layout map[string]struct{}
	order  uint64
}

type PrivacyObserver func(camera string, active bool)
type AvailabilityObserver func(available bool)
type RecordingObserver func(event model.Event)

const streamCheckpointInterval = 5 * time.Minute

type Manager struct {
	mu sync.RWMutex

	cfg    config.Config
	store  *store.Store
	client *go2rtc.Client
	log    *slog.Logger
	rules  []compiledRule

	sessions             map[string]*model.ActiveSession
	activities           map[string]model.Activity
	liveHTTP             map[int64]liveHTTP
	leases               map[string]activityLease
	signals              []signal
	privacy              map[string]bool
	zeroSince            map[string]time.Time
	birdseyeControlConns map[uint64]birdseyeControl
	nextBirdseyeControl  uint64
	nextBirdseyeLayout   uint64
	lastStreamCheckpoint time.Time
	lastPoll             time.Time
	fresh                bool
	dot                  string
	observer             PrivacyObserver
	availabilityObserver AvailabilityObserver
	recordingObserver    RecordingObserver
}

func New(cfg config.Config, s *store.Store, log *slog.Logger) (*Manager, error) {
	m := &Manager{
		cfg: cfg, store: s, client: go2rtc.New(cfg.Go2RTCURL, cfg.Go2RTCUsername, cfg.Go2RTCPassword), log: log,
		sessions: make(map[string]*model.ActiveSession), activities: make(map[string]model.Activity),
		liveHTTP: make(map[int64]liveHTTP), leases: make(map[string]activityLease),
		privacy: make(map[string]bool), zeroSince: make(map[string]time.Time),
		birdseyeControlConns: make(map[uint64]birdseyeControl),
	}
	for _, r := range cfg.Rules {
		cr := compiledRule{Rule: r}
		if r.RemoteCIDR != "" {
			p, _ := netip.ParsePrefix(r.RemoteCIDR)
			cr.cidr = &p
		}
		if r.UserAgent != "" {
			cr.ua = regexp.MustCompile(r.UserAgent)
		}
		m.rules = append(m.rules, cr)
	}
	return m, nil
}

func (m *Manager) SetObserver(fn PrivacyObserver) {
	m.mu.Lock()
	m.observer = fn
	m.mu.Unlock()
}

func (m *Manager) SetAvailabilityObserver(fn AvailabilityObserver) {
	m.mu.Lock()
	m.availabilityObserver = fn
	m.mu.Unlock()
}

func (m *Manager) SetRecordingObserver(fn RecordingObserver) {
	m.mu.Lock()
	m.recordingObserver = fn
	m.mu.Unlock()
}

// BirdseyeControlOpened marks a proxied Frigate control WebSocket as active.
// A layout learned while at least one control socket is active takes priority
// over the static fallback in birdseye_cameras.
func (m *Manager) BirdseyeControlOpened() uint64 {
	m.mu.Lock()
	m.nextBirdseyeControl++
	id := m.nextBirdseyeControl
	if m.birdseyeControlConns == nil {
		m.birdseyeControlConns = make(map[uint64]birdseyeControl)
	}
	m.birdseyeControlConns[id] = birdseyeControl{}
	m.mu.Unlock()
	return id
}

func (m *Manager) BirdseyeControlClosed(id uint64) {
	m.mu.Lock()
	delete(m.birdseyeControlConns, id)
	m.mu.Unlock()
}

// UpdateBirdseyeLayout records the physical cameras Frigate currently renders
// in its composite. The layout contains no image data or viewer identity.
func (m *Manager) UpdateBirdseyeLayout(connectionID uint64, cameras []string) {
	layout := make(map[string]struct{}, len(cameras))
	for _, camera := range cameras {
		camera = strings.TrimSpace(camera)
		if camera != "" && camera != "birdseye" {
			layout[camera] = struct{}{}
		}
	}
	m.mu.Lock()
	if _, connected := m.birdseyeControlConns[connectionID]; !connected {
		m.mu.Unlock()
		return
	}
	m.nextBirdseyeLayout++
	m.birdseyeControlConns[connectionID] = birdseyeControl{layout: layout, order: m.nextBirdseyeLayout}
	m.mu.Unlock()
}

func (m *Manager) Run(ctx context.Context) {
	poll := time.NewTicker(m.cfg.PollInterval.Value())
	state := time.NewTicker(time.Second)
	prune := time.NewTicker(24 * time.Hour)
	dotDone := make(chan struct{})
	go func() {
		defer close(dotDone)
		m.runDOT(ctx)
	}()
	defer poll.Stop()
	defer state.Stop()
	defer prune.Stop()
	defer func() { <-dotDone }()
	defer m.closeTracked()
	m.poll(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
			m.poll(ctx)
		case now := <-state.C:
			m.tick(now)
		case now := <-prune.C:
			if err := m.store.Prune(ctx, now.Add(-m.cfg.Retention.Value())); err != nil {
				m.log.Error("prune audit history", "error", err)
			}
		}
	}
}

func (m *Manager) closeTracked() {
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, session := range m.sessions {
		if err := m.store.EndStream(context.Background(), session.EventID, now, session.LastSeenAt); err != nil {
			m.log.Error("close stream session during shutdown", "error", err)
		}
	}
	for _, activity := range m.activities {
		if activity.EventID != 0 {
			_ = m.store.End(context.Background(), activity.EventID, now)
		}
	}
	for _, lease := range m.leases {
		_ = m.store.End(context.Background(), lease.eventID, now)
	}
	for eventID := range m.liveHTTP {
		_ = m.store.End(context.Background(), eventID, now)
	}
}

func (m *Manager) poll(ctx context.Context) {
	streams, err := m.client.Streams(ctx)
	if err != nil {
		// Preserve the last inventory while go2rtc is unreachable. Ending it here
		// would turn a transient polling failure into false disconnect history.
		m.mu.Lock()
		wasFresh := m.fresh
		m.fresh = false
		availabilityObserver := m.availabilityObserver
		m.mu.Unlock()
		if wasFresh && availabilityObserver != nil {
			availabilityObserver(false)
		}
		m.log.Warn("poll go2rtc streams", "error", err)
		return
	}
	now := time.Now().UTC()

	m.mu.Lock()
	wasFresh := m.fresh
	m.fresh = true
	m.lastPoll = now
	if !wasFresh {
		// We cannot prove that a connection survived the observation gap. Close
		// the old intervals and let this successful snapshot establish new ones.
		for key, session := range m.sessions {
			if err := m.store.EndStream(ctx, session.EventID, now, session.LastSeenAt); err != nil {
				m.log.Error("close pre-outage stream session", "error", err)
			}
			delete(m.sessions, key)
		}
	}
	seen := make(map[string]bool)
	for camera, stream := range streams {
		for _, c := range stream.Consumers {
			key := fmt.Sprintf("%s/%d", camera, c.ID)
			seen[key] = true
			if existing := m.sessions[key]; existing != nil {
				if existing.Protocol == c.Protocol && existing.RemoteAddr == hostOnly(c.RemoteAddr) && existing.UserAgent == c.UserAgent {
					existing.Misses = 0
					existing.LastSeenAt = now
					if sig, ok := m.matchSignal(camera, c.RemoteAddr, c.UserAgent, now); ok {
						m.upgradeSessionIdentityLocked(ctx, existing, sig)
					}
					continue
				}
				if err := m.store.EndStream(ctx, existing.EventID, now, existing.LastSeenAt); err != nil {
					m.log.Error("close reused go2rtc connection ID", "error", err)
				}
				delete(m.sessions, key)
			}
			actor, actorType, confidence, suppressed, rule := m.classify(camera, c.Protocol, c.RemoteAddr, c.UserAgent)
			if sig, ok := m.matchSignal(camera, c.RemoteAddr, c.UserAgent, now); ok {
				actor, actorType, confidence = sig.actor, sig.actorType, sig.confidence
			}
			e := model.Event{Kind: "stream", Actor: actor, ActorType: actorType, Confidence: confidence,
				Camera: camera, Protocol: c.Protocol, RemoteAddr: hostOnly(c.RemoteAddr), UserAgent: c.UserAgent,
				Suppressed: suppressed, SuppressionRule: rule, StartedAt: now}
			id, err := m.store.Start(ctx, e)
			if err != nil {
				m.log.Error("persist stream start", "error", err)
				continue
			}
			m.sessions[key] = &model.ActiveSession{Key: key, EventID: id, Camera: camera, ConnectionID: c.ID,
				Actor: actor, ActorType: actorType, Confidence: confidence, Protocol: c.Protocol,
				RemoteAddr: hostOnly(c.RemoteAddr), UserAgent: c.UserAgent, Suppressed: suppressed,
				SuppressionRule: rule, StartedAt: now, LastSeenAt: now}
		}
	}
	for key, session := range m.sessions {
		if seen[key] {
			continue
		}
		session.Misses++
		// A consumer can disappear from one inventory snapshot during go2rtc
		// churn. Require a second successful miss before ending its audit event.
		if session.Misses < 2 {
			continue
		}
		if err := m.store.EndStream(ctx, session.EventID, now, session.LastSeenAt); err != nil {
			m.log.Error("persist stream end", "error", err)
		}
		delete(m.sessions, key)
	}
	m.checkpointStreamsLocked(ctx, now)
	m.pruneSignalsLocked(now)
	availabilityObserver := m.availabilityObserver
	m.mu.Unlock()
	if !wasFresh && availabilityObserver != nil {
		availabilityObserver(true)
	}
}

func shouldUpgradeIdentity(current, candidate string) bool {
	rank := func(confidence string) int {
		switch confidence {
		case "exact":
			return 3
		case "correlated":
			return 2
		case "inferred":
			return 1
		default:
			return 0
		}
	}
	return rank(candidate) > rank(current)
}

func (m *Manager) upgradeSessionIdentityLocked(ctx context.Context, session *model.ActiveSession, candidate signal) {
	if !shouldUpgradeIdentity(session.Confidence, candidate.confidence) {
		return
	}
	if m.store != nil {
		if err := m.store.UpdateEventIdentity(ctx, session.EventID, candidate.actor, candidate.actorType, candidate.confidence); err != nil {
			m.log.Error("upgrade active stream identity", "error", err)
			return
		}
	}
	session.Actor, session.ActorType, session.Confidence = candidate.actor, candidate.actorType, candidate.confidence
}

func (m *Manager) checkpointStreamsLocked(ctx context.Context, now time.Time) {
	if m.lastStreamCheckpoint.IsZero() {
		m.lastStreamCheckpoint = now
		return
	}
	if now.Sub(m.lastStreamCheckpoint) < streamCheckpointInterval {
		return
	}
	seen := make(map[int64]time.Time, len(m.sessions))
	for _, session := range m.sessions {
		seen[session.EventID] = session.LastSeenAt
	}
	if err := m.store.TouchEvents(ctx, seen); err != nil {
		m.log.Error("checkpoint active stream last seen", "error", err)
		return
	}
	m.lastStreamCheckpoint = now
}

func (m *Manager) runDOT(ctx context.Context) {
	ticker := time.NewTicker(m.cfg.PollInterval.Value())
	defer ticker.Stop()
	for {
		m.refreshDOT(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (m *Manager) refreshDOT(ctx context.Context) {
	dot, err := m.client.SanitizedDOT(ctx)
	if err != nil {
		if ctx.Err() == nil {
			m.log.Debug("fetch go2rtc graph", "error", err)
		}
		return
	}
	m.mu.Lock()
	m.dot = dot
	m.mu.Unlock()
}

func (m *Manager) classify(camera, protocol, remote, ua string) (string, string, string, bool, string) {
	host := hostOnly(remote)
	for _, r := range m.rules {
		if r.Stream != "" {
			ok, _ := path.Match(r.Stream, camera)
			if !ok {
				continue
			}
		}
		if r.Protocol != "" && !strings.EqualFold(r.Protocol, protocol) {
			continue
		}
		if r.ua != nil && !r.ua.MatchString(ua) {
			continue
		}
		if r.cidr != nil {
			addr, err := netip.ParseAddr(host)
			if err != nil || !r.cidr.Contains(addr) {
				continue
			}
		}
		t := r.ActorType
		if t == "" {
			t = "service"
		}
		return r.Actor, t, "service/device", r.Suppressed, r.Name
	}
	if strings.Contains(strings.ToLower(ua), "homeassistant") {
		return "Home Assistant", "service", "service/device", false, ""
	}
	if actor, ok := InferredBrowserActor(remote, ua); ok {
		return actor, "person", "inferred", false, ""
	}
	if host == "" {
		host = "unknown"
	}
	return "Unknown (" + host + ")", "unknown", "service/device", false, ""
}

func (m *Manager) matchSignal(camera, remote, ua string, now time.Time) (signal, bool) {
	// Search newest-first because repeated signaling for one camera is common.
	// This is a correlation hint, not proof, hence the caller's confidence value.
	host := hostOnly(remote)
	var userAgentCandidate signal
	candidateIdentity := ""
	ambiguousUserAgent := false
	for i := len(m.signals) - 1; i >= 0; i-- {
		s := m.signals[i]
		if s.camera != camera || now.Sub(s.at) > 15*time.Second {
			continue
		}
		signalHost := hostOnly(s.remote)
		if s.actorType == "service" {
			return s, true
		}
		sameHost := signalHost == "" || host == "" || host == signalHost
		sameUserAgent := s.userAgent != "" && ua != "" && s.userAgent == ua
		compatibleUserAgent := s.userAgent == "" || ua == "" || sameUserAgent
		if sameHost && compatibleUserAgent {
			return s, true
		}
		// Home Assistant and reverse proxies can make signaling and media appear
		// on different network addresses. A unique, exact browser user-agent for
		// the same camera is still a useful correlation hint. Do not guess when
		// two different people produced indistinguishable recent signals.
		if sameUserAgent {
			identity := s.actor + "\x00" + s.actorType
			if candidateIdentity == "" {
				candidateIdentity = identity
				userAgentCandidate = s
			} else if candidateIdentity != identity {
				ambiguousUserAgent = true
			}
		}
	}
	if candidateIdentity != "" && !ambiguousUserAgent {
		return userAgentCandidate, true
	}
	return signal{}, false
}

// InferredBrowserActor distinguishes interactive browser viewers from backend
// services when no authenticated username reaches the gateway. It intentionally
// does not claim which person is using the browser.
func InferredBrowserActor(remote, ua string) (string, bool) {
	lower := strings.ToLower(ua)
	if !strings.Contains(lower, "mozilla/") ||
		(!strings.Contains(lower, "applewebkit/") && !strings.Contains(lower, "firefox/") && !strings.Contains(lower, "gecko/")) {
		return "", false
	}
	host := hostOnly(remote)
	if host == "" {
		host = "unknown"
	}
	return "Browser viewer (" + host + ")", true
}

func hostOnly(remote string) string {
	fields := strings.Fields(remote)
	for i := len(fields) - 1; i >= 0; i-- {
		s := fields[i]
		if h, _, err := net.SplitHostPort(s); err == nil {
			if a, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
				return a.String()
			}
		}
		if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
			return a.String()
		}
	}
	return ""
}

func (m *Manager) RecordActivity(ctx context.Context, actor, remote, ua string, now time.Time) {
	a := model.Activity{Actor: actor, RemoteAddr: remote, UserAgent: ua, LastSeen: now.UTC()}
	key := actor + "\x00" + remote + "\x00" + ua
	m.mu.Lock()
	previous, exists := m.activities[key]
	if exists {
		a.EventID = previous.EventID
	} else {
		id, err := m.store.Start(ctx, model.Event{Kind: "frigate_activity", Actor: actor, ActorType: "person",
			Confidence: "exact", RemoteAddr: remote, UserAgent: ua, StartedAt: now.UTC()})
		if err != nil {
			m.log.Error("persist Frigate activity start", "error", err)
		} else {
			a.EventID = id
		}
	}
	m.activities[key] = a
	m.mu.Unlock()
	if err := m.store.TouchEvent(ctx, a.EventID, a.LastSeen); err != nil {
		m.log.Error("persist Frigate activity last seen", "error", err)
	}
	if err := m.store.TouchActivity(ctx, a); err != nil {
		m.log.Error("persist Frigate activity", "error", err)
	}
}

func (m *Manager) RecordSignal(ctx context.Context, camera, actor, actorType, confidence, remote, ua string, now time.Time) {
	m.mu.Lock()
	m.pruneSignalsLocked(now)
	m.signals = append(m.signals, signal{camera: camera, actor: actor, actorType: actorType,
		confidence: confidence, remote: remote, userAgent: ua, at: now.UTC()})
	for _, session := range m.sessions {
		if session.Camera != camera {
			continue
		}
		if candidate, ok := m.matchSignal(camera, session.RemoteAddr, session.UserAgent, now); ok {
			m.upgradeSessionIdentityLocked(ctx, session, candidate)
		}
	}
	m.mu.Unlock()
}

func (m *Manager) pruneSignalsLocked(now time.Time) {
	cut := now.UTC().Add(-15 * time.Second)
	i := 0
	for _, s := range m.signals {
		if s.at.After(cut) {
			m.signals[i] = s
			i++
		}
	}
	m.signals = m.signals[:i]
}

func (m *Manager) StartHTTP(ctx context.Context, kind, camera, details, actor, actorType, confidence, protocol, remote, ua string, now time.Time) int64 {
	classifiedActor, classifiedType, _, suppressed, rule := m.classify(camera, protocol, remote, ua)
	if rule != "" && actorType != "person" {
		actor, actorType = classifiedActor, classifiedType
	}
	leaseDuration, leasePrivacy := m.httpLease(kind, protocol)
	leaseKey := kind + "\x00" + camera + "\x00" + details + "\x00" + actor + "\x00" + remote + "\x00" + ua
	e := model.Event{Kind: kind, Actor: actor, ActorType: actorType, Confidence: confidence, Camera: camera,
		Protocol: protocol, RemoteAddr: remote, UserAgent: ua, Suppressed: suppressed, SuppressionRule: rule,
		StartedAt: now.UTC(), Details: details}
	if leaseDuration > 0 {
		// Snapshots and playback arrive as many short requests. Renew one logical
		// interval and return zero so ServeHTTP does not close it with the request.
		m.mu.Lock()
		if lease, ok := m.leases[leaseKey]; ok {
			lease.expires = now.Add(leaseDuration)
			m.leases[leaseKey] = lease
			m.mu.Unlock()
			if err := m.store.TouchEvent(ctx, lease.eventID, now); err != nil {
				m.log.Error("persist leased Frigate access last seen", "error", err)
			}
			return 0
		}
		// Keep the lookup and creation in one critical section so concurrent
		// identical requests cannot create an unreachable duplicate event.
		id, err := m.store.Start(ctx, e)
		if err != nil {
			m.mu.Unlock()
			m.log.Error("persist HTTP camera access", "error", err)
			return 0
		}
		m.leases[leaseKey] = activityLease{eventID: id, camera: camera, suppressed: suppressed, privacy: leasePrivacy, expires: now.Add(leaseDuration)}
		recordingObserver := m.recordingObserver
		m.mu.Unlock()
		if kind == "recording_playback" && recordingObserver != nil {
			e.ID = id
			recordingObserver(e)
		}
		return 0
	}
	id, err := m.store.Start(ctx, e)
	if err != nil {
		m.log.Error("persist HTTP camera access", "error", err)
		return 0
	}
	if kind == "webrtc_signal" {
		if err := m.store.End(ctx, id, now.UTC()); err != nil {
			m.log.Error("persist WebRTC signal end", "error", err)
		}
		return 0
	} else if httpAccessAffectsPrivacy(kind) {
		m.mu.Lock()
		m.liveHTTP[id] = liveHTTP{camera: camera, suppressed: suppressed}
		m.mu.Unlock()
	}
	return id
}

func (m *Manager) httpLease(kind, protocol string) (time.Duration, bool) {
	switch kind {
	case "snapshot_live":
		return m.cfg.SnapshotLease.Value(), true
	case "birdseye_live":
		if protocol == "http" {
			return m.cfg.SnapshotLease.Value(), true
		}
		return 0, false
	case "recording_playback", "recording_export_download", "recording_download":
		return m.cfg.ActivityWindow.Value(), false
	default:
		return 0, false
	}
}

func httpAccessAffectsPrivacy(kind string) bool {
	switch kind {
	case "jsmpeg", "mse", "birdseye_live":
		return true
	default:
		return false
	}
}

func (m *Manager) EndHTTP(ctx context.Context, id int64, now time.Time) {
	if id == 0 {
		return
	}
	m.mu.Lock()
	delete(m.liveHTTP, id)
	m.mu.Unlock()
	if err := m.store.End(ctx, id, now.UTC()); err != nil {
		m.log.Error("persist HTTP camera access end", "error", err)
	}
}

func (m *Manager) tick(now time.Time) {
	m.mu.Lock()
	m.pruneSignalsLocked(now)
	for k, a := range m.activities {
		if now.Sub(a.LastSeen) > m.cfg.ActivityWindow.Value() {
			if a.EventID != 0 {
				if err := m.store.End(context.Background(), a.EventID, a.LastSeen.Add(m.cfg.ActivityWindow.Value())); err != nil {
					m.log.Error("persist Frigate activity end", "error", err)
				}
			}
			delete(m.activities, k)
		}
	}
	for key, lease := range m.leases {
		if now.After(lease.expires) {
			if err := m.store.End(context.Background(), lease.eventID, lease.expires); err != nil {
				m.log.Error("persist leased Frigate access end", "error", err)
			}
			delete(m.leases, key)
		}
	}
	raw := make(map[string]bool)
	for _, s := range m.sessions {
		if !s.Suppressed {
			raw[s.Camera] = true
		}
	}
	for _, s := range m.liveHTTP {
		if !s.suppressed {
			raw[s.camera] = true
		}
	}
	for _, lease := range m.leases {
		if lease.privacy && !lease.suppressed {
			raw[lease.camera] = true
		}
	}
	if raw["birdseye"] {
		delete(raw, "birdseye")
		for _, camera := range m.birdseyeTargetsLocked() {
			raw[camera] = true
		}
	}
	all := make(map[string]bool)
	for camera := range m.privacy {
		all[camera] = true
	}
	for camera := range raw {
		all[camera] = true
	}
	var changes []struct {
		camera string
		active bool
	}
	for camera := range all {
		current := m.privacy[camera]
		if raw[camera] {
			// Alert immediately on observation; only the OFF transition is delayed.
			delete(m.zeroSince, camera)
			if !current {
				m.privacy[camera] = true
				changes = append(changes, struct {
					camera string
					active bool
				}{camera, true})
			}
			continue
		}
		if !current {
			continue
		}
		zero := m.zeroSince[camera]
		if zero.IsZero() {
			m.zeroSince[camera] = now
		} else if now.Sub(zero) >= m.cfg.PrivacyClearDelay.Value() {
			m.privacy[camera] = false
			delete(m.zeroSince, camera)
			changes = append(changes, struct {
				camera string
				active bool
			}{camera, false})
		}
	}
	observer := m.observer
	m.mu.Unlock()
	// Observers may perform network I/O, so never invoke them while holding the
	// manager mutex used by HTTP handlers and the polling loop.
	if observer != nil {
		for _, c := range changes {
			observer(c.camera, c.active)
		}
	}
}

func (m *Manager) birdseyeTargetsLocked() []string {
	var latest birdseyeControl
	for _, control := range m.birdseyeControlConns {
		if control.order > latest.order {
			latest = control
		}
	}
	if latest.order != 0 {
		cameras := make([]string, 0, len(latest.layout))
		for camera := range latest.layout {
			cameras = append(cameras, camera)
		}
		sort.Strings(cameras)
		return cameras
	}
	cameras := append([]string(nil), m.cfg.BirdseyeCameras...)
	sort.Strings(cameras)
	return cameras
}

func (m *Manager) hasBirdseyeLayoutSocketLocked() bool {
	for _, control := range m.birdseyeControlConns {
		if control.order != 0 {
			return true
		}
	}
	return false
}

func (m *Manager) Current() model.Current {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c := model.Current{Fresh: m.fresh, LastPoll: m.lastPoll, Privacy: make(map[string]bool), SanitizedGraph: m.dot}
	c.BirdseyeLayout = m.birdseyeTargetsLocked()
	if m.hasBirdseyeLayoutSocketLocked() {
		c.BirdseyeLayoutSource = "websocket"
	} else if len(m.cfg.BirdseyeCameras) > 0 {
		c.BirdseyeLayoutSource = "fallback"
	} else {
		c.BirdseyeLayoutSource = "unavailable"
	}
	for _, s := range m.sessions {
		c.Sessions = append(c.Sessions, *s)
	}
	for _, a := range m.activities {
		c.Activities = append(c.Activities, a)
	}
	for k, v := range m.privacy {
		c.Privacy[k] = v
	}
	// go2rtc does not expose a connection-start timestamp, so StartedAt is the
	// first successful poll that observed the consumer. The remaining fields
	// make the order total and prevent map iteration order from shuffling rows
	// whose sessions were first observed in the same poll.
	sort.Slice(c.Sessions, func(i, j int) bool {
		left, right := c.Sessions[i], c.Sessions[j]
		if !left.StartedAt.Equal(right.StartedAt) {
			return left.StartedAt.Before(right.StartedAt)
		}
		if left.Camera != right.Camera {
			return left.Camera < right.Camera
		}
		if left.ConnectionID != right.ConnectionID {
			return left.ConnectionID < right.ConnectionID
		}
		return left.Key < right.Key
	})
	sort.Slice(c.Activities, func(i, j int) bool { return c.Activities[i].LastSeen.After(c.Activities[j].LastSeen) })
	return c
}
