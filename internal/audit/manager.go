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

type snapshotLease struct {
	eventID    int64
	camera     string
	suppressed bool
	expires    time.Time
}

type PrivacyObserver func(camera string, active bool)
type AvailabilityObserver func(available bool)

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
	leases               map[string]snapshotLease
	signals              []signal
	privacy              map[string]bool
	zeroSince            map[string]time.Time
	lastPoll             time.Time
	fresh                bool
	dot                  string
	observer             PrivacyObserver
	availabilityObserver AvailabilityObserver
}

func New(cfg config.Config, s *store.Store, log *slog.Logger) (*Manager, error) {
	m := &Manager{
		cfg: cfg, store: s, client: go2rtc.New(cfg.Go2RTCURL), log: log,
		sessions: make(map[string]*model.ActiveSession), activities: make(map[string]model.Activity),
		liveHTTP: make(map[int64]liveHTTP), leases: make(map[string]snapshotLease),
		privacy: make(map[string]bool), zeroSince: make(map[string]time.Time),
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

func (m *Manager) SetObserver(fn PrivacyObserver)                  { m.observer = fn }
func (m *Manager) SetAvailabilityObserver(fn AvailabilityObserver) { m.availabilityObserver = fn }

func (m *Manager) Run(ctx context.Context) {
	poll := time.NewTicker(m.cfg.PollInterval.Value())
	state := time.NewTicker(time.Second)
	prune := time.NewTicker(24 * time.Hour)
	defer poll.Stop()
	defer state.Stop()
	defer prune.Stop()
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
		_ = m.store.End(context.Background(), session.EventID, now)
	}
	for _, activity := range m.activities {
		if activity.EventID != 0 {
			_ = m.store.End(context.Background(), activity.EventID, now)
		}
	}
	for _, lease := range m.leases {
		_ = m.store.End(context.Background(), lease.eventID, now)
	}
}

func (m *Manager) poll(ctx context.Context) {
	streams, err := m.client.Streams(ctx)
	if err != nil {
		m.mu.Lock()
		wasFresh := m.fresh
		m.fresh = false
		m.mu.Unlock()
		if wasFresh && m.availabilityObserver != nil {
			m.availabilityObserver(false)
		}
		m.log.Warn("poll go2rtc streams", "error", err)
		return
	}
	dot, dotErr := m.client.SanitizedDOT(ctx)
	now := time.Now().UTC()

	m.mu.Lock()
	defer m.mu.Unlock()
	wasFresh := m.fresh
	m.fresh = true
	m.lastPoll = now
	if dotErr == nil {
		m.dot = dot
	} else {
		m.log.Debug("fetch go2rtc graph", "error", dotErr)
	}
	if !wasFresh {
		for key, session := range m.sessions {
			if err := m.store.End(ctx, session.EventID, now); err != nil {
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
					continue
				}
				if err := m.store.End(ctx, existing.EventID, now); err != nil {
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
				SuppressionRule: rule, StartedAt: now}
		}
	}
	for key, session := range m.sessions {
		if seen[key] {
			continue
		}
		session.Misses++
		if session.Misses < 2 {
			continue
		}
		if err := m.store.End(ctx, session.EventID, now); err != nil {
			m.log.Error("persist stream end", "error", err)
		}
		delete(m.sessions, key)
	}
	cut := now.Add(-15 * time.Second)
	i := 0
	for _, s := range m.signals {
		if s.at.After(cut) {
			m.signals[i] = s
			i++
		}
	}
	m.signals = m.signals[:i]
	if !wasFresh && m.availabilityObserver != nil {
		go m.availabilityObserver(true)
	}
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
	if host == "" {
		host = "unknown"
	}
	return "Unknown (" + host + ")", "unknown", "service/device", false, ""
}

func (m *Manager) matchSignal(camera, remote, ua string, now time.Time) (signal, bool) {
	host := hostOnly(remote)
	for i := len(m.signals) - 1; i >= 0; i-- {
		s := m.signals[i]
		if s.camera != camera || now.Sub(s.at) > 15*time.Second {
			continue
		}
		if s.actorType != "service" && s.remote != "" && host != "" && !strings.Contains(remote, s.remote) {
			continue
		}
		if s.actorType != "service" && s.userAgent != "" && ua != "" && s.userAgent != ua {
			continue
		}
		return s, true
	}
	return signal{}, false
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
	if err := m.store.TouchActivity(ctx, a); err != nil {
		m.log.Error("persist Frigate activity", "error", err)
	}
}

func (m *Manager) RecordSignal(camera, actor, actorType, confidence, remote, ua string, now time.Time) {
	m.mu.Lock()
	m.signals = append(m.signals, signal{camera: camera, actor: actor, actorType: actorType,
		confidence: confidence, remote: remote, userAgent: ua, at: now.UTC()})
	m.mu.Unlock()
}

func (m *Manager) StartHTTP(ctx context.Context, kind, camera, actor, actorType, confidence, protocol, remote, ua string, now time.Time) int64 {
	classifiedActor, classifiedType, _, suppressed, rule := m.classify(camera, protocol, remote, ua)
	if rule != "" && actorType != "person" {
		actor, actorType = classifiedActor, classifiedType
	}
	if kind == "snapshot_live" {
		key := camera + "\x00" + actor + "\x00" + remote
		m.mu.Lock()
		if lease, ok := m.leases[key]; ok {
			lease.expires = now.Add(m.cfg.SnapshotLease.Value())
			m.leases[key] = lease
			m.mu.Unlock()
			return 0
		}
		m.mu.Unlock()
	}
	e := model.Event{Kind: kind, Actor: actor, ActorType: actorType, Confidence: confidence, Camera: camera,
		Protocol: protocol, RemoteAddr: remote, UserAgent: ua, Suppressed: suppressed, SuppressionRule: rule, StartedAt: now.UTC()}
	id, err := m.store.Start(ctx, e)
	if err != nil {
		m.log.Error("persist HTTP camera access", "error", err)
		return 0
	}
	if kind == "snapshot_live" {
		m.mu.Lock()
		key := camera + "\x00" + actor + "\x00" + remote
		m.leases[key] = snapshotLease{eventID: id, camera: camera, suppressed: suppressed, expires: now.Add(m.cfg.SnapshotLease.Value())}
		m.mu.Unlock()
	} else if kind == "webrtc_signal" {
		if err := m.store.End(ctx, id, now.UTC()); err != nil {
			m.log.Error("persist WebRTC signal end", "error", err)
		}
		return 0
	} else {
		m.mu.Lock()
		m.liveHTTP[id] = liveHTTP{camera: camera, suppressed: suppressed}
		m.mu.Unlock()
	}
	return id
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
				m.log.Error("persist snapshot-live end", "error", err)
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
		if !lease.suppressed {
			raw[lease.camera] = true
		}
	}
	if raw["birdseye"] {
		for _, camera := range m.cfg.BirdseyeCameras {
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
	m.mu.Unlock()
	if m.observer != nil {
		for _, c := range changes {
			m.observer(c.camera, c.active)
		}
	}
}

func (m *Manager) Current() model.Current {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c := model.Current{Fresh: m.fresh, LastPoll: m.lastPoll, Privacy: make(map[string]bool), SanitizedGraph: m.dot}
	for _, s := range m.sessions {
		c.Sessions = append(c.Sessions, *s)
	}
	for _, a := range m.activities {
		c.Activities = append(c.Activities, a)
	}
	for k, v := range m.privacy {
		c.Privacy[k] = v
	}
	sort.Slice(c.Sessions, func(i, j int) bool { return c.Sessions[i].StartedAt.Before(c.Sessions[j].StartedAt) })
	sort.Slice(c.Activities, func(i, j int) bool { return c.Activities[i].LastSeen.After(c.Activities[j].LastSeen) })
	return c
}
