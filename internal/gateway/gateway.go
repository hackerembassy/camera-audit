package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"xkem.am/camera-audit/internal/audit"
	"xkem.am/camera-audit/internal/config"
	"xkem.am/camera-audit/internal/model"
	"xkem.am/camera-audit/internal/store"
)

type Gateway struct {
	cfg      config.Config
	manager  *audit.Manager
	store    *store.Store
	proxy    *httputil.ReverseProxy
	target   *url.URL
	tls      *tls.Config
	location *time.Location
	trusted  []netip.Prefix
	log      *slog.Logger
}

func New(cfg config.Config, manager *audit.Manager, store *store.Store, log *slog.Logger) (*Gateway, error) {
	target, err := url.Parse(cfg.FrigateURL)
	if err != nil {
		return nil, err
	}
	location, err := cfg.Location()
	if err != nil {
		return nil, err
	}
	transport, tlsConfig, err := frigateTransport(cfg)
	if err != nil {
		return nil, err
	}
	p := httputil.NewSingleHostReverseProxy(target)
	p.Transport = transport
	director := p.Director
	p.Director = func(r *http.Request) {
		director(r)
		if cfg.FrigateProxySecret != "" {
			r.Header.Set("X-Proxy-Secret", cfg.FrigateProxySecret)
		}
	}
	p.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Error("Frigate proxy", "error", err, "path", r.URL.Path)
		http.Error(w, "Frigate upstream unavailable", http.StatusBadGateway)
	}
	g := &Gateway{cfg: cfg, manager: manager, store: store, proxy: p, target: target, tls: tlsConfig, location: location, log: log}
	for _, raw := range cfg.TrustedProxies {
		prefix, _ := netip.ParsePrefix(raw)
		g.trusted = append(g.trusted, prefix)
	}
	return g, nil
}

func frigateTransport(cfg config.Config) (*http.Transport, *tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         cfg.FrigateTLSServerName,
		InsecureSkipVerify: cfg.FrigateTLSInsecureSkipVerify, // Explicit opt-in for Frigate's generated self-signed certificate.
	}
	if cfg.FrigateTLSCAFile != "" {
		certificate, err := os.ReadFile(cfg.FrigateTLSCAFile)
		if err != nil {
			return nil, nil, fmt.Errorf("read Frigate TLS CA: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(certificate) {
			return nil, nil, fmt.Errorf("read Frigate TLS CA: no certificates found")
		}
		tlsConfig.RootCAs = roots
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// net/http may add h2 to its TLS config. Keep the reusable template
	// separate because Gorilla's WebSocket upgrade requires HTTP/1.1 ALPN.
	transport.TLSClientConfig = tlsConfig.Clone()
	return transport, tlsConfig, nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// This credential belongs to the daemon, never to the browser or Authentik.
	r.Header.Del("X-Proxy-Secret")
	identity, trusted := g.identity(r)
	if !trusted {
		// Both identity and client-address headers share the same trust boundary.
		// Removing them also prevents an untrusted caller spoofing Frigate roles.
		stripProxyIdentity(r.Header, g.cfg.IdentityHeader)
	}
	if isAuditPath(r.URL.Path) || r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
		if r.URL.Path != "/healthz" && r.URL.Path != "/readyz" && (!trusted || identity == "") {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		g.serveAudit(w, r)
		return
	}

	now := time.Now().UTC()
	remote := g.clientIP(r, trusted)
	ua := r.UserAgent()
	actor, actorType, confidence := identity, "person", "exact"
	if actor == "" {
		if strings.Contains(strings.ToLower(ua), "homeassistant") {
			actor, actorType, confidence = "Home Assistant", "service", "service/device"
		} else {
			actor, actorType, confidence = "Unauthenticated service ("+remote+")", "unknown", "service/device"
		}
	} else {
		g.manager.RecordActivity(r.Context(), actor, remote, ua, now)
	}

	kind, camera, protocol, details := cameraAccess(r)
	var eventID int64
	if kind != "" {
		eventID = g.manager.StartHTTP(r.Context(), kind, camera, details, actor, actorType, confidence, protocol, remote, ua, now)
		if kind == "webrtc_signal" || kind == "mse" || (kind == "birdseye_live" && protocol == "ws") {
			g.manager.RecordSignal(camera, actor, actorType, "correlated", remote, ua, now)
		}
	}
	if isFrigateControlWebSocket(r) {
		g.serveFrigateControlWebSocket(w, r)
	} else {
		g.proxy.ServeHTTP(w, r)
	}
	if eventID != 0 {
		g.manager.EndHTTP(context.Background(), eventID, time.Now().UTC())
	}
}

func isAuditPath(requestPath string) bool {
	return requestPath == "/audit" || strings.HasPrefix(requestPath, "/audit/")
}

func stripProxyIdentity(h http.Header, configured string) {
	for _, name := range []string{
		configured, "Remote-User", "Remote-Groups", "Remote-Email", "Remote-Name",
		"X-Forwarded-User", "X-Forwarded-Groups", "X-Forwarded-Email",
		"X-authentik-username", "X-authentik-groups", "X-authentik-email", "X-authentik-uid",
		"X-Forwarded-For", "X-Real-IP",
	} {
		if name != "" {
			h.Del(name)
		}
	}
}

func cameraAccess(r *http.Request) (kind, camera, protocol, details string) {
	p := r.URL.Path
	if camera, protocol, details, ok := recordingPlayback(p); ok {
		return "recording_playback", camera, protocol, details
	}
	if strings.HasPrefix(p, "/live/jsmpeg/") {
		camera = strings.TrimPrefix(p, "/live/jsmpeg/")
		if camera == "birdseye" {
			return "birdseye_live", camera, "ws", ""
		}
		return "jsmpeg", camera, "ws", ""
	}
	if p == "/live/mse/api/ws" || p == "/api/go2rtc/api/ws" {
		camera = r.URL.Query().Get("src")
		if camera == "birdseye" {
			return "birdseye_live", camera, "ws", ""
		}
		return "mse", camera, "ws", ""
	}
	if p == "/api/go2rtc/webrtc" {
		return "webrtc_signal", r.URL.Query().Get("src"), "webrtc", ""
	}
	if strings.HasPrefix(p, "/api/") && strings.HasSuffix(p, "/latest.jpg") {
		camera = strings.TrimSuffix(strings.TrimPrefix(p, "/api/"), "/latest.jpg")
		if camera != "" && !strings.Contains(camera, "/") {
			if camera == "birdseye" {
				return "birdseye_live", camera, "http", ""
			}
			return "snapshot_live", camera, "http", ""
		}
	}
	return "", "", "", ""
}

func recordingPlayback(requestPath string) (camera, protocol, details string, ok bool) {
	parts := strings.Split(strings.Trim(requestPath, "/"), "/")
	if len(parts) == 0 {
		return "", "", "", false
	}
	if parts[0] == "api" {
		parts = parts[1:]
	}
	if len(parts) == 0 {
		return "", "", "", false
	}

	if parts[0] == "vod" {
		protocol = "hls"
		parts = parts[1:]
		if len(parts) >= 2 && parts[0] == "event" {
			return "", protocol, "event=" + parts[1], true
		}
		if len(parts) >= 6 && parts[0] == "clip" && parts[2] == "start" && parts[4] == "end" {
			return parts[1], protocol, "start=" + parts[3] + " end=" + parts[5], true
		}
		if len(parts) >= 5 && parts[1] == "start" && parts[3] == "end" {
			return parts[0], protocol, "start=" + parts[2] + " end=" + parts[4], true
		}
		if len(parts) >= 4 && strings.Contains(parts[0], "-") {
			return parts[3], protocol, "hour=" + strings.Join(parts[:3], "/"), true
		}
		return "", "", "", false
	}

	protocol = "http"
	if len(parts) >= 6 && parts[1] == "start" && parts[3] == "end" && parts[5] == "clip.mp4" {
		return parts[0], protocol, "start=" + parts[2] + " end=" + parts[4], true
	}
	if len(parts) >= 3 && parts[0] == "events" && parts[2] == "clip.mp4" {
		return "", protocol, "event=" + parts[1], true
	}
	if len(parts) >= 3 && parts[0] == "review" && parts[2] == "clip.mp4" {
		return "", protocol, "review=" + parts[1], true
	}
	if len(parts) == 3 && parts[2] == "clip.mp4" && parts[0] != "events" && parts[0] != "review" {
		return parts[0], protocol, "label=" + parts[1], true
	}
	return "", "", "", false
}

func (g *Gateway) identity(r *http.Request) (string, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return "", false
	}
	for _, p := range g.trusted {
		if p.Contains(addr) {
			return strings.TrimSpace(r.Header.Get(g.cfg.IdentityHeader)), true
		}
	}
	return "", false
}

func (g *Gateway) clientIP(r *http.Request, trusted bool) string {
	if trusted {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			candidate := strings.TrimSpace(strings.Split(xff, ",")[0])
			if a, err := netip.ParseAddr(candidate); err == nil {
				return a.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (g *Gateway) serveAudit(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz":
		w.WriteHeader(http.StatusNoContent)
	case "/readyz":
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		if err := g.store.Ping(ctx); err != nil {
			g.log.Warn("readiness database check", "error", err)
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		if !g.manager.Current().Fresh {
			http.Error(w, "go2rtc state is stale", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "/audit/api/v1/current":
		writeJSON(w, g.manager.Current())
	case "/audit/api/v1/dashboard":
		data, err := g.dashboardData(r.Context())
		if err != nil {
			g.log.Error("load dashboard data", "error", err)
			http.Error(w, "dashboard data unavailable", http.StatusInternalServerError)
			return
		}
		writeJSON(w, data)
	case "/audit/api/v1/history":
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		camera := r.URL.Query().Get("camera")
		var events []model.Event
		var err error
		switch r.URL.Query().Get("type") {
		case "":
			events, err = g.store.Recent(r.Context(), limit, camera)
		case "frigate":
			events, err = g.store.RecentNonRecordingFrigate(r.Context(), limit, camera)
		case "recordings":
			events, err = g.store.RecentRecordings(r.Context(), limit, camera)
		case "streams":
			events, err = g.store.RecentStreams(r.Context(), limit, camera)
		default:
			http.Error(w, "invalid history type", http.StatusBadRequest)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, events)
	case "/audit/api/v1/graph":
		w.Header().Set("Content-Type", "text/vnd.graphviz; charset=utf-8")
		_, _ = w.Write([]byte(g.manager.Current().SanitizedGraph))
	case "/audit/export.csv":
		g.exportCSV(w, r)
	default:
		if r.URL.Path == "/audit" || r.URL.Path == "/audit/" {
			g.dashboard(w, r)
			return
		}
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func (g *Gateway) exportCSV(w http.ResponseWriter, r *http.Request) {
	events, err := g.store.Recent(r.Context(), 1000, r.URL.Query().Get("camera"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="camera-audit.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "kind", "actor", "confidence", "camera", "protocol", "remote_addr", "suppressed", "started_at", "last_seen_at", "ended_at", "details"})
	for _, e := range events {
		end := ""
		if e.EndedAt != nil {
			end = g.csvTime(*e.EndedAt)
		}
		_ = cw.Write([]string{strconv.FormatInt(e.ID, 10), e.Kind, e.Actor, e.Confidence, e.Camera, e.Protocol,
			e.RemoteAddr, strconv.FormatBool(e.Suppressed), g.csvTime(e.StartedAt),
			g.csvTime(e.LastSeenAt), end, e.Details})
	}
	cw.Flush()
}

func (g *Gateway) csvTime(value time.Time) string {
	return value.In(g.location).Format(time.RFC3339)
}

const dashboardTimeLayout = "2006-01-02 15:04:05 -07:00"

func (g *Gateway) dashboardTime(value time.Time) string {
	if value.IsZero() {
		return "never"
	}
	return value.In(g.location).Format(dashboardTimeLayout)
}

type dashboardActivity struct {
	Actor      string `json:"actor"`
	RemoteAddr string `json:"remote_addr"`
	LastSeen   string `json:"last_seen"`
}

type dashboardEvent struct {
	Kind       string `json:"kind"`
	Camera     string `json:"camera"`
	Actor      string `json:"actor"`
	Protocol   string `json:"protocol"`
	Details    string `json:"details"`
	UserAgent  string `json:"user_agent,omitempty"`
	Expected   bool   `json:"expected"`
	StartedAt  string `json:"started_at"`
	LastSeenAt string `json:"last_seen_at"`
}

type dashboardSession struct {
	Camera     string `json:"camera"`
	Actor      string `json:"actor"`
	Confidence string `json:"identity_confidence"`
	Protocol   string `json:"protocol"`
	RemoteAddr string `json:"remote_addr"`
	UserAgent  string `json:"user_agent,omitempty"`
	Expected   bool   `json:"expected"`
	StartedAt  string `json:"started_at"`
	LastSeenAt string `json:"last_seen_at"`
}

type dashboardPrivacy struct {
	Camera string `json:"camera"`
	Active bool   `json:"active"`
}

type dashboardSnapshot struct {
	Fresh                bool                `json:"fresh"`
	LastPoll             string              `json:"last_poll"`
	Timezone             string              `json:"timezone"`
	BirdseyeLayout       []string            `json:"birdseye_layout"`
	BirdseyeLayoutSource string              `json:"birdseye_layout_source"`
	Privacy              []dashboardPrivacy  `json:"privacy"`
	Sessions             []dashboardSession  `json:"sessions"`
	Activities           []dashboardActivity `json:"activities"`
	Events               []dashboardEvent    `json:"events"`
	Recordings           []dashboardEvent    `json:"recordings"`
	StreamEvents         []dashboardEvent    `json:"stream_events"`
}

func (g *Gateway) dashboardActivities(activities []model.Activity) []dashboardActivity {
	out := make([]dashboardActivity, 0, len(activities))
	for _, activity := range activities {
		out = append(out, dashboardActivity{
			Actor: activity.Actor, RemoteAddr: activity.RemoteAddr,
			LastSeen: g.dashboardTime(activity.LastSeen),
		})
	}
	return out
}

func (g *Gateway) dashboardEvents(events []model.Event) []dashboardEvent {
	out := make([]dashboardEvent, 0, len(events))
	for _, event := range events {
		out = append(out, dashboardEvent{
			Kind: event.Kind, Camera: event.Camera, Actor: event.Actor, Protocol: event.Protocol,
			Details: event.Details, UserAgent: dashboardUserAgent(event.ActorType, event.Suppressed, event.UserAgent),
			Expected:   event.Suppressed,
			StartedAt:  g.dashboardTime(event.StartedAt),
			LastSeenAt: g.dashboardTime(event.LastSeenAt),
		})
	}
	return out
}

func dashboardUserAgent(actorType string, expected bool, userAgent string) string {
	if actorType == "unknown" || !expected {
		return userAgent
	}
	return ""
}

func (g *Gateway) dashboardSessions(sessions []model.ActiveSession) []dashboardSession {
	out := make([]dashboardSession, 0, len(sessions))
	for _, session := range sessions {
		out = append(out, dashboardSession{
			Camera: session.Camera, Actor: session.Actor, Confidence: session.Confidence,
			Protocol: session.Protocol, RemoteAddr: session.RemoteAddr,
			UserAgent: dashboardUserAgent(session.ActorType, session.Suppressed, session.UserAgent),
			Expected:  session.Suppressed, StartedAt: g.dashboardTime(session.StartedAt),
			LastSeenAt: g.dashboardTime(session.LastSeenAt),
		})
	}
	return out
}

func (g *Gateway) dashboardData(ctx context.Context) (dashboardSnapshot, error) {
	current := g.manager.Current()
	events, err := g.store.RecentNonRecordingFrigate(ctx, 100, "")
	if err != nil {
		return dashboardSnapshot{}, err
	}
	recordings, err := g.store.RecentRecordings(ctx, 100, "")
	if err != nil {
		return dashboardSnapshot{}, err
	}
	streamEvents, err := g.store.RecentStreams(ctx, 100, "")
	if err != nil {
		return dashboardSnapshot{}, err
	}
	overlayActiveStreamLastSeen(streamEvents, current.Sessions)
	sort.SliceStable(streamEvents, func(i, j int) bool {
		if streamEvents[i].LastSeenAt.Equal(streamEvents[j].LastSeenAt) {
			return streamEvents[i].ID > streamEvents[j].ID
		}
		return streamEvents[i].LastSeenAt.After(streamEvents[j].LastSeenAt)
	})
	privacy := make([]dashboardPrivacy, 0, len(current.Privacy))
	for camera, active := range current.Privacy {
		privacy = append(privacy, dashboardPrivacy{Camera: camera, Active: active})
	}
	sort.Slice(privacy, func(i, j int) bool { return privacy[i].Camera < privacy[j].Camera })
	return dashboardSnapshot{
		Fresh: current.Fresh, LastPoll: g.dashboardTime(current.LastPoll), Timezone: g.location.String(),
		BirdseyeLayout: current.BirdseyeLayout, BirdseyeLayoutSource: current.BirdseyeLayoutSource,
		Privacy: privacy, Sessions: g.dashboardSessions(current.Sessions),
		Activities: g.dashboardActivities(current.Activities), Events: g.dashboardEvents(events),
		Recordings: g.dashboardEvents(recordings), StreamEvents: g.dashboardEvents(streamEvents),
	}, nil
}

func overlayActiveStreamLastSeen(events []model.Event, sessions []model.ActiveSession) {
	activeLastSeen := make(map[int64]time.Time, len(sessions))
	for _, session := range sessions {
		activeLastSeen[session.EventID] = session.LastSeenAt
	}
	for i := range events {
		if lastSeen, active := activeLastSeen[events[i].ID]; active {
			events[i].LastSeenAt = lastSeen
		}
	}
}

var dashboardTemplate = template.Must(template.New("dashboard").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Camera access audit</title><style>
body{font:15px system-ui,sans-serif;max-width:1400px;margin:2rem auto;padding:0 1rem;color:#1f2937}h1,h2{color:#111827}
.meta{color:#4b5563}.ok{color:#047857}.bad{color:#b91c1c}.pill{display:inline-block;padding:.15rem .5rem;border-radius:1rem;background:#e5e7eb;margin-left:.25rem}
.table-wrap{overflow-x:auto;margin-bottom:2rem}table{border-collapse:collapse;width:100%;min-width:680px}th,td{text-align:left;padding:.45rem;border-bottom:1px solid #ddd;vertical-align:top}th{background:#f3f4f6;white-space:nowrap}
code{font-size:.85em}.ua{max-width:34rem;overflow-wrap:anywhere}.muted{color:#6b7280}a{color:#1d4ed8}</style></head><body>
<h1>Camera access audit</h1>
<p class="meta" aria-live="polite">go2rtc state: <strong id="fresh-state" class="muted">loading</strong> · last poll <span id="last-poll">loading</span> · <span id="update-state">updating</span></p>
<p>Displayed timezone: <strong id="timezone">loading</strong>. JSON API timestamps remain UTC.</p>
<p>Birdseye layout: <strong id="birdseye-source">loading</strong><span id="birdseye-layout"></span></p>
<h2>Room privacy alerts</h2><div class="table-wrap"><table><thead><tr><th>Camera</th><th>State</th></tr></thead><tbody id="privacy-rows"></tbody></table></div>
<h2>Current go2rtc consumers</h2><div class="table-wrap"><table><thead><tr><th>Last seen</th><th>Started</th><th>Camera</th><th>Actor</th><th>Confidence</th><th>Protocol</th><th>Remote</th><th>User agent</th><th>Expected</th></tr></thead><tbody id="session-rows"></tbody></table></div>
<h2>Active Frigate users</h2><div class="table-wrap"><table><thead><tr><th>User</th><th>Remote</th><th>Last activity</th></tr></thead><tbody id="activity-rows"></tbody></table></div>
<h2>Recent Frigate and viewer activity</h2><p><a href="/audit/export.csv">Export all CSV</a> · <a href="/audit/api/v1/history">All history JSON</a> · <a href="/audit/api/v1/current">Current JSON</a> · <a href="/audit/api/v1/graph">Sanitized go2rtc DOT</a></p>
<div class="table-wrap"><table><thead><tr><th>Last seen</th><th>Started</th><th>Kind</th><th>Camera</th><th>Actor</th><th>Details</th><th>Expected</th></tr></thead><tbody id="event-rows"></tbody></table></div>
<h2>Recording playback history</h2><div class="table-wrap"><table><thead><tr><th>Last seen</th><th>Started</th><th>Camera</th><th>Actor</th><th>Protocol</th><th>Details</th></tr></thead><tbody id="recording-rows"></tbody></table></div>
<h2>Recent go2rtc session history</h2><div class="table-wrap"><table><thead><tr><th>Last seen</th><th>Started</th><th>Camera</th><th>Actor</th><th>Protocol</th><th>User agent</th><th>Expected</th></tr></thead><tbody id="stream-rows"></tbody></table></div>
<script>
(function () {
  "use strict";
  var loading = false;
  function byID(id) { return document.getElementById(id); }
  function addCell(row, value, className, code) {
    var cell = document.createElement("td");
    var content = code ? document.createElement("code") : document.createElement("span");
    content.textContent = value || "—";
    if (className) { cell.className = className; }
    cell.appendChild(content); row.appendChild(cell);
  }
  function addExpected(row, expected) {
    var cell = document.createElement("td");
    var label = document.createElement("strong");
    label.textContent = expected ? "yes" : "no";
    label.className = expected ? "ok" : "bad";
    cell.appendChild(label); row.appendChild(cell);
  }
  function renderRows(id, items, columns, render) {
    var body = byID(id); body.replaceChildren();
    if (!items || items.length === 0) {
      var empty = document.createElement("tr");
      var cell = document.createElement("td"); cell.colSpan = columns; cell.className = "muted"; cell.textContent = "None observed";
      empty.appendChild(cell); body.appendChild(empty); return;
    }
    items.forEach(function (item) { var row = document.createElement("tr"); render(row, item); body.appendChild(row); });
  }
  function render(data) {
    var fresh = byID("fresh-state"); fresh.textContent = data.fresh ? "fresh" : "stale"; fresh.className = data.fresh ? "ok" : "bad";
    byID("last-poll").textContent = data.last_poll; byID("timezone").textContent = data.timezone;
    byID("birdseye-source").textContent = data.birdseye_layout_source;
    var layout = byID("birdseye-layout"); layout.replaceChildren();
    (data.birdseye_layout || []).forEach(function (camera) { var pill = document.createElement("span"); pill.className = "pill"; pill.textContent = camera; layout.appendChild(pill); });
    renderRows("privacy-rows", data.privacy, 2, function (row, item) { addCell(row, item.camera); addCell(row, item.active ? "VIEWED" : "clear", item.active ? "bad" : "ok"); });
    renderRows("session-rows", data.sessions, 9, function (row, item) {
      addCell(row, item.last_seen_at); addCell(row, item.started_at); addCell(row, item.camera); addCell(row, item.actor); addCell(row, item.identity_confidence);
      addCell(row, item.protocol); addCell(row, item.remote_addr, "", true); addCell(row, item.user_agent, "ua", true); addExpected(row, item.expected);
    });
    renderRows("activity-rows", data.activities, 3, function (row, item) { addCell(row, item.actor); addCell(row, item.remote_addr, "", true); addCell(row, item.last_seen); });
    renderRows("event-rows", data.events, 7, function (row, item) {
      addCell(row, item.last_seen_at); addCell(row, item.started_at); addCell(row, item.kind); addCell(row, item.camera); addCell(row, item.actor); addCell(row, item.details, "", true); addExpected(row, item.expected);
    });
    renderRows("recording-rows", data.recordings, 6, function (row, item) {
      addCell(row, item.last_seen_at); addCell(row, item.started_at); addCell(row, item.camera); addCell(row, item.actor); addCell(row, item.protocol); addCell(row, item.details, "", true);
    });
    renderRows("stream-rows", data.stream_events, 7, function (row, item) {
      addCell(row, item.last_seen_at); addCell(row, item.started_at); addCell(row, item.camera); addCell(row, item.actor); addCell(row, item.protocol); addCell(row, item.user_agent, "ua", true); addExpected(row, item.expected);
    });
    byID("update-state").textContent = "updated automatically"; byID("update-state").className = "";
  }
  async function refresh() {
    if (loading) { return; } loading = true;
    try {
      var response = await fetch("/audit/api/v1/dashboard", {cache: "no-store"});
      if (!response.ok) { throw new Error("HTTP " + response.status); }
      render(await response.json());
    } catch (error) {
      byID("update-state").textContent = "update failed; retrying"; byID("update-state").className = "bad";
    } finally { loading = false; }
  }
  refresh();
  setInterval(function () { if (!document.hidden) { refresh(); } }, 5000);
  document.addEventListener("visibilitychange", function () { if (!document.hidden) { refresh(); } });
}());
</script></body></html>`))

func (g *Gateway) dashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := dashboardTemplate.Execute(w, nil); err != nil {
		g.log.Error("render dashboard", "error", err)
	}
}

func (g *Gateway) String() string { return fmt.Sprintf("gateway(%s)", g.cfg.FrigateURL) }
