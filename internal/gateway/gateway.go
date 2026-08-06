package gateway

import (
	"context"
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
	"strconv"
	"strings"
	"time"

	"xkem.am/camera-audit/internal/audit"
	"xkem.am/camera-audit/internal/config"
	"xkem.am/camera-audit/internal/model"
	"xkem.am/camera-audit/internal/store"
)

type Gateway struct {
	cfg     config.Config
	manager *audit.Manager
	store   *store.Store
	proxy   *httputil.ReverseProxy
	trusted []netip.Prefix
	log     *slog.Logger
}

func New(cfg config.Config, manager *audit.Manager, store *store.Store, log *slog.Logger) (*Gateway, error) {
	target, err := url.Parse(cfg.FrigateURL)
	if err != nil {
		return nil, err
	}
	p := httputil.NewSingleHostReverseProxy(target)
	p.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Error("Frigate proxy", "error", err, "path", r.URL.Path)
		http.Error(w, "Frigate upstream unavailable", http.StatusBadGateway)
	}
	g := &Gateway{cfg: cfg, manager: manager, store: store, proxy: p, log: log}
	for _, raw := range cfg.TrustedProxies {
		prefix, _ := netip.ParsePrefix(raw)
		g.trusted = append(g.trusted, prefix)
	}
	return g, nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	identity, trusted := g.identity(r)
	if !trusted {
		stripProxyIdentity(r.Header, g.cfg.IdentityHeader)
	}
	if strings.HasPrefix(r.URL.Path, "/audit") || r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
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

	kind, camera, protocol := cameraAccess(r)
	var eventID int64
	if kind != "" {
		eventID = g.manager.StartHTTP(r.Context(), kind, camera, actor, actorType, confidence, protocol, remote, ua, now)
		if kind == "webrtc_signal" || kind == "mse" {
			g.manager.RecordSignal(camera, actor, actorType, "correlated", remote, ua, now)
		}
	}
	g.proxy.ServeHTTP(w, r)
	if eventID != 0 && kind != "snapshot_live" {
		g.manager.EndHTTP(context.Background(), eventID, time.Now().UTC())
	}
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

func cameraAccess(r *http.Request) (kind, camera, protocol string) {
	p := r.URL.Path
	if strings.HasPrefix(p, "/live/jsmpeg/") {
		return "jsmpeg", strings.TrimPrefix(p, "/live/jsmpeg/"), "ws"
	}
	if p == "/live/mse/api/ws" || p == "/api/go2rtc/api/ws" {
		return "mse", r.URL.Query().Get("src"), "ws"
	}
	if p == "/api/go2rtc/webrtc" {
		return "webrtc_signal", r.URL.Query().Get("src"), "webrtc"
	}
	if strings.HasPrefix(p, "/api/") && strings.HasSuffix(p, "/latest.jpg") {
		camera = strings.TrimSuffix(strings.TrimPrefix(p, "/api/"), "/latest.jpg")
		if camera != "" && !strings.Contains(camera, "/") {
			return "snapshot_live", camera, "http"
		}
	}
	return "", "", ""
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
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		if !g.manager.Current().Fresh {
			http.Error(w, "go2rtc state is stale", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "/audit/api/v1/current":
		writeJSON(w, g.manager.Current())
	case "/audit/api/v1/history":
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		events, err := g.store.Recent(r.Context(), limit, r.URL.Query().Get("camera"))
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
		g.dashboard(w, r)
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
	_ = cw.Write([]string{"id", "kind", "actor", "confidence", "camera", "protocol", "remote_addr", "suppressed", "started_at", "ended_at"})
	for _, e := range events {
		end := ""
		if e.EndedAt != nil {
			end = e.EndedAt.Format(time.RFC3339)
		}
		_ = cw.Write([]string{strconv.FormatInt(e.ID, 10), e.Kind, e.Actor, e.Confidence, e.Camera, e.Protocol,
			e.RemoteAddr, strconv.FormatBool(e.Suppressed), e.StartedAt.Format(time.RFC3339), end})
	}
	cw.Flush()
}

var dashboardTemplate = template.Must(template.New("dashboard").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Camera access audit</title><style>
body{font:15px system-ui,sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem;color:#1f2937}h1,h2{color:#111827}
.ok{color:#047857}.bad{color:#b91c1c}.pill{display:inline-block;padding:.15rem .5rem;border-radius:1rem;background:#e5e7eb}
table{border-collapse:collapse;width:100%;margin-bottom:2rem}th,td{text-align:left;padding:.45rem;border-bottom:1px solid #ddd}th{background:#f3f4f6}
code{font-size:.85em}a{color:#1d4ed8}</style></head><body>
<h1>Camera access audit</h1><p>go2rtc state: {{if .Current.Fresh}}<strong class="ok">fresh</strong>{{else}}<strong class="bad">stale</strong>{{end}} · last poll {{.Current.LastPoll}}</p>
<h2>Room privacy alerts</h2><table><tr><th>Camera</th><th>State</th></tr>{{range $camera,$active := .Current.Privacy}}<tr><td>{{$camera}}</td><td>{{if $active}}<strong class="bad">VIEWED</strong>{{else}}clear{{end}}</td></tr>{{else}}<tr><td colspan="2">No states yet</td></tr>{{end}}</table>
<h2>Current go2rtc consumers</h2><table><tr><th>Camera</th><th>Actor</th><th>Confidence</th><th>Protocol</th><th>Remote</th><th>Expected</th></tr>
{{range .Current.Sessions}}<tr><td>{{.Camera}}</td><td>{{.Actor}}</td><td>{{.Confidence}}</td><td>{{.Protocol}}</td><td><code>{{.RemoteAddr}}</code></td><td>{{.Suppressed}}</td></tr>{{else}}<tr><td colspan="6">None observed</td></tr>{{end}}</table>
<h2>Active Frigate users</h2><table><tr><th>User</th><th>Remote</th><th>Last activity</th></tr>{{range .Current.Activities}}<tr><td>{{.Actor}}</td><td><code>{{.RemoteAddr}}</code></td><td>{{.LastSeen}}</td></tr>{{else}}<tr><td colspan="3">None</td></tr>{{end}}</table>
<h2>Recent history</h2><p><a href="/audit/export.csv">Export CSV</a> · <a href="/audit/api/v1/current">Current JSON</a> · <a href="/audit/api/v1/graph">Sanitized go2rtc DOT</a></p>
<table><tr><th>Started</th><th>Kind</th><th>Camera</th><th>Actor</th><th>Confidence</th><th>Expected</th></tr>{{range .Events}}<tr><td>{{.StartedAt}}</td><td>{{.Kind}}</td><td>{{.Camera}}</td><td>{{.Actor}}</td><td>{{.Confidence}}</td><td>{{.Suppressed}}</td></tr>{{end}}</table>
</body></html>`))

func (g *Gateway) dashboard(w http.ResponseWriter, r *http.Request) {
	events, err := g.store.Recent(r.Context(), 100, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := dashboardTemplate.Execute(w, struct {
		Current model.Current
		Events  []model.Event
	}{g.manager.Current(), events}); err != nil {
		g.log.Error("render dashboard", "error", err)
	}
}

func (g *Gateway) String() string { return fmt.Sprintf("gateway(%s)", g.cfg.FrigateURL) }
