package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"xkem.am/camera-audit/internal/audit"
	"xkem.am/camera-audit/internal/auditweb"
	"xkem.am/camera-audit/internal/config"
	"xkem.am/camera-audit/internal/store"
)

type Gateway struct {
	cfg      config.Config
	manager  *audit.Manager
	store    *store.Store
	proxy    *httputil.ReverseProxy
	metadata *http.Client
	target   *url.URL
	tls      *tls.Config
	trusted  []netip.Prefix
	log      *slog.Logger
	auditWeb http.Handler

	exportMu    sync.Mutex
	exportCache map[string]cachedExportMetadata
}

type cachedExportMetadata struct {
	camera, name string
	found        bool
	expires      time.Time
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
	metadataClient := &http.Client{
		Transport: transport,
		Timeout:   2 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	g := &Gateway{
		cfg: cfg, manager: manager, store: store, proxy: p, metadata: metadataClient,
		target: target, tls: tlsConfig, log: log,
		auditWeb:    auditweb.New(manager, store, location, log),
		exportCache: make(map[string]cachedExportMetadata),
	}
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
	if isAuditPath(r.URL.Path) || isHealthPath(r.URL.Path) {
		if !isHealthPath(r.URL.Path) && (!trusted || identity == "") {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if isHealthPath(r.URL.Path) {
			g.serveHealth(w, r)
			return
		}
		if r.URL.Path == "/audit/export.csv" {
			g.serveAuditedCSVExport(w, r, identity, trusted)
			return
		}
		g.auditWeb.ServeHTTP(w, r)
		return
	}

	now := time.Now().UTC()
	remote := g.clientIP(r, trusted)
	ua := r.UserAgent()
	actor, actorType, confidence := identity, "person", "exact"
	if actor == "" {
		if strings.Contains(strings.ToLower(ua), "homeassistant") {
			actor, actorType, confidence = "Home Assistant", "service", "service/device"
		} else if browserActor, ok := audit.InferredBrowserActor(remote, ua); ok {
			actor, actorType, confidence = browserActor, "person", "inferred"
		} else {
			actor, actorType, confidence = "Unauthenticated service ("+remote+")", "unknown", "service/device"
		}
	} else {
		g.manager.RecordActivity(r.Context(), actor, remote, ua, now)
	}

	accesses := requestAccesses(r)
	g.enrichExportDownloads(r, accesses, now)
	eventIDs := make([]int64, 0, len(accesses))
	for _, access := range accesses {
		eventID := g.manager.StartHTTP(r.Context(), access.kind, access.camera, access.details, actor, actorType, confidence, access.protocol, remote, ua, now)
		if eventID != 0 {
			eventIDs = append(eventIDs, eventID)
		}
		if access.kind == "webrtc_signal" || access.kind == "mse" || (access.kind == "birdseye_live" && access.protocol == "ws") {
			g.manager.RecordSignal(r.Context(), access.camera, actor, actorType, "correlated", remote, ua, now)
		}
	}
	if isFrigateControlWebSocket(r) {
		g.serveFrigateControlWebSocket(w, r)
	} else {
		g.proxy.ServeHTTP(w, r)
	}
	endedAt := time.Now().UTC()
	for _, eventID := range eventIDs {
		g.manager.EndHTTP(context.Background(), eventID, endedAt)
	}
}

func (g *Gateway) serveAuditedCSVExport(w http.ResponseWriter, r *http.Request, actor string, trusted bool) {
	now := time.Now().UTC()
	details := "scope=all"
	if camera := auditToken(r.URL.Query().Get("camera")); camera != "" {
		details = "camera=" + camera
	}
	eventID := g.manager.StartHTTP(r.Context(), "audit_export_download", "", details, actor, "person", "exact", "csv",
		g.clientIP(r, trusted), r.UserAgent(), now)
	g.auditWeb.ServeHTTP(w, r)
	if eventID != 0 {
		g.manager.EndHTTP(context.Background(), eventID, time.Now().UTC())
	}
}

func isAuditPath(requestPath string) bool {
	return requestPath == "/audit" || strings.HasPrefix(requestPath, "/audit/")
}

func isHealthPath(requestPath string) bool {
	return requestPath == "/healthz" || requestPath == "/readyz"
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

type httpAccess struct {
	kind, camera, protocol, details string
}

const (
	maxInspectedExportBody = 1 << 20
	maxBatchExportItems    = 50
)

func requestAccesses(r *http.Request) []httpAccess {
	if r.Method == http.MethodPost && r.URL.Path == "/api/exports/batch" {
		return batchExportAccesses(r)
	}
	kind, camera, protocol, details := cameraAccess(r)
	if kind == "" {
		return nil
	}
	access := httpAccess{kind: kind, camera: camera, protocol: protocol, details: details}
	if kind == "recording_export_requested" {
		if name := singleExportFriendlyName(r); name != "" {
			access.details += " export_name=" + name
		}
	}
	return []httpAccess{access}
}

func cameraAccess(r *http.Request) (kind, camera, protocol, details string) {
	p := r.URL.Path
	if kind, camera, protocol, details, ok := recordingAction(r.Method, p); ok {
		return kind, camera, protocol, details
	}
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

func recordingAction(method, requestPath string) (kind, camera, protocol, details string, ok bool) {
	parts := strings.Split(strings.Trim(requestPath, "/"), "/")
	if method == http.MethodPost && len(parts) >= 7 && parts[0] == "api" && parts[1] == "export" {
		if parts[2] == "custom" && len(parts) >= 8 && parts[4] == "start" && parts[6] == "end" {
			return "recording_export_requested", auditToken(parts[3]), "http",
				"mode=custom start=" + auditToken(parts[5]) + " end=" + auditToken(parts[7]), true
		}
		if parts[3] == "start" && parts[5] == "end" {
			return "recording_export_requested", auditToken(parts[2]), "http",
				"mode=standard start=" + auditToken(parts[4]) + " end=" + auditToken(parts[6]), true
		}
	}
	if method != http.MethodGet {
		return "", "", "", "", false
	}
	if len(parts) == 2 && parts[0] == "exports" && strings.EqualFold(path.Ext(parts[1]), ".mp4") {
		return "recording_export_download", "", "http", "export_file=" + auditToken(path.Base(parts[1])), true
	}
	if len(parts) == 4 && parts[0] == "api" && parts[1] == "cases" && parts[3] == "download" {
		return "recording_export_download", "", "zip", "export_case=" + auditToken(parts[2]), true
	}
	if len(parts) >= 5 && parts[0] == "recordings" && strings.EqualFold(path.Ext(parts[len(parts)-1]), ".mp4") {
		return "recording_download", auditToken(parts[3]), "http",
			"date=" + auditToken(parts[1]) + " hour=" + auditToken(parts[2]) + " file=" + auditToken(path.Base(parts[len(parts)-1])), true
	}
	return "", "", "", "", false
}

type replayReadCloser struct {
	io.Reader
	io.Closer
}

func batchExportAccesses(r *http.Request) []httpAccess {
	if r.Body == nil {
		return []httpAccess{{kind: "recording_export_requested", protocol: "http", details: "mode=batch metadata=missing"}}
	}
	original := r.Body
	prefix, err := io.ReadAll(io.LimitReader(original, maxInspectedExportBody+1))
	r.Body = replayReadCloser{Reader: io.MultiReader(bytes.NewReader(prefix), original), Closer: original}
	if err != nil || len(prefix) > maxInspectedExportBody {
		return []httpAccess{{kind: "recording_export_requested", protocol: "http", details: "mode=batch metadata=unavailable"}}
	}
	var body struct {
		Items []struct {
			Camera       string  `json:"camera"`
			StartTime    float64 `json:"start_time"`
			EndTime      float64 `json:"end_time"`
			FriendlyName string  `json:"friendly_name"`
		} `json:"items"`
	}
	if json.Unmarshal(prefix, &body) != nil || len(body.Items) == 0 || len(body.Items) > maxBatchExportItems {
		return []httpAccess{{kind: "recording_export_requested", protocol: "http", details: "mode=batch metadata=invalid"}}
	}
	accesses := make([]httpAccess, 0, len(body.Items))
	for index, item := range body.Items {
		details := fmt.Sprintf("mode=batch item=%d/%d start=%s end=%s", index+1, len(body.Items),
			strconv.FormatFloat(item.StartTime, 'f', -1, 64), strconv.FormatFloat(item.EndTime, 'f', -1, 64))
		if name := auditToken(item.FriendlyName); name != "" {
			details += " export_name=" + name
		}
		accesses = append(accesses, httpAccess{
			kind: "recording_export_requested", camera: auditToken(item.Camera), protocol: "http",
			details: details,
		})
	}
	return accesses
}

func singleExportFriendlyName(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	original := r.Body
	prefix, err := io.ReadAll(io.LimitReader(original, maxInspectedExportBody+1))
	r.Body = replayReadCloser{Reader: io.MultiReader(bytes.NewReader(prefix), original), Closer: original}
	if err != nil || len(prefix) > maxInspectedExportBody {
		return ""
	}
	var body struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(prefix, &body) != nil {
		return ""
	}
	return auditToken(body.Name)
}

var exportFilenamePattern = regexp.MustCompile(`^(.+)_\d{8}_\d{6}-\d{8}_\d{6}_([a-z0-9]{6})\.mp4$`)

func exportFileIdentity(filename string) (camera, exportID string, ok bool) {
	matches := exportFilenamePattern.FindStringSubmatch(path.Base(filename))
	if len(matches) != 3 {
		return "", "", false
	}
	camera = auditToken(matches[1])
	return camera, camera + "_" + matches[2], camera != ""
}

func (g *Gateway) enrichExportDownloads(r *http.Request, accesses []httpAccess, now time.Time) {
	for index := range accesses {
		access := &accesses[index]
		if access.kind != "recording_export_download" || access.protocol != "http" || !strings.HasPrefix(access.details, "export_file=") {
			continue
		}
		filename := strings.TrimPrefix(access.details, "export_file=")
		camera, exportID, ok := exportFileIdentity(filename)
		if !ok {
			continue
		}
		access.camera = camera
		metadata := g.cachedExportMetadata(r, exportID, now)
		if metadata.found {
			if metadata.camera != "" {
				access.camera = metadata.camera
			}
			if metadata.name != "" {
				access.details += " export_name=" + metadata.name
			}
		}
	}
}

func (g *Gateway) cachedExportMetadata(r *http.Request, exportID string, now time.Time) cachedExportMetadata {
	g.exportMu.Lock()
	if cached, ok := g.exportCache[exportID]; ok && now.Before(cached.expires) {
		g.exportMu.Unlock()
		return cached
	}
	g.exportMu.Unlock()

	metadata := g.fetchExportMetadata(r, exportID)
	metadata.expires = now.Add(5 * time.Minute)
	g.exportMu.Lock()
	g.exportCache[exportID] = metadata
	g.exportMu.Unlock()
	return metadata
}

func (g *Gateway) fetchExportMetadata(r *http.Request, exportID string) cachedExportMetadata {
	metadataURL := *g.target
	metadataURL.Path = strings.TrimRight(g.target.Path, "/") + "/api/exports/" + exportID
	metadataURL.RawPath = ""
	metadataURL.RawQuery = ""
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, metadataURL.String(), nil)
	if err != nil {
		return cachedExportMetadata{}
	}
	request.Header = r.Header.Clone()
	for _, header := range []string{"Accept-Encoding", "Content-Length", "Content-Type", "If-Match", "If-Modified-Since", "If-None-Match", "If-Unmodified-Since", "Range"} {
		request.Header.Del(header)
	}
	request.Header.Set("Accept", "application/json")
	if g.cfg.FrigateProxySecret != "" {
		request.Header.Set("X-Proxy-Secret", g.cfg.FrigateProxySecret)
	}
	response, err := g.metadata.Do(request)
	if err != nil {
		g.log.Debug("Frigate export metadata lookup", "error", err, "export_id", exportID)
		return cachedExportMetadata{}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return cachedExportMetadata{}
	}
	var body struct {
		Camera string `json:"camera"`
		Name   string `json:"name"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&body) != nil {
		return cachedExportMetadata{}
	}
	return cachedExportMetadata{camera: auditToken(body.Camera), name: auditToken(body.Name), found: true}
}

func auditToken(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	const maxRunes = 256
	runes := []rune(value)
	if len(runes) > maxRunes {
		value = string(runes[:maxRunes])
	}
	return value
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

func (g *Gateway) serveHealth(w http.ResponseWriter, r *http.Request) {
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
	default:
		http.NotFound(w, r)
	}
}

func (g *Gateway) String() string { return fmt.Sprintf("gateway(%s)", g.cfg.FrigateURL) }
