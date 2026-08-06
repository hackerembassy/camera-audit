package gateway

import (
	"context"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"xkem.am/camera-audit/internal/audit"
	"xkem.am/camera-audit/internal/config"
	"xkem.am/camera-audit/internal/model"
	"xkem.am/camera-audit/internal/store"
)

func TestCameraAccess(t *testing.T) {
	tests := []struct {
		url, kind, camera, protocol, details string
	}{
		{"http://x/live/jsmpeg/workshop", "jsmpeg", "workshop", "ws", ""},
		{"http://x/live/jsmpeg/birdseye", "birdseye_live", "birdseye", "ws", ""},
		{"http://x/live/mse/api/ws?src=electronics", "mse", "electronics", "ws", ""},
		{"http://x/live/mse/api/ws?src=birdseye", "birdseye_live", "birdseye", "ws", ""},
		{"http://x/api/go2rtc/webrtc?src=birdseye", "webrtc_signal", "birdseye", "webrtc", ""},
		{"http://x/api/workshop/latest.jpg?h=100", "snapshot_live", "workshop", "http", ""},
		{"http://x/api/birdseye/latest.jpg?h=100", "birdseye_live", "birdseye", "http", ""},
		{"http://x/vod/workshop/start/100/end/200/index.m3u8", "recording_playback", "workshop", "hls", "start=100 end=200"},
		{"http://x/api/vod/clip/hall/start/300/end/400", "recording_playback", "hall", "hls", "start=300 end=400"},
		{"http://x/vod/2026-08/06/12/meeting_room/master.m3u8", "recording_playback", "meeting_room", "hls", "hour=2026-08/06/12"},
		{"http://x/api/workshop/start/100/end/200/clip.mp4", "recording_playback", "workshop", "http", "start=100 end=200"},
		{"http://x/api/events/abc/clip.mp4", "recording_playback", "", "http", "event=abc"},
		{"http://x/api/review/def/clip.mp4", "recording_playback", "", "http", "review=def"},
		{"http://x/api/events/abc/snapshot.jpg", "", "", "", ""},
	}
	for _, tt := range tests {
		r := httptest.NewRequest("GET", tt.url, nil)
		kind, camera, protocol, details := cameraAccess(r)
		if kind != tt.kind || camera != tt.camera || protocol != tt.protocol || details != tt.details {
			t.Errorf("%s: got %q %q %q %q", tt.url, kind, camera, protocol, details)
		}
	}
}

func TestConfiguredTimezoneFormatsHumanAndCSVTimes(t *testing.T) {
	location, err := time.LoadLocation("Asia/Yerevan")
	if err != nil {
		t.Fatal(err)
	}
	gateway := &Gateway{location: location}
	value := time.Date(2026, 8, 6, 7, 30, 0, 0, time.UTC)
	if got, want := gateway.csvTime(value), "2026-08-06T11:30:00+04:00"; got != want {
		t.Fatalf("csvTime=%q, want %q", got, want)
	}
	if got, want := gateway.dashboardTime(value), "2026-08-06 11:30:00 +04:00"; got != want {
		t.Fatalf("dashboardTime=%q, want %q", got, want)
	}
	if got := gateway.dashboardTime(time.Time{}); got != "never" {
		t.Fatalf("zero dashboard time=%q", got)
	}
}

func TestStripProxyIdentity(t *testing.T) {
	h := http.Header{
		"X-Authentik-Username": []string{"mallory"},
		"X-Forwarded-For":      []string{"203.0.113.9"},
		"Authorization":        []string{"Bearer service-token"},
	}
	stripProxyIdentity(h, "X-authentik-username")
	if h.Get("X-authentik-username") != "" || h.Get("X-Forwarded-For") != "" {
		t.Fatal("proxy identity headers were not removed")
	}
	if h.Get("Authorization") == "" {
		t.Fatal("service authorization must be preserved")
	}
}

func TestAuditPathBoundaryAndUnknownRoute(t *testing.T) {
	for requestPath, want := range map[string]bool{
		"/audit": true, "/audit/": true, "/audit/api/v1/current": true,
		"/auditor": false, "/audit-log": false,
	} {
		if got := isAuditPath(requestPath); got != want {
			t.Errorf("isAuditPath(%q)=%v, want %v", requestPath, got, want)
		}
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/audit/api/v1/unknown", nil)
	(&Gateway{}).serveAudit(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("unknown audit route status=%d, want %d", recorder.Code, http.StatusNotFound)
	}
}

func TestDashboardUserAgentVisibility(t *testing.T) {
	for _, tt := range []struct {
		name, actorType, userAgent string
		expected, visible          bool
	}{
		{name: "known expected service", actorType: "service", userAgent: "Frigate", expected: true},
		{name: "unknown expected client", actorType: "unknown", userAgent: "mystery-client", expected: true, visible: true},
		{name: "unexpected known client", actorType: "service", userAgent: "HomeAssistant", visible: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := dashboardUserAgent(tt.actorType, tt.expected, tt.userAgent)
			if (got != "") != tt.visible {
				t.Fatalf("dashboardUserAgent()=%q, visible=%v", got, tt.visible)
			}
		})
	}
}

func TestDashboardSeparatesRecordingsAndAutoUpdates(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	for _, event := range []model.Event{
		{Kind: "frigate_activity", Actor: "alice", ActorType: "person", Confidence: "exact", StartedAt: now},
		{Kind: "recording_playback", Actor: "alice", ActorType: "person", Confidence: "exact", Camera: "workshop", StartedAt: now},
		{Kind: "stream", Actor: "Unknown (192.0.2.1)", ActorType: "unknown", Confidence: "service/device", Camera: "workshop", UserAgent: "mystery-client", StartedAt: now},
	} {
		if _, err := s.Start(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager, err := audit.New(config.Config{}, s, log)
	if err != nil {
		t.Fatal(err)
	}
	gateway := &Gateway{manager: manager, store: s, location: time.UTC, log: log}
	data, err := gateway.dashboardData(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Events) != 1 || data.Events[0].Kind != "frigate_activity" || len(data.Recordings) != 1 || data.Recordings[0].Kind != "recording_playback" {
		t.Fatalf("dashboard history was not separated: %#v", data)
	}
	if len(data.StreamEvents) != 1 || data.StreamEvents[0].UserAgent != "mystery-client" {
		t.Fatalf("stream user agent missing: %#v", data.StreamEvents)
	}
	var page strings.Builder
	if err := dashboardTemplate.Execute(&page, nil); err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"/audit/api/v1/dashboard", "setInterval", "Recording playback history", "User agent", "First observed", "vis.parseDOTNetwork", "vis-network@10.0.2"} {
		if !strings.Contains(page.String(), marker) {
			t.Errorf("dashboard is missing %q", marker)
		}
	}
}

func TestDashboardOverlaysActiveStreamLastSeenFromMemory(t *testing.T) {
	persisted := time.Date(2026, 8, 6, 7, 0, 0, 0, time.UTC)
	live := persisted.Add(4*time.Minute + 59*time.Second)
	events := []model.Event{{ID: 42, Kind: "stream", LastSeenAt: persisted}}
	sessions := []model.ActiveSession{{EventID: 42, LastSeenAt: live}}
	active := overlayActiveStreamLastSeen(events, sessions)
	if !events[0].LastSeenAt.Equal(live) {
		t.Fatalf("dashboard history last seen=%v, want live value %v", events[0].LastSeenAt, live)
	}
	gateway := &Gateway{location: time.UTC}
	rows := gateway.dashboardStreamEvents(events, active)
	if len(rows) != 1 || !rows[0].Live {
		t.Fatalf("active dashboard history row was not marked live: %#v", rows)
	}
}

func TestParseBirdseyeLayout(t *testing.T) {
	tests := []struct {
		name    string
		message string
		want    map[string]bool
		ok      bool
	}{
		{
			name:    "Frigate string payload",
			message: `{"topic":"birdseye_layout","payload":"{\"workshop\":{\"x\":0},\"hall\":{\"x\":100}}"}`,
			want:    map[string]bool{"workshop": true, "hall": true},
			ok:      true,
		},
		{
			name:    "object payload",
			message: `{"topic":"birdseye_layout","payload":{"entrance":{"x":0}}}`,
			want:    map[string]bool{"entrance": true},
			ok:      true,
		},
		{name: "unrelated", message: `{"topic":"events","payload":{}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cameras, ok := parseBirdseyeLayout([]byte(tt.message))
			if ok != tt.ok {
				t.Fatalf("ok=%v, want %v", ok, tt.ok)
			}
			got := make(map[string]bool, len(cameras))
			for _, camera := range cameras {
				got[camera] = true
			}
			if len(got) != len(tt.want) {
				t.Fatalf("cameras=%v, want %v", got, tt.want)
			}
			for camera := range tt.want {
				if !got[camera] {
					t.Fatalf("camera %q missing from %v", camera, got)
				}
			}
		})
	}
}

func TestFrigateControlWebSocketRelayObservesLayout(t *testing.T) {
	const layoutMessage = `{"topic":"birdseye_layout","payload":"{\"workshop\":{\"x\":0},\"hall\":{\"x\":100}}"}`
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("X-Proxy-Secret") != "gateway-secret" {
			http.Error(w, "missing proxy secret", http.StatusUnauthorized)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		if err := conn.WriteMessage(websocket.TextMessage, []byte(layoutMessage)); err != nil {
			return
		}
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			return
		}
		_ = conn.WriteMessage(messageType, message)
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager, err := audit.New(config.Config{BirdseyeCameras: []string{"fallback"}}, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := New(config.Config{
		FrigateURL:                   upstream.URL,
		FrigateTLSInsecureSkipVerify: true,
		FrigateProxySecret:           "gateway-secret",
	}, manager, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	client, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, message, err := client.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if string(message) != layoutMessage {
		t.Fatalf("layout message changed in transit: %s", message)
	}

	deadline := time.Now().Add(time.Second)
	for {
		current := manager.Current()
		if current.BirdseyeLayoutSource == "websocket" && strings.Join(current.BirdseyeLayout, ",") == "hall,workshop" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("layout was not observed: %#v", current)
		}
		time.Sleep(time.Millisecond)
	}

	payload := []byte{0, 1, 2, 3, 4}
	if err := client.WriteMessage(websocket.BinaryMessage, payload); err != nil {
		t.Fatal(err)
	}
	messageType, echoed, err := client.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if messageType != websocket.BinaryMessage || string(echoed) != string(payload) {
		t.Fatalf("binary message changed in transit: type=%d payload=%v", messageType, echoed)
	}
}

func TestFrigateTLSCAAndProxySecret(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Proxy-Secret") != "gateway-secret" {
			http.Error(w, "missing proxy secret", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	caFile := filepath.Join(t.TempDir(), "frigate-ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})
	if err := os.WriteFile(caFile, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	gateway, err := New(config.Config{
		FrigateURL:         upstream.URL,
		FrigateTLSCAFile:   caFile,
		FrigateProxySecret: "gateway-secret",
	}, nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway)
	defer server.Close()

	request, err := http.NewRequest(http.MethodGet, server.URL+"/api/version", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Proxy-Secret", "browser-supplied-secret")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%s", response.Status)
	}
}

func TestAuthenticatedRecordingPlaybackIsAuditedWithoutPrivacy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	auditStore, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer auditStore.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.Config{
		FrigateURL:     upstream.URL,
		IdentityHeader: "X-authentik-username",
		TrustedProxies: []string{"127.0.0.0/8"},
		ActivityWindow: config.Duration(time.Minute),
	}
	manager, err := audit.New(cfg, auditStore, log)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := New(cfg, manager, auditStore, log)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway)
	defer server.Close()

	request, err := http.NewRequest(http.MethodGet, server.URL+"/vod/workshop/start/100/end/200/index.m3u8", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-authentik-username", "alice")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()

	events, err := auditStore.RecentFrigate(context.Background(), 10, "")
	if err != nil {
		t.Fatal(err)
	}
	kinds := make(map[string]model.Event, len(events))
	for _, event := range events {
		kinds[event.Kind] = event
	}
	playback, ok := kinds["recording_playback"]
	if !ok || playback.Actor != "alice" || playback.Camera != "workshop" || playback.Details != "start=100 end=200" {
		t.Fatalf("playback was not audited: %#v", events)
	}
	if manager.Current().Privacy["workshop"] {
		t.Fatal("recording playback activated privacy")
	}
}
