package gateway

import (
	"context"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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
		method, url, kind, camera, protocol, details string
	}{
		{"", "http://x/live/jsmpeg/workshop", "jsmpeg", "workshop", "ws", ""},
		{"", "http://x/live/jsmpeg/birdseye", "birdseye_live", "birdseye", "ws", ""},
		{"", "http://x/live/mse/api/ws?src=electronics", "mse", "electronics", "ws", ""},
		{"", "http://x/live/mse/api/ws?src=birdseye", "birdseye_live", "birdseye", "ws", ""},
		{"", "http://x/api/go2rtc/webrtc?src=birdseye", "webrtc_signal", "birdseye", "webrtc", ""},
		{"", "http://x/api/workshop/latest.jpg?h=100", "snapshot_live", "workshop", "http", ""},
		{"", "http://x/api/birdseye/latest.jpg?h=100", "birdseye_live", "birdseye", "http", ""},
		{"", "http://x/vod/workshop/start/100/end/200/index.m3u8", "recording_playback", "workshop", "hls", "start=100 end=200"},
		{"", "http://x/api/vod/clip/hall/start/300/end/400", "recording_playback", "hall", "hls", "start=300 end=400"},
		{"", "http://x/vod/2026-08/06/12/meeting_room/master.m3u8", "recording_playback", "meeting_room", "hls", "hour=2026-08/06/12"},
		{"", "http://x/api/workshop/start/100/end/200/clip.mp4", "recording_playback", "workshop", "http", "start=100 end=200"},
		{"", "http://x/api/events/abc/clip.mp4", "recording_playback", "", "http", "event=abc"},
		{"", "http://x/api/review/def/clip.mp4", "recording_playback", "", "http", "review=def"},
		{http.MethodPost, "http://x/api/export/workshop/start/100/end/200", "recording_export_requested", "workshop", "http", "mode=standard start=100 end=200"},
		{http.MethodPost, "http://x/api/export/custom/hall/start/300/end/400", "recording_export_requested", "hall", "http", "mode=custom start=300 end=400"},
		{"", "http://x/exports/export-123.mp4", "recording_export_download", "", "http", "export_file=export-123.mp4"},
		{"", "http://x/api/cases/case-123/download", "recording_export_download", "", "zip", "export_case=case-123"},
		{"", "http://x/recordings/2026-08-06/12/workshop/11.00.mp4", "recording_download", "workshop", "http", "date=2026-08-06 hour=12 file=11.00.mp4"},
		{"", "http://x/exports/export-123.webp", "", "", "", ""},
		{"", "http://x/api/export/workshop/start/100/end/200", "", "", "", ""},
		{"", "http://x/api/events/abc/snapshot.jpg", "", "", "", ""},
	}
	for _, tt := range tests {
		method := tt.method
		if method == "" {
			method = http.MethodGet
		}
		r := httptest.NewRequest(method, tt.url, nil)
		kind, camera, protocol, details := cameraAccess(r)
		if kind != tt.kind || camera != tt.camera || protocol != tt.protocol || details != tt.details {
			t.Errorf("%s: got %q %q %q %q", tt.url, kind, camera, protocol, details)
		}
	}
}

func TestBatchExportInspectionRestoresBodyAndKeepsOnlyExplicitFriendlyName(t *testing.T) {
	body := `{"items":[{"camera":"workshop","start_time":100.5,"end_time":200,"friendly_name":"private incident name"},{"camera":"hall","start_time":300,"end_time":400,"client_item_id":"opaque-secret"}],"new_case_name":"private case"}`
	request := httptest.NewRequest(http.MethodPost, "http://x/api/exports/batch", strings.NewReader(body))
	accesses := requestAccesses(request)
	restored, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != body {
		t.Fatalf("request body changed: %q", restored)
	}
	if len(accesses) != 2 {
		t.Fatalf("accesses=%#v", accesses)
	}
	if accesses[0].camera != "workshop" || accesses[0].details != "mode=batch item=1/2 start=100.5 end=200 export_name=private incident name" ||
		accesses[1].camera != "hall" || accesses[1].details != "mode=batch item=2/2 start=300 end=400" {
		t.Fatalf("unexpected batch metadata: %#v", accesses)
	}
	for _, access := range accesses {
		if strings.Contains(access.details, "private case") || strings.Contains(access.details, "secret") {
			t.Fatalf("free text leaked into audit details: %#v", access)
		}
	}
}

func TestSingleExportInspectionRestoresBodyAndKeepsFriendlyName(t *testing.T) {
	body := `{"name":"Doorbell package delivery","ffmpeg_input_args":"not audited"}`
	request := httptest.NewRequest(http.MethodPost, "http://x/api/export/doorbell/start/100/end/200", strings.NewReader(body))
	accesses := requestAccesses(request)
	restored, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != body {
		t.Fatalf("request body changed: %q", restored)
	}
	if len(accesses) != 1 || accesses[0].details != "mode=standard start=100 end=200 export_name=Doorbell package delivery" {
		t.Fatalf("accesses=%#v", accesses)
	}
}

func TestExportFileIdentity(t *testing.T) {
	camera, exportID, ok := exportFileIdentity("doorbell_20260806_222434-20260806_222507_m8y925.mp4")
	if !ok || camera != "doorbell" || exportID != "doorbell_m8y925" {
		t.Fatalf("camera=%q exportID=%q ok=%v", camera, exportID, ok)
	}
	if _, _, ok := exportFileIdentity("arbitrary.mp4"); ok {
		t.Fatal("accepted a non-Frigate export filename")
	}
}

func TestOversizedBatchExportBodyIsRestoredWithoutParsing(t *testing.T) {
	body := strings.Repeat("x", maxInspectedExportBody+100)
	request := httptest.NewRequest(http.MethodPost, "http://x/api/exports/batch", strings.NewReader(body))
	accesses := requestAccesses(request)
	restored, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != body {
		t.Fatal("oversized request body changed")
	}
	if len(accesses) != 1 || accesses[0].details != "mode=batch metadata=unavailable" {
		t.Fatalf("accesses=%#v", accesses)
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

func TestAuditPathBoundary(t *testing.T) {
	for requestPath, want := range map[string]bool{
		"/audit": true, "/audit/": true, "/audit/api/v1/current": true,
		"/auditor": false, "/audit-log": false,
	} {
		if got := isAuditPath(requestPath); got != want {
			t.Errorf("isAuditPath(%q)=%v, want %v", requestPath, got, want)
		}
	}
}

func TestAuditDelegationRequiresTrustedIdentity(t *testing.T) {
	called := false
	gateway := &Gateway{
		cfg:     config.Config{IdentityHeader: "X-authentik-username"},
		trusted: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		auditWeb: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			called = true
			w.WriteHeader(http.StatusNoContent)
		}),
	}

	request := httptest.NewRequest(http.MethodGet, "/audit/", nil)
	request.Header.Set("X-authentik-username", "alice")
	recorder := httptest.NewRecorder()
	gateway.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || !called {
		t.Fatalf("authenticated audit request was not delegated: status=%d called=%v", recorder.Code, called)
	}

	called = false
	request = httptest.NewRequest(http.MethodGet, "/audit/", nil)
	recorder = httptest.NewRecorder()
	gateway.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized || called {
		t.Fatalf("unauthenticated audit request crossed boundary: status=%d called=%v", recorder.Code, called)
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

func TestAuthenticatedBatchExportsAreAuditedPerCameraAndBodyIsPreserved(t *testing.T) {
	body := `{"items":[{"camera":"workshop","start_time":100,"end_time":200},{"camera":"hall","start_time":300,"end_time":400}],"new_case_name":"case name is not audited"}`
	receivedBody := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ := io.ReadAll(r.Body)
		receivedBody <- string(payload)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer upstream.Close()

	auditStore, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer auditStore.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.Config{
		FrigateURL: upstream.URL, IdentityHeader: "X-authentik-username",
		TrustedProxies: []string{"127.0.0.0/8"}, ActivityWindow: config.Duration(time.Minute),
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

	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/exports/batch", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-authentik-username", "alice")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusAccepted || <-receivedBody != body {
		t.Fatal("batch export was not proxied unchanged")
	}

	events, err := auditStore.RecentRecordings(context.Background(), 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events=%#v", events)
	}
	cameras := map[string]bool{}
	for _, event := range events {
		cameras[event.Camera] = true
		if event.Kind != "recording_export_requested" || event.Actor != "alice" || event.EndedAt == nil || strings.Contains(event.Details, "case name") {
			t.Fatalf("unexpected export event: %#v", event)
		}
	}
	if !cameras["workshop"] || !cameras["hall"] || manager.Current().Privacy["workshop"] || manager.Current().Privacy["hall"] {
		t.Fatalf("cameras=%v privacy=%v", cameras, manager.Current().Privacy)
	}
}

func TestExportDownloadInfersCameraAndResolvesFriendlyName(t *testing.T) {
	const filename = "doorbell_20260806_222434-20260806_222507_m8y925.mp4"
	var metadataCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/exports/doorbell_m8y925":
			metadataCalls.Add(1)
			if r.Header.Get("X-authentik-username") != "dipierro" {
				http.Error(w, "missing identity", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"camera":"doorbell","name":"Package at the front door"}`))
		case "/exports/" + filename:
			_, _ = w.Write([]byte("video"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	auditStore, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer auditStore.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.Config{
		FrigateURL: upstream.URL, IdentityHeader: "X-authentik-username",
		TrustedProxies: []string{"127.0.0.0/8"}, ActivityWindow: config.Duration(time.Minute),
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

	for range 2 {
		request, err := http.NewRequest(http.MethodGet, server.URL+"/exports/"+filename, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-authentik-username", "dipierro")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("status=%s", response.Status)
		}
	}

	events, err := auditStore.RecentRecordings(context.Background(), 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Camera != "doorbell" || events[0].Actor != "dipierro" ||
		events[0].Details != "export_file="+filename+" export_name=Package at the front door" {
		t.Fatalf("events=%#v", events)
	}
	if got := metadataCalls.Load(); got != 1 {
		t.Fatalf("metadata calls=%d, want one cached lookup", got)
	}
}

func TestAuditCSVDownloadIsAudited(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	auditStore, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer auditStore.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.Config{
		FrigateURL: upstream.URL, IdentityHeader: "X-authentik-username",
		TrustedProxies: []string{"127.0.0.0/8"},
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

	request, err := http.NewRequest(http.MethodGet, server.URL+"/audit/export.csv?camera=workshop", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-authentik-username", "alice")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%s", response.Status)
	}
	events, err := auditStore.RecentNonRecordingFrigate(context.Background(), 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != "audit_export_download" || events[0].Actor != "alice" ||
		events[0].Details != "camera=workshop" || events[0].EndedAt == nil {
		t.Fatalf("audit export events=%#v", events)
	}
}
