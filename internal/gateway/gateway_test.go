package gateway

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"xkem.am/camera-audit/internal/audit"
	"xkem.am/camera-audit/internal/config"
)

func TestCameraAccess(t *testing.T) {
	tests := []struct {
		url, kind, camera, protocol string
	}{
		{"http://x/live/jsmpeg/workshop", "jsmpeg", "workshop", "ws"},
		{"http://x/live/mse/api/ws?src=electronics", "mse", "electronics", "ws"},
		{"http://x/api/go2rtc/webrtc?src=birdseye", "webrtc_signal", "birdseye", "webrtc"},
		{"http://x/api/workshop/latest.jpg?h=100", "snapshot_live", "workshop", "http"},
		{"http://x/api/events/abc/snapshot.jpg", "", "", ""},
	}
	for _, tt := range tests {
		r := httptest.NewRequest("GET", tt.url, nil)
		kind, camera, protocol := cameraAccess(r)
		if kind != tt.kind || camera != tt.camera || protocol != tt.protocol {
			t.Errorf("%s: got %q %q %q", tt.url, kind, camera, protocol)
		}
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
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws" {
			http.NotFound(w, r)
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
	defer upstream.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager, err := audit.New(config.Config{BirdseyeCameras: []string{"fallback"}}, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := New(config.Config{FrigateURL: upstream.URL}, manager, nil, log)
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
