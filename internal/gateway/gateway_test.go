package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
