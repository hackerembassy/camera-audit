package mqttpub

import (
	"io"
	"log/slog"
	"testing"

	"xkem.am/camera-audit/internal/config"
)

func TestSlug(t *testing.T) {
	if got := slug("Electronics Room / Main"); got != "electronics_room_main" {
		t.Fatalf("unexpected slug %q", got)
	}
}

func TestShouldClearStaleRetainedViewerState(t *testing.T) {
	p := &Publisher{
		cfg: config.MQTT{TopicPrefix: "camera_audit"},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		states: map[string]bool{
			"workshop": false,
			"hall":     true,
		},
	}
	tests := []struct {
		name           string
		topic, payload string
		retained, want bool
	}{
		{name: "unknown stale ON", topic: "camera_audit/old_camera/viewer", payload: "ON", retained: true, want: true},
		{name: "known inactive ON", topic: "camera_audit/workshop/viewer", payload: "ON", retained: true, want: true},
		{name: "known active ON", topic: "camera_audit/hall/viewer", payload: "ON", retained: true, want: false},
		{name: "retained OFF", topic: "camera_audit/workshop/viewer", payload: "OFF", retained: true, want: false},
		{name: "live ON", topic: "camera_audit/workshop/viewer", payload: "ON", retained: false, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p.shouldClearRetained(tt.topic, tt.payload, tt.retained); got != tt.want {
				t.Fatalf("shouldClearRetained()=%v, want %v", got, tt.want)
			}
		})
	}
}

func TestShouldNotClearSlugCollisionWithActiveCamera(t *testing.T) {
	p := &Publisher{
		cfg: config.MQTT{TopicPrefix: "camera_audit"},
		states: map[string]bool{
			"Camera A": false,
			"Camera-A": true,
		},
	}
	if p.shouldClearRetained("camera_audit/camera_a/viewer", "ON", true) {
		t.Fatal("active camera sharing the state topic was cleared")
	}
}
