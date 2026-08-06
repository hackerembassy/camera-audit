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
	workshopTopic := p.stateTopic("workshop")
	hallTopic := p.stateTopic("hall")
	tests := []struct {
		name           string
		topic, payload string
		retained, want bool
	}{
		{name: "unknown stale ON", topic: "camera_audit/old_camera/viewer", payload: "ON", retained: true, want: true},
		{name: "known inactive ON", topic: workshopTopic, payload: "ON", retained: true, want: true},
		{name: "known active ON", topic: hallTopic, payload: "ON", retained: true, want: false},
		{name: "retained OFF", topic: workshopTopic, payload: "OFF", retained: true, want: false},
		{name: "live ON", topic: workshopTopic, payload: "ON", retained: false, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p.shouldClearRetained(tt.topic, tt.payload, tt.retained); got != tt.want {
				t.Fatalf("shouldClearRetained()=%v, want %v", got, tt.want)
			}
		})
	}
}

func TestCameraTopicsDoNotCollideAfterSlugging(t *testing.T) {
	p := &Publisher{
		cfg: config.MQTT{TopicPrefix: "camera_audit"},
		states: map[string]bool{
			"Camera A": false,
			"Camera-A": true,
		},
	}
	inactiveTopic := p.stateTopic("Camera A")
	activeTopic := p.stateTopic("Camera-A")
	if inactiveTopic == activeTopic {
		t.Fatalf("camera topics collide: %q", activeTopic)
	}
	if !p.shouldClearRetained(inactiveTopic, "ON", true) {
		t.Fatal("inactive camera state was not cleared")
	}
	if p.shouldClearRetained(activeTopic, "ON", true) {
		t.Fatal("active camera state was cleared")
	}
	if got := cameraID("Камера"); got == "" || got == cameraID("相机") {
		t.Fatalf("non-ASCII camera IDs are not distinct: %q", got)
	}
}
