package audit

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"xkem.am/camera-audit/internal/config"
)

func TestHostOnly(t *testing.T) {
	tests := map[string]string{
		"192.168.1.2:54321":                     "192.168.1.2",
		"127.0.0.1:54321 forwarded 192.168.1.3": "192.168.1.3",
		"udp4 host 192.168.1.4:5555":            "192.168.1.4",
		"[2001:db8::1]:8555":                    "2001:db8::1",
	}
	for input, want := range tests {
		if got := hostOnly(input); got != want {
			t.Errorf("hostOnly(%q)=%q, want %q", input, got, want)
		}
	}
}

func TestHomeAssistantSignalMayHaveDifferentWebRTCPeerAddress(t *testing.T) {
	now := time.Now()
	m := &Manager{signals: []signal{{camera: "workshop", actor: "Home Assistant", actorType: "service", confidence: "correlated", remote: "10.0.0.2", userAgent: "HomeAssistant", at: now}}}
	got, ok := m.matchSignal("workshop", "udp4 host 10.0.0.99:50000", "Mozilla/5.0", now.Add(time.Second))
	if !ok || got.actor != "Home Assistant" {
		t.Fatalf("service-side HA signal was not correlated: %#v %v", got, ok)
	}
}

func TestClassifierFirstMatch(t *testing.T) {
	cfg := config.Config{Rules: []config.Rule{
		{Name: "frigate", Stream: "*", UserAgent: "(?i)frigate", Actor: "Frigate", Suppressed: true},
		{Name: "lan", Stream: "work*", RemoteCIDR: "192.168.0.0/16", Actor: "LAN device"},
	}}
	m, err := New(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	actor, _, _, suppressed, rule := m.classify("workshop", "tcp", "192.168.1.2:1234", "FFmpeg Frigate/1")
	if actor != "Frigate" || !suppressed || rule != "frigate" {
		t.Fatalf("unexpected classification: %q %v %q", actor, suppressed, rule)
	}
}
