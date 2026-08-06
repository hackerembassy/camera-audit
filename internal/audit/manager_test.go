package audit

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"xkem.am/camera-audit/internal/config"
	"xkem.am/camera-audit/internal/model"
	"xkem.am/camera-audit/internal/store"
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

func TestBirdseyeUsesWebSocketLayoutBeforeFallback(t *testing.T) {
	m := &Manager{
		cfg:            config.Config{BirdseyeCameras: []string{"fallback"}},
		sessions:       map[string]*model.ActiveSession{"birdseye/1": {Camera: "birdseye"}},
		activities:     make(map[string]model.Activity),
		liveHTTP:       make(map[int64]liveHTTP),
		leases:         make(map[string]activityLease),
		privacy:        make(map[string]bool),
		zeroSince:      make(map[string]time.Time),
		birdseyeLayout: make(map[string]struct{}),
	}
	controlID := m.BirdseyeControlOpened()
	m.UpdateBirdseyeLayout(controlID, []string{"workshop", "hall", "workshop", "birdseye", ""})
	m.tick(time.Now())

	current := m.Current()
	if !reflect.DeepEqual(current.BirdseyeLayout, []string{"hall", "workshop"}) {
		t.Fatalf("unexpected Birdseye layout: %v", current.BirdseyeLayout)
	}
	if !current.Privacy["hall"] || !current.Privacy["workshop"] || current.Privacy["fallback"] || current.Privacy["birdseye"] {
		t.Fatalf("unexpected privacy fan-out: %v", current.Privacy)
	}
}

func TestBirdseyeFallsBackWithoutControlWebSocket(t *testing.T) {
	m := &Manager{
		cfg:        config.Config{BirdseyeCameras: []string{"fallback"}},
		sessions:   map[string]*model.ActiveSession{"birdseye/1": {Camera: "birdseye"}},
		activities: make(map[string]model.Activity),
		liveHTTP:   make(map[int64]liveHTTP),
		leases:     make(map[string]activityLease),
		privacy:    make(map[string]bool),
		zeroSince:  make(map[string]time.Time),
	}
	m.tick(time.Now())

	current := m.Current()
	if current.BirdseyeLayoutSource != "fallback" || !current.Privacy["fallback"] {
		t.Fatalf("fallback was not used: %#v", current)
	}
}

func TestBirdseyeLayoutExpiresWithSupplyingControlWebSocket(t *testing.T) {
	m := &Manager{cfg: config.Config{BirdseyeCameras: []string{"fallback"}}}
	supplyingID := m.BirdseyeControlOpened()
	idleID := m.BirdseyeControlOpened()
	defer m.BirdseyeControlClosed(idleID)
	m.UpdateBirdseyeLayout(supplyingID, []string{"workshop"})
	m.BirdseyeControlClosed(supplyingID)

	current := m.Current()
	if current.BirdseyeLayoutSource != "fallback" || !reflect.DeepEqual(current.BirdseyeLayout, []string{"fallback"}) {
		t.Fatalf("stale WebSocket layout remained authoritative: %#v", current)
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

func TestRecordingPlaybackIsLeasedWithoutPrivacyAlert(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := config.Config{ActivityWindow: config.Duration(time.Minute)}
	m, err := New(cfg, s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 6, 7, 0, 0, 0, time.UTC)
	if id := m.StartHTTP(context.Background(), "recording_playback", "workshop", "start=100 end=200", "alice", "person", "exact", "hls", "192.0.2.1", "browser", now); id != 0 {
		t.Fatalf("leased playback returned event id %d", id)
	}
	m.tick(now.Add(time.Second))
	if m.Current().Privacy["workshop"] {
		t.Fatal("historical playback activated room privacy")
	}

	touched := now.Add(30 * time.Second)
	m.StartHTTP(context.Background(), "recording_playback", "workshop", "start=100 end=200", "alice", "person", "exact", "hls", "192.0.2.1", "browser", touched)
	events, err := s.RecentFrigate(context.Background(), 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != "recording_playback" || events[0].Details != "start=100 end=200" || !events[0].LastSeenAt.Equal(touched) {
		t.Fatalf("unexpected playback events: %#v", events)
	}
}

func TestFrigateActivityUpdatesEventLastSeen(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m, err := New(config.Config{}, s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 6, 7, 0, 0, 0, time.UTC)
	m.RecordActivity(context.Background(), "alice", "192.0.2.1", "browser", now)
	lastSeen := now.Add(time.Minute)
	m.RecordActivity(context.Background(), "alice", "192.0.2.1", "browser", lastSeen)
	events, err := s.RecentFrigate(context.Background(), 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != "frigate_activity" || !events[0].LastSeenAt.Equal(lastSeen) {
		t.Fatalf("unexpected activity events: %#v", events)
	}
}

func TestBirdseyeHTTPSnapshotLeaseActivatesLayoutPrivacy(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := config.Config{
		SnapshotLease:   config.Duration(time.Minute),
		BirdseyeCameras: []string{"hall", "workshop"},
	}
	m, err := New(cfg, s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 6, 7, 0, 0, 0, time.UTC)
	m.StartHTTP(context.Background(), "birdseye_live", "birdseye", "", "alice", "person", "exact", "http", "192.0.2.1", "browser", now)
	m.tick(now.Add(time.Second))
	privacy := m.Current().Privacy
	if !privacy["hall"] || !privacy["workshop"] || privacy["birdseye"] {
		t.Fatalf("unexpected Birdseye privacy: %#v", privacy)
	}
}
