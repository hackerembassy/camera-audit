package audit

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"reflect"
	"sync"
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
		cfg:        config.Config{BirdseyeCameras: []string{"fallback"}},
		sessions:   map[string]*model.ActiveSession{"birdseye/1": {Camera: "birdseye"}},
		activities: make(map[string]model.Activity),
		liveHTTP:   make(map[int64]liveHTTP),
		leases:     make(map[string]activityLease),
		privacy:    make(map[string]bool),
		zeroSince:  make(map[string]time.Time),
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

func TestBirdseyeLayoutReturnsToLatestRemainingControlWebSocket(t *testing.T) {
	m := &Manager{cfg: config.Config{BirdseyeCameras: []string{"fallback"}}}
	first := m.BirdseyeControlOpened()
	second := m.BirdseyeControlOpened()
	m.UpdateBirdseyeLayout(first, []string{"hall"})
	m.UpdateBirdseyeLayout(second, []string{"workshop"})
	m.BirdseyeControlClosed(second)

	current := m.Current()
	if current.BirdseyeLayoutSource != "websocket" || !reflect.DeepEqual(current.BirdseyeLayout, []string{"hall"}) {
		t.Fatalf("latest remaining WebSocket layout was not restored: %#v", current)
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

func TestPersonSignalDoesNotMatchAddressSubstring(t *testing.T) {
	now := time.Now()
	m := &Manager{signals: []signal{{camera: "workshop", actor: "alice", actorType: "person", confidence: "correlated", remote: "10.0.0.1", at: now}}}
	if got, ok := m.matchSignal("workshop", "udp4 host 110.0.0.10:50000", "", now.Add(time.Second)); ok {
		t.Fatalf("unrelated address was correlated: %#v", got)
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

func TestConcurrentIdenticalRequestsCreateOneLease(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m, err := New(config.Config{SnapshotLease: config.Duration(time.Minute)}, s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 6, 7, 0, 0, 0, time.UTC)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 32 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			m.StartHTTP(context.Background(), "snapshot_live", "workshop", "", "alice", "person", "exact", "http", "192.0.2.1", "browser", now)
		}()
	}
	close(start)
	workers.Wait()

	events, err := s.RecentFrigate(context.Background(), 100, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || len(m.leases) != 1 {
		t.Fatalf("concurrent requests created %d events and %d leases", len(events), len(m.leases))
	}
}

func TestRecordSignalPrunesExpiredHints(t *testing.T) {
	now := time.Now().UTC()
	m := &Manager{signals: []signal{{camera: "old", at: now.Add(-time.Minute)}}}
	m.RecordSignal("current", "alice", "person", "correlated", "192.0.2.1", "browser", now)
	if len(m.signals) != 1 || m.signals[0].camera != "current" {
		t.Fatalf("expired signals were retained: %#v", m.signals)
	}
}

func TestCloseTrackedEndsLiveHTTPRequest(t *testing.T) {
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
	id := m.StartHTTP(context.Background(), "mse", "workshop", "", "alice", "person", "exact", "ws", "192.0.2.1", "browser", now)
	if id == 0 {
		t.Fatal("live request did not create an event")
	}
	m.closeTracked()
	events, err := s.RecentFrigate(context.Background(), 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].EndedAt == nil {
		t.Fatalf("live request was not closed: %#v", events)
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
