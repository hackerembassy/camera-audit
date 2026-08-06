package audit

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
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

func TestCurrentSessionsUseDeterministicFirstObservedOrder(t *testing.T) {
	firstSeen := time.Date(2026, 8, 6, 7, 0, 0, 0, time.UTC)
	m := &Manager{sessions: map[string]*model.ActiveSession{
		"workshop/20": {Key: "workshop/20", Camera: "workshop", ConnectionID: 20, StartedAt: firstSeen},
		"hall/30":     {Key: "hall/30", Camera: "hall", ConnectionID: 30, StartedAt: firstSeen.Add(-time.Second)},
		"hall/20":     {Key: "hall/20", Camera: "hall", ConnectionID: 20, StartedAt: firstSeen},
		"hall/10":     {Key: "hall/10", Camera: "hall", ConnectionID: 10, StartedAt: firstSeen},
	}}

	want := []string{"hall/30", "hall/10", "hall/20", "workshop/20"}
	for attempt := 0; attempt < 20; attempt++ {
		current := m.Current()
		got := make([]string, 0, len(current.Sessions))
		for _, session := range current.Sessions {
			got = append(got, session.Key)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("session order=%v, want %v", got, want)
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

func TestPersonSignalDoesNotMatchAddressSubstring(t *testing.T) {
	now := time.Now()
	m := &Manager{signals: []signal{{camera: "workshop", actor: "alice", actorType: "person", confidence: "correlated", remote: "10.0.0.1", at: now}}}
	if got, ok := m.matchSignal("workshop", "udp4 host 110.0.0.10:50000", "", now.Add(time.Second)); ok {
		t.Fatalf("unrelated address was correlated: %#v", got)
	}
}

func TestPersonSignalMayCrossHomeAssistantProxyWithSameBrowser(t *testing.T) {
	now := time.Now()
	const safari = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/27.0 Safari/605.1.15"
	m := &Manager{signals: []signal{{camera: "doorbell_sub", actor: "alice", actorType: "person", confidence: "correlated", remote: "37.186.119.0", userAgent: safari, at: now}}}
	got, ok := m.matchSignal("doorbell_sub", "10.13.37.3:49152", safari, now.Add(8*time.Second))
	if !ok || got.actor != "alice" || got.actorType != "person" {
		t.Fatalf("proxied browser signal was not correlated: %#v %v", got, ok)
	}
}

func TestPersonSignalDoesNotCrossProxyWhenBrowserIdentityIsAmbiguous(t *testing.T) {
	now := time.Now()
	const safari = "Mozilla/5.0 AppleWebKit/605.1.15 Version/27.0 Safari/605.1.15"
	m := &Manager{signals: []signal{
		{camera: "doorbell_sub", actor: "alice", actorType: "person", remote: "192.0.2.1", userAgent: safari, at: now},
		{camera: "doorbell_sub", actor: "bob", actorType: "person", remote: "192.0.2.2", userAgent: safari, at: now},
	}}
	if got, ok := m.matchSignal("doorbell_sub", "10.13.37.3:49152", safari, now.Add(time.Second)); ok {
		t.Fatalf("ambiguous browser signal was correlated: %#v", got)
	}
}

func TestClassifyInfersInteractiveBrowserAsPerson(t *testing.T) {
	m := &Manager{}
	actor, actorType, confidence, _, _ := m.classify("doorbell_sub", "ws", "10.13.37.3:49152", "Mozilla/5.0 AppleWebKit/605.1.15 Version/27.0 Safari/605.1.15")
	if actor != "Browser viewer (10.13.37.3)" || actorType != "person" || confidence != "inferred" {
		t.Fatalf("browser classification=%q %q %q", actor, actorType, confidence)
	}
}

func TestIdentityConfidenceOnlyUpgrades(t *testing.T) {
	for _, tt := range []struct {
		current, candidate string
		want               bool
	}{
		{current: "service/device", candidate: "inferred", want: true},
		{current: "inferred", candidate: "correlated", want: true},
		{current: "correlated", candidate: "inferred"},
		{current: "exact", candidate: "correlated"},
	} {
		if got := shouldUpgradeIdentity(tt.current, tt.candidate); got != tt.want {
			t.Errorf("shouldUpgradeIdentity(%q,%q)=%v, want %v", tt.current, tt.candidate, got, tt.want)
		}
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
	var notified []model.Event
	m.SetRecordingObserver(func(event model.Event) { notified = append(notified, event) })
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
	if len(notified) != 1 || notified[0].Actor != "alice" || notified[0].Camera != "workshop" || notified[0].ID == 0 {
		t.Fatalf("recording notifications=%#v, want one logical playback", notified)
	}
	events, err := s.RecentFrigate(context.Background(), 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != "recording_playback" || events[0].Details != "start=100 end=200" || !events[0].LastSeenAt.Equal(touched) {
		t.Fatalf("unexpected playback events: %#v", events)
	}
}

func TestRecordingExportAndDownloadEventsDoNotAffectPrivacy(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m, err := New(config.Config{ActivityWindow: config.Duration(time.Minute)}, s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	var notified []model.Event
	m.SetRecordingObserver(func(event model.Event) { notified = append(notified, event) })
	now := time.Date(2026, 8, 6, 7, 0, 0, 0, time.UTC)
	exportID := m.StartHTTP(context.Background(), "recording_export_requested", "workshop", "mode=standard start=100 end=200", "alice", "person", "exact", "http", "192.0.2.1", "browser", now)
	if exportID == 0 || len(m.liveHTTP) != 0 {
		t.Fatalf("export event id=%d liveHTTP=%v", exportID, m.liveHTTP)
	}
	m.EndHTTP(context.Background(), exportID, now.Add(time.Second))
	if id := m.StartHTTP(context.Background(), "recording_export_download", "", "export_file=one.mp4", "alice", "person", "exact", "http", "192.0.2.1", "browser", now); id != 0 {
		t.Fatalf("leased download returned event id %d", id)
	}
	m.tick(now.Add(time.Second))
	if m.Current().Privacy["workshop"] || m.Current().Privacy[""] {
		t.Fatalf("recording actions activated privacy: %v", m.Current().Privacy)
	}
	events, err := s.RecentRecordings(context.Background(), 10, "")
	if err != nil || len(events) != 2 {
		t.Fatalf("recording events=%#v err=%v", events, err)
	}
	if len(notified) != 2 || notified[0].Kind != "recording_export_requested" || notified[1].Kind != "recording_export_download" {
		t.Fatalf("recording notifications=%#v", notified)
	}
}

func TestRecordingActivityKinds(t *testing.T) {
	for _, kind := range []string{"recording_playback", "recording_export_requested", "recording_export_download", "recording_download"} {
		if !isRecordingActivity(kind) {
			t.Errorf("isRecordingActivity(%q)=false", kind)
		}
	}
	if isRecordingActivity("audit_export_download") {
		t.Error("audit CSV download must not be a recording notification")
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
	m.RecordSignal(context.Background(), "current", "alice", "person", "correlated", "192.0.2.1", "browser", now)
	if len(m.signals) != 1 || m.signals[0].camera != "current" {
		t.Fatalf("expired signals were retained: %#v", m.signals)
	}
}

func TestRecordSignalImmediatelyUpgradesActiveGenericSession(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	const safari = "Mozilla/5.0 AppleWebKit/605.1.15 Version/27.0 Safari/605.1.15"
	eventID, err := s.Start(ctx, model.Event{Kind: "stream", Actor: "Browser viewer (10.13.37.3)", ActorType: "person", Confidence: "inferred", Camera: "doorbell_sub", RemoteAddr: "10.13.37.3", UserAgent: safari, StartedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	session := &model.ActiveSession{EventID: eventID, Camera: "doorbell_sub", Actor: "Browser viewer (10.13.37.3)", ActorType: "person", Confidence: "inferred", RemoteAddr: "10.13.37.3", UserAgent: safari}
	m := &Manager{
		store: s, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		sessions: map[string]*model.ActiveSession{"doorbell_sub/42": session},
	}

	m.RecordSignal(ctx, "doorbell_sub", "alice", "person", "correlated", "37.186.119.0", safari, now)
	if session.Actor != "alice" || session.ActorType != "person" || session.Confidence != "correlated" {
		t.Fatalf("active session identity was not upgraded: %#v", session)
	}
	events, err := s.RecentStreams(ctx, 10, "")
	if err != nil || len(events) != 1 || events[0].Actor != "alice" || events[0].Confidence != "correlated" {
		t.Fatalf("persisted session identity was not upgraded: %#v err=%v", events, err)
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

func TestStreamLastSeenIsLiveCheckpointedAndFinalized(t *testing.T) {
	var present atomic.Bool
	present.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/streams" {
			http.NotFound(w, r)
			return
		}
		if present.Load() {
			_, _ = io.WriteString(w, `{"workshop":{"consumers":[{"id":1,"protocol":"rtsp","remote_addr":"192.0.2.1:1234","user_agent":"mystery-client"}]}}`)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	s, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m, err := New(config.Config{Go2RTCURL: server.URL}, s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	m.poll(ctx)
	first := m.Current().Sessions[0].LastSeenAt
	m.mu.Lock()
	m.lastStreamCheckpoint = time.Now().Add(-streamCheckpointInterval)
	m.mu.Unlock()
	time.Sleep(time.Millisecond)
	m.poll(ctx)
	current := m.Current()
	if len(current.Sessions) != 1 || !current.Sessions[0].LastSeenAt.After(first) {
		t.Fatalf("live last seen did not advance: %#v", current.Sessions)
	}
	observed := current.Sessions[0].LastSeenAt
	events, err := s.RecentStreams(ctx, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || !events[0].LastSeenAt.Equal(observed) {
		t.Fatalf("checkpointed last seen=%#v, want %v", events, observed)
	}

	present.Store(false)
	m.poll(ctx) // First miss is tolerated, without inventing a new observation.
	m.poll(ctx) // Second miss closes the session.
	events, err = s.RecentStreams(ctx, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].EndedAt == nil || !events[0].LastSeenAt.Equal(observed) {
		t.Fatalf("finalized stream event=%#v, want last seen %v", events, observed)
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
