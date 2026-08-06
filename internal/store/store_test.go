package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"xkem.am/camera-audit/internal/model"
)

func TestEventLifecycleAndRecovery(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	id, err := s.Start(context.Background(), model.Event{Kind: "stream", Actor: "alice", ActorType: "person", Confidence: "exact", StartedAt: now})
	if err != nil || id == 0 {
		t.Fatalf("start: id=%d err=%v", id, err)
	}
	if err := s.RecoverOpen(context.Background(), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	events, err := s.Recent(context.Background(), 10, "")
	if err != nil || len(events) != 1 || events[0].EndedAt == nil || !events[0].LastSeenAt.Equal(now) {
		t.Fatalf("events=%#v err=%v", events, err)
	}
}

func TestUpdateOpenEventIdentity(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	id, err := s.Start(ctx, model.Event{Kind: "stream", Actor: "Unknown", ActorType: "unknown", Confidence: "service/device", StartedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateEventIdentity(ctx, id, "alice", "person", "correlated"); err != nil {
		t.Fatal(err)
	}
	events, err := s.RecentStreams(ctx, 10, "")
	if err != nil || len(events) != 1 || events[0].Actor != "alice" || events[0].ActorType != "person" || events[0].Confidence != "correlated" {
		t.Fatalf("updated stream identity=%#v err=%v", events, err)
	}
	if err := s.End(ctx, id, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateEventIdentity(ctx, id, "bob", "person", "correlated"); err != nil {
		t.Fatal(err)
	}
	events, err = s.RecentStreams(ctx, 10, "")
	if err != nil || events[0].Actor != "alice" {
		t.Fatalf("closed event identity changed: %#v err=%v", events, err)
	}
}

func TestRecentUsesLastSeenAndSeparatesStreamHistory(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	start := time.Date(2026, 8, 6, 7, 0, 0, 0, time.UTC)
	streamID, err := s.Start(ctx, model.Event{Kind: "stream", Actor: "camera", ActorType: "service", Confidence: "service/device", StartedAt: start.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	activityID, err := s.Start(ctx, model.Event{Kind: "frigate_activity", Actor: "alice", ActorType: "person", Confidence: "exact", StartedAt: start})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.End(ctx, streamID, start.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	lastSeen := start.Add(3 * time.Minute)
	if err := s.TouchEvent(ctx, activityID, lastSeen); err != nil {
		t.Fatal(err)
	}
	if err := s.TouchEvent(ctx, activityID, start.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}

	events, err := s.Recent(ctx, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].ID != activityID || !events[0].LastSeenAt.Equal(lastSeen) {
		t.Fatalf("unexpected recent events: %#v", events)
	}
	frigate, err := s.RecentFrigate(ctx, 10, "")
	if err != nil || len(frigate) != 1 || frigate[0].Kind != "frigate_activity" {
		t.Fatalf("Frigate history=%#v err=%v", frigate, err)
	}
	streams, err := s.RecentStreams(ctx, 10, "")
	if err != nil || len(streams) != 1 || streams[0].Kind != "stream" {
		t.Fatalf("stream history=%#v err=%v", streams, err)
	}
}

func TestMigratesExistingEventsWithLastSeen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE events (
id INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT NOT NULL,actor TEXT NOT NULL,actor_type TEXT NOT NULL,
confidence TEXT NOT NULL,camera TEXT NOT NULL DEFAULT '',protocol TEXT NOT NULL DEFAULT '',remote_addr TEXT NOT NULL DEFAULT '',
user_agent TEXT NOT NULL DEFAULT '',suppressed INTEGER NOT NULL DEFAULT 0,suppression_rule TEXT NOT NULL DEFAULT '',
started_at TEXT NOT NULL,ended_at TEXT,details TEXT NOT NULL DEFAULT '');
INSERT INTO events(kind,actor,actor_type,confidence,started_at,ended_at) VALUES('frigate_activity','alice','person','exact','2026-08-06T07:00:00Z','2026-08-06T07:05:00Z');`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	events, err := s.Recent(context.Background(), 10, "")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 8, 6, 7, 5, 0, 0, time.UTC)
	if len(events) != 1 || !events[0].LastSeenAt.Equal(want) {
		t.Fatalf("migrated events=%#v", events)
	}
}

func TestBatchCheckpointAndStreamEndPreserveActualLastSeen(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	started := time.Date(2026, 8, 6, 7, 0, 0, 0, time.UTC)
	firstID, err := s.Start(ctx, model.Event{Kind: "stream", Actor: "expected", ActorType: "service", Confidence: "service/device", StartedAt: started})
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := s.Start(ctx, model.Event{Kind: "stream", Actor: "unknown", ActorType: "unknown", Confidence: "service/device", StartedAt: started})
	if err != nil {
		t.Fatal(err)
	}
	observed := started.Add(5 * time.Minute)
	if err := s.TouchEvents(ctx, map[int64]time.Time{firstID: observed, secondID: observed}); err != nil {
		t.Fatal(err)
	}
	ended := observed.Add(10 * time.Second)
	if err := s.EndStream(ctx, firstID, ended, observed); err != nil {
		t.Fatal(err)
	}
	events, err := s.RecentStreams(ctx, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("stream events=%d, want 2", len(events))
	}
	for _, event := range events {
		if !event.LastSeenAt.Equal(observed) {
			t.Errorf("event %d last_seen=%v, want %v", event.ID, event.LastSeenAt, observed)
		}
		if event.ID == firstID && (event.EndedAt == nil || !event.EndedAt.Equal(ended)) {
			t.Errorf("ended_at=%v, want %v", event.EndedAt, ended)
		}
	}
}

func TestRecentSeparatesRecordingPlayback(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	for _, event := range []model.Event{
		{Kind: "frigate_activity", Actor: "alice", ActorType: "person", Confidence: "exact", StartedAt: now},
		{Kind: "recording_playback", Actor: "alice", ActorType: "person", Confidence: "exact", StartedAt: now},
		{Kind: "stream", Actor: "unknown", ActorType: "unknown", Confidence: "service/device", StartedAt: now},
	} {
		if _, err := s.Start(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	frigate, err := s.RecentNonRecordingFrigate(ctx, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	recordings, err := s.RecentRecordings(ctx, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(frigate) != 1 || frigate[0].Kind != "frigate_activity" {
		t.Fatalf("non-recording Frigate history=%#v", frigate)
	}
	if len(recordings) != 1 || recordings[0].Kind != "recording_playback" {
		t.Fatalf("recording history=%#v", recordings)
	}
}
