package store

import (
	"context"
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
	if err != nil || len(events) != 1 || events[0].EndedAt == nil {
		t.Fatalf("events=%#v err=%v", events, err)
	}
}
