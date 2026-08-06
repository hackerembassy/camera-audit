package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"xkem.am/camera-audit/internal/model"
)

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// The workload is small and write-heavy. One connection gives SQLite
	// deterministic write ordering while WAL still permits efficient reads.
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;`); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 kind TEXT NOT NULL, actor TEXT NOT NULL, actor_type TEXT NOT NULL,
 confidence TEXT NOT NULL, camera TEXT NOT NULL DEFAULT '', protocol TEXT NOT NULL DEFAULT '',
 remote_addr TEXT NOT NULL DEFAULT '', user_agent TEXT NOT NULL DEFAULT '',
 suppressed INTEGER NOT NULL DEFAULT 0, suppression_rule TEXT NOT NULL DEFAULT '',
 started_at TEXT NOT NULL, last_seen_at TEXT, ended_at TEXT, details TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS events_started_idx ON events(started_at DESC);
CREATE INDEX IF NOT EXISTS events_camera_idx ON events(camera, started_at DESC);
CREATE TABLE IF NOT EXISTS activity (
 actor TEXT NOT NULL, remote_addr TEXT NOT NULL, user_agent TEXT NOT NULL,
 first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
 PRIMARY KEY(actor, remote_addr, user_agent)
);`); err != nil {
		return err
	}

	rows, err := s.db.Query(`PRAGMA table_info(events)`)
	if err != nil {
		return err
	}
	hasLastSeen := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, dataType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return err
		}
		if name == "last_seen_at" {
			hasLastSeen = true
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if !hasLastSeen {
		if _, err := s.db.Exec(`ALTER TABLE events ADD COLUMN last_seen_at TEXT`); err != nil {
			return err
		}
	}
	_, err = s.db.Exec(`
UPDATE events SET last_seen_at=COALESCE(ended_at,started_at) WHERE last_seen_at IS NULL;
CREATE INDEX IF NOT EXISTS events_last_seen_idx ON events(last_seen_at DESC);
CREATE INDEX IF NOT EXISTS events_camera_last_seen_idx ON events(camera,last_seen_at DESC);`)
	return err
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) RecoverOpen(ctx context.Context, at time.Time) error {
	// Live truth is rebuilt from go2rtc and new gateway traffic. Carrying an
	// open interval across a process gap would claim continuity we did not see.
	now := at.UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `UPDATE events SET ended_at=?,last_seen_at=COALESCE(last_seen_at,started_at),details=CASE WHEN details='' THEN 'closed after daemon restart' ELSE details END WHERE ended_at IS NULL`, now)
	return err
}

func (s *Store) Start(ctx context.Context, e model.Event) (int64, error) {
	lastSeen := e.LastSeenAt
	if lastSeen.IsZero() {
		lastSeen = e.StartedAt
	}
	r, err := s.db.ExecContext(ctx, `INSERT INTO events
(kind,actor,actor_type,confidence,camera,protocol,remote_addr,user_agent,suppressed,suppression_rule,started_at,last_seen_at,details)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, e.Kind, e.Actor, e.ActorType, e.Confidence, e.Camera,
		e.Protocol, e.RemoteAddr, e.UserAgent, e.Suppressed, e.SuppressionRule,
		e.StartedAt.UTC().Format(time.RFC3339Nano), lastSeen.UTC().Format(time.RFC3339Nano), e.Details)
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}

func (s *Store) End(ctx context.Context, id int64, at time.Time) error {
	return s.EndStream(ctx, id, at, at)
}

// EndStream records when disappearance was detected separately from the last
// inventory that actually contained the consumer.
func (s *Store) EndStream(ctx context.Context, id int64, endedAt, lastSeenAt time.Time) error {
	if lastSeenAt.IsZero() {
		lastSeenAt = endedAt
	}
	ended := endedAt.UTC().Format(time.RFC3339Nano)
	seen := lastSeenAt.UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `UPDATE events SET ended_at=?,last_seen_at=CASE WHEN last_seen_at IS NULL OR last_seen_at<? THEN ? ELSE last_seen_at END WHERE id=? AND ended_at IS NULL`, ended, seen, seen, id)
	return err
}

func (s *Store) TouchEvent(ctx context.Context, id int64, at time.Time) error {
	if id == 0 {
		return nil
	}
	now := at.UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `UPDATE events SET last_seen_at=CASE WHEN last_seen_at IS NULL OR last_seen_at<? THEN ? ELSE last_seen_at END WHERE id=? AND ended_at IS NULL`, now, now, id)
	return err
}

// TouchEvents checkpoints multiple active events in one SQLite transaction.
// The caller supplies each event's actual observation time, which may differ
// when a consumer has missed one inventory but has not yet been closed.
func (s *Store) TouchEvents(ctx context.Context, seen map[int64]time.Time) error {
	if len(seen) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	statement, err := tx.PrepareContext(ctx, `UPDATE events SET last_seen_at=CASE WHEN last_seen_at IS NULL OR last_seen_at<? THEN ? ELSE last_seen_at END WHERE id=? AND ended_at IS NULL`)
	if err != nil {
		return err
	}
	defer statement.Close()
	for id, at := range seen {
		value := at.UTC().Format(time.RFC3339Nano)
		if _, err := statement.ExecContext(ctx, value, value, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) TouchActivity(ctx context.Context, a model.Activity) error {
	now := a.LastSeen.UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `INSERT INTO activity(actor,remote_addr,user_agent,first_seen,last_seen)
VALUES(?,?,?,?,?) ON CONFLICT(actor,remote_addr,user_agent) DO UPDATE SET last_seen=CASE WHEN activity.last_seen<excluded.last_seen THEN excluded.last_seen ELSE activity.last_seen END`,
		a.Actor, a.RemoteAddr, a.UserAgent, now, now)
	return err
}

func (s *Store) Recent(ctx context.Context, limit int, camera string) ([]model.Event, error) {
	return s.recent(ctx, limit, camera, "")
}

func (s *Store) RecentFrigate(ctx context.Context, limit int, camera string) ([]model.Event, error) {
	return s.recent(ctx, limit, camera, "kind<>'stream'")
}

func (s *Store) RecentNonRecordingFrigate(ctx context.Context, limit int, camera string) ([]model.Event, error) {
	return s.recent(ctx, limit, camera, "kind<>'stream' AND kind<>'recording_playback'")
}

func (s *Store) RecentRecordings(ctx context.Context, limit int, camera string) ([]model.Event, error) {
	return s.recent(ctx, limit, camera, "kind='recording_playback'")
}

func (s *Store) RecentStreams(ctx context.Context, limit int, camera string) ([]model.Event, error) {
	return s.recent(ctx, limit, camera, "kind='stream'")
}

func (s *Store) recent(ctx context.Context, limit int, camera, kindFilter string) ([]model.Event, error) {
	if limit < 1 || limit > 1000 {
		limit = 200
	}
	q := `SELECT id,kind,actor,actor_type,confidence,camera,protocol,remote_addr,user_agent,suppressed,suppression_rule,started_at,last_seen_at,ended_at,details FROM events`
	args := []any{}
	if camera != "" {
		q += ` WHERE camera=?`
		args = append(args, camera)
	}
	if kindFilter != "" {
		if len(args) == 0 {
			q += ` WHERE `
		} else {
			q += ` AND `
		}
		q += kindFilter
	}
	q += ` ORDER BY last_seen_at DESC,id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Event
	for rows.Next() {
		var e model.Event
		var start string
		var lastSeen string
		var end sql.NullString
		if err := rows.Scan(&e.ID, &e.Kind, &e.Actor, &e.ActorType, &e.Confidence, &e.Camera, &e.Protocol,
			&e.RemoteAddr, &e.UserAgent, &e.Suppressed, &e.SuppressionRule, &start, &lastSeen, &end, &e.Details); err != nil {
			return nil, err
		}
		e.StartedAt, _ = time.Parse(time.RFC3339Nano, start)
		e.LastSeenAt, _ = time.Parse(time.RFC3339Nano, lastSeen)
		if end.Valid {
			t, _ := time.Parse(time.RFC3339Nano, end.String)
			e.EndedAt = &t
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) Prune(ctx context.Context, before time.Time) error {
	r, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE last_seen_at < ?`, before.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM activity WHERE last_seen < ?`, before.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("prune activity after %v events: %w", r, err)
	}
	return nil
}

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }
