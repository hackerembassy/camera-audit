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
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 kind TEXT NOT NULL, actor TEXT NOT NULL, actor_type TEXT NOT NULL,
 confidence TEXT NOT NULL, camera TEXT NOT NULL DEFAULT '', protocol TEXT NOT NULL DEFAULT '',
 remote_addr TEXT NOT NULL DEFAULT '', user_agent TEXT NOT NULL DEFAULT '',
 suppressed INTEGER NOT NULL DEFAULT 0, suppression_rule TEXT NOT NULL DEFAULT '',
 started_at TEXT NOT NULL, ended_at TEXT, details TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS events_started_idx ON events(started_at DESC);
CREATE INDEX IF NOT EXISTS events_camera_idx ON events(camera, started_at DESC);
CREATE TABLE IF NOT EXISTS activity (
 actor TEXT NOT NULL, remote_addr TEXT NOT NULL, user_agent TEXT NOT NULL,
 first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
 PRIMARY KEY(actor, remote_addr, user_agent)
);`)
	return err
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) RecoverOpen(ctx context.Context, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE events SET ended_at=?, details=CASE WHEN details='' THEN 'closed after daemon restart' ELSE details END WHERE ended_at IS NULL`,
		at.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) Start(ctx context.Context, e model.Event) (int64, error) {
	r, err := s.db.ExecContext(ctx, `INSERT INTO events
(kind,actor,actor_type,confidence,camera,protocol,remote_addr,user_agent,suppressed,suppression_rule,started_at,details)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, e.Kind, e.Actor, e.ActorType, e.Confidence, e.Camera,
		e.Protocol, e.RemoteAddr, e.UserAgent, e.Suppressed, e.SuppressionRule,
		e.StartedAt.UTC().Format(time.RFC3339Nano), e.Details)
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}

func (s *Store) End(ctx context.Context, id int64, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE events SET ended_at=? WHERE id=? AND ended_at IS NULL`, at.UTC().Format(time.RFC3339Nano), id)
	return err
}

func (s *Store) TouchActivity(ctx context.Context, a model.Activity) error {
	now := a.LastSeen.UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `INSERT INTO activity(actor,remote_addr,user_agent,first_seen,last_seen)
VALUES(?,?,?,?,?) ON CONFLICT(actor,remote_addr,user_agent) DO UPDATE SET last_seen=excluded.last_seen`,
		a.Actor, a.RemoteAddr, a.UserAgent, now, now)
	return err
}

func (s *Store) Recent(ctx context.Context, limit int, camera string) ([]model.Event, error) {
	if limit < 1 || limit > 1000 {
		limit = 200
	}
	q := `SELECT id,kind,actor,actor_type,confidence,camera,protocol,remote_addr,user_agent,suppressed,suppression_rule,started_at,ended_at,details FROM events`
	args := []any{}
	if camera != "" {
		q += ` WHERE camera=?`
		args = append(args, camera)
	}
	q += ` ORDER BY started_at DESC LIMIT ?`
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
		var end sql.NullString
		if err := rows.Scan(&e.ID, &e.Kind, &e.Actor, &e.ActorType, &e.Confidence, &e.Camera, &e.Protocol,
			&e.RemoteAddr, &e.UserAgent, &e.Suppressed, &e.SuppressionRule, &start, &end, &e.Details); err != nil {
			return nil, err
		}
		e.StartedAt, _ = time.Parse(time.RFC3339Nano, start)
		if end.Valid {
			t, _ := time.Parse(time.RFC3339Nano, end.String)
			e.EndedAt = &t
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) Prune(ctx context.Context, before time.Time) error {
	r, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE started_at < ?`, before.UTC().Format(time.RFC3339Nano))
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
