package model

import "time"

type Event struct {
	ID              int64      `json:"id"`
	Kind            string     `json:"kind"`
	Actor           string     `json:"actor"`
	ActorType       string     `json:"actor_type"`
	Confidence      string     `json:"identity_confidence"`
	Camera          string     `json:"camera,omitempty"`
	Protocol        string     `json:"protocol,omitempty"`
	RemoteAddr      string     `json:"remote_addr,omitempty"`
	UserAgent       string     `json:"user_agent,omitempty"`
	Suppressed      bool       `json:"suppressed"`
	SuppressionRule string     `json:"suppression_rule,omitempty"`
	StartedAt       time.Time  `json:"started_at"`
	LastSeenAt      time.Time  `json:"last_seen_at"`
	EndedAt         *time.Time `json:"ended_at,omitempty"`
	Details         string     `json:"details,omitempty"`
}

type Consumer struct {
	ID         uint32 `json:"id"`
	FormatName string `json:"format_name"`
	Protocol   string `json:"protocol"`
	RemoteAddr string `json:"remote_addr"`
	Source     string `json:"source"`
	URL        string `json:"url"`
	UserAgent  string `json:"user_agent"`
	BytesSend  int64  `json:"bytes_send"`
}

type Stream struct {
	Producers []Consumer `json:"producers"`
	Consumers []Consumer `json:"consumers"`
}

type ActiveSession struct {
	Key             string    `json:"key"`
	EventID         int64     `json:"event_id"`
	Camera          string    `json:"camera"`
	ConnectionID    uint32    `json:"connection_id"`
	Actor           string    `json:"actor"`
	ActorType       string    `json:"actor_type"`
	Confidence      string    `json:"identity_confidence"`
	Protocol        string    `json:"protocol"`
	RemoteAddr      string    `json:"remote_addr"`
	UserAgent       string    `json:"user_agent"`
	Suppressed      bool      `json:"suppressed"`
	SuppressionRule string    `json:"suppression_rule,omitempty"`
	StartedAt       time.Time `json:"started_at"`
	LastSeenAt      time.Time `json:"last_seen_at"`
	Misses          int       `json:"-"`
}

type Activity struct {
	EventID    int64     `json:"-"`
	Actor      string    `json:"actor"`
	RemoteAddr string    `json:"remote_addr"`
	UserAgent  string    `json:"user_agent"`
	LastSeen   time.Time `json:"last_seen"`
}

type Current struct {
	Fresh                bool            `json:"fresh"`
	LastPoll             time.Time       `json:"last_poll"`
	Sessions             []ActiveSession `json:"sessions"`
	Activities           []Activity      `json:"frigate_users"`
	Privacy              map[string]bool `json:"privacy"`
	BirdseyeLayout       []string        `json:"birdseye_layout"`
	BirdseyeLayoutSource string          `json:"birdseye_layout_source"`
	SanitizedGraph       string          `json:"sanitized_graph,omitempty"`
}
