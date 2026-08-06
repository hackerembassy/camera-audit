package auditweb

import (
	"context"
	"sort"
	"strings"
	"time"

	"xkem.am/camera-audit/internal/model"
	"xkem.am/camera-audit/internal/presentation"
)

const dashboardTimeLayout = "2006-01-02 15:04:05 -07:00"

func (h *Handler) dashboardTime(value time.Time) string {
	if value.IsZero() {
		return "never"
	}
	return value.In(h.location).Format(dashboardTimeLayout)
}

type dashboardActivity struct {
	Actor      string `json:"actor"`
	RemoteAddr string `json:"remote_addr"`
	LastSeen   string `json:"last_seen"`
}

type dashboardEvent struct {
	Kind       string `json:"kind"`
	Camera     string `json:"camera"`
	Actor      string `json:"actor"`
	Protocol   string `json:"protocol"`
	Details    string `json:"details"`
	UserAgent  string `json:"user_agent,omitempty"`
	Expected   bool   `json:"expected"`
	Live       bool   `json:"live,omitempty"`
	StartedAt  string `json:"started_at"`
	LastSeenAt string `json:"last_seen_at"`
}

type dashboardSession struct {
	Camera     string `json:"camera"`
	Actor      string `json:"actor"`
	Confidence string `json:"identity_confidence"`
	Protocol   string `json:"protocol"`
	RemoteAddr string `json:"remote_addr"`
	UserAgent  string `json:"user_agent,omitempty"`
	Expected   bool   `json:"expected"`
	StartedAt  string `json:"started_at"`
	LastSeenAt string `json:"last_seen_at"`
}

type dashboardPrivacy struct {
	Camera string `json:"camera"`
	Active bool   `json:"active"`
}

type liveSnapshot struct {
	Fresh                bool                `json:"fresh"`
	LastPoll             string              `json:"last_poll"`
	Timezone             string              `json:"timezone"`
	BirdseyeLayout       []string            `json:"birdseye_layout"`
	BirdseyeLayoutSource string              `json:"birdseye_layout_source"`
	Privacy              []dashboardPrivacy  `json:"privacy"`
	Sessions             []dashboardSession  `json:"sessions"`
	Activities           []dashboardActivity `json:"activities"`
}

type historySnapshot struct {
	Events       []dashboardEvent `json:"events"`
	Recordings   []dashboardEvent `json:"recordings"`
	StreamEvents []dashboardEvent `json:"stream_events"`
}

type historyPageSnapshot struct {
	Timezone string `json:"timezone"`
	historySnapshot
}

type dashboardSnapshot struct {
	liveSnapshot
	historySnapshot
}

func (h *Handler) dashboardActivities(activities []model.Activity) []dashboardActivity {
	out := make([]dashboardActivity, 0, len(activities))
	for _, activity := range activities {
		out = append(out, dashboardActivity{
			Actor: activity.Actor, RemoteAddr: activity.RemoteAddr,
			LastSeen: h.dashboardTime(activity.LastSeen),
		})
	}
	return out
}

func (h *Handler) dashboardEvents(events []model.Event) []dashboardEvent {
	out := make([]dashboardEvent, 0, len(events))
	for _, event := range events {
		details := event.Details
		if strings.HasPrefix(event.Kind, "recording_") {
			details = presentation.RecordingDetails(details, h.location)
		}
		out = append(out, dashboardEvent{
			Kind: event.Kind, Camera: event.Camera, Actor: event.Actor, Protocol: event.Protocol,
			Details: details, UserAgent: dashboardUserAgent(event.ActorType, event.Suppressed, event.UserAgent),
			Expected: event.Suppressed, StartedAt: h.dashboardTime(event.StartedAt), LastSeenAt: h.dashboardTime(event.LastSeenAt),
		})
	}
	return out
}

func (h *Handler) dashboardStreamEvents(events []model.Event, activeEventIDs map[int64]bool) []dashboardEvent {
	out := h.dashboardEvents(events)
	for i, event := range events {
		out[i].Live = activeEventIDs[event.ID]
	}
	return out
}

func dashboardUserAgent(actorType string, expected bool, userAgent string) string {
	if actorType == "unknown" || !expected {
		return userAgent
	}
	return ""
}

func (h *Handler) dashboardSessions(sessions []model.ActiveSession) []dashboardSession {
	out := make([]dashboardSession, 0, len(sessions))
	for _, session := range sessions {
		out = append(out, dashboardSession{
			Camera: session.Camera, Actor: session.Actor, Confidence: session.Confidence,
			Protocol: session.Protocol, RemoteAddr: session.RemoteAddr,
			UserAgent: dashboardUserAgent(session.ActorType, session.Suppressed, session.UserAgent),
			Expected:  session.Suppressed, StartedAt: h.dashboardTime(session.StartedAt), LastSeenAt: h.dashboardTime(session.LastSeenAt),
		})
	}
	return out
}

func (h *Handler) liveData() liveSnapshot {
	current := h.manager.Current()
	privacy := make([]dashboardPrivacy, 0, len(current.Privacy))
	for camera, active := range current.Privacy {
		privacy = append(privacy, dashboardPrivacy{Camera: camera, Active: active})
	}
	sort.Slice(privacy, func(i, j int) bool { return privacy[i].Camera < privacy[j].Camera })
	return liveSnapshot{
		Fresh: current.Fresh, LastPoll: h.dashboardTime(current.LastPoll), Timezone: h.location.String(),
		BirdseyeLayout: current.BirdseyeLayout, BirdseyeLayoutSource: current.BirdseyeLayoutSource,
		Privacy: privacy, Sessions: h.dashboardSessions(current.Sessions),
		Activities: h.dashboardActivities(current.Activities),
	}
}

func (h *Handler) historyData(ctx context.Context) (historySnapshot, error) {
	current := h.manager.Current()
	events, err := h.store.RecentNonRecordingFrigate(ctx, 100, "")
	if err != nil {
		return historySnapshot{}, err
	}
	recordings, err := h.store.RecentRecordings(ctx, 100, "")
	if err != nil {
		return historySnapshot{}, err
	}
	streamEvents, err := h.store.RecentStreams(ctx, 100, "")
	if err != nil {
		return historySnapshot{}, err
	}
	activeStreamEvents := overlayActiveStreamLastSeen(streamEvents, current.Sessions)
	sort.SliceStable(streamEvents, func(i, j int) bool {
		if streamEvents[i].LastSeenAt.Equal(streamEvents[j].LastSeenAt) {
			return streamEvents[i].ID > streamEvents[j].ID
		}
		return streamEvents[i].LastSeenAt.After(streamEvents[j].LastSeenAt)
	})
	return historySnapshot{
		Events:     h.dashboardEvents(events),
		Recordings: h.dashboardEvents(recordings), StreamEvents: h.dashboardStreamEvents(streamEvents, activeStreamEvents),
	}, nil
}

func (h *Handler) historyPageData(ctx context.Context) (historyPageSnapshot, error) {
	history, err := h.historyData(ctx)
	if err != nil {
		return historyPageSnapshot{}, err
	}
	return historyPageSnapshot{Timezone: h.location.String(), historySnapshot: history}, nil
}

func (h *Handler) dashboardData(ctx context.Context) (dashboardSnapshot, error) {
	history, err := h.historyData(ctx)
	if err != nil {
		return dashboardSnapshot{}, err
	}
	return dashboardSnapshot{liveSnapshot: h.liveData(), historySnapshot: history}, nil
}

func overlayActiveStreamLastSeen(events []model.Event, sessions []model.ActiveSession) map[int64]bool {
	activeLastSeen := make(map[int64]time.Time, len(sessions))
	for _, session := range sessions {
		if session.EventID != 0 {
			activeLastSeen[session.EventID] = session.LastSeenAt
		}
	}
	activeEventIDs := make(map[int64]bool, len(activeLastSeen))
	for i := range events {
		if lastSeen, active := activeLastSeen[events[i].ID]; active {
			events[i].LastSeenAt = lastSeen
			activeEventIDs[events[i].ID] = true
		}
	}
	return activeEventIDs
}
