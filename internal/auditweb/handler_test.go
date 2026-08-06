package auditweb

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xkem.am/camera-audit/internal/audit"
	"xkem.am/camera-audit/internal/config"
	"xkem.am/camera-audit/internal/model"
	"xkem.am/camera-audit/internal/store"
)

func TestConfiguredTimezoneFormatsHumanAndCSVTimes(t *testing.T) {
	location, err := time.LoadLocation("Asia/Yerevan")
	if err != nil {
		t.Fatal(err)
	}
	handler := &Handler{location: location}
	value := time.Date(2026, 8, 6, 7, 30, 0, 0, time.UTC)
	if got, want := handler.csvTime(value), "2026-08-06T11:30:00+04:00"; got != want {
		t.Fatalf("csvTime=%q, want %q", got, want)
	}
	if got, want := handler.dashboardTime(value), "2026-08-06 11:30:00 +04:00"; got != want {
		t.Fatalf("dashboardTime=%q, want %q", got, want)
	}
	if got := handler.dashboardTime(time.Time{}); got != "never" {
		t.Fatalf("zero dashboard time=%q", got)
	}
}

func TestDashboardFormatsRecordingRangeWithoutChangingOtherDetails(t *testing.T) {
	location, err := time.LoadLocation("Asia/Yerevan")
	if err != nil {
		t.Fatal(err)
	}
	handler := &Handler{location: location}
	events := handler.dashboardEvents([]model.Event{
		{Kind: "recording_playback", Details: "start=1786001400 end=1786002300"},
		{Kind: "frigate_request", Details: "start=1786001400 end=1786002300"},
	})
	if got, want := events[0].Details, "range=2026-08-06 11:30–11:45 +04"; got != want {
		t.Fatalf("recording details=%q, want %q", got, want)
	}
	if got, want := events[1].Details, "start=1786001400 end=1786002300"; got != want {
		t.Fatalf("non-recording details=%q, want %q", got, want)
	}
}

func TestUnknownRoute(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/audit/api/v1/unknown", nil)
	(&Handler{}).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("unknown audit route status=%d, want %d", recorder.Code, http.StatusNotFound)
	}
}

func TestDashboardUserAgentVisibility(t *testing.T) {
	for _, tt := range []struct {
		name, actorType, userAgent string
		expected, visible          bool
	}{
		{name: "known expected service", actorType: "service", userAgent: "Frigate", expected: true},
		{name: "unknown expected client", actorType: "unknown", userAgent: "mystery-client", expected: true, visible: true},
		{name: "unexpected known client", actorType: "service", userAgent: "HomeAssistant", visible: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := dashboardUserAgent(tt.actorType, tt.expected, tt.userAgent)
			if (got != "") != tt.visible {
				t.Fatalf("dashboardUserAgent()=%q, visible=%v", got, tt.visible)
			}
		})
	}
}

func TestLiveAndHistoryDataAreSeparated(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	for _, event := range []model.Event{
		{Kind: "frigate_activity", Actor: "alice", ActorType: "person", Confidence: "exact", StartedAt: now},
		{Kind: "recording_playback", Actor: "alice", ActorType: "person", Confidence: "exact", Camera: "workshop", StartedAt: now},
		{Kind: "recording_export_requested", Actor: "alice", ActorType: "person", Confidence: "exact", Camera: "workshop", StartedAt: now},
		{Kind: "stream", Actor: "Unknown (192.0.2.1)", ActorType: "unknown", Confidence: "service/device", Camera: "workshop", UserAgent: "mystery-client", StartedAt: now},
	} {
		if _, err := s.Start(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager, err := audit.New(config.Config{}, s, log)
	if err != nil {
		t.Fatal(err)
	}
	handler := New(manager, s, time.UTC, log)
	history, err := handler.historyPageData(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(history.Events) != 1 || history.Events[0].Kind != "frigate_activity" || len(history.Recordings) != 2 {
		t.Fatalf("history data was not separated by category: %#v", history)
	}
	if len(history.StreamEvents) != 1 || history.StreamEvents[0].UserAgent != "mystery-client" {
		t.Fatalf("stream user agent missing: %#v", history.StreamEvents)
	}
	live := handler.liveData()
	if live.Timezone != "UTC" {
		t.Fatalf("live payload lost timezone: %#v", live)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/audit/api/v1/live", nil))
	if strings.Contains(recorder.Body.String(), `"events"`) || strings.Contains(recorder.Body.String(), `"recordings"`) || strings.Contains(recorder.Body.String(), `"stream_events"`) {
		t.Fatalf("live endpoint contains history data: %s", recorder.Body.String())
	}
	compatibility, err := handler.dashboardData(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(compatibility.Recordings) != 2 || compatibility.Timezone != "UTC" {
		t.Fatalf("compatibility dashboard lost data: %#v", compatibility)
	}
	for _, endpoint := range []string{"/audit/api/v1/dashboard", "/audit/api/v1/history/dashboard"} {
		recorder = httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, endpoint, nil))
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"recordings"`) || !strings.Contains(recorder.Body.String(), `"timezone"`) {
			t.Fatalf("endpoint %s lost display data: status=%d body=%s", endpoint, recorder.Code, recorder.Body.String())
		}
	}

	for _, page := range []struct {
		name       string
		template   interface{ Execute(io.Writer, any) error }
		markers    []string
		notMarkers []string
	}{
		{name: "overview", template: overviewTemplate, markers: []string{"/audit/api/v1/live", "href=\"#privacy\"", "First observed", "vis-network@10.0.2"}, notMarkers: []string{"recording-rows"}},
		{name: "history", template: historyTemplate, markers: []string{"/audit/api/v1/history/dashboard", "href=\"#recordings\"", "Refresh now", "recording-rows"}, notMarkers: []string{"vis-network"}},
	} {
		t.Run(page.name, func(t *testing.T) {
			var rendered strings.Builder
			if err := page.template.Execute(&rendered, nil); err != nil {
				t.Fatal(err)
			}
			for _, marker := range page.markers {
				if !strings.Contains(rendered.String(), marker) {
					t.Errorf("page is missing %q", marker)
				}
			}
			for _, marker := range page.notMarkers {
				if strings.Contains(rendered.String(), marker) {
					t.Errorf("page unexpectedly contains %q", marker)
				}
			}
		})
	}
}

func TestPageAndAssetRoutes(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := &Handler{log: log}
	for _, tt := range []struct {
		path, contentType, marker string
	}{
		{path: "/audit/", contentType: "text/html; charset=utf-8", marker: "Live overview"},
		{path: "/audit/history", contentType: "text/html; charset=utf-8", marker: "Activity history"},
		{path: "/audit/assets/audit.css", contentType: "text/css; charset=utf-8", marker: ".topbar"},
		{path: "/audit/assets/overview.js", contentType: "text/javascript; charset=utf-8", marker: "/audit/api/v1/live"},
	} {
		t.Run(tt.path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, tt.path, nil))
			if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != tt.contentType || !strings.Contains(recorder.Body.String(), tt.marker) {
				t.Fatalf("route response: status=%d content-type=%q body=%q", recorder.Code, recorder.Header().Get("Content-Type"), recorder.Body.String())
			}
		})
	}
}

func TestDashboardOverlaysActiveStreamLastSeenFromMemory(t *testing.T) {
	persisted := time.Date(2026, 8, 6, 7, 0, 0, 0, time.UTC)
	live := persisted.Add(4*time.Minute + 59*time.Second)
	events := []model.Event{{ID: 42, Kind: "stream", LastSeenAt: persisted}}
	sessions := []model.ActiveSession{{EventID: 42, LastSeenAt: live}}
	active := overlayActiveStreamLastSeen(events, sessions)
	if !events[0].LastSeenAt.Equal(live) {
		t.Fatalf("dashboard history last seen=%v, want live value %v", events[0].LastSeenAt, live)
	}
	handler := &Handler{location: time.UTC}
	rows := handler.dashboardStreamEvents(events, active)
	if len(rows) != 1 || !rows[0].Live {
		t.Fatalf("active dashboard history row was not marked live: %#v", rows)
	}
}
