package telegram

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"xkem.am/camera-audit/internal/config"
	"xkem.am/camera-audit/internal/model"
)

func TestMessageGroupsRecordingPlayback(t *testing.T) {
	n := New(config.Telegram{}, "Asia/Yerevan", slog.New(slog.NewTextHandler(io.Discard, nil)))
	at := time.Date(2026, 8, 6, 7, 0, 0, 0, time.UTC)
	message := n.message([]model.Event{
		{Kind: "recording_playback", Actor: "<alice>", Camera: "workshop", Details: "start=1786001400 end=1786002300", Protocol: "hls", StartedAt: at},
		{Kind: "recording_playback", Actor: "<alice>", Camera: "workshop", Details: "start=1786001400 end=1786002300", Protocol: "hls", StartedAt: at.Add(time.Minute)},
		{Kind: "recording_export_download", Actor: "bob", Details: "export_file=abc.mp4", Protocol: "http", StartedAt: at.Add(2 * time.Minute)},
	})
	for _, want := range []string{
		"📼 <b>Recording activity</b>", "<b>3 actions</b>", "2026-08-06 11:00–11:02 +04",
		"<b>Playback</b> — <code>workshop</code>", "&lt;alice&gt;", "<code>range=2026-08-06 11:30–11:45 +04</code> <b>×2</b>",
		"<b>Export downloaded</b> — <code>unknown camera</code>", "<code>export_file=abc.mp4</code>",
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("message %q does not contain %q", message, want)
		}
	}
	if strings.Contains(message, "<alice>") {
		t.Fatalf("message contains unescaped HTML: %q", message)
	}
}

func TestActionLabelsCoverAuditedRecordingKinds(t *testing.T) {
	tests := map[string]string{
		"recording_playback":         "Playback",
		"recording_export_requested": "Export requested",
		"recording_export_download":  "Export downloaded",
		"recording_download":         "Recording downloaded",
	}
	for kind, want := range tests {
		if got := actionLabel(kind); got != want {
			t.Errorf("actionLabel(%q)=%q, want %q", kind, got, want)
		}
	}
}

func TestRunSendsImmediatelyThenEditsMessage(t *testing.T) {
	type request struct {
		path string
		body map[string]any
	}
	received := make(chan request, 2)
	n := New(config.Telegram{Enabled: true, BotToken: "token", ChatID: "chat", BatchWindow: config.Duration(time.Minute)}, "UTC", slog.New(slog.NewTextHandler(io.Discard, nil)))
	n.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		received <- request{path: r.URL.Path, body: body}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"ok":true,"result":{"message_id":42}}`)), Header: make(http.Header)}, nil
	})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { n.Run(ctx); close(done) }()
	n.Add(model.Event{Kind: "recording_export_requested", Actor: "alice", Camera: "one", StartedAt: time.Now()})
	select {
	case request := <-received:
		text, _ := request.body["text"].(string)
		if request.path != "/bottoken/sendMessage" || request.body["chat_id"] != "chat" || request.body["parse_mode"] != "HTML" || !strings.Contains(text, "<b>1 action</b>") {
			t.Fatalf("initial request=%#v", request)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("initial Telegram message was not sent immediately")
	}

	n.Add(model.Event{Kind: "recording_download", Actor: "bob", Camera: "two", StartedAt: time.Now()})
	select {
	case request := <-received:
		text, _ := request.body["text"].(string)
		if request.path != "/bottoken/editMessageText" || request.body["message_id"] != float64(42) || !strings.Contains(text, "<b>2 actions</b>") || !strings.Contains(text, "Recording downloaded") {
			t.Fatalf("edit request=%#v", request)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Telegram message was not edited immediately")
	}
	cancel()
	<-done
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}
