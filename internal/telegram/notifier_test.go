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
		{Actor: "alice", Camera: "workshop", Details: "start=1786001400 end=1786002300", Protocol: "hls", StartedAt: at},
		{Actor: "alice", Camera: "workshop", Details: "start=1786001400 end=1786002300", Protocol: "hls", StartedAt: at.Add(time.Minute)},
		{Actor: "bob", Details: "event=abc", Protocol: "http", StartedAt: at.Add(2 * time.Minute)},
	})
	for _, want := range []string{"3 new sessions", "11:00 – 11:02 +04", "alice — workshop (range=2026-08-06 11:30–11:45 +04) via hls ×2", "bob — unknown camera (event=abc) via http"} {
		if !strings.Contains(message, want) {
			t.Fatalf("message %q does not contain %q", message, want)
		}
	}
}

func TestRunBatchesAndSends(t *testing.T) {
	received := make(chan map[string]string, 1)
	n := New(config.Telegram{Enabled: true, BotToken: "token", ChatID: "chat", BatchWindow: config.Duration(10 * time.Millisecond)}, "UTC", slog.New(slog.NewTextHandler(io.Discard, nil)))
	n.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/bottoken/sendMessage" {
			t.Errorf("path=%q", r.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		received <- body
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{}")), Header: make(http.Header)}, nil
	})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { n.Run(ctx); close(done) }()
	n.Add(model.Event{Actor: "alice", Camera: "one", StartedAt: time.Now()})
	n.Add(model.Event{Actor: "bob", Camera: "two", StartedAt: time.Now()})
	select {
	case body := <-received:
		if body["chat_id"] != "chat" || !strings.Contains(body["text"], "2 new sessions") {
			t.Fatalf("body=%#v", body)
		}
	case <-time.After(time.Second):
		t.Fatal("Telegram batch was not sent")
	}
	cancel()
	<-done
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}
