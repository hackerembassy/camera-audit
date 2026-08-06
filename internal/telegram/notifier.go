package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"xkem.am/camera-audit/internal/config"
	"xkem.am/camera-audit/internal/model"
	"xkem.am/camera-audit/internal/presentation"
)

// Telegram accepts up to 4096 characters. A byte limit leaves room for the
// omission marker and is conservative for multibyte text.
const maxMessageBytes = 4000

type Notifier struct {
	cfg      config.Telegram
	location *time.Location
	log      *slog.Logger
	client   *http.Client
	baseURL  string
	events   chan model.Event
}

func New(cfg config.Telegram, timezone string, log *slog.Logger) *Notifier {
	location, err := time.LoadLocation(strings.TrimSpace(timezone))
	if err != nil {
		location = time.UTC
	}
	return &Notifier{
		cfg: cfg, location: location, log: log,
		client:  &http.Client{Timeout: 10 * time.Second},
		baseURL: "https://api.telegram.org", events: make(chan model.Event, 1024),
	}
}

// Add queues a new logical recording playback without delaying the proxied
// request. An overflowing queue is preferable to blocking camera playback.
func (n *Notifier) Add(event model.Event) {
	if !n.cfg.Enabled {
		return
	}
	select {
	case n.events <- event:
	default:
		n.log.Warn("Telegram recording notification queue full; dropping event")
	}
}

func (n *Notifier) Run(ctx context.Context) {
	if !n.cfg.Enabled {
		<-ctx.Done()
		return
	}
	var pending []model.Event
	var timer *time.Timer
	var timerC <-chan time.Time
	for {
		select {
		case event := <-n.events:
			pending = append(pending, event)
			if timer == nil {
				timer = time.NewTimer(n.cfg.BatchWindow.Value())
				timerC = timer.C
			}
		case <-timerC:
			if err := n.send(ctx, pending); err != nil {
				n.log.Warn("send Telegram recording summary", "error", err)
				timer.Reset(n.cfg.BatchWindow.Value())
				timerC = timer.C
				continue
			}
			pending = nil
			timer = nil
			timerC = nil
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			for {
				select {
				case event := <-n.events:
					pending = append(pending, event)
				default:
					flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					if err := n.send(flushCtx, pending); err != nil {
						n.log.Warn("flush Telegram recording summary", "error", err)
					}
					cancel()
					return
				}
			}
		}
	}
}

type summaryKey struct {
	actor, camera, details, protocol string
}

func (n *Notifier) message(events []model.Event) string {
	counts := make(map[summaryKey]int)
	for _, event := range events {
		details := presentation.RecordingDetails(event.Details, n.location)
		counts[summaryKey{event.Actor, event.Camera, details, event.Protocol}]++
	}
	keys := make([]summaryKey, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		return a.actor < b.actor || a.actor == b.actor && (a.camera < b.camera || a.camera == b.camera && (a.details < b.details || a.details == b.details && a.protocol < b.protocol))
	})

	var b strings.Builder
	fmt.Fprintf(&b, "Recording playback summary: %d new session", len(events))
	if len(events) != 1 {
		b.WriteByte('s')
	}
	if len(events) > 0 {
		start, end := events[0].StartedAt, events[0].StartedAt
		for _, event := range events[1:] {
			if event.StartedAt.Before(start) {
				start = event.StartedAt
			}
			if event.StartedAt.After(end) {
				end = event.StartedAt
			}
		}
		fmt.Fprintf(&b, "\n%s – %s", start.In(n.location).Format("2006-01-02 15:04"), end.In(n.location).Format("15:04 MST"))
	}
	for _, key := range keys {
		actor, camera := fallback(key.actor, "Unknown actor"), fallback(key.camera, "unknown camera")
		line := fmt.Sprintf("\n• %s — %s", actor, camera)
		if key.details != "" {
			line += " (" + clean(key.details) + ")"
		}
		if key.protocol != "" {
			line += " via " + clean(key.protocol)
		}
		if counts[key] > 1 {
			line += fmt.Sprintf(" ×%d", counts[key])
		}
		if b.Len()+len(line) > maxMessageBytes {
			b.WriteString("\n• …additional entries omitted")
			break
		}
		b.WriteString(line)
	}
	return b.String()
}

func fallback(value, replacement string) string {
	value = clean(value)
	if value == "" {
		return replacement
	}
	return value
}

func clean(value string) string { return strings.Join(strings.Fields(value), " ") }

func (n *Notifier) send(ctx context.Context, events []model.Event) error {
	if len(events) == 0 {
		return nil
	}
	body, err := json.Marshal(map[string]string{"chat_id": n.cfg.ChatID, "text": n.message(events)})
	if err != nil {
		return err
	}
	url := strings.TrimRight(n.baseURL, "/") + "/bot" + n.cfg.BotToken + "/sendMessage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return fmt.Errorf("Telegram API returned %s: %s", response.Status, strings.TrimSpace(string(message)))
	}
	return nil
}
