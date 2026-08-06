package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
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

// Add queues a new logical recording action without delaying the proxied
// request. An overflowing queue is preferable to blocking camera access.
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
	var session []model.Event
	var messageID int64
	var dirty bool
	var timer *time.Timer
	var timerC <-chan time.Time
	publish := func(publishCtx context.Context) {
		id, err := n.publish(publishCtx, session, messageID)
		if err != nil {
			n.log.Warn("publish Telegram recording activity", "error", err)
			return
		}
		messageID = id
		dirty = false
	}
	for {
		select {
		case event := <-n.events:
			session = append(session, event)
			dirty = true
			if timer == nil {
				timer = time.NewTimer(n.cfg.BatchWindow.Value())
				timerC = timer.C
			}
			// The first action sends a new message. Later actions edit that same
			// message immediately until the session window closes.
			publish(ctx)
		case <-timerC:
			if dirty {
				publish(ctx)
			}
			session = nil
			messageID = 0
			dirty = false
			timer = nil
			timerC = nil
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			for {
				select {
				case event := <-n.events:
					session = append(session, event)
					dirty = true
				default:
					if dirty {
						flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
						publish(flushCtx)
						cancel()
					}
					return
				}
			}
		}
	}
}

type summaryKey struct {
	kind, actor, camera, details, protocol string
}

func (n *Notifier) message(events []model.Event) string {
	counts := make(map[summaryKey]int)
	keys := make([]summaryKey, 0, len(events))
	for _, event := range events {
		details := presentation.RecordingDetails(event.Details, n.location)
		key := summaryKey{event.Kind, event.Actor, event.Camera, details, event.Protocol}
		if counts[key] == 0 {
			keys = append(keys, key)
		}
		counts[key]++
	}

	var b strings.Builder
	fmt.Fprintf(&b, "📼 <b>Recording activity</b>\n<b>%d action", len(events))
	if len(events) != 1 {
		b.WriteByte('s')
	}
	b.WriteString("</b>")
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
		b.WriteString(" · ")
		b.WriteString(actionWindow(start.In(n.location), end.In(n.location)))
	}
	for _, key := range keys {
		actor := html.EscapeString(fallback(key.actor, "Unknown actor"))
		camera := html.EscapeString(fallback(key.camera, "unknown camera"))
		line := fmt.Sprintf("\n\n• <b>%s</b> — <code>%s</code>", actionLabel(key.kind), camera)
		line += "\n  " + actor
		if key.protocol != "" {
			line += " · <code>" + html.EscapeString(clean(key.protocol)) + "</code>"
		}
		details, exportName := exportNameFromDetails(key.details)
		if exportName != "" {
			line += "\n  <i>“" + html.EscapeString(clean(exportName)) + "”</i>"
		}
		if details != "" {
			line += "\n  <code>" + html.EscapeString(clean(details)) + "</code>"
		}
		if counts[key] > 1 {
			line += fmt.Sprintf(" <b>×%d</b>", counts[key])
		}
		if b.Len()+len(line) > maxMessageBytes {
			b.WriteString("\n• …additional entries omitted")
			break
		}
		b.WriteString(line)
	}
	return b.String()
}

func exportNameFromDetails(details string) (string, string) {
	const marker = " export_name="
	if index := strings.Index(details, marker); index >= 0 {
		return details[:index], details[index+len(marker):]
	}
	if strings.HasPrefix(details, "export_name=") {
		return "", strings.TrimPrefix(details, "export_name=")
	}
	return details, ""
}

func actionLabel(kind string) string {
	switch kind {
	case "recording_playback":
		return "Playback"
	case "recording_export_requested":
		return "Export requested"
	case "recording_export_download":
		return "Export downloaded"
	case "recording_download":
		return "Recording downloaded"
	default:
		return "Recording action"
	}
}

func actionWindow(start, end time.Time) string {
	if start.Equal(end) {
		return start.Format("2006-01-02 15:04 -07")
	}
	_, startOffset := start.Zone()
	_, endOffset := end.Zone()
	if startOffset == endOffset && start.Year() == end.Year() && start.YearDay() == end.YearDay() {
		return start.Format("2006-01-02 15:04") + "–" + end.Format("15:04 -07")
	}
	return start.Format("2006-01-02 15:04 -07") + "–" + end.Format("2006-01-02 15:04 -07")
}

func fallback(value, replacement string) string {
	value = clean(value)
	if value == "" {
		return replacement
	}
	return value
}

func clean(value string) string { return strings.Join(strings.Fields(value), " ") }

func (n *Notifier) publish(ctx context.Context, events []model.Event, messageID int64) (int64, error) {
	if len(events) == 0 {
		return messageID, nil
	}
	payload := map[string]any{
		"chat_id": n.cfg.ChatID, "text": n.message(events), "parse_mode": "HTML",
	}
	method := "sendMessage"
	if messageID != 0 {
		method = "editMessageText"
		payload["message_id"] = messageID
	}
	resultID, err := n.call(ctx, method, payload)
	if err != nil {
		return messageID, err
	}
	if messageID != 0 {
		return messageID, nil
	}
	if resultID == 0 {
		return 0, fmt.Errorf("Telegram sendMessage response omitted message_id")
	}
	return resultID, nil
}

func (n *Notifier) call(ctx context.Context, method string, payload map[string]any) (int64, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	url := strings.TrimRight(n.baseURL, "/") + "/bot" + n.cfg.BotToken + "/" + method
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := n.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return 0, fmt.Errorf("Telegram API returned %s: %s", response.Status, strings.TrimSpace(string(message)))
	}
	var result struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
		Result      struct {
			MessageID int64 `json:"message_id"`
		} `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&result); err != nil {
		return 0, fmt.Errorf("decode Telegram API response: %w", err)
	}
	if !result.OK {
		return 0, fmt.Errorf("Telegram API rejected %s: %s", method, result.Description)
	}
	return result.Result.MessageID, nil
}
