package auditweb

import (
	"encoding/csv"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"xkem.am/camera-audit/internal/audit"
	"xkem.am/camera-audit/internal/model"
	"xkem.am/camera-audit/internal/store"
)

type Handler struct {
	manager  *audit.Manager
	store    *store.Store
	location *time.Location
	log      *slog.Logger
}

func New(manager *audit.Manager, store *store.Store, location *time.Location, log *slog.Logger) *Handler {
	return &Handler{manager: manager, store: store, location: location, log: log}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/audit/api/v1/current":
		writeJSON(w, h.manager.Current())
	case "/audit/api/v1/live":
		writeJSON(w, h.liveData())
	case "/audit/api/v1/dashboard":
		data, err := h.dashboardData(r.Context())
		if err != nil {
			h.log.Error("load dashboard data", "error", err)
			http.Error(w, "dashboard data unavailable", http.StatusInternalServerError)
			return
		}
		writeJSON(w, data)
	case "/audit/api/v1/history/dashboard":
		data, err := h.historyPageData(r.Context())
		if err != nil {
			h.log.Error("load history page data", "error", err)
			http.Error(w, "history data unavailable", http.StatusInternalServerError)
			return
		}
		writeJSON(w, data)
	case "/audit/api/v1/history":
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		camera := r.URL.Query().Get("camera")
		var events []model.Event
		var err error
		switch r.URL.Query().Get("type") {
		case "":
			events, err = h.store.Recent(r.Context(), limit, camera)
		case "frigate":
			events, err = h.store.RecentNonRecordingFrigate(r.Context(), limit, camera)
		case "recordings":
			events, err = h.store.RecentRecordings(r.Context(), limit, camera)
		case "streams":
			events, err = h.store.RecentStreams(r.Context(), limit, camera)
		default:
			http.Error(w, "invalid history type", http.StatusBadRequest)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, events)
	case "/audit/api/v1/graph":
		w.Header().Set("Content-Type", "text/vnd.graphviz; charset=utf-8")
		_, _ = w.Write([]byte(h.manager.Current().SanitizedGraph))
	case "/audit/export.csv":
		h.exportCSV(w, r)
	case "/audit/assets/audit.css":
		serveAsset(w, "text/css; charset=utf-8", auditCSS)
	case "/audit/assets/common.js":
		serveAsset(w, "text/javascript; charset=utf-8", commonJS)
	case "/audit/assets/overview.js":
		serveAsset(w, "text/javascript; charset=utf-8", overviewJS)
	case "/audit/assets/history.js":
		serveAsset(w, "text/javascript; charset=utf-8", historyJS)
	case "/audit/history", "/audit/history/":
		h.page(w, historyTemplate)
	default:
		if r.URL.Path == "/audit" || r.URL.Path == "/audit/" {
			h.page(w, overviewTemplate)
			return
		}
		http.NotFound(w, r)
	}
}

func serveAsset(w http.ResponseWriter, contentType, content string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write([]byte(content))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func (h *Handler) exportCSV(w http.ResponseWriter, r *http.Request) {
	events, err := h.store.Recent(r.Context(), 1000, r.URL.Query().Get("camera"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="camera-audit.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "kind", "actor", "confidence", "camera", "protocol", "remote_addr", "suppressed", "started_at", "last_seen_at", "ended_at", "details"})
	for _, event := range events {
		endedAt := ""
		if event.EndedAt != nil {
			endedAt = h.csvTime(*event.EndedAt)
		}
		_ = cw.Write([]string{strconv.FormatInt(event.ID, 10), event.Kind, event.Actor, event.Confidence, event.Camera, event.Protocol,
			event.RemoteAddr, strconv.FormatBool(event.Suppressed), h.csvTime(event.StartedAt),
			h.csvTime(event.LastSeenAt), endedAt, event.Details})
	}
	cw.Flush()
}

func (h *Handler) csvTime(value time.Time) string {
	return value.In(h.location).Format(time.RFC3339)
}

var overviewTemplate = template.Must(template.New("overview").Parse(overviewHTML))
var historyTemplate = template.Must(template.New("history").Parse(historyHTML))

func (h *Handler) page(w http.ResponseWriter, page *template.Template) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := page.Execute(w, nil); err != nil {
		h.log.Error("render audit page", "error", err)
	}
}
