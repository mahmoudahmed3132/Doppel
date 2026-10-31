// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

package httpapi

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/domain"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/ingest"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/ported"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/store"
)

// ConfirmDeleteAll must be sent to delete every event.
const ConfirmDeleteAll = "DELETE ALL EVENTS"

// EventStore is the persistence the events API needs.
type EventStore interface {
	Events(ctx context.Context, f store.EventFilter) ([]domain.Event, error)
	Event(ctx context.Context, seq int64) (*domain.Event, error)
	UnreadCount(ctx context.Context) (int64, error)
	MarkRead(ctx context.Context, seq int64) (int64, error)
	Archive(ctx context.Context, seq int64) (int64, error)
	DeleteAllEvents(ctx context.Context) (int64, error)
	ListHoneytokens(ctx context.Context) ([]ported.Honeytoken, error)
}

// Events serves events and honeytokens.
type Events struct {
	Store    EventStore
	Enricher ingest.Enricher
	Log      *slog.Logger
}

// Register mounts the routes.
func (e *Events) Register(a *Admin) {
	a.RouteFull("GET /api/v3/events", "", e.list)
	a.RouteFull("GET /api/v3/events/unread-count", "", e.unread)
	a.RouteFull("GET /api/v3/events/export", "events.export", e.export)
	a.RouteFull("GET /api/v3/events/{seq}", "", e.get)
	a.RouteFull("POST /api/v3/events/{seq}/read", "events.mark_read", e.markRead)
	a.RouteFull("POST /api/v3/events/read-all", "events.mark_read_all", e.markReadAll)
	a.RouteFull("POST /api/v3/events/{seq}/archive", "events.archive", e.archive)
	a.RouteFull("POST /api/v3/events/archive-all", "events.archive_all", e.archiveAll)
	a.RouteFull("POST /api/v3/events/delete-all", "events.delete_all", e.deleteAll)
	a.RouteFull("GET /api/v3/honeytokens", "", e.honeytokens)
	a.RouteFull("GET /api/v3/honeytokens/export", "honeytokens.export", e.honeytokensCSV)
}

func badQuery(w http.ResponseWriter, msg string) { Fail(w, http.StatusBadRequest, CodeInvalid, msg) }

// parseFilter reads list/export filters from the query string.
func parseFilter(q url.Values) (store.EventFilter, string) {
	f := store.EventFilter{Limit: 100}
	switch q.Get("archived") {
	case "", "false":
		v := false
		f.Archived = &v
	case "true":
		v := true
		f.Archived = &v
	case "any":
	default:
		return f, "archived must be true, false or any"
	}
	if v := q.Get("node"); v != "" {
		if !domain.ValidNodeID(v) {
			return f, "invalid node"
		}
		f.NodeID = v
	}
	if v := q.Get("sensor"); v != "" {
		if !domain.ValidSensorID(v) {
			return f, "invalid sensor"
		}
		f.SensorID = v
	}
	if v := q.Get("trigger"); v != "" {
		if !domain.ValidTrigger(v) {
			return f, "invalid trigger"
		}
		f.Trigger = v
	}
	if v := q.Get("severity"); v != "" {
		for _, s := range strings.Split(v, ",") {
			sev := domain.Severity(strings.TrimSpace(s))
			if !sev.Valid() {
				return f, "invalid severity"
			}
			f.Severities = append(f.Severities, sev)
		}
	}
	for key, dst := range map[string]*time.Time{"from": &f.From, "to": &f.To} {
		if v := q.Get(key); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return f, key + " must be RFC 3339"
			}
			*dst = t
		}
	}
	if v := q.Get("q"); v != "" {
		if len(v) > 200 {
			return f, "q too long"
		}
		f.Text = v
	}
	if v := q.Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			return f, "invalid cursor"
		}
		f.BeforeSeq = n
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			return f, "limit must be 1..500"
		}
		f.Limit = n
	}
	return f, ""
}

func (e *Events) enrich(ctx context.Context, evs []domain.Event) []domain.EnrichedEvent {
	out := make([]domain.EnrichedEvent, 0, len(evs))
	for i := range evs {
		if e.Enricher != nil {
			out = append(out, e.Enricher.Enrich(ctx, &evs[i]))
		} else {
			out = append(out, domain.EnrichedEvent{Event: evs[i]})
		}
	}
	return out
}

func (e *Events) fail(w http.ResponseWriter, err error) {
	e.Log.Error("events operation failed", "error", err.Error())
	Fail(w, http.StatusInternalServerError, CodeInternal, "internal error")
}

func (e *Events) list(w http.ResponseWriter, r *http.Request) {
	f, msg := parseFilter(r.URL.Query())
	if msg != "" {
		badQuery(w, msg)
		return
	}
	evs, err := e.Store.Events(r.Context(), f)
	if err != nil {
		e.fail(w, err)
		return
	}
	var next any
	if len(evs) == f.Limit {
		next = strconv.FormatInt(evs[len(evs)-1].Seq, 10)
	}
	OK(w, map[string]any{"events": e.enrich(r.Context(), evs), "next_cursor": next})
}

func seqOf(w http.ResponseWriter, r *http.Request) (int64, bool) {
	n, err := strconv.ParseInt(r.PathValue("seq"), 10, 64)
	if err != nil || n < 1 {
		Fail(w, http.StatusNotFound, CodeNotFound, "event not found")
		return 0, false
	}
	return n, true
}

func (e *Events) get(w http.ResponseWriter, r *http.Request) {
	seq, ok := seqOf(w, r)
	if !ok {
		return
	}
	ev, err := e.Store.Event(r.Context(), seq)
	if err != nil {
		Fail(w, http.StatusNotFound, CodeNotFound, "event not found")
		return
	}
	OK(w, map[string]any{"event": e.enrich(r.Context(), []domain.Event{*ev})[0]})
}

func (e *Events) unread(w http.ResponseWriter, r *http.Request) {
	n, err := e.Store.UnreadCount(r.Context())
	if err != nil {
		e.fail(w, err)
		return
	}
	OK(w, map[string]any{"unread": n})
}

func (e *Events) flag(w http.ResponseWriter, r *http.Request, seq int64, op func(context.Context, int64) (int64, error)) {
	n, err := op(r.Context(), seq)
	if err != nil {
		e.fail(w, err)
		return
	}
	OK(w, map[string]any{"updated": n})
}

func (e *Events) markRead(w http.ResponseWriter, r *http.Request) {
	if seq, ok := seqOf(w, r); ok {
		e.flag(w, r, seq, e.Store.MarkRead)
	}
}
func (e *Events) markReadAll(w http.ResponseWriter, r *http.Request) {
	e.flag(w, r, 0, e.Store.MarkRead)
}
func (e *Events) archive(w http.ResponseWriter, r *http.Request) {
	if seq, ok := seqOf(w, r); ok {
		e.flag(w, r, seq, e.Store.Archive)
	}
}
func (e *Events) archiveAll(w http.ResponseWriter, r *http.Request) { e.flag(w, r, 0, e.Store.Archive) }

func (e *Events) deleteAll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Confirm string `json:"confirm"`
	}
	if !decodeInto(w, r, &req) {
		return
	}
	if req.Confirm != ConfirmDeleteAll {
		Fail(w, http.StatusBadRequest, "confirmation_required", `send {"confirm": "`+ConfirmDeleteAll+`"}`)
		return
	}
	n, err := e.Store.DeleteAllEvents(r.Context())
	if err != nil {
		e.fail(w, err)
		return
	}
	OK(w, map[string]any{"deleted": n})
}

// CSVSafe neutralises spreadsheet formula injection: a cell starting with
// = + - @ (or tab/CR) is prefixed with an apostrophe.
func CSVSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func attachment(w http.ResponseWriter, name, contentType string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
}

const maxExport = 1_000_000

// export streams events page by page (JSON array or CSV).
func (e *Events) export(w http.ResponseWriter, r *http.Request) {
	f, msg := parseFilter(r.URL.Query())
	if msg != "" {
		badQuery(w, msg)
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		badQuery(w, "format must be json or csv")
		return
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	var (
		cw    *csv.Writer
		enc   *json.Encoder
		first = true
	)
	if format == "csv" {
		attachment(w, "truesignal-events-"+stamp+".csv", "text/csv; charset=utf-8")
		cw = csv.NewWriter(w)
		cw.Write([]string{"seq", "event_id", "received_at", "occurred_at", "severity", "trigger", "node_id", "node", "sensor_id",
			"source", "target", "whitelisted", "known_scanner", "read", "archived", "details"})
	} else {
		attachment(w, "truesignal-events-"+stamp+".json", "application/json")
		w.Write([]byte("[\n"))
		enc = json.NewEncoder(w)
	}
	f.Limit = 1000
	written := 0
	for written < maxExport {
		evs, err := e.Store.Events(r.Context(), f)
		if err != nil {
			e.Log.Error("export aborted", "error", err.Error())
			break
		}
		for _, ev := range e.enrich(r.Context(), evs) {
			if cw != nil {
				cw.Write([]string{strconv.FormatInt(ev.Seq, 10), ev.EventID, ev.ReceivedAt.Format(time.RFC3339Nano),
					ev.OccurredAt.Format(time.RFC3339Nano), string(ev.Severity), ev.Trigger, ev.NodeID, CSVSafe(ev.NodeAlias),
					ev.SensorID, CSVSafe(ev.Source), CSVSafe(ev.Target), strconv.FormatBool(ev.Whitelisted),
					strconv.FormatBool(ev.KnownScanner), strconv.FormatBool(ev.Read), strconv.FormatBool(ev.Archived), CSVSafe(string(ev.Details))})
			} else {
				if !first {
					w.Write([]byte(",\n"))
				}
				first = false
				enc.Encode(ev)
			}
			written++
		}
		if len(evs) < f.Limit {
			break
		}
		f.BeforeSeq = evs[len(evs)-1].Seq
	}
	if cw != nil {
		cw.Flush()
	} else {
		w.Write([]byte("]\n"))
	}
}

func (e *Events) honeytokens(w http.ResponseWriter, r *http.Request) {
	l, err := e.Store.ListHoneytokens(r.Context())
	if err != nil {
		e.fail(w, err)
		return
	}
	OK(w, map[string]any{"honeytokens": l}) // Secret has json:"-"
}

func (e *Events) honeytokensCSV(w http.ResponseWriter, r *http.Request) {
	l, err := e.Store.ListHoneytokens(r.Context())
	if err != nil {
		e.fail(w, err)
		return
	}
	attachment(w, "truesignal-honeytokens.csv", "text/csv; charset=utf-8")
	cw := csv.NewWriter(w)
	cw.Write([]string{"username", "honeytoken_id", "planted_node_id", "planted_sensor_id", "created_at"})
	for _, h := range l {
		cw.Write([]string{CSVSafe(h.Username), h.ID, h.PlantedNodeID, h.PlantedSensorID, h.CreatedAt.Format(time.RFC3339)})
	}
	cw.Flush()
}
