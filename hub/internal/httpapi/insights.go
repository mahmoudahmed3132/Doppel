// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package httpapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/analytics"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/auth"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/hubsettings"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ingest"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/livefeed"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/semver"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/updatecheck"
)

// InsightStore is the persistence analytics needs.
type InsightStore interface {
	SeverityCounts(ctx context.Context, since time.Time) (map[domain.Severity]int64, error)
	Velocity(ctx context.Context, since time.Time, bucket time.Duration) (map[int64]int64, error)
	EventCounts(ctx context.Context, since time.Time) (total, unread, recent, recentCritical int64, err error)
	Nodes(ctx context.Context) ([]domain.Node, error)
	Sensors(ctx context.Context, nodeID string) ([]domain.Sensor, error)
	StatusHistory(ctx context.Context, since time.Time) ([]store.StatusChange, error)
	Events(ctx context.Context, f store.EventFilter) ([]domain.Event, error)
}

// Insights serves analytics, system status and the live feed.
type Insights struct {
	Store       InsightStore
	Enricher    ingest.Enricher
	Projections map[string]ported.Projection // PORTED; may be empty
	Attack      ported.AttackMapper          // PORTED; may be nil
	Updates     *updatecheck.Checker
	Settings    *hubsettings.Service
	Auth        *auth.Service
	Live        *livefeed.Broker
	Armed       func() bool
	SIEMStats   func() (int, uint64)
	Version     string
	Schema      int
	StartedAt   time.Time
	Development bool
	Log         *slog.Logger
	Now         func() time.Time
	TickEvery   time.Duration
	// Origin returns the expected Hub origin for a request (Admin.expectedOrigin).
	Origin func(*http.Request) string
}

// Register mounts the routes.
func (in *Insights) Register(a *Admin) {
	a.RouteFull("GET /api/v3/analytics/summary", "", needViewer, in.summary)
	a.RouteFull("GET /api/v3/analytics/severity", "", needViewer, in.severity)
	a.RouteFull("GET /api/v3/analytics/velocity", "", needViewer, in.velocity)
	a.RouteFull("GET /api/v3/analytics/uptime", "", needViewer, in.uptime)
	a.RouteFull("GET /api/v3/analytics/attack/navigator", "", needViewer, in.navigator)
	a.RouteFull("GET /api/v3/analytics/projections/{name}", "", needViewer, in.projection)
	a.RouteFull("GET /api/v3/system/status", "", needViewer, in.status)
	a.RouteFull("POST /api/v3/system/update-check", "system.update_check", needAdmin, in.updateCheck)
	a.RouteFull("GET /api/v3/live", "", needViewer, in.live)
}

func intParam(r *http.Request, name string, def, min, max int) (int, bool) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		return 0, false
	}
	return n, true
}

func (in *Insights) fail(w http.ResponseWriter, err error) {
	in.Log.Error("analytics failed", "error", err.Error())
	Fail(w, http.StatusInternalServerError, CodeInternal, "internal error")
}

func (in *Insights) summary(w http.ResponseWriter, r *http.Request) {
	now := in.Now()
	total, unread, recent, crit, err := in.Store.EventCounts(r.Context(), now.Add(-24*time.Hour))
	if err != nil {
		in.fail(w, err)
		return
	}
	nodes, _ := in.Store.Nodes(r.Context())
	sensors, _ := in.Store.Sensors(r.Context(), "")
	nOnline, sOnline := 0, 0
	for _, n := range nodes {
		if n.Online(now) {
			nOnline++
		}
	}
	for _, s := range sensors {
		if s.Status == domain.StatusOnline {
			sOnline++
		}
	}
	OK(w, map[string]any{"summary": map[string]any{
		"events_total": total, "events_unread": unread, "events_24h": recent, "critical_24h": crit,
		"nodes_total": len(nodes), "nodes_online": nOnline, "sensors_total": len(sensors), "sensors_online": sOnline,
	}})
}

func (in *Insights) severity(w http.ResponseWriter, r *http.Request) {
	days, ok := intParam(r, "days", 7, 1, 365)
	if !ok {
		badQuery(w, "days must be 1..365")
		return
	}
	c, err := in.Store.SeverityCounts(r.Context(), in.Now().Add(-time.Duration(days)*24*time.Hour))
	if err != nil {
		in.fail(w, err)
		return
	}
	OK(w, map[string]any{"days": days, "severity": c})
}

func (in *Insights) velocity(w http.ResponseWriter, r *http.Request) {
	hours, ok1 := intParam(r, "hours", 24, 1, 24*90)
	bucket, ok2 := intParam(r, "bucket", 3600, 60, 86400)
	if !ok1 || !ok2 || hours*3600/bucket > 1000 {
		badQuery(w, "hours 1..2160, bucket 60..86400 s, at most 1000 buckets")
		return
	}
	b := time.Duration(bucket) * time.Second
	now := in.Now()
	start := now.Add(-time.Duration(hours) * time.Hour).Truncate(b)
	m, err := in.Store.Velocity(r.Context(), start, b)
	if err != nil {
		in.fail(w, err)
		return
	}
	type point struct {
		T     time.Time `json:"t"`
		Count int64     `json:"count"`
	}
	series := []point{}
	for t := start; !t.After(now); t = t.Add(b) {
		series = append(series, point{t.UTC(), m[t.UnixMilli()]})
	}
	OK(w, map[string]any{"bucket_seconds": bucket, "series": series})
}

func (in *Insights) uptime(w http.ResponseWriter, r *http.Request) {
	days, ok := intParam(r, "days", 14, 1, 90)
	if !ok {
		badQuery(w, "days must be 1..90")
		return
	}
	now := in.Now().UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	start := today.AddDate(0, 0, -(days - 1))
	sensors, err := in.Store.Sensors(r.Context(), "")
	if err != nil {
		in.fail(w, err)
		return
	}
	hist, err := in.Store.StatusHistory(r.Context(), start)
	if err != nil {
		in.fail(w, err)
		return
	}
	rows := analytics.Uptime(sensors, hist, days, now)
	if rows == nil {
		rows = []analytics.UptimeRow{}
	}
	OK(w, map[string]any{"days": days, "sensors": rows})
}

const maxProjectionEvents = 50_000

// windowEvents loads enriched events of the last days (bounded).
func (in *Insights) windowEvents(ctx context.Context, days int) ([]domain.EnrichedEvent, error) {
	f := store.EventFilter{From: in.Now().Add(-time.Duration(days) * 24 * time.Hour), Limit: 1000}
	var out []domain.EnrichedEvent
	for len(out) < maxProjectionEvents {
		evs, err := in.Store.Events(ctx, f)
		if err != nil {
			return nil, err
		}
		for i := range evs {
			if in.Enricher != nil {
				out = append(out, in.Enricher.Enrich(ctx, &evs[i]))
			} else {
				out = append(out, domain.EnrichedEvent{Event: evs[i]})
			}
		}
		if len(evs) < f.Limit {
			break
		}
		f.BeforeSeq = evs[len(evs)-1].Seq
	}
	return out, nil
}

func (in *Insights) navigator(w http.ResponseWriter, r *http.Request) {
	days, ok := intParam(r, "days", 30, 1, 365)
	if !ok {
		badQuery(w, "days must be 1..365")
		return
	}
	evs, err := in.windowEvents(r.Context(), days)
	if err != nil {
		in.fail(w, err)
		return
	}
	layer, err := in.Attack.NavigatorLayer(evs)
	if err != nil {
		in.fail(w, err)
		return
	}
	attachment(w, "truesignal-attack-layer.json", "application/json")
	w.Write(layer)
}

var projectionRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// projection runs an analytics projection by name. Query parameters
// other than days are passed through (bounded).
func (in *Insights) projection(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	p, ok := in.Projections[name]
	if !projectionRE.MatchString(name) || !ok {
		Fail(w, http.StatusNotFound, CodeNotFound, "unknown projection")
		return
	}
	days, ok := intParam(r, "days", 30, 1, 365)
	if !ok {
		badQuery(w, "days must be 1..365")
		return
	}
	params := map[string]string{}
	for k, v := range r.URL.Query() {
		if k != "days" && len(params) < 16 && len(k) <= 32 && len(v) > 0 && len(v[0]) <= 256 {
			params[k] = v[0]
		}
	}
	evs, err := in.windowEvents(r.Context(), days)
	if err != nil {
		in.fail(w, err)
		return
	}
	dto, err := p.Build(ported.WithWindowDays(r.Context(), days), evs, params)
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeInvalid, err.Error())
		return
	}
	b, err := json.Marshal(dto)
	if err != nil {
		in.fail(w, err)
		return
	}
	OK(w, map[string]any{"projection": name, "days": days, "data": json.RawMessage(b)})
}

func (in *Insights) statusJSON(ctx context.Context) map[string]any {
	st := updatecheck.State{}
	if in.Updates != nil {
		st = in.Updates.State()
	}
	ack := in.Settings.CLINoticeAck(ctx)
	depth, dropped := in.SIEMStats()
	projections := []string{}
	for n := range in.Projections {
		projections = append(projections, n)
	}
	return map[string]any{
		"version": in.Version, "schema": in.Schema, "uptime_seconds": int64(in.Now().Sub(in.StartedAt) / time.Second),
		"armed": in.Armed(), "siem_queue": map[string]any{"depth": depth, "dropped": dropped},
		"updates":              st,
		"hub_update_available": st.LatestHub != "" && semver.Less(in.Version, st.LatestHub),
		"cli_release_notice":   st.LatestCLI != "" && st.LatestCLI != ack,
		"cli_notice_ack":       ack,
		"modules":              map[string]any{"attack": true, "projections": projections},
		"live_clients":         in.Live.Clients(),
	}
}

func (in *Insights) status(w http.ResponseWriter, r *http.Request) {
	OK(w, map[string]any{"status": in.statusJSON(r.Context())})
}

func (in *Insights) updateCheck(w http.ResponseWriter, r *http.Request) {
	if in.Updates == nil {
		Fail(w, http.StatusServiceUnavailable, "module_unavailable", "update checks are disabled")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	in.Updates.Check(ctx)
	OK(w, map[string]any{"status": in.statusJSON(r.Context())})
}

// live upgrades to the WebSocket feed. The admin wrapper has already
// authenticated a full session; the Origin must equal the Hub's (§6.4)
// except in development, and the session is re-checked on every tick
// without refreshing its idle timer.
func (in *Insights) live(w http.ResponseWriter, r *http.Request) {
	if !in.Development {
		if o := r.Header.Get("Origin"); o == "" || !sameOrigin(r, in.Origin(r)) {
			Fail(w, http.StatusForbidden, "origin_mismatch", "cross-origin live feed refused")
			return
		}
	}
	cookie, err := r.Cookie(SessionCookie)
	if err != nil {
		Fail(w, http.StatusUnauthorized, "unauthenticated", "login required")
		return
	}
	conn, err := livefeed.Upgrade(w, r)
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeInvalid, "websocket upgrade required")
		return
	}
	ch, cancel := in.Live.Subscribe()
	defer cancel()
	tick := in.TickEvery
	if tick <= 0 {
		tick = 15 * time.Second
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case m, ok := <-ch:
			if !ok {
				conn.Close(1008) // too slow
				return
			}
			if conn.WriteText(m) != nil {
				conn.Close(1011)
				return
			}
		case now := <-t.C:
			if in.Auth.Check(context.WithoutCancel(r.Context()), cookie.Value) != nil {
				conn.Close(1008) // session ended (logout, expiry, password or MFA change)
				return
			}
			b, _ := json.Marshal(livefeed.Message{Type: "tick", Data: map[string]any{"time": now.UTC()}})
			if conn.WriteText(b) != nil {
				conn.Close(1011)
				return
			}
		case <-conn.Done():
			return
		}
	}
}
