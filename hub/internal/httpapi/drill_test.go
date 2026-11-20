// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package httpapi

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported/stub"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/projections"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
)

func insertDrill(t *testing.T, db *store.DB, id, trigger string, at time.Time, archived bool) {
	insertDrillOn(t, db, "node-0000000a", id, trigger, at, archived)
}

func insertDrillOn(t *testing.T, db *store.DB, node, id, trigger string, at time.Time, archived bool) {
	t.Helper()
	if ok, err := db.InsertEvent(context.Background(), &domain.Event{EventID: id, NodeID: node, SensorID: "ts-sensor-a",
		Trigger: trigger, Severity: domain.SeverityInfo, OccurredAt: at, ReceivedAt: at, Source: domain.DrillSource,
		Target: "SSH (port 22)", Details: []byte(`{"original_severity":"critical","username":"drill"}`), Drill: true,
		Archived: archived, Read: archived}); !ok || err != nil {
		t.Fatal(id, err)
	}
}

// TestEventViews covers the Active / Archived / Drills / All views and the
// archived parameter's compatibility (F-001).
func TestEventViews(t *testing.T) {
	h := newSysHub(t)
	ctx := context.Background()
	const node = "node-0000000c" // the fixture seeds other events on other nodes
	h.db.CreateNode(ctx, &domain.Node{ID: node, Alias: "c", KeyHash: []byte("kc"), CreatedAt: time.Now()})
	_, base, _ := h.c.do("GET", "/api/v3/events/unread-count", nil)
	now := time.Now().UTC()
	h.db.InsertEvent(ctx, &domain.Event{EventID: "active", NodeID: node, SensorID: "ts-sensor-a", Trigger: "x",
		Severity: "high", OccurredAt: now, ReceivedAt: now, Source: "198.51.100.1", Target: "t", Details: []byte("{}")})
	h.db.InsertEvent(ctx, &domain.Event{EventID: "archived", NodeID: node, SensorID: "ts-sensor-a", Trigger: "x",
		Severity: "high", OccurredAt: now, ReceivedAt: now, Source: "198.51.100.2", Target: "t", Details: []byte("{}"), Archived: true})
	insertDrillOn(t, h.db, node, "drill-1", "ssh_login", now, false)
	insertDrillOn(t, h.db, node, "drill-2", "ssh_login", now, false)
	insertDrillOn(t, h.db, node, "drill-3", "ssh_login", now, true)

	ids := func(q string) string {
		t.Helper()
		sep := "?"
		if q != "" {
			sep = "&"
		}
		code, out, _ := h.c.do("GET", "/api/v3/events"+q+sep+"node="+node, nil)
		if code != 200 {
			t.Fatalf("%s: %d %v", q, code, out)
		}
		var got []string
		for _, e := range out["events"].([]any) {
			m := e.(map[string]any)
			got = append(got, fmt.Sprintf("%s:%v", m["event_id"], m["drill"]))
		}
		return strings.Join(got, ",")
	}
	for q, want := range map[string]string{
		"":                "active:false",
		"?view=active":    "active:false",
		"?archived=false": "active:false",
		"?view=archived":  "archived:false",
		"?archived=true":  "archived:false",
		"?view=drills":    "drill-3:true,drill-2:true,drill-1:true",
		"?view=all":       "drill-3:true,drill-2:true,drill-1:true,archived:false,active:false",
		"?archived=any":   "drill-3:true,drill-2:true,drill-1:true,archived:false,active:false",
	} {
		if got := ids(q); got != want {
			t.Errorf("%q: got %s, want %s", q, got, want)
		}
	}
	for _, q := range []string{"?view=drill", "?view=drills&archived=any", "?view=active&archived=false"} {
		if code, _, _ := h.c.do("GET", "/api/v3/events"+q, nil); code != 400 {
			t.Errorf("%s: %d, want 400", q, code)
		}
	}
	if _, out, _ := h.c.do("GET", "/api/v3/events/unread-count", nil); out["unread"] != base["unread"].(float64)+1 {
		t.Fatalf("unread badge counts drills: %v (before %v)", out, base)
	}

	// Export follows the view and carries the drill column.
	resp, err := h.c.http.Get(h.srv.URL + "/api/v3/events/export?format=csv&view=drills&node=" + node)
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := csv.NewReader(resp.Body).ReadAll()
	resp.Body.Close()
	if len(rows) != 4 || rows[0][len(rows[0])-1] != "drill" || rows[1][len(rows[1])-1] != "true" {
		t.Fatalf("export: %v", rows)
	}
}

// TestDrillsLeaveAnalyticsUnchanged is the F-001 acceptance at the API: a
// fire drill leaves the dashboard (summary, severity, velocity), every
// projection (insights incl. touched decoys and distinct sources, sources,
// geo, attack path, report) and the ATT&CK layer unchanged by default.
func TestDrillsLeaveAnalyticsUnchanged(t *testing.T) {
	var db *store.DB
	fixed := time.Now().UTC()
	h := newInsightHubWith(t, func(in *Insights) {
		db = in.Store.(*store.DB)
		in.Attack = stub.Attack{Map: map[string]domain.AttackMapping{
			"ssh_login": {Primary: domain.Technique{ID: "T1021.004", Name: "SSH", Tactics: []string{"lateral-movement"}}},
			"x":         {Primary: domain.Technique{ID: "T1046", Name: "Network Service Discovery", Tactics: []string{"discovery"}}},
		}}
		in.Projections = map[string]ported.Projection{}
		for _, p := range []ported.Projection{
			projections.NewInsights(in.Store, nil, nil),
			projections.Sources{},
			projections.GeoMap{},
			projections.AttackPath{},
			projections.Report{Now: func() time.Time { return fixed }},
		} {
			in.Projections[p.Name()] = p
		}
	})
	paths := []string{
		"/api/v3/analytics/summary",
		"/api/v3/analytics/severity?days=1",
		"/api/v3/analytics/velocity?hours=6&bucket=3600",
		"/api/v3/analytics/projections/insights?days=7",
		"/api/v3/analytics/projections/sources",
		"/api/v3/analytics/projections/geo_map",
		"/api/v3/analytics/projections/attack_path?source=" + domain.DrillSource,
		"/api/v3/analytics/projections/report",
		"/api/v3/analytics/attack/navigator",
	}
	snapshot := func(extra string) map[string]string {
		t.Helper()
		out := map[string]string{}
		for _, p := range paths {
			sep := "?"
			if strings.Contains(p, "?") {
				sep = "&"
			}
			u := p
			if extra != "" {
				u += sep + extra
			}
			resp, err := h.c.http.Get(h.srv.URL + strings.ReplaceAll(u, " ", "%20"))
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("%s: %d %s", u, resp.StatusCode, b)
			}
			out[p] = normaliseVolatile(t, b)
		}
		return out
	}
	before := snapshot("")
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		insertDrill(t, db, fmt.Sprintf("drill-%d", i), "ssh_login", now.Add(-time.Duration(i)*time.Minute), false)
	}
	after := snapshot("")
	for _, p := range paths {
		if before[p] != after[p] {
			t.Errorf("%s changed after a fire drill:\nbefore %s\nafter  %s", p, before[p], after[p])
		}
	}
	// Opting in (admin) brings the drills back.
	with := snapshot("include_drills=true")
	for _, p := range []string{"/api/v3/analytics/summary", "/api/v3/analytics/projections/report", "/api/v3/analytics/attack/navigator"} {
		if with[p] == after[p] {
			t.Errorf("%s: include_drills=true did not include the drills", p)
		}
	}
	var s struct{ Summary map[string]float64 }
	json.Unmarshal([]byte(with["/api/v3/analytics/summary"]), &s)
	if s.Summary["events_total"] != 7 {
		t.Fatalf("summary with drills: %v", s.Summary)
	}
	if code, _, _ := h.c.do("GET", "/api/v3/analytics/summary?include_drills=yes", nil); code != 400 {
		t.Fatalf("invalid include_drills: %d", code)
	}
}

// normaliseVolatile drops fields that depend on the wall clock.
func normaliseVolatile(t *testing.T, b []byte) string {
	t.Helper()
	var v any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return string(b) // navigator layer: raw JSON
	}
	var walk func(any)
	walk = func(x any) {
		switch m := x.(type) {
		case map[string]any:
			for _, k := range []string{"generatedAt", "generated_at", "uptime_seconds"} {
				delete(m, k)
			}
			for _, c := range m {
				walk(c)
			}
		case []any:
			for _, c := range m {
				walk(c)
			}
		}
	}
	walk(v)
	out, _ := json.Marshal(v)
	return string(out)
}

// TestIncludeDrillsNeedsAnalyst: viewers cannot opt in to drills; analysts
// and admins can (F-001 requirement 6).
func TestIncludeDrillsNeedsAnalyst(t *testing.T) {
	var in *Insights
	var db *store.DB
	h := newInsightHubWith(t, func(i *Insights) {
		in, db = i, i.Store.(*store.DB)
		i.Projections = map[string]ported.Projection{"report": projections.Report{}}
	})
	ctx := context.Background()
	toks := map[string]string{}
	for _, u := range []store.User{
		{ID: "usr_v", Username: "victor", Role: store.RoleViewer, Source: store.SourceOIDC},
		{ID: "usr_n", Username: "nadia", Role: store.RoleAnalyst, Source: store.SourceOIDC},
	} {
		if err := db.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
		uu, _ := db.UserByID(ctx, u.ID)
		s, err := in.Auth.NewUserSession(ctx, uu)
		if err != nil {
			t.Fatal(err)
		}
		toks[u.Role] = s.Token
	}
	call := func(tok, path string) int {
		req, _ := http.NewRequest("GET", h.srv.URL+path, nil)
		req.AddCookie(&http.Cookie{Name: SessionCookie, Value: tok})
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for _, p := range []string{"/api/v3/analytics/summary", "/api/v3/analytics/severity", "/api/v3/analytics/velocity",
		"/api/v3/analytics/attack/navigator", "/api/v3/analytics/projections/report"} {
		if code := call(toks[store.RoleViewer], p); code != 200 {
			t.Errorf("viewer %s: %d", p, code)
		}
		if code := call(toks[store.RoleViewer], p+"?include_drills=true"); code != http.StatusForbidden {
			t.Errorf("viewer %s?include_drills=true: %d, want 403", p, code)
		}
		if code := call(toks[store.RoleAnalyst], p+"?include_drills=true"); code != 200 {
			t.Errorf("analyst %s?include_drills=true: %d", p, code)
		}
	}
}

// TestDrillsOnlyFromAuthenticatedSensors: the only way to create a drill is
// the node API with a valid node key; the admin API has no route that
// creates events (F-001 requirement 3).
func TestDrillsOnlyFromAuthenticatedSensors(t *testing.T) {
	f := newHub(t, 50, 200)
	drill := evJSON("ts-sensor-demo", "ssh_login", `,"drill":true`)
	for _, key := range []string{"", "tsk_" + strings.Repeat("0", 64)} {
		if code, _, _ := f.post(t, "/v3/ingest/events", key, `{"events":[`+drill+`]}`); code != http.StatusUnauthorized {
			t.Fatalf("drill with key %q: %d", key, code)
		}
	}
	if evs, _ := f.db.Events(context.Background(), store.EventFilter{}); len(evs) != 0 {
		t.Fatal("unauthenticated drill stored")
	}
	if code, out, _ := f.post(t, "/v3/ingest/events", f.keyA, `{"events":[`+drill+`]}`); code != 200 || out["accepted"] != 1.0 {
		t.Fatalf("authenticated drill: %d %v", code, out)
	}
	yes := true
	if evs, _ := f.db.Events(context.Background(), store.EventFilter{Drill: &yes}); len(evs) != 1 || evs[0].Severity != domain.SeverityInfo {
		t.Fatalf("drill not stored as info: %+v", evs)
	}

	// No admin route writes events: every event route is GET or a flag
	// change (read/archive) or the delete-all danger action.
	sys := newSysHub(t)
	for _, m := range []string{"POST", "PUT", "PATCH"} {
		if code, _, _ := sys.c.do(m, "/api/v3/events", map[string]any{"trigger": "x", "drill": true}); code != http.StatusMethodNotAllowed && code != http.StatusNotFound {
			t.Errorf("%s /api/v3/events: %d", m, code)
		}
	}
}
