// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

package httpapi

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/auth"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/domain"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/enrich"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/hubsettings"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/ported"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/ported/stub"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/store"
)

type deliverer struct {
	err  error
	recs []domain.Record
}

func (d *deliverer) DeliverNow(_ context.Context, r domain.Record) error {
	d.recs = append(d.recs, r)
	return d.err
}

type sysHub struct {
	db    *store.DB
	c     *client
	audit *auditLog
	siem  *deliverer
	reset []bool
	srv   *httptest.Server
}

func newSysHub(t *testing.T) *sysHub {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "ts.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc, _ := auth.New(auth.Options{Store: db, Hasher: auth.NewHasher(auth.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1}, 4),
		TOTP: stub.TOTP{}, Log: log, Now: time.Now, SessionTTL: time.Hour, SessionIdle: time.Hour})
	tok, _ := svc.Init(ctx)
	h := &sysHub{db: db, audit: &auditLog{}, siem: &deliverer{}}
	settings := &hubsettings.Service{Store: db, Parser: stub.ExactSourceList{}, Log: log}
	settings.Load(ctx)
	admin := &Admin{Auth: svc, Settings: db, Audit: h.audit, Log: log, Now: time.Now, Development: true}
	(&Events{Store: db, Enricher: &enrich.Enricher{Nodes: db}, Log: log}).Register(admin)
	(&System{Settings: settings, Auth: svc, BeaconDB: db, SIEM: h.siem, Log: log, Now: time.Now,
		Reset: func(ctx context.Context, purge bool) error {
			h.reset = append(h.reset, purge)
			return db.FactoryReset(ctx, purge)
		}}).Register(admin)
	h.srv = httptest.NewServer(SecurityHeaders(Network{}, admin.Handler()))
	t.Cleanup(h.srv.Close)
	jar, _ := cookiejar.New(nil)
	h.c = &client{t: t, http: &http.Client{Jar: jar}, base: h.srv.URL, origin: h.srv.URL}
	h.c.do("POST", "/api/v3/setup", map[string]string{"setup_token": tok, "password": adminPW, "public_endpoint": h.srv.URL})
	h.c.do("POST", "/api/v3/session/login", map[string]string{"password": adminPW})

	db.CreateNode(ctx, &domain.Node{ID: "node-0000000a", Alias: "=HYPERLINK(\"evil\")", KeyHash: []byte("k"), CreatedAt: time.Now()})
	now := time.Now()
	for i := 0; i < 7; i++ {
		sev := domain.SeverityHigh
		if i%2 == 0 {
			sev = domain.SeverityLow
		}
		db.InsertEvent(ctx, &domain.Event{EventID: fmt.Sprintf("e%d", i), NodeID: "node-0000000a", SensorID: "ts-sensor-a",
			Trigger: "tcp_connection", Severity: sev, OccurredAt: now, ReceivedAt: now.Add(time.Duration(i) * time.Second),
			Source: fmt.Sprintf("=cmd|' /C calc'!A%d", i), Target: "SSH", Details: []byte(`{"k":1}`)})
	}
	db.InsertHoneytoken(ctx, ported.Honeytoken{ID: "ht_1", Username: "+svc", Secret: "TOP-SECRET", PlantedNodeID: "node-0000000a",
		PlantedSensorID: "ts-sensor-f", CreatedAt: now})
	return h
}

func (h *sysHub) raw(t *testing.T, path string) (int, string) {
	req, _ := http.NewRequest("GET", h.srv.URL+path, nil)
	resp, err := h.c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestEventsListFiltersCursorFlags(t *testing.T) {
	h := newSysHub(t)
	code, out, _ := h.c.do("GET", "/api/v3/events?severity=high&limit=2", nil)
	evs := out["events"].([]any)
	if code != 200 || len(evs) != 2 || out["next_cursor"] == nil {
		t.Fatalf("%d %v", code, out)
	}
	first := evs[0].(map[string]any)
	if first["severity"] != "high" || first["node_alias"] != `=HYPERLINK("evil")` {
		t.Fatalf("%v", first)
	}
	_, out2, _ := h.c.do("GET", "/api/v3/events?severity=high&limit=2&before="+out["next_cursor"].(string), nil)
	if n := len(out2["events"].([]any)); n != 1 {
		t.Fatalf("second page %d", n)
	}
	for _, bad := range []string{"severity=urgent", "limit=9999", "node=../x", "before=-1", "from=yesterday", "archived=maybe"} {
		if code, _, _ := h.c.do("GET", "/api/v3/events?"+bad, nil); code != 400 {
			t.Errorf("%s: %d", bad, code)
		}
	}
	_, out, _ = h.c.do("GET", "/api/v3/events/unread-count", nil)
	if out["unread"] != 7.0 {
		t.Fatalf("%v", out)
	}
	seq := fmt.Sprint(int64(first["seq"].(float64)))
	h.c.do("POST", "/api/v3/events/"+seq+"/read", nil)
	_, out, _ = h.c.do("GET", "/api/v3/events/unread-count", nil)
	if out["unread"] != 6.0 {
		t.Fatal("mark read")
	}
	h.c.do("POST", "/api/v3/events/archive-all", nil)
	_, out, _ = h.c.do("GET", "/api/v3/events", nil)
	if len(out["events"].([]any)) != 0 {
		t.Fatal("archive all")
	}
	_, out, _ = h.c.do("GET", "/api/v3/events?archived=true", nil)
	if len(out["events"].([]any)) != 7 {
		t.Fatal("archived filter")
	}
	if code, _, _ := h.c.do("GET", "/api/v3/events/999999", nil); code != 404 {
		t.Fatal("missing event")
	}
}

func TestDeleteAllNeedsConfirmation(t *testing.T) {
	h := newSysHub(t)
	if code, out, _ := h.c.do("POST", "/api/v3/events/delete-all", map[string]string{"confirm": "yes"}); code != 400 || out["error"] != "confirmation_required" {
		t.Fatalf("%d %v", code, out)
	}
	if code, out, _ := h.c.do("POST", "/api/v3/events/delete-all", map[string]string{"confirm": ConfirmDeleteAll}); code != 200 || out["deleted"] != 7.0 {
		t.Fatalf("%d %v", code, out)
	}
	if !strings.Contains(strings.Join(h.audit.actions(), " "), "events.delete_all:200") {
		t.Fatal("not audited")
	}
}

func TestExportsNeutraliseFormulasAndHideSecrets(t *testing.T) {
	h := newSysHub(t)
	code, body := h.raw(t, "/api/v3/events/export?format=csv&archived=any")
	if code != 200 {
		t.Fatal(code)
	}
	rows, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil || len(rows) != 8 {
		t.Fatalf("%d rows %v", len(rows), err)
	}
	for _, row := range rows[1:] {
		for _, cell := range row {
			if cell != "" && strings.ContainsRune("=+-@", rune(cell[0])) {
				t.Fatalf("formula cell %q", cell)
			}
		}
	}
	code, body = h.raw(t, "/api/v3/events/export?format=json")
	var arr []map[string]any
	if code != 200 || json.Unmarshal([]byte(body), &arr) != nil || len(arr) != 7 {
		t.Fatalf("json export: %d %d", code, len(arr))
	}
	_, body = h.raw(t, "/api/v3/honeytokens/export")
	if strings.Contains(body, "TOP-SECRET") || !strings.HasPrefix(body, "username,honeytoken_id,planted_node_id,planted_sensor_id,created_at\n'+svc,ht_1") {
		t.Fatalf("%q", body)
	}
	_, out, _ := h.c.do("GET", "/api/v3/honeytokens", nil)
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "TOP-SECRET") {
		t.Fatal("honeytoken secret in API")
	}
	acts := strings.Join(h.audit.actions(), " ")
	if !strings.Contains(acts, "events.export:200") || !strings.Contains(acts, "honeytokens.export:200") {
		t.Fatalf("exports not audited: %s", acts)
	}
}

func TestSettingsAndAssets(t *testing.T) {
	h := newSysHub(t)
	code, out, _ := h.c.do("PATCH", "/api/v3/settings", map[string]any{"whitelist": []string{"10.0.0.7"}, "update_check_hours": 12})
	s := out["settings"].(map[string]any)
	if code != 200 || s["update_check_hours"] != 12.0 || s["whitelist"].([]any)[0] != "10.0.0.7" || s["source_lists_active"] != true {
		t.Fatalf("%d %v", code, out)
	}
	if code, _, _ := h.c.do("PATCH", "/api/v3/settings", map[string]any{"update_check_hours": -5}); code != 400 {
		t.Fatal("invalid patch accepted")
	}
	if code, _, _ := h.c.do("PATCH", "/api/v3/settings", map[string]any{"siem_token": "x"}); code != 400 {
		t.Fatal("unknown field accepted")
	}
	if code, out, _ := h.c.do("PUT", "/api/v3/assets", map[string]any{"assets": []any{}}); code != 503 || out["error"] != "module_unavailable" {
		t.Fatalf("%d %v", code, out)
	}
	if code, out, _ := h.c.do("POST", "/api/v3/beacons", map[string]any{"type": "dns", "name": "x"}); code != 503 {
		t.Fatalf("%d %v", code, out)
	}
	if code, out, _ := h.c.do("GET", "/api/v3/beacons", nil); code != 200 || out["available"] != false {
		t.Fatalf("%d %v", code, out)
	}
}

func TestFactoryReset(t *testing.T) {
	h := newSysHub(t)
	if code, _, _ := h.c.do("POST", "/api/v3/system/factory-reset", map[string]any{"password": adminPW, "confirm": "reset"}); code != 400 {
		t.Fatal("missing confirmation accepted")
	}
	if code, _, _ := h.c.do("POST", "/api/v3/system/factory-reset", map[string]any{"password": "wrong password!!", "confirm": ConfirmFactoryReset}); code != 401 {
		t.Fatal("wrong password accepted")
	}
	h.siem.err = errors.New("collector down")
	code, out, _ := h.c.do("POST", "/api/v3/system/factory-reset", map[string]any{"password": adminPW, "confirm": ConfirmFactoryReset})
	if code != 502 || out["error"] != "audit_undeliverable" || len(h.reset) != 0 {
		t.Fatalf("reset ran without a delivered audit: %d %v %v", code, out, h.reset)
	}
	h.siem.err = nil
	code, out, _ = h.c.do("POST", "/api/v3/system/factory-reset", map[string]any{"password": adminPW, "confirm": ConfirmFactoryReset})
	if code != 200 || len(h.reset) != 1 || h.reset[0] {
		t.Fatalf("%d %v %v", code, out, h.reset)
	}
	last := h.siem.recs[len(h.siem.recs)-1]
	if last.Kind != domain.RecordAudit || last.Audit.Action != "system.factory_reset" {
		t.Fatalf("audit before reset: %+v", last)
	}
	if ok, _ := h.db.AdminExists(context.Background()); ok {
		t.Fatal("admin survived")
	}
	if code, _, _ := h.c.do("GET", "/api/v3/events", nil); code != 401 {
		t.Fatal("session survived the reset")
	}
	if l, _ := h.db.ListHoneytokens(context.Background()); len(l) != 1 {
		t.Fatal("honeytokens purged without the option")
	}
}
