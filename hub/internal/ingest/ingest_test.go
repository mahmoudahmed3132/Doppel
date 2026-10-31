// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package ingest

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/domain"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/ids"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/ported"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/ported/stub"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/store"
)

var now = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

func raw(mod func(*RawEvent)) *RawEvent {
	r := &RawEvent{
		EventID:    ids.UUIDv7(now),
		SensorID:   "ts-sensor-ssh",
		Trigger:    "ssh_login_attempt",
		Severity:   "high",
		OccurredAt: now.Add(-time.Second).Format(time.RFC3339),
		Source:     "203.0.113.9:51234",
		Target:     "SSH (port 22)",
		Details:    json.RawMessage(`{"username":"root"}`),
	}
	if mod != nil {
		mod(r)
	}
	return r
}

func TestNormalize(t *testing.T) {
	ev, warns, code := Normalize(raw(nil), "node-00000001", now)
	if code != "" || len(warns) != 0 || ev.Severity != "high" || ev.Source != "203.0.113.9:51234" {
		t.Fatalf("%+v %v %s", ev, warns, code)
	}

	cases := map[string]struct {
		mod  func(*RawEvent)
		code string
	}{
		"bad uuid":      {func(r *RawEvent) { r.EventID = "not-a-uuid" }, CodeInvalidEventID},
		"uuid v4":       {func(r *RawEvent) { r.EventID = "1b4e28ba-2fa1-41d2-883f-0016d3cca427" }, CodeInvalidEventID},
		"reserved":      {func(r *RawEvent) { r.Trigger = "honeytoken_used" }, CodeReservedTrigger},
		"bad trigger":   {func(r *RawEvent) { r.Trigger = "Bad Trigger" }, CodeInvalidTrigger},
		"bad sensor id": {func(r *RawEvent) { r.SensorID = "../../x" }, CodeSensorNotRegistered},
		"empty trigger": {func(r *RawEvent) { r.Trigger = "" }, CodeInvalidTrigger},
	}
	for name, c := range cases {
		if _, _, code := Normalize(raw(c.mod), "n", now); code != c.code {
			t.Errorf("%s: code %q want %q", name, code, c.code)
		}
	}

	// Invalid UTF-8, oversize, empty fields.
	ev, _, _ = Normalize(raw(func(r *RawEvent) {
		r.Source = "\xff\xfe" + strings.Repeat("é", 300)
		r.Target = "   "
		r.Severity = "urgent"
		r.OccurredAt = now.Add(48 * time.Hour).Format(time.RFC3339)
	}), "n", now)
	if !strings.HasPrefix(ev.Source, "�") || len(ev.Source) > MaxFieldBytes || !strings.HasSuffix(ev.Source, "é") {
		t.Fatalf("source not clamped: %q (%d)", ev.Source, len(ev.Source))
	}
	if ev.Target != "Unknown" || ev.Severity != "medium" || !ev.OccurredAt.Equal(now) {
		t.Fatalf("%+v", ev)
	}
	var d map[string]any
	json.Unmarshal(ev.Details, &d)
	if d["sensor_time"] == nil || d["username"] != "root" {
		t.Fatalf("details %s", ev.Details)
	}

	// Oversized and non-object details.
	big := `{"x":"` + strings.Repeat("a", MaxDetailsBytes) + `"}`
	for _, det := range []string{big, `[1,2]`, `"str"`, `{"a":1}{"b":2}`} {
		ev, warns, _ := Normalize(raw(func(r *RawEvent) { r.Details = json.RawMessage(det) }), "n", now)
		if string(ev.Details) != `{"details_dropped":true}` || warns[0] != WarnDetailsDropped {
			t.Fatalf("details %q not dropped: %s", det[:min(len(det), 20)], ev.Details)
		}
	}
	// Invalid UTF-8 in details is replaced, not rejected.
	ev, _, _ = Normalize(raw(func(r *RawEvent) { r.Details = json.RawMessage("{\"u\":\"a\xffb\"}") }), "n", now)
	if !strings.Contains(string(ev.Details), "a�b") {
		t.Fatalf("details utf-8: %q", ev.Details)
	}
}

func TestDecodeRawEventStrict(t *testing.T) {
	if _, ok := DecodeRawEvent([]byte(`{"event_id":"x","extra":1}`)); ok {
		t.Fatal("unknown field accepted")
	}
	if _, ok := DecodeRawEvent([]byte(`{"event_id":"x"}`)); !ok {
		t.Fatal("valid object refused")
	}
}

// --- pipeline -------------------------------------------------------------

type lists struct{ wl, sc ported.SourceMatcher }

func (l lists) Whitelist() ported.SourceMatcher     { return l.wl }
func (l lists) KnownScanners() ported.SourceMatcher { return l.sc }

type recorder struct {
	mu     sync.Mutex
	siem   []domain.Record
	notify []domain.EnrichedEvent
	live   []domain.EnrichedEvent
}

func (r *recorder) Enqueue(rec domain.Record) {
	r.mu.Lock()
	r.siem = append(r.siem, rec)
	r.mu.Unlock()
}
func (r *recorder) Notify(e domain.EnrichedEvent) {
	r.mu.Lock()
	r.notify = append(r.notify, e)
	r.mu.Unlock()
}
func (r *recorder) PublishEvent(e domain.EnrichedEvent) {
	r.mu.Lock()
	r.live = append(r.live, e)
	r.mu.Unlock()
}

func newPipeline(t *testing.T) (*Pipeline, *store.DB, *recorder, *stub.Beacons, *stub.Honeytokens) {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "ts.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()
	db.CreateNode(ctx, &domain.Node{ID: "node-00000001", Alias: "dmz-1", KeyHash: []byte("k"), CreatedAt: now})
	db.CreateSensor(ctx, &domain.Sensor{NodeID: "node-00000001", ID: "ts-sensor-ssh", CatalogueName: "x", Version: "1.0.0", CreatedAt: now})

	wl, _ := stub.ExactSourceList{}.Parse([]string{"10.0.0.7"})
	sc, _ := stub.ExactSourceList{}.Parse([]string{"10.0.0.99"})
	rec := &recorder{}
	bc := stub.NewBeacons()
	ht := &stub.Honeytokens{}
	p := &Pipeline{
		Store: db, Lists: lists{wl, sc}, Beacons: bc, Honeytokens: ht,
		SIEM: rec, Notifier: rec, Live: rec,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now },
	}
	return p, db, rec, bc, ht
}

func normalized(t *testing.T, mod func(*RawEvent)) *domain.Event {
	t.Helper()
	ev, _, code := Normalize(raw(mod), "node-00000001", now)
	if code != "" {
		t.Fatal(code)
	}
	return ev
}

func TestPipelineDuplicate(t *testing.T) {
	p, _, rec, _, _ := newPipeline(t)
	r := raw(nil)
	ev1, _, _ := Normalize(r, "node-00000001", now)
	ev2, _, _ := Normalize(r, "node-00000001", now)
	if res, err := p.Process(context.Background(), ev1); err != nil || !res.Stored {
		t.Fatal(res, err)
	}
	if res, err := p.Process(context.Background(), ev2); err != nil || res.Stored {
		t.Fatal("duplicate stored", res, err)
	}
	if len(rec.siem) != 1 || len(rec.notify) != 1 || len(rec.live) != 1 {
		t.Fatalf("duplicate re-emitted: %d %d %d", len(rec.siem), len(rec.notify), len(rec.live))
	}
}

func TestPipelineWhitelisted(t *testing.T) {
	p, db, rec, _, _ := newPipeline(t)
	ctx := context.Background()
	p.Process(ctx, normalized(t, func(r *RawEvent) { r.Source = "10.0.0.7:5555" }))
	ev, _ := db.Events(ctx, store.EventFilter{})
	if len(ev) != 1 || !ev[0].Whitelisted || !ev[0].Read || !ev[0].Archived {
		t.Fatalf("stored %+v", ev)
	}
	if len(rec.siem) != 1 || !rec.siem[0].Event.Whitelisted {
		t.Fatal("whitelisted event not sent to SIEM flagged")
	}
	if len(rec.notify) != 0 || len(rec.live) != 0 {
		t.Fatal("whitelisted event notified or pushed")
	}

	p.Process(ctx, normalized(t, func(r *RawEvent) { r.Source = "10.0.0.99" }))
	ev, _ = db.Events(ctx, store.EventFilter{Limit: 1})
	if !ev[0].KnownScanner || ev[0].Whitelisted || !ev[0].Archived {
		t.Fatalf("known scanner %+v", ev[0])
	}
}

func TestPipelineBeacon(t *testing.T) {
	p, db, rec, bc, _ := newPipeline(t)
	ctx := context.Background()
	bc.Add(ported.Beacon{ID: "bcn_1", Token: "abc123", Type: "dns", Name: "finance share", Domain: "x.example"})

	// Known beacon from a whitelisted source: not flagged, critical.
	p.Process(ctx, normalized(t, func(r *RawEvent) {
		r.Trigger, r.Severity, r.Source = "beacon_triggered", "low", "10.0.0.7"
		r.Details = json.RawMessage(`{"token":"abc123","beacon_known":true,"beacon":"spoofed"}`)
	}))
	ev, _ := db.Events(ctx, store.EventFilter{Limit: 1})
	if ev[0].Whitelisted || ev[0].Severity != "critical" {
		t.Fatalf("known beacon %+v", ev[0])
	}
	var d map[string]any
	json.Unmarshal(ev[0].Details, &d)
	if _, ok := d["beacon_known"]; ok {
		t.Fatal("beacon_known not removed")
	}
	if b := d["beacon"].(map[string]any); b["id"] != "bcn_1" || b["name"] != "finance share" {
		t.Fatalf("beacon details %v", b)
	}
	bl, _ := bc.List(ctx)
	if bl[0].UseCount != 1 {
		t.Fatal("beacon use not recorded")
	}
	if len(rec.notify) != 1 {
		t.Fatal("known beacon not notified")
	}

	// Unknown beacon: medium, beacon_known=false.
	p.Process(ctx, normalized(t, func(r *RawEvent) {
		r.Trigger, r.Severity = "beacon_triggered", "critical"
		r.Details = json.RawMessage(`{"token":"nope"}`)
	}))
	ev, _ = db.Events(ctx, store.EventFilter{Limit: 1})
	json.Unmarshal(ev[0].Details, &d)
	if ev[0].Severity != "medium" || d["beacon_known"] != false {
		t.Fatalf("unknown beacon %+v %v", ev[0], d)
	}
}

func TestPipelineHoneytokenOnWhitelistedSource(t *testing.T) {
	p, db, rec, _, ht := newPipeline(t)
	ctx := context.Background()
	ht.Add(ported.Honeytoken{ID: "ht_1", Username: "svc_backup", PlantedNodeID: "node-00000002", PlantedSensorID: "ts-sensor-files"})

	orig := normalized(t, func(r *RawEvent) {
		r.Source = "10.0.0.7"
		r.Details = json.RawMessage(`{"username":"svc_backup"}`)
	})
	p.Process(ctx, orig)
	ev, _ := db.Events(ctx, store.EventFilter{})
	if len(ev) != 2 {
		t.Fatalf("expected original + honeytoken_used, got %d", len(ev))
	}
	used, o := ev[0], ev[1]
	if !o.Whitelisted || used.Whitelisted || used.Archived {
		t.Fatalf("flags: original %+v used %+v", o, used)
	}
	if used.Trigger != "honeytoken_used" || used.Severity != "critical" || used.Source != "10.0.0.7" || used.SensorID != "ts-sensor-ssh" {
		t.Fatalf("honeytoken event %+v", used)
	}
	var d map[string]any
	json.Unmarshal(used.Details, &d)
	for _, k := range []string{"honeytoken_id", "honeytoken_username", "matched_on", "planted_node_id", "planted_sensor_id",
		"triggering_event_id", "triggering_trigger", "protocol", "dst_port"} {
		if _, ok := d[k]; !ok {
			t.Errorf("missing detail %s", k)
		}
	}
	if d["triggering_event_id"] != orig.EventID {
		t.Fatal("triggering_event_id mismatch")
	}
	if len(rec.siem) != 2 || len(rec.notify) != 1 || rec.notify[0].Trigger != "honeytoken_used" {
		t.Fatalf("siem=%d notify=%d", len(rec.siem), len(rec.notify))
	}
}

func TestPipelineSilencedSensor(t *testing.T) {
	p, db, rec, _, _ := newPipeline(t)
	ctx := context.Background()
	db.SetSensorSilenced(ctx, "node-00000001", "ts-sensor-ssh", true)
	p.Process(ctx, normalized(t, nil))
	if len(rec.notify) != 0 || len(rec.live) != 1 || len(rec.siem) != 1 {
		t.Fatalf("silenced: notify=%d live=%d siem=%d", len(rec.notify), len(rec.live), len(rec.siem))
	}
	s, _ := db.Sensor(ctx, "node-00000001", "ts-sensor-ssh")
	if s.LastActivityAt == nil {
		t.Fatal("sensor activity not updated")
	}
}
