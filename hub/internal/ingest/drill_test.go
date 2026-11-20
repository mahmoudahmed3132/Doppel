// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package ingest

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
)

func boolPtr(b bool) *bool { return &b }

func detailsOf(t *testing.T, ev *domain.Event) map[string]any {
	t.Helper()
	var d map[string]any
	if err := json.Unmarshal(ev.Details, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// TestNormalizeDrill covers the drill flag (new SDK), the legacy source shim
// (old SDK) and the severity clamp (F-001).
func TestNormalizeDrill(t *testing.T) {
	cases := map[string]struct {
		mod          func(*RawEvent)
		drill        bool
		legacyWarned bool
	}{
		"flag true":                       {func(r *RawEvent) { r.Drill, r.Source = boolPtr(true), domain.DrillSource }, true, false},
		"flag true, any source":           {func(r *RawEvent) { r.Drill = boolPtr(true) }, true, false},
		"legacy: no flag, drill source":   {func(r *RawEvent) { r.Source = domain.DrillSource }, true, true},
		"flag false wins over source":     {func(r *RawEvent) { r.Drill, r.Source = boolPtr(false), domain.DrillSource }, false, false},
		"no flag, attack source":          {nil, false, false},
		"no flag, near-miss drill source": {func(r *RawEvent) { r.Source = "fire drill" }, false, false},
	}
	for name, c := range cases {
		before := LegacyDrills()
		ev, warns, code := Normalize(raw(c.mod), "node-00000001", now)
		if code != "" {
			t.Fatalf("%s: rejected %s", name, code)
		}
		if ev.Drill != c.drill {
			t.Errorf("%s: drill = %v", name, ev.Drill)
		}
		warned := false
		for _, w := range warns {
			warned = warned || w == WarnLegacyDrill
		}
		if warned != c.legacyWarned || (LegacyDrills()-before == 1) != c.legacyWarned {
			t.Errorf("%s: legacy warning %v, counter +%d", name, warned, LegacyDrills()-before)
		}
		d := detailsOf(t, ev)
		if c.drill {
			if ev.Severity != domain.SeverityInfo || d[OriginalSeverityKey] != "high" || d["username"] != "root" {
				t.Errorf("%s: severity %s details %v", name, ev.Severity, d)
			}
		} else if ev.Severity != "high" || d[OriginalSeverityKey] != nil {
			t.Errorf("%s: non-drill changed: severity %s details %v", name, ev.Severity, d)
		}
	}

	// The flag must be a JSON boolean; anything else is an invalid event.
	for _, body := range []string{`{"event_id":"x","drill":"true"}`, `{"event_id":"x","drill":1}`} {
		if _, ok := DecodeRawEvent([]byte(body)); ok {
			t.Errorf("non-boolean drill accepted: %s", body)
		}
	}
	if r, ok := DecodeRawEvent([]byte(`{"event_id":"x","drill":true}`)); !ok || r.Drill == nil || !*r.Drill {
		t.Fatal("boolean drill refused")
	}

	// Oversized details: the fallback keeps original_severity.
	ev, _, _ := Normalize(raw(func(r *RawEvent) {
		r.Drill, r.Severity = boolPtr(true), "critical"
		r.Details = json.RawMessage(`{"blob":"` + strings.Repeat("a", MaxDetailsBytes) + `"}`)
	}), "node-00000001", now)
	if d := detailsOf(t, ev); ev.Severity != domain.SeverityInfo || d["details_dropped"] != true || d[OriginalSeverityKey] != "critical" {
		t.Fatalf("oversized drill: %s %v", ev.Severity, d)
	}
}

// TestPipelineDrill: a drill is stored flagged, forwarded to the SIEM and the
// live feed, but never notified, never resolved as a beacon and never raises
// honeytoken_used (F-001).
func TestPipelineDrill(t *testing.T) {
	p, db, rec, bc, ht := newPipeline(t)
	ctx := context.Background()
	bc.Add(ported.Beacon{ID: "bcn_1", Token: "abc123", Type: "dns", Name: "finance share", Domain: "x.example"})
	ht.Add(ported.Honeytoken{ID: "ht_1", Username: "svc_backup", PlantedNodeID: "node-00000002", PlantedSensorID: "ts-sensor-files"})

	p.Process(ctx, normalized(t, func(r *RawEvent) {
		r.Drill, r.Severity, r.Source = boolPtr(true), "critical", domain.DrillSource
		r.Details = json.RawMessage(`{"username":"svc_backup"}`)
	}))
	p.Process(ctx, normalized(t, func(r *RawEvent) {
		r.Drill, r.Trigger, r.Source = boolPtr(true), "beacon_triggered", domain.DrillSource
		r.Details = json.RawMessage(`{"token":"abc123"}`)
	}))
	evs, _ := db.Events(ctx, store.EventFilter{})
	if len(evs) != 2 {
		t.Fatalf("stored %d events (honeytoken_used raised by a drill?)", len(evs))
	}
	for _, e := range evs {
		if !e.Drill || e.Severity != domain.SeverityInfo {
			t.Errorf("stored %+v", e)
		}
		if _, ok := detailsOf(t, &e)["beacon"]; ok {
			t.Errorf("drill resolved as a beacon: %s", e.Details)
		}
	}
	if bl, _ := bc.List(ctx); bl[0].UseCount != 0 {
		t.Fatal("drill counted as a beacon use")
	}
	if len(rec.notify) != 0 {
		t.Fatalf("drill notified %d times", len(rec.notify))
	}
	if len(rec.siem) != 2 || !rec.siem[0].Event.Drill || len(rec.live) != 2 {
		t.Fatalf("siem=%d live=%d", len(rec.siem), len(rec.live))
	}

	// Hub-raised events are never drills, whatever the caller sets.
	ev := &domain.Event{EventID: "0192f000-0000-7000-8000-000000000001", NodeID: "node-00000001", SensorID: "ts-sensor-ssh",
		Trigger: domain.TriggerSensorStopped, Severity: domain.SeverityLow, OccurredAt: now, ReceivedAt: now,
		Source: domain.DrillSource, Target: "x", Details: []byte("{}"), HubRaised: true, Drill: true}
	if _, err := p.Process(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if ev.Drill || len(rec.notify) != 1 {
		t.Fatalf("hub-raised event kept the drill flag: %+v notify=%d", ev, len(rec.notify))
	}
}
