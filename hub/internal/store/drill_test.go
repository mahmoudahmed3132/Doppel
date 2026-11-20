// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
)

// TestDrillMigrationBackfill opens a schema v6 database holding a legacy
// drill (source "Fire drill", no flag) and an attack event, migrates it to
// v7 and checks the backfill, the partial index and that the attack event is
// untouched (F-001).
func TestDrillMigrationBackfill(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ts.db")
	db, err := Open(ctx, path, Options{Migrations: migrations[:6]})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, e := range []struct{ id, source string }{{"legacy-drill", domain.DrillSource}, {"attack", "198.51.100.7"}} {
		if _, err := db.sql.ExecContext(ctx, `INSERT INTO events (event_id, node_id, sensor_id, trigger, severity, occurred_at,
			received_at, source, target, details) VALUES (?, 'node-00000001', 'ts-sensor-a', 'x', 'high', ?, ?, ?, 't', '{}')`,
			e.id, ms(now), ms(now), e.source); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	db, err = Open(ctx, path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if v, _ := db.schemaVersion(ctx); v != SchemaVersion() || SchemaVersion() < 7 {
		t.Fatalf("schema %d", v)
	}
	evs, err := db.Events(ctx, EventFilter{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range evs {
		got[e.EventID] = e.Drill
	}
	if !got["legacy-drill"] || got["attack"] || len(got) != 2 {
		t.Fatalf("backfill: %v", got)
	}
	var idx int
	if err := db.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'events_nondrill'
		AND sql LIKE '%WHERE is_drill = 0%'`).Scan(&idx); err != nil || idx != 1 {
		t.Fatalf("partial index events_nondrill: %d %v", idx, err)
	}
}

// TestDrillExcludedFromAnalytics checks every store-side aggregate and the
// unread count ignore drills by default, and that the drill filter selects
// them (F-001).
func TestDrillExcludedFromAnalytics(t *testing.T) {
	db, _ := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	insert := func(id string, sev domain.Severity, drill bool) {
		t.Helper()
		if ok, err := db.InsertEvent(ctx, &domain.Event{EventID: id, NodeID: "node-00000001", SensorID: "ts-sensor-a", Trigger: "x",
			Severity: sev, OccurredAt: now, ReceivedAt: now, Source: "s", Target: "t", Details: []byte("{}"), Drill: drill}); !ok || err != nil {
			t.Fatal(id, err)
		}
	}
	insert("real", domain.SeverityCritical, false)
	insert("drill-1", domain.SeverityInfo, true)
	insert("drill-2", domain.SeverityInfo, true)

	since := now.Add(-time.Hour)
	total, unread, recent, crit, _ := db.EventCounts(ctx, since, false)
	if total != 1 || unread != 1 || recent != 1 || crit != 1 {
		t.Fatalf("counts without drills: %d %d %d %d", total, unread, recent, crit)
	}
	if total, _, _, _, _ = db.EventCounts(ctx, since, true); total != 3 {
		t.Fatalf("counts with drills: %d", total)
	}
	if sev, _ := db.SeverityCounts(ctx, since, false); sev[domain.SeverityInfo] != 0 || sev[domain.SeverityCritical] != 1 {
		t.Fatalf("severity without drills: %v", sev)
	}
	if sev, _ := db.SeverityCounts(ctx, since, true); sev[domain.SeverityInfo] != 2 {
		t.Fatalf("severity with drills: %v", sev)
	}
	sum := func(m map[int64]int64) (n int64) {
		for _, v := range m {
			n += v
		}
		return n
	}
	if v, _ := db.Velocity(ctx, since, time.Hour, false); sum(v) != 1 {
		t.Fatalf("velocity without drills: %v", v)
	}
	if v, _ := db.Velocity(ctx, since, time.Hour, true); sum(v) != 3 {
		t.Fatalf("velocity with drills: %v", v)
	}
	if n, _ := db.UnreadCount(ctx); n != 1 {
		t.Fatalf("unread badge counts drills: %d", n)
	}
	yes, no := true, false
	if evs, _ := db.Events(ctx, EventFilter{Drill: &yes}); len(evs) != 2 || !evs[0].Drill {
		t.Fatalf("drill filter: %+v", evs)
	}
	if evs, _ := db.Events(ctx, EventFilter{Drill: &no}); len(evs) != 1 || evs[0].EventID != "real" {
		t.Fatalf("non-drill filter: %+v", evs)
	}
}
