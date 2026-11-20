// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package store

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
)

// TestDurabilityPragmas pins F-603 / NFR-7: WAL with synchronous=FULL, so a
// commit has been fsynced before it returns and an acknowledged event
// survives an OS crash or power loss, not only a process kill.
func TestDurabilityPragmas(t *testing.T) {
	db, _ := openTest(t)
	ctx := context.Background()
	var mode string
	if err := db.sql.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal_mode = %q (%v), want wal", mode, err)
	}
	var sync int
	if err := db.sql.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&sync); err != nil || sync != 2 {
		t.Fatalf("synchronous = %d (%v), want 2 (FULL)", sync, err)
	}
	// The pragma must hold on a fresh connection too (the pool may reopen).
	db.sql.SetConnMaxLifetime(time.Nanosecond)
	time.Sleep(time.Millisecond)
	if err := db.sql.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&sync); err != nil || sync != 2 {
		t.Fatalf("synchronous on a new connection = %d (%v), want 2 (FULL)", sync, err)
	}
}

func TestDroppedEventsAccumulateAndSaturate(t *testing.T) {
	db, _ := openTest(t)
	ctx := context.Background()
	seedNode(t, db, "node-00000001")
	save := func(delta int64) int64 {
		t.Helper()
		if err := db.SaveSensorLiveness(ctx, "node-00000001", "ts-sensor-a",
			SensorLiveness{Status: domain.StatusOnline, DroppedDelta: delta}, time.Now()); err != nil {
			t.Fatal(err)
		}
		s, err := db.Sensor(ctx, "node-00000001", "ts-sensor-a")
		if err != nil {
			t.Fatal(err)
		}
		return s.DroppedEvents
	}
	if got := save(0); got != 0 {
		t.Fatalf("new sensor dropped = %d", got)
	}
	if got := save(3); got != 3 {
		t.Fatalf("dropped = %d, want 3", got)
	}
	if got := save(4); got != 7 {
		t.Fatalf("dropped = %d, want 7", got)
	}
	if got := save(-5); got != 7 {
		t.Fatalf("negative delta changed the count: %d", got)
	}
	// A hostile or buggy node must not overflow the column into a REAL,
	// which would make every later read of the sensor fail.
	if got := save(math.MaxInt64); got != math.MaxInt64 {
		t.Fatalf("dropped = %d, want saturation at MaxInt64", got)
	}
	if got := save(math.MaxInt64); got != math.MaxInt64 {
		t.Fatalf("dropped = %d after second huge delta", got)
	}
	if all, err := db.Sensors(ctx, ""); err != nil || len(all) != 1 || all[0].DroppedEvents != math.MaxInt64 {
		t.Fatalf("listing after saturation: %+v %v", all, err)
	}
}
