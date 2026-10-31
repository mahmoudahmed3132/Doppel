// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

package analytics

import (
	"testing"
	"time"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/domain"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/store"
)

func TestUptime(t *testing.T) {
	day := func(d, h int) time.Time { return time.Date(2026, 10, d, h, 0, 0, 0, time.UTC) }
	now := day(31, 12) // today is half over
	sensors := []domain.Sensor{
		{NodeID: "n", ID: "a", CreatedAt: day(1, 0)},
		{NodeID: "n", ID: "b", CreatedAt: day(30, 12)}, // created yesterday noon
	}
	history := []store.StatusChange{
		{NodeID: "n", SensorID: "a", Status: domain.StatusOnline, At: day(20, 0)}, // before the window
		{NodeID: "n", SensorID: "a", Status: domain.StatusOffline, At: day(29, 6)},
		{NodeID: "n", SensorID: "a", Status: domain.StatusOnline, At: day(29, 12)},
		{NodeID: "n", SensorID: "b", Status: domain.StatusOnline, At: day(30, 18)},
	}
	rows := Uptime(sensors, history, 4, now)
	a, b := rows[0], rows[1]
	if a.Days[0] != "2026-10-28" || a.Days[3] != "2026-10-31" {
		t.Fatalf("%v", a.Days)
	}
	// 28: online all day; 29: offline 06-12 → 75%; 30: 100%; 31: online so far.
	want := []float64{100, 75, 100, 100}
	for i, p := range a.Percent {
		if p != want[i] {
			t.Fatalf("a day %d = %v, want %v", i, p, want[i])
		}
	}
	// b: did not exist on 28 and 29; on 30 existed from 12:00, online from 18:00 → 50%.
	if b.Percent[0] != -1 || b.Percent[1] != -1 || b.Percent[2] != 50 || b.Percent[3] != 100 {
		t.Fatalf("b %v", b.Percent)
	}
}
