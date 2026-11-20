// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package projections

import (
	"context"
	"testing"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
)

// TestProjectionsDrillFlag (F-001): projections recognise drills by the
// stored flag, drop them unless the request opted in, and keep a real event
// whose source text merely reads "Fire drill".
func TestProjectionsDrillFlag(t *testing.T) {
	evs := []domain.EnrichedEvent{
		mk(0, "n1", "ts-sensor-tcp-tarpit", "tcp_connection", "high", "198.51.100.7:4444"),
		drillEv(mk(1, "n1", "ts-sensor-tcp-tarpit", "tcp_connection", "info", "Fire drill")),
	}
	sources := func(ctx context.Context, evs []domain.EnrichedEvent) []string {
		t.Helper()
		out, err := Sources{}.Build(ctx, evs, nil)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, p := range out.(map[string]any)["sources"].([]Profile) {
			got = append(got, p.Source)
		}
		return got
	}
	ctx := context.Background()
	if got := sources(ctx, evs); len(got) != 1 || got[0] != "198.51.100.7" {
		t.Fatalf("default: %v", got)
	}
	if got := sources(ported.WithIncludeDrills(ctx), evs); len(got) != 2 {
		t.Fatalf("include_drills: %v", got)
	}
	// Unflagged: a real event (attacker-influenced source text), counted.
	if got := sources(ctx, []domain.EnrichedEvent{mk(2, "n1", "ts-sensor-web-router-decoy", "web_page_view", "low", "Fire drill")}); len(got) != 1 {
		t.Fatalf("unflagged 'Fire drill' source dropped: %v", got)
	}
}
