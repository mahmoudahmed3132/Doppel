// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package projections holds the analytics projections behind
// ported.Projection (QUESTIONS Q56): sources, geo_map, attack_path and
// report. Each receives the window's events, already enriched by the Hub
// (asset, location, ATT&CK).
//
// Imported from TrueSignal (see PROVENANCE.md): the aggregations are that
// codebase's sources, geomap, path and report projections, adapted from its
// event store to domain.EnrichedEvent; the insights summary they used is
// not imported (MERGE-INVENTORY.md H12).
package projections

import (
	"sort"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
)

// attacker excludes what the Hub raises about its own fleet (liveness and
// apply failures); honeytoken and beacon use are attacker activity.
func attacker(e domain.Event) bool {
	if e.Source == domain.HubSource {
		return false
	}
	switch e.Trigger {
	case domain.TriggerSensorStopped, domain.TriggerSensorHeartbeatLost, domain.TriggerSensorRecovered, domain.TriggerNodeApplyFailed:
		return false
	}
	return true
}

var sevRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func sortedKeys(m map[string]bool, max int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}

// oldestFirst returns the events sorted by occurrence, oldest first.
func oldestFirst(events []domain.EnrichedEvent) []domain.EnrichedEvent {
	out := append([]domain.EnrichedEvent(nil), events...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].OccurredAt.Before(out[j].OccurredAt) })
	return out
}
