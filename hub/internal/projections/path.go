// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package projections

import (
	"context"
	"errors"
	"strings"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/attack"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/geoip"
)

// MaxPathEvents bounds one source's timeline.
const MaxPathEvents = 2000

// Step is one decoy on the path, in order of first contact.
type Step struct {
	NodeID      string   `json:"nodeId"`
	SensorID    string   `json:"sensorId"`
	FirstSeen   string   `json:"firstSeen"`
	LastSeen    string   `json:"lastSeen"`
	Events      int      `json:"events"`
	MaxSeverity string   `json:"maxSeverity"`
	Triggers    []string `json:"triggers"`
	Techniques  []string `json:"techniques"`
}

// ProgressStep is a technique that brought new tactics into the path, in
// order of first appearance. A technique filed under several tactics
// (Valid Accounts) is one step listing them all, not several stages.
type ProgressStep struct {
	FirstSeen string          `json:"firstSeen"`
	Technique string          `json:"technique"`
	Name      string          `json:"name"`
	Tactics   []attack.Tactic `json:"tactics"`
}

// PathDTO is the attack_path read-model for one source.
type PathDTO struct {
	Source      string                 `json:"source"`
	Asset       *domain.AssetMatch     `json:"asset"`
	Events      int                    `json:"events"`
	Truncated   bool                   `json:"truncated"`
	FirstSeen   string                 `json:"firstSeen"`
	LastSeen    string                 `json:"lastSeen"`
	Steps       []Step                 `json:"steps"`
	Progression []ProgressStep         `json:"progression"`
	Timeline    []domain.EnrichedEvent `json:"timeline"`
}

// AttackPath is the attack_path projection. Parameter `source` selects the
// source; without it the busiest source in the window is shown.
type AttackPath struct {
	GeoIP *geoip.Service // optional; used for group_by=asn when events are not pre-enriched
}

func (AttackPath) Name() string { return "attack_path" }

func (ap AttackPath) Build(ctx context.Context, events []domain.EnrichedEvent, params map[string]string) (any, error) {
	groupBy, err := parseGroupBy(params)
	if err != nil {
		return nil, err
	}
	source := strings.TrimSpace(params["source"])
	if len(source) > 256 {
		return nil, errors.New("source is limited to 256 bytes")
	}
	if source == "" {
		top, _ := (Sources{GeoIP: ap.GeoIP}).Build(ctx, events, map[string]string{"group_by": groupBy})
		if l := top.(map[string]any)["sources"].([]Profile); len(l) > 0 {
			source = l[0].Source
		}
	} else {
		source = normalizeQuerySource(source, groupBy, ap.GeoIP)
	}
	return buildPath(source, groupBy, ap.GeoIP, events), nil
}

func buildPath(source, groupBy string, geo *geoip.Service, events []domain.EnrichedEvent) *PathDTO {
	d := &PathDTO{Source: source, Steps: []Step{}, Progression: []ProgressStep{}, Timeline: []domain.EnrichedEvent{}}
	type key struct{ node, sensor string }
	index := map[key]int{}
	triggers := []map[string]bool{}
	techniques := []map[string]bool{}
	seenTactic := map[string]bool{}

	for _, e := range oldestFirst(events) {
		if source == "" || !attacker(e.Event) || sourceKey(e, groupBy, geo) != source {
			continue
		}
		if d.Events >= MaxPathEvents {
			d.Truncated = true
			break
		}
		d.Timeline = append(d.Timeline, e)
		d.Events++
		at := ts(e.OccurredAt)
		if d.FirstSeen == "" {
			d.FirstSeen = at
		}
		d.LastSeen = at
		if e.Enrichment.Asset != nil {
			d.Asset = e.Enrichment.Asset
		}

		k := key{e.NodeID, e.SensorID}
		i, ok := index[k]
		if !ok {
			i = len(d.Steps)
			index[k] = i
			d.Steps = append(d.Steps, Step{NodeID: e.NodeID, SensorID: e.SensorID, FirstSeen: at, MaxSeverity: string(e.Severity)})
			triggers = append(triggers, map[string]bool{})
			techniques = append(techniques, map[string]bool{})
		}
		s := &d.Steps[i]
		s.Events++
		s.LastSeen = at
		if sevRank[string(e.Severity)] > sevRank[s.MaxSeverity] {
			s.MaxSeverity = string(e.Severity)
		}
		triggers[i][e.Trigger] = true
		if e.Enrichment.Attack == nil {
			continue
		}
		m, ok := attack.For(e.Trigger)
		if !ok {
			continue
		}
		techniques[i][m.Primary.ID] = true
		var fresh []attack.Tactic
		for _, tc := range m.Primary.Tactics {
			if !seenTactic[tc.ID] {
				seenTactic[tc.ID] = true
				fresh = append(fresh, tc)
			}
		}
		if len(fresh) > 0 {
			d.Progression = append(d.Progression, ProgressStep{FirstSeen: at, Technique: m.Primary.ID, Name: m.Primary.Name, Tactics: fresh})
		}
	}
	for i := range d.Steps {
		d.Steps[i].Triggers = sortedKeys(triggers[i], 0)
		d.Steps[i].Techniques = sortedKeys(techniques[i], 0)
	}
	return d
}
