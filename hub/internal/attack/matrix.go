// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package attack

// Activity by ATT&CK technique (the attack_matrix projection) and its
// ATT&CK Navigator layer export. Imported from TrueSignal's attackmap
// package (see PROVENANCE.md), adapted to domain.EnrichedEvent.

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
)

// attackerEvent excludes what the Hub raises about its own fleet
// (liveness and apply failures); honeytoken and beacon use are attacker
// activity and count.
func attackerEvent(e domain.Event) bool {
	if e.Source == domain.HubSource {
		return false
	}
	switch e.Trigger {
	case domain.TriggerSensorStopped, domain.TriggerSensorHeartbeatLost, domain.TriggerSensorRecovered, domain.TriggerNodeApplyFailed:
		return false
	}
	return true
}

// TechniqueStat is one technique's activity. Every technique TrueSignal can
// evidence is listed, so the matrix also shows coverage without hits.
type TechniqueStat struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Tactics         []string `json:"tactics"`
	PrimaryEvents   int      `json:"primaryEvents"`
	SecondaryEvents int      `json:"secondaryEvents"`
	Sources         int      `json:"sources"`
	LastSeen        string   `json:"lastSeen"`
	Triggers        []string `json:"triggers"`
}

// DTO is the read-model of the attack_matrix projection and the layer.
type DTO struct {
	Timeframe          string          `json:"timeframe"`
	MappedEvents       int             `json:"mappedEvents"`
	TechniquesObserved int             `json:"techniquesObserved"`
	TechniquesCovered  int             `json:"techniquesCovered"`
	Tactics            []Tactic        `json:"tactics"`
	Techniques         []TechniqueStat `json:"techniques"`
}

// Calculate counts each event once for its primary technique (the matrix
// score) and once for each secondary technique.
func Calculate(events []domain.EnrichedEvent, timeframe string, since time.Time) *DTO {
	stats := map[string]*TechniqueStat{}
	last := map[string]time.Time{}
	sources := map[string]map[string]bool{}
	triggers := map[string]map[string]bool{}
	for _, t := range Covered() {
		tactics := make([]string, len(t.Tactics))
		for i, tc := range t.Tactics {
			tactics[i] = tc.ID
		}
		stats[t.ID] = &TechniqueStat{ID: t.ID, Name: t.Name, Tactics: tactics, Triggers: []string{}}
		sources[t.ID] = map[string]bool{}
		triggers[t.ID] = map[string]bool{}
	}

	dto := &DTO{Timeframe: timeframe, Tactics: TacticOrder, Techniques: []TechniqueStat{}}
	touch := func(id string, e domain.EnrichedEvent, primary bool) {
		s := stats[id]
		if s == nil {
			return
		}
		if primary {
			s.PrimaryEvents++
		} else {
			s.SecondaryEvents++
		}
		sources[id][e.Source] = true
		triggers[id][e.Trigger] = true
		if e.OccurredAt.After(last[id]) {
			last[id] = e.OccurredAt
			s.LastSeen = e.OccurredAt.UTC().Format(time.RFC3339)
		}
	}
	for _, e := range events {
		if !attackerEvent(e.Event) {
			continue
		}
		if !since.IsZero() && e.OccurredAt.Before(since) {
			continue
		}
		m, ok := For(e.Trigger)
		if !ok {
			continue
		}
		dto.MappedEvents++
		touch(m.Primary.ID, e, true)
		for _, sec := range m.Secondary {
			touch(sec.ID, e, false)
		}
	}

	for id, s := range stats {
		s.Sources = len(sources[id])
		for t := range triggers[id] {
			s.Triggers = append(s.Triggers, t)
		}
		sort.Strings(s.Triggers)
		if s.PrimaryEvents+s.SecondaryEvents > 0 {
			dto.TechniquesObserved++
		}
		dto.Techniques = append(dto.Techniques, *s)
	}
	dto.TechniquesCovered = len(stats)
	sort.Slice(dto.Techniques, func(i, j int) bool { return dto.Techniques[i].ID < dto.Techniques[j].ID })
	return dto
}

// Layer renders the projection as an ATT&CK Navigator layer (format 4.5).
// The score is the number of events whose primary technique it is;
// covered techniques without events are listed with score 0 so the layer
// also shows detection coverage.
func Layer(d *DTO, generated time.Time) map[string]any {
	maxScore := 1
	techniques := make([]map[string]any, 0, len(d.Techniques))
	for _, t := range d.Techniques {
		if t.PrimaryEvents > maxScore {
			maxScore = t.PrimaryEvents
		}
		comment := "Covered by the decoys; no events in this timeframe."
		if t.PrimaryEvents+t.SecondaryEvents > 0 {
			comment = fmt.Sprintf("%d events (primary), %d (secondary) from %d sources; last %s; triggers: %s",
				t.PrimaryEvents, t.SecondaryEvents, t.Sources, t.LastSeen, strings.Join(t.Triggers, ", "))
		}
		techniques = append(techniques, map[string]any{
			"techniqueID": t.ID,
			"score":       t.PrimaryEvents,
			"comment":     comment,
			"enabled":     true,
		})
	}
	return map[string]any{
		"name":        "Doppel decoy detections",
		"versions":    map[string]any{"layer": "4.5"},
		"domain":      "enterprise-attack",
		"description": fmt.Sprintf("Decoy and honeytoken activity mapped to ATT&CK by Doppel. Timeframe: %s. Generated %s.", d.Timeframe, generated.UTC().Format(time.RFC3339)),
		"techniques":  techniques,
		"gradient": map[string]any{
			"colors":   []string{"#ffffff", "#f4a3a3", "#c8283f"},
			"minValue": 0,
			"maxValue": maxScore,
		},
		"legendItems": []map[string]any{
			{"label": "Covered, no events", "color": "#ffffff"},
			{"label": "Observed (darker = more events)", "color": "#c8283f"},
		},
		"hideDisabled": false,
	}
}
