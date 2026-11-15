// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package attack

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
)

func ev(trigger, source string, at time.Time) domain.EnrichedEvent {
	return domain.EnrichedEvent{Event: domain.Event{Trigger: trigger, Source: source, OccurredAt: at}}
}

// Adapted from TrueSignal's attackmap test (PROVENANCE.md) to domain events.
func TestCalculateAndLayer(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	at := now.Add(-time.Hour)
	events := []domain.EnrichedEvent{
		ev("ssh_login", "10.0.0.5", at),
		ev("ssh_login", "10.0.0.6", at.Add(time.Minute)),
		ev("mysql_login", "10.0.0.5", at),
		ev("web_page_view", "10.0.0.5", at),               // unmapped
		ev("sensor_heartbeat_lost", domain.HubSource, at), // liveness
		ev("node_apply_failed", "node-0000000a", at),      // Hub-raised, not attacker activity
	}
	d := Calculate(events, "alltime", time.Time{})
	if d.MappedEvents != 3 {
		t.Fatalf("mapped = %d, want 3", d.MappedEvents)
	}
	by := map[string]TechniqueStat{}
	for _, s := range d.Techniques {
		by[s.ID] = s
	}
	if s := by["T1021.004"]; s.PrimaryEvents != 2 || s.Sources != 2 || s.LastSeen != at.Add(time.Minute).Format(time.RFC3339) {
		t.Errorf("T1021.004 = %+v", s)
	}
	if s := by["T1110"]; s.PrimaryEvents != 1 || s.SecondaryEvents != 2 || len(s.Triggers) != 2 {
		t.Errorf("T1110 = %+v", s)
	}
	if d.TechniquesCovered != len(Covered()) || len(d.Techniques) != d.TechniquesCovered {
		t.Errorf("covered = %d, listed = %d", d.TechniquesCovered, len(d.Techniques))
	}
	if d.TechniquesObserved != 3 {
		t.Errorf("observed = %d, want 3", d.TechniquesObserved)
	}
	if Calculate(events, "1d", now).MappedEvents != 0 {
		t.Error("events before since counted")
	}

	b, _ := json.Marshal(Layer(d, now))
	var layer struct {
		Domain     string                 `json:"domain"`
		Versions   struct{ Layer string } `json:"versions"`
		Techniques []struct {
			TechniqueID string `json:"techniqueID"`
			Score       int    `json:"score"`
		} `json:"techniques"`
		Gradient struct{ MaxValue int } `json:"gradient"`
	}
	if err := json.Unmarshal(b, &layer); err != nil {
		t.Fatal(err)
	}
	if layer.Domain != "enterprise-attack" || layer.Versions.Layer != "4.5" || layer.Gradient.MaxValue != 2 {
		t.Errorf("layer header = %+v", layer)
	}
	for _, lt := range layer.Techniques {
		if lt.TechniqueID == "T1021.004" && lt.Score != 2 {
			t.Errorf("T1021.004 score = %d", lt.Score)
		}
	}
}

func TestMapperAdapter(t *testing.T) {
	m := (Mapper{}).For("honeytoken_used")
	if m == nil || m.Primary.ID != "T1078" || len(m.Primary.Tactics) != 4 || m.Primary.Tactics[0] != "TA0001" || m.Secondary[0].ID != "T1552.001" {
		t.Fatalf("%+v", m)
	}
	if (Mapper{}).For("web_page_view") != nil {
		t.Fatal("unmapped trigger mapped")
	}
	if m := (Mapper{}).For("postgres_login"); m == nil || m.Primary.ID != "T1110" {
		t.Fatalf("suffix rule: %+v", m)
	}
}
