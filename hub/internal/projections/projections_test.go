// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package projections

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/attack"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
)

var t0 = time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)

func mk(min int, node, sensor, trigger, sev, source string) domain.EnrichedEvent {
	e := domain.EnrichedEvent{Event: domain.Event{NodeID: node, SensorID: sensor, Trigger: trigger, Severity: domain.Severity(sev),
		Source: source, OccurredAt: t0.Add(time.Duration(min) * time.Minute), Details: json.RawMessage(`{}`)}}
	e.Enrichment.Attack = attack.Mapper{}.For(trigger)
	return e
}

func fixture() []domain.EnrichedEvent {
	jump := &domain.AssetMatch{Name: "jump", Criticality: "critical"}
	evs := []domain.EnrichedEvent{
		mk(0, "n1", "s-scan", "network_scan_detected", "medium", "10.0.0.5"),
		mk(5, "n1", "s-web", "web_login_attempt", "high", "10.0.0.5"),
		mk(9, "n2", "s-files", "decoy_file_accessed", "critical", "10.0.0.5"),
		mk(20, "n1", "s-web", "web_path_probe", "low", "203.0.113.7"),
		mk(21, "n1", "s-web", "sensor_heartbeat_lost", "high", domain.HubSource),
		mk(30, "n2", "s-files", "honeytoken_used", "critical", "10.0.0.5"),
	}
	for i := range evs {
		if evs[i].Source == "10.0.0.5" {
			evs[i].Enrichment.Asset = jump
		}
	}
	evs[3].Enrichment.Location = &domain.Location{CountryCode: "NL", Country: "Netherlands", City: "Amsterdam", Lat: 52.374, Lon: 4.889, Basis: "source", Address: "203.0.113.7"}
	evs[5].Details = json.RawMessage(`{"honeytoken_username":"svc_etl0a0a"}`)
	return evs
}

func TestSourcesProfiles(t *testing.T) {
	out, _ := Sources{}.Build(context.Background(), fixture(), nil)
	l := out.(map[string]any)["sources"].([]Profile)
	if len(l) != 2 || l[0].Source != "10.0.0.5" || l[0].Events != 4 || l[0].Decoys != 3 || !l[0].Internal || l[0].Asset == nil {
		t.Fatalf("%+v", l)
	}
	if l[1].Source != "203.0.113.7" || l[1].Internal || !l[1].IsIP || l[1].FirstSeen != ts(t0.Add(20*time.Minute)) {
		t.Fatalf("%+v", l[1])
	}
	if ip, in := Classify("[fe80::1]:22"); !ip || !in {
		t.Fatal("link-local with port")
	}
	if ip, _ := Classify("drill-host"); ip {
		t.Fatal("name classified as IP")
	}
}

func TestGeoMap(t *testing.T) {
	out, _ := GeoMap{}.Build(context.Background(), fixture(), nil)
	d := out.(*GeoDTO)
	if d.Events != 5 || d.LocatedEvents != 1 || d.InternalEvents != 4 || d.UnlocatedEvents != 0 {
		t.Fatalf("%+v", d)
	}
	if len(d.Points) != 1 || d.Points[0].Lat != 52.37 || d.Points[0].City != "Amsterdam" || d.Countries[0].CountryCode != "NL" {
		t.Fatalf("%+v", d.Points)
	}
	if d.GeoIP.Enabled || d.GeoIP.Attribution == "" {
		t.Fatalf("geoip status %+v", d.GeoIP)
	}
}

func TestAttackPath(t *testing.T) {
	out, err := AttackPath{}.Build(context.Background(), fixture(), map[string]string{"source": "10.0.0.5"})
	if err != nil {
		t.Fatal(err)
	}
	d := out.(*PathDTO)
	if d.Events != 4 || len(d.Steps) != 3 || d.Steps[0].SensorID != "s-scan" || d.Steps[2].MaxSeverity != "critical" || d.Asset == nil {
		t.Fatalf("%+v", d)
	}
	// Discovery, then Credential Access (web login), then Initial Access & co. (honeytoken).
	if len(d.Progression) < 3 || d.Progression[0].Technique != "T1046" || d.Progression[1].Technique != "T1110" {
		t.Fatalf("progression %+v", d.Progression)
	}
	// Default: the busiest source.
	out, _ = AttackPath{}.Build(context.Background(), fixture(), nil)
	if out.(*PathDTO).Source != "10.0.0.5" {
		t.Fatal("default source")
	}
}

func TestReport(t *testing.T) {
	evs := fixture()
	evs = append(evs, mk(40, "n1", "s-web", "web_login_attempt", "high", "198.51.100.1"))
	evs[len(evs)-1].Archived = true
	r := Report{Now: func() time.Time { return t0.Add(48 * time.Hour) }}
	out, err := r.Build(context.Background(), evs, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := out.(*ReportDTO)
	if d.Events != 5 || d.ArchivedEvents != 1 || d.Severity.Critical != 2 || d.SourcesTotal != 2 || len(d.Daily) != 3 {
		t.Fatalf("%+v", d)
	}
	if d.TopSources[0].Source != "10.0.0.5" || len(d.Assets) != 1 || d.Assets[0].Events != 4 || len(d.HoneytokenUses) != 1 || d.HoneytokenUses[0].Username != "svc_etl0a0a" {
		t.Fatalf("%+v", d)
	}
	if len(d.Techniques) == 0 {
		t.Fatal("no techniques")
	}
	for _, bad := range []map[string]string{{"from": "yesterday"}, {"from": "2026-11-12", "to": "2026-11-11"}, {"from": "2024-01-01", "to": "2026-01-02"}} {
		if _, err := r.Build(context.Background(), evs, bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	out, _ = r.Build(context.Background(), evs, map[string]string{"from": "2026-11-10T09:10:00Z", "to": "2026-11-11"})
	if out.(*ReportDTO).Events != 2 {
		t.Fatalf("narrowed: %+v", out)
	}
}
