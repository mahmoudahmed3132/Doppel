// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package projections

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/attack"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/geoip"
)

var t0 = time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)

func mk(min int, node, sensor, trigger, sev, source string) domain.EnrichedEvent {
	ip, port, kind := domain.ParseSource(source)
	e := domain.EnrichedEvent{Event: domain.Event{
		NodeID: node, SensorID: sensor, Trigger: trigger, Severity: domain.Severity(sev),
		Source: source, SourceIP: ip, SourcePort: port, SourceKind: kind, Labels: domain.SourceLabels(ip),
		OccurredAt: t0.Add(time.Duration(min) * time.Minute), Details: json.RawMessage(`{}`),
	}}
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
	if !slices.Contains(l[0].Labels, "multi-decoy") || !slices.Contains(l[0].Labels, "repeat") {
		t.Fatalf("expected multi-decoy and repeat labels on 10.0.0.5, got %v", l[0].Labels)
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

func TestOneIPThreeDecoysFromThreePortsIsOneMultiDecoySource(t *testing.T) {
	evs := []domain.EnrichedEvent{
		mk(0, "n1", "ts-sensor-ssh", "ssh_login", "high", "10.0.0.5:41001"),
		mk(2, "n1", "ts-sensor-db", "postgres_login", "high", "10.0.0.5:41002"),
		mk(4, "n1", "ts-sensor-web", "web_login_attempt", "critical", "10.0.0.5:41003"),
	}
	ctx := context.Background()

	// Sources projection: 1 source ("10.0.0.5") with 3 decoys, 3 events, labelled multi-decoy and repeat.
	out, err := Sources{}.Build(ctx, evs, nil)
	if err != nil {
		t.Fatal(err)
	}
	srcs := out.(map[string]any)["sources"].([]Profile)
	if len(srcs) != 1 {
		t.Fatalf("got %d sources, want 1: %+v", len(srcs), srcs)
	}
	if srcs[0].Source != "10.0.0.5" || srcs[0].Decoys != 3 || srcs[0].Events != 3 {
		t.Fatalf("unexpected source profile: %+v", srcs[0])
	}
	if !slices.Contains(srcs[0].Labels, "multi-decoy") || !slices.Contains(srcs[0].Labels, "repeat") {
		t.Fatalf("labels = %v, want multi-decoy and repeat", srcs[0].Labels)
	}

	// AttackPath projection: 1 source with 3 steps across the 3 decoys, timeline preserves raw IP:port.
	pOut, err := AttackPath{}.Build(ctx, evs, nil)
	if err != nil {
		t.Fatal(err)
	}
	pDTO := pOut.(*PathDTO)
	if pDTO.Source != "10.0.0.5" || pDTO.Events != 3 || len(pDTO.Steps) != 3 {
		t.Fatalf("attack_path = %+v", pDTO)
	}
	if pDTO.Timeline[0].Source != "10.0.0.5:41001" || pDTO.Timeline[2].Source != "10.0.0.5:41003" {
		t.Fatalf("timeline did not preserve raw source display values: %+v", pDTO.Timeline)
	}

	// Report projection: SourcesTotal == 1, TopSources[0].Decoys == 3.
	rOut, err := (Report{Now: func() time.Time { return t0.Add(24 * time.Hour) }}).Build(ctx, evs, nil)
	if err != nil {
		t.Fatal(err)
	}
	rDTO := rOut.(*ReportDTO)
	if rDTO.SourcesTotal != 1 || len(rDTO.TopSources) != 1 || rDTO.TopSources[0].Source != "10.0.0.5" || rDTO.TopSources[0].Decoys != 3 {
		t.Fatalf("report = %+v", rDTO)
	}

	// Insights projection: distinct_sources per type correlates on source_ip.
	evsSameType := append(evs, mk(5, "n1", "ts-sensor-ssh", "ssh_login", "high", "10.0.0.5:41004"))
	iOut, err := NewInsights(nil, nil, nil).Build(ctx, evsSameType, nil)
	if err != nil {
		t.Fatal(err)
	}
	iDTO := iOut.(*InsightsDTO)
	for _, row := range iDTO.ByType {
		if row.DistinctSources != 1 {
			t.Fatalf("insights row %s distinct_sources = %d, want 1", row.SensorType, row.DistinctSources)
		}
	}
}

func TestWalkthroughDistinctSourcesAndHostLocalLabels(t *testing.T) {
	// Walk-through scenario (F-002 Acceptance): 3 hits from Docker Desktop NAT
	// (192.168.65.1 on two ephemeral ports plus bare IP), 1 hit from IPv6
	// loopback ([::1]:54321), and 1 fire drill ("Fire drill").
	// Previously 5 distinct raw sources; now 2 (192.168.65.1 and ::1), with
	// drills excluded and both carrying the host_local label.
	evs := []domain.EnrichedEvent{
		mk(0, "n1", "ts-sensor-tcp-tarpit", "tcp_connection", "medium", "192.168.65.1:51001"),
		mk(1, "n1", "ts-sensor-template", "template_connection", "medium", "192.168.65.1:51002"),
		mk(2, "n1", "ts-sensor-web-router-decoy", "web_page_view", "low", "192.168.65.1"),
		mk(3, "n1", "ts-sensor-tcp-tarpit", "tcp_connection", "medium", "[::1]:54321"),
		mk(4, "n1", "ts-sensor-tcp-tarpit", "tcp_connection", "high", "Fire drill"),
	}
	ctx := context.Background()

	out, err := Sources{}.Build(ctx, evs, nil)
	if err != nil {
		t.Fatal(err)
	}
	srcs := out.(map[string]any)["sources"].([]Profile)
	if len(srcs) != 2 {
		t.Fatalf("distinct sources = %d, want 2: %+v", len(srcs), srcs)
	}
	if srcs[0].Source != "192.168.65.1" || srcs[0].Events != 3 || srcs[0].Decoys != 3 {
		t.Fatalf("srcs[0] = %+v", srcs[0])
	}
	if !slices.Contains(srcs[0].Labels, "host_local") || !slices.Contains(srcs[0].Labels, "multi-decoy") || !slices.Contains(srcs[0].Labels, "repeat") {
		t.Fatalf("srcs[0].Labels = %v", srcs[0].Labels)
	}
	if srcs[1].Source != "::1" || srcs[1].Events != 1 || srcs[1].Decoys != 1 {
		t.Fatalf("srcs[1] = %+v", srcs[1])
	}
	if len(srcs[1].Labels) != 1 || srcs[1].Labels[0] != "host_local" {
		t.Fatalf("srcs[1].Labels = %v, want [host_local]", srcs[1].Labels)
	}

	rOut, err := (Report{Now: func() time.Time { return t0.Add(24 * time.Hour) }}).Build(ctx, evs, nil)
	if err != nil {
		t.Fatal(err)
	}
	rDTO := rOut.(*ReportDTO)
	if rDTO.SourcesTotal != 2 || rDTO.Events != 4 {
		t.Fatalf("report SourcesTotal=%d Events=%d, want 2 and 4", rDTO.SourcesTotal, rDTO.Events)
	}
}

func TestGroupByRollups(t *testing.T) {
	ctx := context.Background()
	evs := []domain.EnrichedEvent{
		mk(0, "n1", "s1", "tcp_connection", "medium", "203.0.113.10:40001"),
		mk(1, "n1", "s2", "tcp_connection", "medium", "203.0.113.25:40002"),
		mk(2, "n1", "s1", "tcp_connection", "medium", "[2a02:c7f::1]:443"),
		mk(3, "n1", "s2", "tcp_connection", "medium", "[2a02:c7f::99]:8443"),
		mk(4, "n1", "s1", "decoy_file_accessed", "high", "local"),
	}

	// group_by=subnet24 rolls up IPv4 /24.
	out24, err := Sources{}.Build(ctx, evs, map[string]string{"group_by": "subnet24"})
	if err != nil {
		t.Fatal(err)
	}
	srcs24 := out24.(map[string]any)["sources"].([]Profile)
	if srcs24[0].Source != "203.0.113.0/24" || srcs24[0].Events != 2 || srcs24[0].Decoys != 2 {
		t.Fatalf("subnet24 top source = %+v", srcs24[0])
	}

	// group_by=subnet64 rolls up IPv6 /64.
	out64, err := Sources{}.Build(ctx, evs, map[string]string{"group_by": "subnet64"})
	if err != nil {
		t.Fatal(err)
	}
	srcs64 := out64.(map[string]any)["sources"].([]Profile)
	if srcs64[0].Source != "2a02:c7f::/64" || srcs64[0].Events != 2 || srcs64[0].Decoys != 2 {
		t.Fatalf("subnet64 top source = %+v", srcs64[0])
	}

	// group_by=asn with loaded GeoIP ASN DB.
	asnFixture, err := os.ReadFile("../geoip/testdata/dbip-asn-test.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	asnPath := filepath.Join(t.TempDir(), "dbip-asn-lite.mmdb")
	if err := os.WriteFile(asnPath, asnFixture, 0o600); err != nil {
		t.Fatal(err)
	}
	geo := geoip.New("", false, nil)
	t.Cleanup(geo.Close)
	if err := geo.SetASNPath(asnPath); err != nil {
		t.Fatal(err)
	}
	outASN, err := (Sources{GeoIP: geo}).Build(ctx, evs, map[string]string{"group_by": "asn"})
	if err != nil {
		t.Fatal(err)
	}
	srcsASN := outASN.(map[string]any)["sources"].([]Profile)
	if len(srcsASN) != 3 {
		t.Fatalf("asn sources = %+v, want 3 (AS64500, AS12345, local)", srcsASN)
	}
	gotNames := []string{srcsASN[0].Source, srcsASN[1].Source, srcsASN[2].Source}
	if !slices.Contains(gotNames, "AS64500") || !slices.Contains(gotNames, "AS12345") || !slices.Contains(gotNames, "local") {
		t.Fatalf("asn source names = %v", gotNames)
	}

	// Invalid group_by rejected.
	if _, err := (Sources{}).Build(ctx, evs, map[string]string{"group_by": "invalid"}); err == nil {
		t.Fatal("invalid group_by accepted")
	}
}

func TestGeoMap(t *testing.T) {
	evs := fixture()
	// Add a second hit from the same public IP on a different port: still 1 source in NL.
	second := mk(22, "n1", "s-web", "web_path_probe", "low", "203.0.113.7:55111")
	second.Enrichment.Location = evs[3].Enrichment.Location
	evs = append(evs, second)

	out, _ := GeoMap{}.Build(context.Background(), evs, nil)
	d := out.(*GeoDTO)
	if d.Events != 6 || d.LocatedEvents != 2 || d.InternalEvents != 4 || d.UnlocatedEvents != 0 {
		t.Fatalf("%+v", d)
	}
	if len(d.Points) != 1 || d.Points[0].Lat != 52.37 || d.Points[0].City != "Amsterdam" || d.Points[0].SourceCount != 1 || d.Countries[0].CountryCode != "NL" || d.Countries[0].Sources != 1 {
		t.Fatalf("points=%+v countries=%+v", d.Points, d.Countries)
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
