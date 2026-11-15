// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package ecs_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/attack"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ecs"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/siem"
)

// The real renderer behind ported.ECSRenderer, through the SIEM service's
// ECS format: every record kind becomes one JSON line with ECS fields.
func TestRendererThroughSIEMService(t *testing.T) {
	at := time.Date(2026, 11, 15, 11, 0, 0, 0, time.UTC)
	svc := &siem.Service{Renderer: ecs.Renderer{Now: func() time.Time { return at }}}
	if !svc.Capabilities().ECS {
		t.Fatal("ECS capability not reported")
	}
	cfg := siem.Config{Format: siem.FormatECS}
	ev := &domain.EnrichedEvent{Event: domain.Event{EventID: "0192f000-0000-7000-8000-0000000000e1", NodeID: "node-0000000e", SensorID: "ts-sensor-web",
		Trigger: "web_login_attempt", Severity: "high", OccurredAt: at, Source: "203.0.113.7", Target: "router",
		Details: json.RawMessage(`{"username":"admin","password_hmac":"ab12","dst_port":8080,"path":"/login","user_agent":"curl/8"}`)},
		NodeAlias: "edge-1",
		Enrichment: domain.Enrichment{Attack: attack.Mapper{}.For("web_login_attempt"),
			Asset:    &domain.AssetMatch{Name: "jump", Criticality: "high"},
			Location: &domain.Location{CountryCode: "NL", Country: "Netherlands", Lat: 52.37, Lon: 4.89, Basis: "source", Address: "203.0.113.7"}}}
	recs := []domain.Record{
		{Kind: domain.RecordEvent, Event: ev},
		{Kind: domain.RecordAudit, Audit: &domain.AuditRecord{Time: at, Action: "siem.update", Method: "PUT", Path: "/api/v3/outputs/siem", Status: 200, Outcome: "success", ActorIP: "10.0.0.2"}},
		{Kind: domain.RecordHoneytoken, Honeytoken: &domain.HoneytokenInventory{Time: at, HoneytokenID: "ht_1", Username: "svc_etl0a0a", PlantedNodeID: "node-0000000e", PlantedSensorID: "ts-sensor-files", Status: "active"}},
		{Kind: domain.RecordHeartbeat, Heartbeat: &domain.HubHeartbeat{Time: at, Version: "3.0.0", NodesTotal: 2, NodesOnline: 1}},
	}
	want := []string{"truesignal.alert", "truesignal.audit", "truesignal.honeytoken", "truesignal.heartbeat"}
	for i, rec := range recs {
		b, err := svc.Render(cfg, rec)
		if err != nil || strings.Contains(string(b), "\n") {
			t.Fatalf("record %d: %q %v", i, b, err)
		}
		var doc map[string]any
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		if ev, _ := doc["event"].(map[string]any); ev["dataset"] != want[i] || doc["ecs"] == nil {
			t.Fatalf("record %d: %s", i, b)
		}
	}
	b, _ := svc.Render(cfg, recs[0])
	for _, s := range []string{`"threat":{`, `"T1110"`, `"country_iso_code":"NL"`, `"source_asset":{"name":"jump"`, `"user":{"name":"admin"}`, `"url":{"path":"/login"}`} {
		if !strings.Contains(string(b), s) {
			t.Errorf("event document lacks %s: %s", s, b)
		}
	}
	if _, err := (ecs.Renderer{}).Render(domain.Record{Kind: domain.RecordEvent}); err == nil {
		t.Fatal("empty record rendered")
	}
}
