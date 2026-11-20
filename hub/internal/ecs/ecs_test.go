// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package ecs

// Adapted from TrueSignal's ECS tests (PROVENANCE.md) to domain records.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/attack"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
)

func ev2(e domain.Event) domain.EnrichedEvent { return domain.EnrichedEvent{Event: e} }

func ldapLoginEvent() domain.EnrichedEvent {
	return domain.EnrichedEvent{Event: domain.Event{
		Seq:        42,
		EventID:    "0192f000-0000-7000-8000-000000000042",
		NodeID:     "node-0a1b2c3d",
		SensorID:   "ts-sensor-identity-decoy",
		OccurredAt: time.Date(2026, 10, 24, 8, 0, 0, 0, time.UTC),
		Trigger:    "ldap_login",
		Severity:   "critical",
		Source:     "10.20.30.40",
		Target:     "LDAP:389 (DC01)",
		Details:    json.RawMessage(`{"protocol":"ldap","dst_port":389,"username":"CORP\\alice","workstation":"WS01","auth":"sicily_ntlm","netntlmv2":"alice::CORP:00:11:22"}`),
	}, NodeAlias: "dc-decoy"}
}

// get walks a decoded JSON document by dotted path.
func get(doc map[string]any, path string) any {
	var cur any = doc
	for _, p := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[p]
	}
	return cur
}

// roundTrip marshals and decodes a document the way a receiver sees it.
func roundTrip(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestECSEventMapping(t *testing.T) {
	doc := roundTrip(t, Renderer{}.ecsEvent(ldapLoginEvent()))

	want := map[string]any{
		"@timestamp":          "2026-10-24T08:00:00Z",
		"ecs.version":         ecsVersion,
		"event.kind":          "alert",
		"event.action":        "ldap_login",
		"event.severity":      float64(99),
		"event.outcome":       "failure",
		"event.dataset":       "truesignal.alert",
		"event.id":            "0192f000-0000-7000-8000-000000000042",
		"source.ip":           "10.20.30.40",
		"destination.port":    float64(389),
		"user.name":           "alice",
		"user.domain":         "CORP",
		"observer.type":       "honeypot",
		"host.id":             "node-0a1b2c3d",
		"truesignal.trigger":  "ldap_login",
		"truesignal.severity": "critical",
	}
	for path, v := range want {
		if got := get(doc, path); got != v {
			t.Errorf("%s = %#v, want %#v", path, got, v)
		}
	}
	cats, _ := get(doc, "event.category").([]any)
	if len(cats) != 2 || cats[0] != "intrusion_detection" || cats[1] != "authentication" {
		t.Errorf("event.category = %v", cats)
	}
	// Captured secrets stay under truesignal.details, never in ECS user.*.
	if get(doc, "truesignal.details.netntlmv2") == nil {
		t.Error("details not preserved under truesignal.details")
	}
	if u, _ := json.Marshal(doc["user"]); strings.Contains(string(u), "alice::") {
		t.Errorf("secret leaked into user: %s", u)
	}
}

func TestECSNonIPSourceAndWhitelist(t *testing.T) {
	ev := ldapLoginEvent()
	ev.Source = "drill-host"
	ev.Whitelisted = true
	doc := roundTrip(t, Renderer{}.ecsEvent(ev))
	if get(doc, "source.ip") != nil || get(doc, "source.address") != "drill-host" {
		t.Errorf("source = %v", doc["source"])
	}
	if get(doc, "event.kind") != "event" {
		t.Errorf("whitelisted event.kind = %v, want event", get(doc, "event.kind"))
	}
}

func TestECSKnownScanner(t *testing.T) {
	ev := ldapLoginEvent()
	ev.KnownScanner = true
	doc := roundTrip(t, Renderer{}.ecsEvent(ev))
	if get(doc, "event.kind") != "event" || get(doc, "truesignal.known_scanner") != true {
		t.Errorf("kind = %v, known_scanner = %v", get(doc, "event.kind"), get(doc, "truesignal.known_scanner"))
	}
	tags, _ := json.Marshal(doc["tags"])
	if !strings.Contains(string(tags), "known_scanner") {
		t.Errorf("tags = %s", tags)
	}
}

func TestECSThreat(t *testing.T) {
	ev := ldapLoginEvent()
	ev.Trigger = "ssh_login"
	ev.Enrichment.Attack = attack.Mapper{}.For("ssh_login")
	doc := roundTrip(t, Renderer{}.ecsEvent(ev))
	if get(doc, "threat.framework") != "MITRE ATT&CK" {
		t.Fatalf("threat = %v", doc["threat"])
	}
	ids, _ := json.Marshal(get(doc, "threat.technique.id"))
	subs, _ := json.Marshal(get(doc, "threat.technique.subtechnique.id"))
	tactics, _ := json.Marshal(get(doc, "threat.tactic.id"))
	// Parent in technique, sub-technique under subtechnique, primary first.
	if string(ids) != `["T1021","T1110"]` || string(subs) != `["T1021.004"]` || string(tactics) != `["TA0008"]` {
		t.Errorf("technique=%s subtechnique=%s tactic=%s", ids, subs, tactics)
	}
	names, _ := json.Marshal(get(doc, "threat.technique.subtechnique.name"))
	if string(names) != `["SSH"]` {
		t.Errorf("subtechnique names = %s", names)
	}

	live := roundTrip(t, Renderer{}.ecsEvent(ev2(domain.Event{Trigger: "sensor_heartbeat_lost", Severity: "high", Source: "truesignal-hub"})))
	if _, ok := live["threat"]; ok {
		t.Errorf("liveness must carry no threat.*: %v", live["threat"])
	}
}

func TestECSLivenessAndFileMapping(t *testing.T) {
	live := roundTrip(t, Renderer{}.ecsEvent(ev2(domain.Event{Trigger: "sensor_heartbeat_lost", Severity: "high", Source: "truesignal-hub"})))
	if get(live, "event.kind") != "event" || get(live, "event.category").([]any)[0] != "host" {
		t.Errorf("liveness = %v", live["event"])
	}
	file := roundTrip(t, Renderer{}.ecsEvent(ev2(domain.Event{Trigger: "decoy_file_accessed", Severity: "high",
		Details: json.RawMessage(`{"path":"/srv/finance/payroll.xlsx"}`)})))
	if get(file, "file.path") != "/srv/finance/payroll.xlsx" || get(file, "url") != nil {
		t.Errorf("file mapping = %v / %v", file["file"], file["url"])
	}
}

func TestECSHoneytokenUsed(t *testing.T) {
	doc := roundTrip(t, Renderer{}.ecsEvent(ev2(domain.Event{Trigger: "honeytoken_used", Severity: "critical", Source: "10.1.2.3",
		Details: json.RawMessage(`{"honeytoken_username":"svc_backup7f3a","planted_node_id":"node-a"}`)})))
	cats, _ := get(doc, "event.category").([]any)
	if get(doc, "user.name") != "svc_backup7f3a" || len(cats) != 2 || cats[1] != "authentication" || get(doc, "event.outcome") != "failure" {
		t.Fatalf("honeytoken_used ECS = %v", doc)
	}
}

func TestECSAuditMapping(t *testing.T) {
	doc := roundTrip(t, Renderer{}.ecsAudit(domain.AuditRecord{Action: "POST /login", Path: "/login", Status: 401, ActorIP: "10.1.1.1"}))
	if get(doc, "event.dataset") != "truesignal.audit" || get(doc, "event.outcome") != "failure" ||
		get(doc, "event.category").([]any)[0] != "authentication" || get(doc, "source.ip") != "10.1.1.1" {
		t.Errorf("audit = %v", doc)
	}
}

func TestECSUserDomainFromAnyField(t *testing.T) {
	for _, d := range []map[string]any{{"bind_dn": `CORP\jdoe`}, {"attempted_username": `CORP\jdoe`}, {"username": `CORP\jdoe`}} {
		if u := ecsUser(d); u["domain"] != "CORP" || u["name"] != "jdoe" {
			t.Errorf("%v -> %v", d, u)
		}
	}
	if u := ecsUser(map[string]any{"bind_dn": `CN=svc\, ops,DC=corp,DC=local`}); u["domain"] != nil {
		t.Errorf("DN was split: %v", u)
	}
}

func TestECSSourceIPAndPort(t *testing.T) {
	cases := []struct {
		source   string
		wantIP   any
		wantPort any
		wantAddr any
	}{
		{source: "203.0.113.9:51234", wantIP: "203.0.113.9", wantPort: float64(51234)},
		{source: "[2001:db8::1]:443", wantIP: "2001:db8::1", wantPort: float64(443)},
		{source: "[::ffff:192.0.2.1]:8080", wantIP: "192.0.2.1", wantPort: float64(8080)},
		{source: "[fe80::1%eth0]:22", wantIP: "fe80::1", wantPort: float64(22)},
		{source: "10.20.30.40", wantIP: "10.20.30.40", wantPort: nil},
		{source: "scanner.example.com:443", wantIP: nil, wantPort: nil, wantAddr: "scanner.example.com:443"},
	}
	for _, tc := range cases {
		ev := ldapLoginEvent()
		ev.Source = tc.source
		ev.SourceIP, ev.SourcePort, ev.SourceKind = domain.ParseSource(tc.source)
		doc := roundTrip(t, Renderer{}.ecsEvent(ev))
		if got := get(doc, "source.ip"); got != tc.wantIP {
			t.Errorf("%q: source.ip = %#v, want %#v", tc.source, got, tc.wantIP)
		}
		if got := get(doc, "source.port"); got != tc.wantPort {
			t.Errorf("%q: source.port = %#v, want %#v", tc.source, got, tc.wantPort)
		}
		if got := get(doc, "source.address"); got != tc.wantAddr {
			t.Errorf("%q: source.address = %#v, want %#v", tc.source, got, tc.wantAddr)
		}
		// Raw display value stays in truesignal.source.
		if got := get(doc, "truesignal.source"); got != tc.source {
			t.Errorf("%q: truesignal.source = %#v, want %#v", tc.source, got, tc.source)
		}
	}
}
