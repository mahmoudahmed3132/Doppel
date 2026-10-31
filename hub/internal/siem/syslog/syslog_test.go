// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package syslog

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/domain"
)

var ts = time.Date(2026, 10, 31, 9, 15, 0, 123456789, time.UTC)

func event(source string) *domain.EnrichedEvent {
	return &domain.EnrichedEvent{
		Event: domain.Event{
			EventID: "019a3c1e-0000-7000-8000-000000000001", NodeID: "node-0000000a", SensorID: "ts-sensor-ssh",
			Trigger: "ssh_login_attempt", Severity: domain.SeverityCritical, ReceivedAt: ts, OccurredAt: ts,
			Source: source, Target: "SSH (port 22)", Details: json.RawMessage(`{"username":"` + "a\\nb" + `"}`),
		},
		NodeAlias: "dmz-1",
		Enrichment: domain.Enrichment{
			Attack: &domain.AttackMapping{Primary: domain.Technique{ID: "T1110", Tactics: []string{"credential-access"}}},
		},
	}
}

// sdRE parses one SD element with escaped values.
var lineRE = regexp.MustCompile(`^<(\d+)>1 (\S+) truesignal truesignal-hub - (\S+) \[(\S+)((?: [a-z_]+="(?:[^"\\\]]|\\["\\\]])*")*)\] (\{.*\})$`)

func TestEventLine(t *testing.T) {
	line, err := Format(domain.Record{Kind: domain.RecordEvent, Event: event("203.0.113.9")}, DefaultPEN)
	if err != nil {
		t.Fatal(err)
	}
	m := lineRE.FindSubmatch(line)
	if m == nil {
		t.Fatalf("not RFC 5424: %s", line)
	}
	if string(m[1]) != "130" || string(m[2]) != "2026-10-31T09:15:00.123456Z" || string(m[3]) != "EVENT" || string(m[4]) != "truesignal@32473" {
		t.Fatalf("header: %s", line)
	}
	wantOrder := []string{"event_id", "trigger", "severity", "source", "target", "node", "node_id", "sensor", "whitelisted",
		"known_scanner", "mitre_technique", "mitre_tactic", "source_asset", "source_asset_criticality", "source_country", "source_geo_basis"}
	names := regexp.MustCompile(` ([a-z_]+)="`).FindAllSubmatch(m[5], -1)
	if len(names) != len(wantOrder) {
		t.Fatalf("got %d params", len(names))
	}
	for i, n := range names {
		if string(n[1]) != wantOrder[i] {
			t.Fatalf("param %d = %s, want %s", i, n[1], wantOrder[i])
		}
	}
	if !bytes.Contains(m[5], []byte(`mitre_technique="T1110" mitre_tactic="credential-access" source_asset=""`)) {
		t.Fatalf("enrichment params: %s", m[5])
	}
	var msg map[string]any
	if err := json.Unmarshal(m[6], &msg); err != nil {
		t.Fatalf("MSG not JSON: %v", err)
	}
}

func TestHostileValueStaysOneLine(t *testing.T) {
	hostile := "evil\"]\n<13>1 2026-01-01T00:00:00Z forged - - - - [x@1 a=\"b\"] \\\r\x00 \xff"
	line, err := Format(domain.Record{Kind: domain.RecordEvent, Event: event(hostile)}, DefaultPEN)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.ContainsAny(line, "\r\n\x00") || strings.Contains(string(line), " ") {
		t.Fatalf("framing broken: %q", line)
	}
	if lineRE.Find(line) == nil {
		t.Fatalf("not a single valid RFC 5424 line: %q", line)
	}
	if !bytes.Contains(line, []byte(`source="evil\"\] <13>1`)) {
		t.Fatalf("escaping: %s", line)
	}
}

func TestEscapeParamValue(t *testing.T) {
	cases := map[string]string{
		`a"b`:      `a\"b`,
		`a\b`:      `a\\b`,
		`a]b`:      `a\]b`,
		"a\tb":     "a b",
		"a\xffb":   "a�b",
		"a\u0085b": "a b",
	}
	for in, want := range cases {
		if got := EscapeParamValue(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("é", 1000) // 2000 bytes
	if got := EscapeParamValue(long); len(got) > 1024 || !strings.HasSuffix(got, "é") {
		t.Fatalf("truncation: %d bytes", len(got))
	}
}

func TestOtherRecordKinds(t *testing.T) {
	recs := []struct {
		rec   domain.Record
		pri   string
		msgID string
		sd    string
	}{
		{domain.Record{Kind: domain.RecordAudit, Audit: &domain.AuditRecord{Time: ts, Action: "siem.update", Method: "PUT", Route: "/api/v3/settings/siem", Path: "/api/v3/settings/siem", Status: 200, Outcome: "success", ActorIP: "10.1.1.1"}}, "<133>", "AUDIT", "truesignal-audit@32473"},
		{domain.Record{Kind: domain.RecordHoneytoken, Honeytoken: &domain.HoneytokenInventory{Time: ts, HoneytokenID: "ht_1", Username: "svc"}}, "<134>", "HONEYTOKEN", "truesignal-honeytoken@32473"},
		{domain.Record{Kind: domain.RecordHeartbeat, Heartbeat: &domain.HubHeartbeat{Time: ts, Version: "3.0.0"}}, "<134>", "HEARTBEAT", "truesignal-hub@32473"},
	}
	for _, c := range recs {
		line, err := Format(c.rec, DefaultPEN)
		if err != nil {
			t.Fatal(err)
		}
		m := lineRE.FindSubmatch(line)
		if m == nil || !bytes.HasPrefix(line, []byte(c.pri)) || string(m[3]) != c.msgID || string(m[4]) != c.sd {
			t.Fatalf("%s: %s", c.msgID, line)
		}
	}
	if _, err := Format(domain.Record{Kind: domain.RecordEvent}, DefaultPEN); err == nil {
		t.Fatal("empty record accepted")
	}
}
