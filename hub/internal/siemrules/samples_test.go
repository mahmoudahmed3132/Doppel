// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package siemrules

// SIEM detection samples (docs/siem/detection-rules.md). Adapted from
// TrueSignal's sample generator (PROVENANCE.md): the scenario list and the
// rule checks are that test's; the generator is rebuilt on Doppel's ingest
// pipeline, enrichment modules and SIEM service.
//
// Each case goes through ingest.Pipeline (source lists, beacon resolution,
// the honeytoken_used raise, asset, GeoIP and ATT&CK enrichment) and the real
// SIEM service's ECS stream output, captured over TCP. The test fails when
// the emitted documents drift from the corpus. Regenerate with:
//
//	TS_UPDATE_SIEM_SAMPLES=1 go test ./internal/siemrules -run TestSIEMDetectionSamples
//
// Wall-clock and random fields are normalised (@timestamp, event.created,
// event IDs); the replay sets @timestamp from each case's offset.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/assets"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/attack"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ecs"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/enrich"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/geoip"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ingest"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/siem"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/sourcelist"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
)

const samplesFile = "../../../docs/siem/testdata/detection-samples.ndjson"

type sampleCase struct {
	Name      string
	OffsetSec int
	Node      string
	Event     *domain.Event
	System    *systemEvent
	Audit     *domain.AuditRecord
}

type systemEvent struct {
	sensor, trigger, severity string
	details                   map[string]any
}

type sampleLine struct {
	Case      string         `json:"case"`
	OffsetSec int            `json:"offset_sec"`
	Doc       map[string]any `json:"doc"`
}

const (
	nodeA   = "node-a1b2c3d4"
	nodeB   = "node-e5f6a7b8"
	nodeDMZ = "node-0dd0beac"

	beaconDomain = "beacon.example"
	htUser       = "svc_ledger1a2b"
)

var at = time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)

func ev(sensor, trigger, severity, source, target string, details map[string]any) *domain.Event {
	raw, _ := json.Marshal(details)
	return &domain.Event{SensorID: sensor, Trigger: trigger, Severity: domain.Severity(severity), Source: source, Target: target, Details: raw}
}

func beaconEv(source string, details map[string]any) *domain.Event {
	channel, _ := details["channel"].(string)
	return ev("ts-sensor-token-receiver", "beacon_triggered", "critical", source,
		strings.ToUpper(channel)+" ("+beaconDomain+")", details)
}

func dnsBeacon(token, resolver, clientSubnet string) map[string]any {
	d := map[string]any{"token": token, "channel": "dns", "query_name": token + "." + beaconDomain,
		"query_type": "A", "transport": "udp", "resolver": resolver}
	if clientSubnet != "" {
		d["client_subnet"] = clientSubnet
	}
	return d
}

func saturated(listener, top string) *domain.Event {
	return ev("ts-sensor-token-receiver", "receiver_saturated", "medium", top,
		strings.ToUpper(listener)+" listener ("+beaconDomain+")", map[string]any{
			"listener": listener, "refused_per_source": 40, "refused_total_cap": 0, "distinct_sources": 3,
			"top_source_refusals": 37,
		})
}

func login(sensor, proto string, port int, source, user string) *domain.Event {
	return ev(sensor, proto+"_login", "critical", source, fmt.Sprintf("%s (port %d)", strings.ToUpper(proto), port),
		map[string]any{"protocol": proto, "dst_port": port, "username": user, "auth": "password", "password_hmac": "0f1e2d3c"})
}

func audit(action, method, path string, status int, ip string) *domain.AuditRecord {
	outcome := "success"
	if status >= 400 {
		outcome = "failure"
	}
	actor := "admin"
	switch {
	case ip == "local":
		actor = "local"
	case action == "session.login" && status >= 400:
		actor = "anonymous"
	}
	return &domain.AuditRecord{Time: at, Action: action, Method: method, Route: method + " " + path, Path: path, Status: status, Outcome: outcome, ActorIP: ip, Actor: actor}
}

func sampleCases() []sampleCase {
	var cs []sampleCase
	add := func(c sampleCase) { cs = append(cs, c) }

	// Beacons (Token Receiver on the DMZ node).
	add(sampleCase{Name: "beacon_dns_client_subnet_eg", OffsetSec: 120, Node: nodeDMZ,
		Event: beaconEv("81.2.69.160", dnsBeacon("tokdns01", "81.2.69.160", "198.51.100.77/24"))})
	add(sampleCase{Name: "beacon_dns_resolver_only_gb", OffsetSec: 115, Node: nodeDMZ,
		Event: beaconEv("81.2.69.160", dnsBeacon("tokdns01", "81.2.69.160", ""))})
	add(sampleCase{Name: "beacon_http_us", OffsetSec: 110, Node: nodeDMZ,
		Event: beaconEv("203.0.113.9", map[string]any{"token": "tokweb01", "channel": "http", "method": "GET",
			"host": beaconDomain, "path": "/tokweb01.gif", "user_agent": "Microsoft Office/16.0"})})
	add(sampleCase{Name: "beacon_dns_private_resolver", OffsetSec: 105, Node: nodeDMZ,
		Event: beaconEv("10.30.0.53", dnsBeacon("tokkube01", "10.30.0.53", ""))})
	add(sampleCase{Name: "beacon_dns_asset_resolver", OffsetSec: 100, Node: nodeDMZ,
		Event: beaconEv("203.0.113.53", dnsBeacon("tokdns01", "203.0.113.53", ""))})
	add(sampleCase{Name: "beacon_known_from_whitelisted", OffsetSec: 95, Node: nodeDMZ,
		Event: beaconEv("10.10.0.5", dnsBeacon("tokdns01", "10.10.0.5", ""))})
	add(sampleCase{Name: "beacon_unknown_token", OffsetSec: 90, Node: nodeDMZ,
		Event: beaconEv("81.2.69.161", dnsBeacon("tokgone01", "81.2.69.161", ""))})
	add(sampleCase{Name: "beacon_unknown_whitelisted", OffsetSec: 85, Node: nodeDMZ,
		Event: beaconEv("10.10.0.5", dnsBeacon("tokgone01", "10.10.0.5", ""))})

	// Receiver saturation: at most one per listener per 5 minutes.
	for i, off := range []int{14 * 60, 9 * 60, 4 * 60} {
		add(sampleCase{Name: fmt.Sprintf("saturated_dns_%d", i+1), OffsetSec: off, Node: nodeDMZ, Event: saturated("dns", "81.2.69.170")})
	}
	for i, off := range []int{13 * 60, 3 * 60} {
		add(sampleCase{Name: fmt.Sprintf("saturated_http_%d", i+1), OffsetSec: off, Node: nodeDMZ, Event: saturated("http", "81.2.69.171")})
	}

	// Logins against decoys.
	add(sampleCase{Name: "ssh_login", OffsetSec: 80, Node: nodeA, Event: login("ts-sensor-remote-access-decoy", "ssh", 22, "10.40.0.9", "root")})
	add(sampleCase{Name: "ssh_login_publickey", OffsetSec: 79, Node: nodeA, Event: ev("ts-sensor-remote-access-decoy", "ssh_login", "critical", "10.40.0.9", "SSH (port 22)",
		map[string]any{"protocol": "ssh", "dst_port": 22, "username": "deploy", "auth": "publickey", "key_type": "ssh-ed25519",
			"key_fingerprint": "SHA256:Q0VSVElGSUNBVEUtTk9ULUEtUkVBTC1LRVktMDAwMDAw", "client_version": "SSH-2.0-OpenSSH_9.6"})})
	add(sampleCase{Name: "rdp_login", OffsetSec: 78, Node: nodeA, Event: ev("ts-sensor-identity-decoy", "rdp_login", "critical", "10.40.0.9", "RDP (port 3389)",
		map[string]any{"protocol": "rdp", "dst_port": 3389, "username": `CORP\admin`, "auth": "ntlm", "workstation": "WS-0001"})})
	add(sampleCase{Name: "mysql_login", OffsetSec: 76, Node: nodeB, Event: login("ts-sensor-database-decoy", "mysql", 3306, "10.40.0.10", "app")})
	add(sampleCase{Name: "web_login_attempt", OffsetSec: 74, Node: nodeB, Event: ev("ts-sensor-web-router-decoy", "web_login_attempt", "critical", "10.40.0.11", "HTTP (port 8080)",
		map[string]any{"username": "admin", "password_hmac": "hmac-sha256:9a8b7c6d", "auth": "form", "skin": "router", "path": "/login", "method": "POST", "user_agent": "Mozilla/5.0", "dst_port": 8080})})
	add(sampleCase{Name: "ldap_login_honeytoken", OffsetSec: 72, Node: nodeA, Event: login("ts-sensor-identity-decoy", "ldap", 389, "10.40.0.12", `CORP\`+htUser)})
	add(sampleCase{Name: "postgres_login_honeytoken_whitelisted", OffsetSec: 70, Node: nodeB, Event: login("ts-sensor-database-decoy", "postgres", 5432, "10.10.0.5", htUser)})
	add(sampleCase{Name: "ssh_login_whitelisted", OffsetSec: 68, Node: nodeA, Event: login("ts-sensor-remote-access-decoy", "ssh", 22, "10.10.0.5", "root")})
	add(sampleCase{Name: "ssh_login_known_scanner", OffsetSec: 66, Node: nodeA, Event: login("ts-sensor-remote-access-decoy", "ssh", 22, "10.10.0.6", "root")})

	// Scan, then touch (sequence by source.ip within 1 h).
	add(sampleCase{Name: "stt_scan", OffsetSec: 40 * 60, Node: nodeB, Event: ev("ts-sensor-network-scan-detector", "network_scan_detected", "high", "10.50.0.7", nodeB,
		map[string]any{"scan_type": "syn", "ports_hit": []int{22, 80, 443, 3389}, "count": 4, "window_sec": 10})})
	add(sampleCase{Name: "stt_touch", OffsetSec: 10 * 60, Node: nodeA, Event: ev("ts-sensor-web-router-decoy", "web_path_probe", "medium", "10.50.0.7", "HTTP (port 8080)",
		map[string]any{"path": "/.env", "method": "GET", "user_agent": "curl/8.5.0", "dst_port": 8080})})
	add(sampleCase{Name: "stt_reverse_touch", OffsetSec: 40 * 60, Node: nodeB, Event: ev("ts-sensor-network-service-decoy", "snmp_query", "medium", "10.50.0.8", "SNMP (port 161)",
		map[string]any{"protocol": "snmp", "dst_port": 161, "community_hmac": "hmac-sha256:11aa", "pdu": "get"})})
	add(sampleCase{Name: "stt_reverse_scan", OffsetSec: 10 * 60, Node: nodeB, Event: ev("ts-sensor-icmp-canary", "icmp_scan_received", "low", "10.50.0.8", nodeB,
		map[string]any{"icmp_type": 8, "icmp_id": 1, "icmp_seq": 1, "packet_size": 64})})
	add(sampleCase{Name: "stt_scan_conn_only", OffsetSec: 30 * 60, Node: nodeB, Event: ev("ts-sensor-icmp-canary", "icmp_scan_received", "low", "10.50.0.9", nodeB,
		map[string]any{"icmp_type": 8, "icmp_id": 2, "icmp_seq": 1, "packet_size": 64})})
	add(sampleCase{Name: "stt_conn_only", OffsetSec: 20 * 60, Node: nodeB, Event: ev("ts-sensor-tcp-tarpit", "tcp_connection", "high", "10.50.0.9", "TCP (port 445)",
		map[string]any{"dst_port": 445, "phase": "connect", "action_taken": "hold"})})
	add(sampleCase{Name: "scanner_scan", OffsetSec: 30 * 60, Node: nodeB, Event: ev("ts-sensor-network-scan-detector", "network_scan_detected", "high", "10.10.0.6", nodeB,
		map[string]any{"scan_type": "syn", "ports_hit": []int{22}, "count": 1, "window_sec": 10})})

	add(sampleCase{Name: "scan_recent", OffsetSec: 100, Node: nodeA, Event: ev("ts-sensor-network-scan-detector", "network_scan_detected", "high", "10.50.0.20", nodeA,
		map[string]any{"scan_type": "syn", "ports_hit": []int{21, 23, 445}, "count": 3, "window_sec": 10})})
	add(sampleCase{Name: "scanner_conn_recent", OffsetSec: 98, Node: nodeA, Event: ev("ts-sensor-tcp-tarpit", "tcp_connection", "high", "10.10.0.6", "TCP (port 23)",
		map[string]any{"dst_port": 23, "phase": "connect", "action_taken": "hold"})})

	// Asset criticality.
	add(sampleCase{Name: "asset_critical_dns_query", OffsetSec: 64, Node: nodeB, Event: ev("ts-sensor-network-service-decoy", "dns_query", "medium", "10.20.4.17", "DNS (port 53)",
		map[string]any{"protocol": "dns", "dst_port": 53, "query_name": "corp.example", "query_type": "AXFR"})})
	add(sampleCase{Name: "asset_medium_snmp_query", OffsetSec: 62, Node: nodeB, Event: ev("ts-sensor-network-service-decoy", "snmp_query", "medium", "10.20.4.30", "SNMP (port 161)",
		map[string]any{"protocol": "snmp", "dst_port": 161, "community_hmac": "hmac-sha256:22bb", "pdu": "get"})})
	add(sampleCase{Name: "file_tampered", OffsetSec: 60, Node: nodeA, Event: ev("ts-sensor-file-canary", "decoy_file_tampered", "critical", "local", "/srv/backup/db.env",
		map[string]any{"path": "/srv/backup/db.env", "action": "modify", "category": "credentials"})})

	// Liveness (Hub-raised).
	add(sampleCase{Name: "hb_lost_dark", OffsetSec: 3 * 3600, Node: nodeA, System: &systemEvent{"ts-sensor-tcp-tarpit", "sensor_heartbeat_lost", "high",
		map[string]any{"reason": "heartbeat_timeout", "timeout_sec": 60, "last_heartbeat": "2026-10-30T00:00:00Z"}}})
	add(sampleCase{Name: "hb_lost_then_recovered", OffsetSec: 3 * 3600, Node: nodeB, System: &systemEvent{"ts-sensor-icmp-canary", "sensor_heartbeat_lost", "high",
		map[string]any{"reason": "heartbeat_timeout", "timeout_sec": 60, "last_heartbeat": "2026-10-30T00:00:00Z"}}})
	add(sampleCase{Name: "hb_recovered", OffsetSec: 150 * 60, Node: nodeB, System: &systemEvent{"ts-sensor-icmp-canary", "sensor_recovered", "info",
		map[string]any{"config_rev": "rev_0a1b2c3d"}}})
	add(sampleCase{Name: "hb_lost_recent", OffsetSec: 120, Node: nodeB, System: &systemEvent{"ts-sensor-database-decoy", "sensor_heartbeat_lost", "high",
		map[string]any{"reason": "heartbeat_timeout", "timeout_sec": 60, "last_heartbeat": "2026-10-30T00:00:00Z"}}})
	add(sampleCase{Name: "sensor_stopped", OffsetSec: 6 * 60, Node: nodeA, System: &systemEvent{"ts-sensor-file-canary", "sensor_stopped", "low",
		map[string]any{"reason": "SIGTERM"}}})
	add(sampleCase{Name: "hb_lost_after_stop", OffsetSec: 60, Node: nodeA, System: &systemEvent{"ts-sensor-file-canary", "sensor_heartbeat_lost", "high",
		map[string]any{"reason": "not_restarted_after_stop", "timeout_sec": 300, "last_heartbeat": "2026-10-30T00:00:00Z"}}})

	// Audit records (actions as docs/audit-actions.md defines them).
	add(sampleCase{Name: "audit_mfa_reset", OffsetSec: 58, Audit: audit("mfa.reset_cli", "CLI", "-", 200, "local")})
	add(sampleCase{Name: "audit_mfa_disable", OffsetSec: 56, Audit: audit("mfa.disable", "POST", "/api/v3/mfa/disable", 200, "10.60.0.4")})
	add(sampleCase{Name: "audit_mfa_disable_failed", OffsetSec: 55, Audit: audit("mfa.disable", "POST", "/api/v3/mfa/disable", 401, "10.60.0.4")})
	add(sampleCase{Name: "audit_config_change", OffsetSec: 54, Audit: audit("config.update", "PATCH", "/api/v3/settings", 200, "10.60.0.4")})
	add(sampleCase{Name: "audit_clear_events", OffsetSec: 52, Audit: audit("events.delete_all", "POST", "/api/v3/events/delete-all", 200, "10.60.0.4")})
	add(sampleCase{Name: "audit_silence_sensor", OffsetSec: 51, Audit: audit("sensor.silence", "POST",
		"/api/v3/nodes/"+nodeA+"/sensors/ts-sensor-tcp-tarpit/silence", 200, "10.60.0.4")})
	add(sampleCase{Name: "audit_config_change_denied", OffsetSec: 50, Audit: audit("config.update", "PATCH", "/api/v3/settings", 403, "10.60.0.4")})
	add(sampleCase{Name: "audit_login_ok", OffsetSec: 49, Audit: audit("session.login", "POST", "/api/v3/session/login", 200, "10.60.0.4")})
	for i := 0; i < 6; i++ {
		add(sampleCase{Name: fmt.Sprintf("audit_login_fail_a%d", i+1), OffsetSec: 9*60 - i*50, Audit: audit("session.login", "POST", "/api/v3/session/login", 401, "198.51.100.23")})
	}
	for i := 0; i < 3; i++ {
		add(sampleCase{Name: fmt.Sprintf("audit_login_fail_b%d", i+1), OffsetSec: 8*60 - i*50, Audit: audit("session.login", "POST", "/api/v3/session/login", 401, "198.51.100.24")})
	}
	return cs
}

// Resolvers the Hub wires in production, faked to fixed data.
type sampleBeacons struct{}

func (sampleBeacons) Resolve(_ context.Context, token string) (*ported.Beacon, error) {
	names := map[string]string{"tokdns01": "Finance share", "tokweb01": "Board pack", "tokkube01": "Jump host kubeconfig"}
	if n, ok := names[token]; ok {
		return &ported.Beacon{ID: "bc_" + token, Token: token, Type: "dns", Name: n, Domain: beaconDomain}, nil
	}
	return nil, nil
}
func (sampleBeacons) Create(context.Context, string, string, string) (ported.Beacon, error) {
	return ported.Beacon{}, nil
}
func (sampleBeacons) Artefact(context.Context, string) (ported.BeaconArtefact, error) {
	return ported.BeaconArtefact{}, nil
}
func (sampleBeacons) RecordUse(context.Context, string, time.Time) error { return nil }
func (sampleBeacons) Delete(context.Context, string) error               { return nil }
func (sampleBeacons) List(context.Context) ([]ported.Beacon, error)      { return nil, nil }

type sampleHoneytokens struct{}

var plantedToken = ported.Honeytoken{ID: "ht_0a1b2c3d", Username: htUser, PlantedNodeID: nodeB, PlantedSensorID: "ts-sensor-file-canary", Status: "active", CreatedAt: at}

func (sampleHoneytokens) Match(_ context.Context, e *domain.Event) ([]ported.HoneytokenMatch, error) {
	var d map[string]any
	_ = json.Unmarshal(e.Details, &d)
	if u, _ := d["username"].(string); strings.Contains(strings.ToLower(u), htUser) {
		p, _ := d["protocol"].(string)
		port, _ := d["dst_port"].(float64)
		return []ported.HoneytokenMatch{{Token: plantedToken, MatchedOn: "username", Protocol: p, DstPort: int(port)}}, nil
	}
	return nil, nil
}
func (sampleHoneytokens) Ensure(context.Context, string, string) (ported.Honeytoken, error) {
	return plantedToken, nil
}
func (sampleHoneytokens) RecordUse(context.Context, string, time.Time) error { return nil }
func (sampleHoneytokens) List(context.Context) ([]ported.Honeytoken, error) {
	return []ported.Honeytoken{plantedToken}, nil
}
func (sampleHoneytokens) Inventory(context.Context, time.Time) ([]domain.HoneytokenInventory, error) {
	return nil, nil
}

type lists struct{ wl, sc ported.SourceMatcher }

func (l lists) Whitelist() ported.SourceMatcher     { return l.wl }
func (l lists) KnownScanners() ported.SourceMatcher { return l.sc }

type assetIndex struct{ ix ported.AssetIndex }

func (a assetIndex) AssetIndex(context.Context) ported.AssetIndex { return a.ix }

// countingSink forwards to the real SIEM service and counts records.
type countingSink struct {
	real *siem.Service
	n    int
}

func (c *countingSink) Enqueue(r domain.Record)           { c.n++; c.real.Enqueue(r) }
func (c *countingSink) Notify(domain.EnrichedEvent)       {}
func (c *countingSink) PublishEvent(domain.EnrichedEvent) {}

func generateSamples(t *testing.T) []sampleLine {
	t.Helper()
	ctx := context.Background()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	real := &siem.Service{Renderer: ecs.Renderer{}, Log: logger}
	if err := real.Start(siem.Config{Protocol: siem.ProtoTCP, Address: ln.Addr().String(), Format: siem.FormatECS}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		sctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		real.Shutdown(sctx)
	}()
	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- c
		}
	}()
	var reader *bufio.Reader
	readDoc := func() map[string]any {
		if reader == nil {
			select {
			case c := <-accepted:
				t.Cleanup(func() { c.Close() })
				reader = bufio.NewReader(c)
			case <-time.After(10 * time.Second):
				t.Fatal("SIEM output never connected")
			}
		}
		line, err := reader.ReadBytes('\n')
		if err != nil {
			t.Fatalf("reading SIEM output: %v", err)
		}
		var doc map[string]any
		if err := json.Unmarshal(line, &doc); err != nil {
			t.Fatalf("SIEM output is not JSON: %v: %s", err, line)
		}
		return doc
	}

	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "hub.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	sensors := map[string]bool{}
	for _, c := range sampleCases() {
		if c.Event != nil {
			sensors[c.Node+"/"+c.Event.SensorID] = true
		}
	}
	for _, n := range []string{nodeA, nodeB, nodeDMZ} {
		db.CreateNode(ctx, &domain.Node{ID: n, Alias: n, KeyHash: []byte(n), CreatedAt: at})
	}
	for k := range sensors {
		node, id, _ := strings.Cut(k, "/")
		db.CreateSensor(ctx, &domain.Sensor{NodeID: node, ID: id, CatalogueName: strings.TrimPrefix(id, "ts-sensor-"), Version: "1.0.0", CreatedAt: at})
	}

	wl, _ := sourcelist.Parser{}.Parse([]string{"10.10.0.5"})
	sc, _ := sourcelist.Parser{}.Parse([]string{"10.10.0.6"})
	norm, err := assets.Module{}.Validate(json.RawMessage(`[{"name":"asset-critical-01","address":"10.20.4.17","criticality":"critical"},` +
		`{"name":"asset-medium-01","address":"10.20.4.30","criticality":"medium"},` +
		`{"name":"resolver-egress-01","address":"203.0.113.53","criticality":"medium"}]`))
	if err != nil {
		t.Fatal(err)
	}
	ix, _ := assets.Module{}.Index(norm)
	mmdb, err := os.ReadFile("../geoip/testdata/dbip-city-test.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "dbip-city-lite.mmdb")
	if err := os.WriteFile(dbPath, mmdb, 0o600); err != nil {
		t.Fatal(err)
	}
	g := geoip.New(dbPath, false, nil)
	defer g.Close()

	sink := &countingSink{real: real}
	p := &ingest.Pipeline{Store: db, Lists: lists{wl, sc}, Beacons: sampleBeacons{}, Honeytokens: sampleHoneytokens{},
		Enricher: &enrich.Enricher{Nodes: db, Attack: attack.Mapper{}, Assets: assetIndex{ix}, Geo: geoip.Locator{S: g}},
		SIEM:     sink, Notifier: sink, Live: sink, Log: logger, Now: func() time.Time { return at }}

	var out []sampleLine
	for i, c := range sampleCases() {
		before := sink.n
		switch {
		case c.Event != nil:
			e := *c.Event
			e.EventID = fmt.Sprintf("0192f000-0000-7000-8000-%012d", i+1)
			e.NodeID, e.OccurredAt, e.ReceivedAt = c.Node, at, at
			if _, err := p.Process(ctx, &e); err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
		case c.System != nil:
			if _, err := p.RaiseHubEvent(ctx, c.Node, c.System.sensor, c.System.trigger, domain.Severity(c.System.severity),
				domain.HubSource, c.System.sensor, c.System.details); err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
		case c.Audit != nil:
			sink.Enqueue(domain.Record{Kind: domain.RecordAudit, Audit: c.Audit})
		}
		for j := before; j < sink.n; j++ {
			doc := readDoc()
			doc["@timestamp"] = "1970-01-01T00:00:00Z"
			if e, ok := doc["event"].(map[string]any); ok {
				delete(e, "created")
				if _, ok := e["id"]; ok {
					e["id"] = "normalised"
				}
			}
			if tsd, ok := doc["truesignal"].(map[string]any); ok {
				if _, ok := tsd["event_id"]; ok {
					tsd["event_id"] = "normalised"
				}
				delete(tsd, "seq")
			}
			name := c.Name
			if j > before {
				name = fmt.Sprintf("%s#%d", c.Name, j-before+1)
			}
			out = append(out, sampleLine{Case: name, OffsetSec: c.OffsetSec, Doc: doc})
		}
	}
	return out
}

func TestSIEMDetectionSamples(t *testing.T) {
	got := generateSamples(t)
	var buf bytes.Buffer
	for _, l := range got {
		b, err := json.Marshal(l)
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	if os.Getenv("TS_UPDATE_SIEM_SAMPLES") == "1" {
		if err := os.WriteFile(samplesFile, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %d samples to %s", len(got), samplesFile)
	}
	want, err := os.ReadFile(samplesFile)
	if err != nil {
		t.Fatalf("%v (regenerate with TS_UPDATE_SIEM_SAMPLES=1)", err)
	}
	if !bytes.Equal(want, buf.Bytes()) {
		wl, gl := bytes.Split(want, []byte("\n")), bytes.Split(buf.Bytes(), []byte("\n"))
		for i := 0; i < len(wl) && i < len(gl); i++ {
			if !bytes.Equal(wl[i], gl[i]) {
				t.Fatalf("SIEM output changed at sample %d; re-run the rule tests (scripts/siem-rules) and regenerate with TS_UPDATE_SIEM_SAMPLES=1.\nwant: %s\ngot:  %s", i+1, wl[i], gl[i])
			}
		}
		t.Fatalf("SIEM output changed (%d samples, want %d); regenerate with TS_UPDATE_SIEM_SAMPLES=1", len(gl), len(wl))
	}

	// The Hub, not the rules, enforces the list bypass: known beacons and
	// honeytoken_used are never flagged, so "not whitelisted" filters are safe
	// for every rule.
	for _, l := range got {
		tsd, ok := l.Doc["truesignal"].(map[string]any)
		if !ok {
			continue
		}
		trigger := tsd["trigger"]
		details, _ := tsd["details"].(map[string]any)
		_, known := details["beacon"]
		if (trigger == "honeytoken_used" || (trigger == "beacon_triggered" && known)) && (tsd["whitelisted"] == true || tsd["known_scanner"] == true) {
			t.Errorf("%s: %s is flagged whitelisted/known_scanner", l.Case, trigger)
		}
	}
}

// ecsFieldRef matches field references in rule queries: ECS and truesignal
// namespaces only, so query keywords and values are not picked up.
var ecsFieldRef = regexp.MustCompile(`\b(?:event|source|destination|truesignal|threat|host|user|url|observer|http|file|user_agent|log)\.[A-Za-z_][\w.]*(?:\[\])?`)

// quotedFieldArg matches string literals LogScale uses as field names
// (in(field="…"), array:contains("…")); other literals are values.
var quotedFieldArg = regexp.MustCompile(`(?:field=|array:contains\()"([^"]*)"`)

var stringLiteral = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)

// fieldRefs returns the field names a query references.
func fieldRefs(query string) []string {
	var refs []string
	for _, m := range quotedFieldArg.FindAllStringSubmatch(query, -1) {
		refs = append(refs, m[1])
	}
	return append(refs, ecsFieldRef.FindAllString(stringLiteral.ReplaceAllString(query, `""`), -1)...)
}

// TestSIEMRuleFieldsExist checks that every field the Elastic rules and the
// LogScale queries reference exists in a document the Hub emits.
func TestSIEMRuleFieldsExist(t *testing.T) {
	want, err := os.ReadFile(samplesFile)
	if err != nil {
		t.Fatal(err)
	}
	present := map[string]bool{}   // dotted paths (Elastic: arrays are transparent)
	flattened := map[string]bool{} // LogScale json-parser names (arrays as name[])
	for _, line := range bytes.Split(bytes.TrimSpace(want), []byte("\n")) {
		var l sampleLine
		if err := json.Unmarshal(line, &l); err != nil {
			t.Fatal(err)
		}
		collectPaths(l.Doc, "", present, flattened)
	}

	elastic, _ := filepath.Glob("../../../docs/siem/elastic/truesignal-*.json")
	logscale, _ := filepath.Glob("../../../docs/siem/logscale/truesignal-*.logscale")
	if len(elastic) < 2 || len(logscale) < 1 {
		t.Fatalf("rules not found: %d elastic, %d logscale", len(elastic), len(logscale))
	}
	for _, f := range elastic {
		var rule map[string]any
		b, _ := os.ReadFile(f)
		if err := json.Unmarshal(b, &rule); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if rule["rule_id"] == "truesignal-honeytoken-authentication" {
			continue // queries other products' logs, not the Hub's
		}
		text := fmt.Sprint(rule["query"])
		if th, ok := rule["threshold"].(map[string]any); ok {
			text += " " + fmt.Sprint(th["field"])
		}
		for _, ref := range fieldRefs(text) {
			if !present[strings.TrimSuffix(ref, "[]")] {
				t.Errorf("%s: field %s is not in any emitted document", filepath.Base(f), ref)
			}
		}
	}
	for _, f := range logscale {
		b, _ := os.ReadFile(f)
		var body []string
		for _, ln := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(ln), "//") {
				body = append(body, ln)
			}
		}
		for _, ref := range fieldRefs(strings.Join(body, "\n")) {
			if !flattened[ref] {
				t.Errorf("%s: field %s is not in any emitted document (LogScale json-parser name)", filepath.Base(f), ref)
			}
		}
	}
}

func collectPaths(v any, prefix string, present, flattened map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			collectPaths(child, p, present, flattened)
		}
	case []any:
		present[prefix] = true
		flattened[prefix+"[]"] = true
		for _, child := range x {
			if m, ok := child.(map[string]any); ok {
				collectPaths(m, prefix, present, map[string]bool{})
			}
		}
	default:
		present[prefix] = true
		flattened[prefix] = true
	}
}

// TestSIEMRulesDocumented checks that every Elastic rule has a LogScale twin
// and a section in docs/siem/detection-rules.md.
func TestSIEMRulesDocumented(t *testing.T) {
	doc, err := os.ReadFile("../../../docs/siem/detection-rules.md")
	if err != nil {
		t.Fatal(err)
	}
	elastic, _ := filepath.Glob("../../../docs/siem/elastic/truesignal-*.json")
	for _, f := range elastic {
		id := strings.TrimSuffix(filepath.Base(f), ".json")
		if id == "truesignal-honeytoken-authentication" {
			continue // documented in honeytoken-detection.md
		}
		if _, err := os.Stat("../../../docs/siem/logscale/" + id + ".logscale"); err != nil {
			t.Errorf("%s: no LogScale query", id)
		}
		if !bytes.Contains(doc, []byte("### "+id+"\n")) {
			t.Errorf("%s: no section in detection-rules.md", id)
		}
	}
}
