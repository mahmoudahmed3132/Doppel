// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/ber"
	"github.com/mahmoudahmed3132/Doppel/sdk/go/decoy"
	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

const testCaptureKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

type reportedEvent struct {
	Severity sensor.Severity
	Trigger  string
	Source   string
	Target   string
	Details  map[string]any
}

type fakeReporter struct {
	mu       sync.Mutex
	settings map[string]string
	events   []reportedEvent
}

func newFakeReporter(overrides map[string]string) *fakeReporter {
	s := map[string]string{
		"TS_CAPTURE_KEY":        testCaptureKey,
		"TS_PASSWORD_CAPTURE":   "hash",
		"TS_SENSOR_ID":          "sen-net-1",
		"TS_EVENT_COOLDOWN_SEC": "0",
	}
	for k, v := range overrides {
		s[k] = v
	}
	return &fakeReporter{settings: s}
}

func (f *fakeReporter) Setting(name string) (string, bool) {
	v, ok := f.settings[name]
	return v, ok
}

func (f *fakeReporter) ReportSeverity(sev sensor.Severity, trigger, source, target string, details sensor.Details) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := map[string]any{}
	switch d := details.(type) {
	case sensor.Fields:
		for _, kv := range d {
			m[kv.Key] = kv.Value
		}
	case sensor.Map:
		for k, v := range d {
			m[k] = v
		}
	}
	f.events = append(f.events, reportedEvent{
		Severity: sev,
		Trigger:  trigger,
		Source:   source,
		Target:   target,
		Details:  m,
	})
}

func (f *fakeReporter) Events() []reportedEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]reportedEvent, len(f.events))
	copy(out, f.events)
	return out
}

func hmacHex(keyHex, val string) string {
	k, _ := hex.DecodeString(keyHex)
	m := hmac.New(sha256.New, k)
	m.Write([]byte(val))
	return hex.EncodeToString(m.Sum(nil))
}

func buildSNMPv1v2cReq(version int64, community string, pduTag uint32, reqID int64, oids ...[]uint32) []byte {
	var vbs [][]byte
	for _, oid := range oids {
		vbs = append(vbs, ber.Sequence(ber.OID(oid), ber.Null()))
	}
	pdu := ber.Encode(ber.ContextSpecific, true, pduTag, ber.Cat(
		ber.Integer(reqID),
		ber.Integer(0),
		ber.Integer(0),
		ber.Sequence(vbs...),
	))
	return ber.Sequence(
		ber.Integer(version),
		ber.OctetString([]byte(community)),
		pdu,
	)
}

func buildSNMPv3Req(msgID int64, flags byte, engineID []byte, user string, encrypted bool, pduTag uint32, reqID int64, oids ...[]uint32) []byte {
	globalData := ber.Sequence(
		ber.Integer(msgID),
		ber.Integer(1472),
		ber.OctetString([]byte{flags}),
		ber.Integer(snmpSecurityModelUSM),
	)
	usmParams := ber.Sequence(
		ber.OctetString(engineID),
		ber.Integer(0),
		ber.Integer(0),
		ber.OctetString([]byte(user)),
		ber.OctetString(nil),
		ber.OctetString(nil),
	)
	var msgData []byte
	if encrypted {
		msgData = ber.OctetString([]byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04})
	} else {
		var vbs [][]byte
		for _, oid := range oids {
			vbs = append(vbs, ber.Sequence(ber.OID(oid), ber.Null()))
		}
		pdu := ber.Encode(ber.ContextSpecific, true, pduTag, ber.Cat(
			ber.Integer(reqID),
			ber.Integer(0),
			ber.Integer(0),
			ber.Sequence(vbs...),
		))
		msgData = ber.Sequence(
			ber.OctetString(engineID),
			ber.OctetString(nil),
			pdu,
		)
	}
	return ber.Sequence(
		ber.Integer(snmpVersion3),
		globalData,
		ber.OctetString(usmParams),
		msgData,
	)
}

func buildDNSQueryPacket(id uint16, qname string, qtype, qclass uint16, extra []byte) []byte {
	var buf []byte
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // RD=1
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT=1
	if len(extra) > 0 {
		binary.BigEndian.PutUint16(hdr[10:12], 1) // ARCOUNT=1
	}
	buf = append(buf, hdr...)
	if qname != "" && qname != "." {
		for _, lbl := range strings.Split(strings.TrimSuffix(qname, "."), ".") {
			buf = append(buf, byte(len(lbl)))
			buf = append(buf, lbl...)
		}
	}
	buf = append(buf, 0)
	tail := make([]byte, 4)
	binary.BigEndian.PutUint16(tail[0:2], qtype)
	binary.BigEndian.PutUint16(tail[2:4], qclass)
	buf = append(buf, tail...)
	buf = append(buf, extra...)
	return buf
}

func TestLoadSettingsValidation(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		r := newFakeReporter(nil)
		cfg, err := LoadSettings(r)
		if err != nil {
			t.Fatalf("LoadSettings: %v", err)
		}
		if !cfg.EnableSNMP || !cfg.EnableDNS || !cfg.EnableDNSTCP {
			t.Fatalf("expected all listeners enabled by default")
		}
		if cfg.SNMPPort != 161 || cfg.DNSPort != 53 || cfg.ReplyRatePerSec != 10 {
			t.Fatalf("unexpected defaults: %+v", cfg)
		}
		if len(cfg.SNMPPersona.EngineID) != 11 {
			t.Fatalf("expected 11-byte engineID, got %d", len(cfg.SNMPPersona.EngineID))
		}
	})

	t.Run("all_disabled_rejected", func(t *testing.T) {
		r := newFakeReporter(map[string]string{
			"TS_ENABLE_SNMP":    "false",
			"TS_ENABLE_DNS":     "false",
			"TS_ENABLE_DNS_TCP": "false",
		})
		if _, err := LoadSettings(r); err == nil {
			t.Fatal("expected error when all listeners disabled")
		}
	})

	t.Run("udp_port_conflict_rejected", func(t *testing.T) {
		r := newFakeReporter(map[string]string{
			"TS_SNMP_PORT": "5353",
			"TS_DNS_PORT":  "5353",
		})
		if _, err := LoadSettings(r); err == nil {
			t.Fatal("expected UDP port conflict error")
		}
	})

	t.Run("invalid_sys_object_id", func(t *testing.T) {
		r := newFakeReporter(map[string]string{
			"TS_SNMP_SYS_OBJECT_ID": "9.1.2",
		})
		if _, err := LoadSettings(r); err == nil {
			t.Fatal("expected error for invalid sysObjectID")
		}
	})
}

func TestSNMPv1v2cBehaviourAndCommunityPolicy(t *testing.T) {
	t.Run("silent_when_community_unconfigured", func(t *testing.T) {
		r := newFakeReporter(nil)
		cfg, err := LoadSettings(r)
		if err != nil {
			t.Fatal(err)
		}
		d, err := NewDecoy(cfg, r)
		if err != nil {
			t.Fatal(err)
		}

		req := buildSNMPv1v2cReq(snmpVersion2c, "public", snmpPDUGetRequest, 42, oidSysDescr)
		reply := d.ProcessSNMP("10.0.0.5", req, 161)
		if reply != nil {
			t.Fatalf("expected silent drop when TS_SNMP_COMMUNITY is empty, got %d bytes", len(reply))
		}
		evs := r.Events()
		if len(evs) != 1 {
			t.Fatalf("expected 1 event, got %d", len(evs))
		}
		ev := evs[0]
		if ev.Trigger != TriggerSNMPQuery || ev.Severity != sensor.SeverityMedium {
			t.Fatalf("unexpected trigger/severity: %+v", ev)
		}
		if ev.Details["version"] != "2c" || ev.Details["pdu_type"] != "GetRequest" {
			t.Fatalf("unexpected details: %+v", ev.Details)
		}
		if ev.Details["community_hmac"] != hmacHex(testCaptureKey, "public") {
			t.Fatalf("expected community_hmac to match, got %v", ev.Details["community_hmac"])
		}
		if _, hasPlain := ev.Details["community"]; hasPlain {
			t.Fatal("cleartext community leaked in hash mode")
		}
	})

	t.Run("matching_community_answers_system_group_only", func(t *testing.T) {
		r := newFakeReporter(map[string]string{
			"TS_SNMP_COMMUNITY": "public",
		})
		cfg, err := LoadSettings(r)
		if err != nil {
			t.Fatal(err)
		}
		d, err := NewDecoy(cfg, r)
		if err != nil {
			t.Fatal(err)
		}

		// Test all 6 system group OIDs via GetRequest.
		sysOIDs := [][]uint32{oidSysDescr, oidSysObjectID, oidSysUpTime, oidSysContact, oidSysName, oidSysLocation}
		for i, oid := range sysOIDs {
			req := buildSNMPv1v2cReq(snmpVersion2c, "public", snmpPDUGetRequest, int64(100+i), oid)
			reply := d.ProcessSNMP("10.0.0.6", req, 161)
			if len(reply) == 0 {
				t.Fatalf("expected reply for %s", formatOID(oid))
			}
			if len(reply) > len(req)+snmpMaxReplyMargin {
				t.Fatalf("anti-amplification violated for %s: reply=%d req=%d", formatOID(oid), len(reply), len(req))
			}
			parsed, err := parseSNMPMessage(reply)
			if err != nil {
				t.Fatalf("reply for %s did not parse cleanly: %v", formatOID(oid), err)
			}
			if parsed.PDUTag != snmpPDUResponse || parsed.RequestID != int64(100+i) {
				t.Fatalf("unexpected response PDU: %+v", parsed)
			}
			if len(parsed.OIDs) != 1 || compareOID(parsed.OIDs[0], oid) != 0 {
				t.Fatalf("expected echoed OID %s, got %v", formatOID(oid), parsed.OIDs)
			}
		}

		// Wrong community -> silent drop.
		wrongReq := buildSNMPv1v2cReq(snmpVersion2c, "private", snmpPDUGetRequest, 200, oidSysDescr)
		if reply := d.ProcessSNMP("10.0.0.6", wrongReq, 161); reply != nil {
			t.Fatalf("expected silent drop for wrong community, got %d bytes", len(reply))
		}

		// Non-system-group OID with matching community -> silent drop.
		otherReq := buildSNMPv1v2cReq(snmpVersion2c, "public", snmpPDUGetRequest, 201, []uint32{1, 3, 6, 1, 2, 1, 2, 1, 0})
		if reply := d.ProcessSNMP("10.0.0.6", otherReq, 161); reply != nil {
			t.Fatalf("expected silent drop for non-system OID, got %d bytes", len(reply))
		}

		// GetNext walk across system group.
		cur := oidSysGroupPrefix
		for idx, expected := range sysOIDs {
			req := buildSNMPv1v2cReq(snmpVersion1, "public", snmpPDUGetNextRequest, int64(300+idx), cur)
			reply := d.ProcessSNMP("10.0.0.6", req, 161)
			if len(reply) == 0 {
				t.Fatalf("expected GetNext reply from %s", formatOID(cur))
			}
			parsed, err := parseSNMPMessage(reply)
			if err != nil {
				t.Fatalf("GetNext reply parse: %v", err)
			}
			if len(parsed.OIDs) != 1 || compareOID(parsed.OIDs[0], expected) != 0 {
				t.Fatalf("GetNext(%s) returned %v, want %s", formatOID(cur), parsed.OIDs, formatOID(expected))
			}
			cur = expected
		}
		// Past sysLocation.0 -> silent drop.
		endReq := buildSNMPv1v2cReq(snmpVersion1, "public", snmpPDUGetNextRequest, 399, oidSysLocation)
		if reply := d.ProcessSNMP("10.0.0.6", endReq, 161); reply != nil {
			t.Fatalf("expected silent drop past sysLocation.0, got %d bytes", len(reply))
		}
	})

	t.Run("set_request_high_severity_and_silent", func(t *testing.T) {
		r := newFakeReporter(map[string]string{"TS_SNMP_COMMUNITY": "private"})
		cfg, err := LoadSettings(r)
		if err != nil {
			t.Fatal(err)
		}
		d, err := NewDecoy(cfg, r)
		if err != nil {
			t.Fatal(err)
		}

		req := buildSNMPv1v2cReq(snmpVersion2c, "private", snmpPDUSetRequest, 77, oidSysName)
		if reply := d.ProcessSNMP("10.0.0.7", req, 161); reply != nil {
			t.Fatalf("SetRequest must stay silent, got %d bytes", len(reply))
		}
		evs := r.Events()
		if len(evs) != 1 || evs[0].Severity != sensor.SeverityHigh || evs[0].Details["pdu_type"] != "SetRequest" {
			t.Fatalf("expected high-severity SetRequest event, got %+v", evs)
		}
	})

	t.Run("oid_list_capped_at_16", func(t *testing.T) {
		r := newFakeReporter(nil)
		cfg, _ := LoadSettings(r)
		d, _ := NewDecoy(cfg, r)
		var oids [][]uint32
		for i := uint32(1); i <= 20; i++ {
			oids = append(oids, []uint32{1, 3, 6, 1, 2, 1, 1, i, 0})
		}
		req := buildSNMPv1v2cReq(snmpVersion2c, "public", snmpPDUGetRequest, 88, oids...)
		d.ProcessSNMP("10.0.0.8", req, 161)
		evs := r.Events()
		if len(evs) != 1 {
			t.Fatalf("expected 1 event, got %d", len(evs))
		}
		reportedOIDs, ok := evs[0].Details["oids"].([]string)
		if !ok || len(reportedOIDs) != snmpMaxOIDs {
			t.Fatalf("expected %d capped OIDs, got %#v", snmpMaxOIDs, evs[0].Details["oids"])
		}
	})
}

func TestSNMPv3EngineDiscoveryAndAuthAttempts(t *testing.T) {
	r := newFakeReporter(nil)
	cfg, err := LoadSettings(r)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDecoy(cfg, r)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Engine discovery (empty engineID, reportable=1).
	discReq := buildSNMPv3Req(1001, snmpFlagReportable, nil, "", false, snmpPDUGetRequest, 1, oidSysDescr)
	reply := d.ProcessSNMP("10.0.0.9", discReq, 161)
	if len(reply) == 0 {
		t.Fatal("expected Report PDU for SNMPv3 engine discovery")
	}
	if len(reply) > len(discReq)+snmpMaxReplyMargin {
		t.Fatalf("v3 Report exceeded anti-amplification margin: reply=%d req=%d", len(reply), len(discReq))
	}
	parsed, err := parseSNMPMessage(reply)
	if err != nil {
		t.Fatalf("failed to parse v3 Report reply: %v", err)
	}
	if parsed.Version != snmpVersion3 || parsed.PDUTag != snmpPDUReport || parsed.MsgID != 1001 {
		t.Fatalf("unexpected v3 Report fields: %+v", parsed)
	}
	if !bytes.Equal(parsed.EngineID, cfg.SNMPPersona.EngineID) {
		t.Fatalf("engineID mismatch: got %x want %x", parsed.EngineID, cfg.SNMPPersona.EngineID)
	}
	if len(parsed.OIDs) != 1 || compareOID(parsed.OIDs[0], oidUSMUnknownEng) != 0 {
		t.Fatalf("expected usmStatsUnknownEngineIDs OID, got %v", parsed.OIDs)
	}

	// 2. Follow-up authPriv query with discovered engineID -> silent, username & security_level reported.
	authReq := buildSNMPv3Req(1002, snmpFlagAuth|snmpFlagPriv|snmpFlagReportable, cfg.SNMPPersona.EngineID, "snmpadmin", true, 0, 0)
	if reply2 := d.ProcessSNMP("10.0.0.9", authReq, 161); reply2 != nil {
		t.Fatalf("expected silent drop for non-discovery v3 request, got %d bytes", len(reply2))
	}

	evs := r.Events()
	if len(evs) != 2 {
		t.Fatalf("expected 2 events, got %d", len(evs))
	}
	if evs[0].Details["version"] != "3" || evs[0].Details["engine_discovery"] != true || evs[0].Details["security_level"] != "noAuthNoPriv" {
		t.Fatalf("unexpected discovery event: %+v", evs[0].Details)
	}
	if evs[1].Details["version"] != "3" || evs[1].Details["username"] != "snmpadmin" || evs[1].Details["security_level"] != "authPriv" || evs[1].Details["pdu_type"] != "Encrypted" {
		t.Fatalf("unexpected authPriv event: %+v", evs[1].Details)
	}
}

func TestDNSRefusedAndAXFRDetection(t *testing.T) {
	r := newFakeReporter(nil)
	cfg, _ := LoadSettings(r)
	d, _ := NewDecoy(cfg, r)

	// UDP A query.
	req := buildDNSQueryPacket(0x1234, "dc01.corp.local", 1, 1, nil)
	reply := d.ProcessDNS("10.0.0.10", req, "udp", 53)
	if len(reply) != len(req) {
		t.Fatalf("expected DNS reply size == req size (%d), got %d", len(req), len(reply))
	}
	if binary.BigEndian.Uint16(reply[0:2]) != 0x1234 {
		t.Fatalf("DNS ID mismatch")
	}
	flags := binary.BigEndian.Uint16(reply[2:4])
	if flags&dnsFlagQR == 0 || flags&0x000f != dnsRcodeRefused {
		t.Fatalf("expected QR=1 and RCODE=5 (REFUSED), got flags=0x%04x", flags)
	}
	if binary.BigEndian.Uint16(reply[4:6]) != 1 || binary.BigEndian.Uint16(reply[6:8]) != 0 || binary.BigEndian.Uint16(reply[8:10]) != 0 || binary.BigEndian.Uint16(reply[10:12]) != 0 {
		t.Fatalf("expected QDCOUNT=1 and AN/NS/AR=0")
	}
	if !bytes.Equal(reply[12:], req[12:]) {
		t.Fatalf("question bytes were not echoed verbatim")
	}

	// TCP AXFR and IXFR over net.Pipe.
	for _, tc := range []struct {
		name  string
		qtype uint16
		want  string
		sev   sensor.Severity
	}{
		{"AXFR", dnsTypeAXFR, "AXFR", sensor.SeverityHigh},
		{"IXFR", dnsTypeIXFR, "IXFR", sensor.SeverityHigh},
		{"A", 1, "A", sensor.SeverityMedium},
	} {
		c1, c2 := net.Pipe()
		go d.HandleDNSTCPConn(c2, 53)

		q := buildDNSQueryPacket(0xabcd, "corp.local", tc.qtype, 1, nil)
		var lbuf [2]byte
		binary.BigEndian.PutUint16(lbuf[:], uint16(len(q)))
		if _, err := c1.Write(append(lbuf[:], q...)); err != nil {
			t.Fatalf("%s write: %v", tc.name, err)
		}
		var rlen [2]byte
		if _, err := io.ReadFull(c1, rlen[:]); err != nil {
			t.Fatalf("%s read len: %v", tc.name, err)
		}
		resp := make([]byte, binary.BigEndian.Uint16(rlen[:]))
		if _, err := io.ReadFull(c1, resp); err != nil {
			t.Fatalf("%s read body: %v", tc.name, err)
		}
		_ = c1.Close()

		if len(resp) > len(q) {
			t.Fatalf("%s TCP reply larger than query: %d > %d", tc.name, len(resp), len(q))
		}
		if binary.BigEndian.Uint16(resp[2:4])&0x000f != dnsRcodeRefused {
			t.Fatalf("%s expected REFUSED", tc.name)
		}
	}

	evs := r.Events()
	if len(evs) != 4 {
		t.Fatalf("expected 4 DNS events, got %d", len(evs))
	}
	if evs[0].Severity != sensor.SeverityMedium || evs[0].Details["qname"] != "dc01.corp.local" || evs[0].Details["qtype"] != "A" || evs[0].Details["transport"] != "udp" {
		t.Fatalf("unexpected UDP event: %+v", evs[0])
	}
	if evs[1].Severity != sensor.SeverityHigh || evs[1].Details["qtype"] != "AXFR" || evs[1].Details["transport"] != "tcp" {
		t.Fatalf("expected high-severity TCP AXFR event, got %+v", evs[1])
	}
	if evs[2].Severity != sensor.SeverityHigh || evs[2].Details["qtype"] != "IXFR" || evs[2].Details["transport"] != "tcp" {
		t.Fatalf("expected high-severity TCP IXFR event, got %+v", evs[2])
	}
	if evs[3].Severity != sensor.SeverityMedium || evs[3].Details["qtype"] != "A" || evs[3].Details["transport"] != "tcp" {
		t.Fatalf("expected medium-severity TCP A event, got %+v", evs[3])
	}
}

func TestAntiAmplificationInvariants(t *testing.T) {
	t.Run("dns_reply_never_exceeds_request", func(t *testing.T) {
		r := newFakeReporter(nil)
		cfg, _ := LoadSettings(r)
		d, _ := NewDecoy(cfg, r)

		// Include EDNS0 OPT record (11 bytes) so request > question-only reply.
		ednsOPT := []byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		for _, tc := range []struct {
			qname string
			qtype uint16
			extra []byte
		}{
			{".", 1, nil},
			{"a.b", 255, nil},
			{"sub.domain.corp.local", 16, ednsOPT},
			{"_ldap._tcp.dc._msdcs.corp.local", 33, ednsOPT},
		} {
			req := buildDNSQueryPacket(0x4242, tc.qname, tc.qtype, 1, tc.extra)
			reply := d.ProcessDNS("10.0.0.20", req, "udp", 53)
			if len(reply) == 0 {
				t.Fatalf("expected reply for %s", tc.qname)
			}
			if len(reply) > len(req) {
				t.Fatalf("DNS amplification violation for %s: reply=%d > req=%d", tc.qname, len(reply), len(req))
			}
		}
	})

	t.Run("snmp_reply_never_exceeds_request_plus_64", func(t *testing.T) {
		// Configure a 255-byte sysDescr and a 1-byte community to stress-test the guard.
		r := newFakeReporter(map[string]string{
			"TS_SNMP_COMMUNITY": "a",
			"TS_SNMP_SYS_DESCR": strings.Repeat("X", 255),
		})
		cfg, err := LoadSettings(r)
		if err != nil {
			t.Fatal(err)
		}
		d, err := NewDecoy(cfg, r)
		if err != nil {
			t.Fatal(err)
		}

		req := buildSNMPv1v2cReq(snmpVersion2c, "a", snmpPDUGetRequest, 1, oidSysDescr)
		reply := d.ProcessSNMP("10.0.0.21", req, 161)
		if len(reply) > len(req)+snmpMaxReplyMargin {
			t.Fatalf("SNMP amplification violation: reply=%d > req+64=%d", len(reply), len(req)+snmpMaxReplyMargin)
		}
	})

	t.Run("per_source_udp_reply_rate_limiter", func(t *testing.T) {
		r := newFakeReporter(map[string]string{
			"TS_REPLY_RATE_PER_SEC": "3",
		})
		cfg, err := LoadSettings(r)
		if err != nil {
			t.Fatal(err)
		}
		d, err := NewDecoy(cfg, r)
		if err != nil {
			t.Fatal(err)
		}

		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go decoy.ServePacket(ctx, pc, dnsMaxUDPPacketSize, func(from net.Addr, payload []byte) {
			d.HandleDNSPacket(pc, from, payload, 53)
		})

		client, err := net.Dial("udp", pc.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()

		req := buildDNSQueryPacket(0x5555, "rate.corp.local", 1, 1, nil)
		for i := 0; i < 10; i++ {
			if _, err := client.Write(req); err != nil {
				t.Fatal(err)
			}
		}

		received := 0
		buf := make([]byte, 512)
		for i := 0; i < 10; i++ {
			_ = client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			_, err := client.Read(buf)
			if err != nil {
				break
			}
			received++
		}
		if received != 3 {
			t.Fatalf("expected exactly 3 replies under rate limit 3/s, got %d", received)
		}
	})
}

func TestE2EUDPListeners(t *testing.T) {
	r := newFakeReporter(map[string]string{
		"TS_SNMP_COMMUNITY": "public",
	})
	cfg, err := LoadSettings(r)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDecoy(cfg, r)
	if err != nil {
		t.Fatal(err)
	}

	snmpPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go decoy.ServePacket(ctx, snmpPC, snmpMaxPacketSize, func(from net.Addr, payload []byte) {
		d.HandleSNMPPacket(snmpPC, from, payload, 161)
	})

	c, err := net.Dial("udp", snmpPC.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	req := buildSNMPv1v2cReq(snmpVersion2c, "public", snmpPDUGetRequest, 505, oidSysName)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("SNMP UDP read: %v", err)
	}
	if n > len(req)+snmpMaxReplyMargin {
		t.Fatalf("SNMP reply too large: %d > %d", n, len(req)+snmpMaxReplyMargin)
	}
	parsed, err := parseSNMPMessage(buf[:n])
	if err != nil {
		t.Fatalf("parse SNMP reply: %v", err)
	}
	if parsed.PDUTag != snmpPDUResponse || parsed.RequestID != 505 {
		t.Fatalf("unexpected SNMP response: %+v", parsed)
	}
}

func TestDNSMalformedInputsRejected(t *testing.T) {
	cases := [][]byte{
		nil,
		{0, 1, 2},
		// QR=1 (response)
		{0x00, 0x01, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01},
		// QDCOUNT=0
		{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		// Compression pointer in question
		{0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01},
	}
	for i, tc := range cases {
		if _, err := parseDNSQuery(tc); err == nil {
			t.Fatalf("case %d: expected error for malformed DNS packet", i)
		}
	}
}
