// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"testing"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

type discardReporter struct {
	settings map[string]string
}

func (d discardReporter) Setting(name string) (string, bool) {
	v, ok := d.settings[name]
	return v, ok
}

func (discardReporter) ReportSeverity(sensor.Severity, string, string, string, sensor.Details) {}

func FuzzSNMP(f *testing.F) {
	f.Add(buildSNMPv1v2cReq(snmpVersion1, "public", snmpPDUGetRequest, 1, oidSysDescr))
	f.Add(buildSNMPv1v2cReq(snmpVersion2c, "public", snmpPDUGetNextRequest, 2, oidSysGroupPrefix))
	f.Add(buildSNMPv1v2cReq(snmpVersion2c, "private", snmpPDUSetRequest, 3, oidSysName))
	f.Add(buildSNMPv3Req(10, snmpFlagReportable, nil, "", false, snmpPDUGetRequest, 1, oidSysDescr))
	f.Add(buildSNMPv3Req(11, snmpFlagAuth|snmpFlagPriv, []byte{1, 2, 3, 4, 5}, "admin", true, 0, 0))
	f.Add([]byte{0x30, 0x80, 0x00, 0x00}) // indefinite length

	r := discardReporter{settings: map[string]string{
		"TS_CAPTURE_KEY":        testCaptureKey,
		"TS_PASSWORD_CAPTURE":   "hash",
		"TS_SENSOR_ID":          "sen-fuzz",
		"TS_EVENT_COOLDOWN_SEC": "0",
		"TS_SNMP_COMMUNITY":     "public",
	}}
	cfg, err := LoadSettings(r)
	if err != nil {
		f.Fatal(err)
	}
	d, err := NewDecoy(cfg, r)
	if err != nil {
		f.Fatal(err)
	}
	d.eventLimiter = nil
	d.replyLimiter = nil

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseSNMPMessage(data)
		reply := d.ProcessSNMP("127.0.0.1", data, 161)
		if len(reply) > 0 && len(reply) > len(data)+snmpMaxReplyMargin {
			t.Fatalf("SNMP anti-amplification violated: reply=%d > req+64=%d", len(reply), len(data)+snmpMaxReplyMargin)
		}
		if len(reply) > snmpMaxPacketSize {
			t.Fatalf("SNMP reply exceeds max packet size: %d", len(reply))
		}
	})
}

func FuzzDNS(f *testing.F) {
	f.Add(buildDNSQueryPacket(0x1111, "example.com", 1, 1, nil))
	f.Add(buildDNSQueryPacket(0x2222, "corp.local", dnsTypeAXFR, 1, nil))
	f.Add(buildDNSQueryPacket(0x3333, ".", 255, 1, nil))
	f.Add([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01})

	r := discardReporter{settings: map[string]string{
		"TS_CAPTURE_KEY":        testCaptureKey,
		"TS_PASSWORD_CAPTURE":   "hash",
		"TS_SENSOR_ID":          "sen-fuzz",
		"TS_EVENT_COOLDOWN_SEC": "0",
	}}
	cfg, err := LoadSettings(r)
	if err != nil {
		f.Fatal(err)
	}
	d, err := NewDecoy(cfg, r)
	if err != nil {
		f.Fatal(err)
	}
	d.eventLimiter = nil
	d.replyLimiter = nil

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseDNSQuery(data)
		for _, transport := range []string{"udp", "tcp"} {
			reply := d.ProcessDNS("127.0.0.1", data, transport, 53)
			if len(reply) > len(data) {
				t.Fatalf("DNS anti-amplification violated (%s): reply=%d > req=%d", transport, len(reply), len(data))
			}
		}
	})
}
