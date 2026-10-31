// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

// Package syslog formats SIEM records as RFC 5424 messages.
//
// Layout: <PRI>1 TIMESTAMP truesignal truesignal-hub - MSGID [SD] MSG
// where SD is a single structured-data element and MSG is the full record
// as single-line JSON. Nothing attacker-controlled can introduce a line
// break: PARAM-VALUEs replace control characters with spaces and MSG is
// JSON (which escapes all control characters).
package syslog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/domain"
)

const (
	facilityLocal0 = 16
	hostname       = "truesignal"
	appName        = "truesignal-hub"
	maxValueBytes  = 1024
)

// DefaultPEN is the default syslog Private Enterprise Number.
const DefaultPEN = 32473

// Severity per RFC 5424 §6.2.1.
func eventSeverity(s domain.Severity) int {
	switch s {
	case domain.SeverityCritical:
		return 2
	case domain.SeverityHigh:
		return 3
	case domain.SeverityMedium:
		return 4
	case domain.SeverityLow:
		return 5
	default:
		return 6
	}
}

type param struct{ name, value string }

// Format renders rec as one RFC 5424 line without a trailing newline.
func Format(rec domain.Record, pen int) ([]byte, error) {
	var (
		sev    int
		msgID  string
		sdName string
		ts     time.Time
		params []param
		body   any
	)
	switch rec.Kind {
	case domain.RecordEvent:
		e := rec.Event
		if e == nil {
			return nil, fmt.Errorf("event record without event")
		}
		sev, msgID, sdName, ts, body = eventSeverity(e.Severity), "EVENT", "truesignal", e.ReceivedAt, e
		params = eventParams(e)
	case domain.RecordAudit:
		a := rec.Audit
		if a == nil {
			return nil, fmt.Errorf("audit record without audit")
		}
		sev, msgID, sdName, ts, body = 5, "AUDIT", "truesignal-audit", a.Time, a
		params = []param{
			{"action", a.Action}, {"route", a.Method + " " + a.Route}, {"path", a.Path},
			{"status", strconv.Itoa(a.Status)}, {"actor_ip", a.ActorIP},
		}
	case domain.RecordHoneytoken:
		h := rec.Honeytoken
		if h == nil {
			return nil, fmt.Errorf("honeytoken record without honeytoken")
		}
		sev, msgID, sdName, ts, body = 6, "HONEYTOKEN", "truesignal-honeytoken", h.Time, h
		params = []param{
			{"honeytoken_id", h.HoneytokenID}, {"username", h.Username}, {"planted_node_id", h.PlantedNodeID},
			{"planted_sensor_id", h.PlantedSensorID}, {"status", h.Status},
		}
	case domain.RecordHeartbeat:
		h := rec.Heartbeat
		if h == nil {
			return nil, fmt.Errorf("heartbeat record without heartbeat")
		}
		sev, msgID, sdName, ts, body = 6, "HEARTBEAT", "truesignal-hub", h.Time, h
		params = []param{
			{"version", h.Version}, {"uptime_seconds", strconv.FormatInt(h.UptimeSeconds, 10)},
			{"nodes_total", strconv.Itoa(h.NodesTotal)}, {"nodes_online", strconv.Itoa(h.NodesOnline)},
			{"sensors_total", strconv.Itoa(h.SensorsTotal)}, {"sensors_online", strconv.Itoa(h.SensorsOnline)},
			{"siem_queue_depth", strconv.Itoa(h.SIEMQueueDepth)}, {"siem_dropped", strconv.FormatUint(h.SIEMDropped, 10)},
		}
	default:
		return nil, fmt.Errorf("unknown record kind %d", rec.Kind)
	}

	msg, err := singleLineJSON(body)
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "<%d>1 %s %s %s - %s [%s@%d", facilityLocal0*8+sev,
		ts.UTC().Format("2006-01-02T15:04:05.000000Z"), hostname, appName, msgID, sdName, pen)
	for _, p := range params {
		b.WriteByte(' ')
		b.WriteString(p.name)
		b.WriteString(`="`)
		b.WriteString(EscapeParamValue(p.value))
		b.WriteByte('"')
	}
	b.WriteString("] ")
	b.Write(msg)
	return b.Bytes(), nil
}

// eventParams returns the EVENT parameters in their contractual order.
// New parameters may only be appended.
func eventParams(e *domain.EnrichedEvent) []param {
	var technique, tactic, asset, crit, country, basis string
	if m := e.Enrichment.Attack; m != nil {
		technique = m.Primary.ID
		tactic = strings.Join(m.Primary.Tactics, ",")
	}
	if a := e.Enrichment.Asset; a != nil {
		asset, crit = a.Name, a.Criticality
	}
	if l := e.Enrichment.Location; l != nil {
		country, basis = l.CountryCode, l.Basis
	}
	return []param{
		{"event_id", e.EventID},
		{"trigger", e.Trigger},
		{"severity", string(e.Severity)},
		{"source", e.Source},
		{"target", e.Target},
		{"node", e.NodeAlias},
		{"node_id", e.NodeID},
		{"sensor", e.SensorID},
		{"whitelisted", strconv.FormatBool(e.Whitelisted)},
		{"known_scanner", strconv.FormatBool(e.KnownScanner)},
		{"mitre_technique", technique},
		{"mitre_tactic", tactic},
		{"source_asset", asset},
		{"source_asset_criticality", crit},
		{"source_country", country},
		{"source_geo_basis", basis},
	}
}

// EscapeParamValue sanitises a PARAM-VALUE (RFC 5424 §6.3.3): invalid UTF-8
// is replaced, control characters become spaces, the value is truncated to
// 1024 bytes on a rune boundary, then '"', '\' and ']' are escaped.
func EscapeParamValue(v string) string {
	v = strings.ToValidUTF8(v, "�")
	if len(v) > maxValueBytes {
		cut := maxValueBytes
		for cut > 0 && !utf8.RuneStart(v[cut]) {
			cut--
		}
		v = v[:cut]
	}
	var b strings.Builder
	b.Grow(len(v) + 8)
	for _, r := range v {
		switch {
		case r == '"' || r == '\\' || r == ']':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == ' ' || r == ' ':
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func singleLineJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	out := bytes.TrimRight(buf.Bytes(), "\n")
	// encoding/json escapes all control characters and U+2028/2029, so the
	// output cannot contain a raw line break. Verify rather than assume.
	if bytes.ContainsAny(out, "\r\n") {
		return nil, fmt.Errorf("record JSON contains a line break")
	}
	return out, nil
}
