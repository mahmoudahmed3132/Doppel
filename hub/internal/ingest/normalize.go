// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package ingest implements sensor event normalisation (§4.2) and the event
// pipeline (§6.5).
package ingest

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ids"
)

// Limits from the contract.
const (
	MaxFieldBytes   = 256
	MaxDetailsBytes = 64 << 10
	MaxFutureSkew   = 24 * time.Hour
)

// Per-event rejection codes.
const (
	CodeInvalidEvent        = "invalid_event"
	CodeInvalidEventID      = "invalid_event_id"
	CodeInvalidTrigger      = "invalid_trigger"
	CodeReservedTrigger     = "reserved_trigger"
	CodeSensorNotRegistered = "sensor_not_registered"
)

// RawEvent is the wire form of a sensor event.
type RawEvent struct {
	EventID    string          `json:"event_id"`
	SensorID   string          `json:"sensor_id"`
	Trigger    string          `json:"trigger"`
	Severity   string          `json:"severity"`
	OccurredAt string          `json:"occurred_at"`
	Source     string          `json:"source"`
	Target     string          `json:"target"`
	Details    json.RawMessage `json:"details"`
	// Drill is the fire-drill flag (contract capability event.drill). nil
	// means the SDK predates the flag; see Normalize for the legacy shim.
	Drill *bool `json:"drill"`
}

// DecodeRawEvent strictly decodes one event object (unknown fields refused).
func DecodeRawEvent(b []byte) (*RawEvent, bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r RawEvent
	if err := dec.Decode(&r); err != nil || dec.More() {
		return nil, false
	}
	return &r, true
}

// Warning describes a normalisation that changed sensor data.
type Warning string

const (
	WarnUnknownSeverity Warning = "unknown_severity"
	WarnTimeReplaced    Warning = "occurred_at_replaced"
	WarnDetailsDropped  Warning = "details_dropped"
	// WarnLegacyDrill: an event without the drill flag whose source is the
	// SDK drill source was treated as a drill (deprecated SDK behaviour).
	WarnLegacyDrill Warning = "legacy_drill_source"
)

// legacyDrills counts events treated as drills by the compatibility shim.
var legacyDrills atomic.Uint64

// LegacyDrills returns how many events the legacy drill shim has flagged
// since the Hub started (deprecation counter, F-001).
func LegacyDrills() uint64 { return legacyDrills.Load() }

// OriginalSeverityKey is the details key holding a drill's sensor-reported
// severity; the stored severity of a drill is always info (F-001).
const OriginalSeverityKey = "original_severity"

// Normalize converts a raw sensor event into a domain event. It never
// trusts sensor input: strings are made valid UTF-8, trimmed and clamped;
// details are re-serialised and size-limited; severities and timestamps are
// sanitised. code is non-empty when the event must be rejected.
//
// Fire drills (F-001): an event is a drill when it carries "drill": true, or
// when it has no drill key at all (an SDK older than capability event.drill)
// and its source is domain.DrillSource. An SDK that knows the flag always
// sends the key, so an attacker-chosen source cannot turn its events into
// drills. A drill is stored with severity info; the sensor's severity is
// kept in details.original_severity.
func Normalize(r *RawEvent, nodeID string, now time.Time) (ev *domain.Event, warns []Warning, code string) {
	eventID, ok := ids.NormalizeUUIDv7(r.EventID)
	if !ok {
		return nil, nil, CodeInvalidEventID
	}
	trigger := Clamp(r.Trigger)
	if !domain.ValidTrigger(trigger) {
		return nil, nil, CodeInvalidTrigger
	}
	if domain.IsReservedTrigger(trigger) {
		return nil, nil, CodeReservedTrigger
	}
	sensorID := Clamp(r.SensorID)
	if !domain.ValidSensorID(sensorID) {
		return nil, nil, CodeSensorNotRegistered
	}

	details, dropped := normalizeDetails(r.Details)
	if dropped {
		warns = append(warns, WarnDetailsDropped)
	}

	sev := domain.Severity(strings.ToLower(strings.TrimSpace(r.Severity)))
	if !sev.Valid() {
		sev = domain.SeverityMedium
		warns = append(warns, WarnUnknownSeverity)
	}

	occurred, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(r.OccurredAt))
	if err != nil || occurred.After(now.Add(MaxFutureSkew)) {
		occurred = now
		details["sensor_time"] = Clamp(r.OccurredAt)
		warns = append(warns, WarnTimeReplaced)
	}

	source := Clamp(r.Source)
	if source == "" {
		source = "Unknown"
	}
	sourceIP, sourcePort, sourceKind := domain.ParseSource(source)
	drill := r.Drill != nil && *r.Drill
	if r.Drill == nil && source == domain.DrillSource {
		drill = true
		legacyDrills.Add(1)
		warns = append(warns, WarnLegacyDrill)
	}
	if drill {
		details[OriginalSeverityKey] = string(sev)
		sev = domain.SeverityInfo
	}
	target := Clamp(r.Target)
	if target == "" {
		target = "Unknown"
	}
	raw, err := marshalDetails(details)
	if err != nil || len(raw) > MaxDetailsBytes {
		// Only reachable when sensor_time pushed details over the limit.
		fallback := map[string]any{"details_dropped": true}
		for _, k := range []string{"sensor_time", OriginalSeverityKey} {
			if v, ok := details[k]; ok {
				fallback[k] = v
			}
		}
		raw, _ = marshalDetails(fallback)
		if !dropped {
			warns = append(warns, WarnDetailsDropped)
		}
	}
	return &domain.Event{
		EventID:    eventID,
		NodeID:     nodeID,
		SensorID:   sensorID,
		Trigger:    trigger,
		Severity:   sev,
		OccurredAt: occurred.UTC(),
		ReceivedAt: now.UTC(),
		Source:     source,
		SourceIP:   sourceIP,
		SourcePort: sourcePort,
		SourceKind: sourceKind,
		Labels:     domain.SourceLabels(sourceIP),
		Target:     target,
		Details:    raw,
		Drill:      drill,
	}, warns, ""
}

// Clamp makes s valid UTF-8 (invalid sequences become U+FFFD), trims
// surrounding space, and truncates it to MaxFieldBytes on a rune boundary.
func Clamp(s string) string {
	s = strings.TrimSpace(strings.ToValidUTF8(s, "�"))
	if len(s) <= MaxFieldBytes {
		return s
	}
	cut := MaxFieldBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return strings.TrimSpace(s[:cut])
}

// normalizeDetails decodes the details object. Anything that is not a JSON
// object of at most MaxDetailsBytes after re-serialisation is replaced with
// {"details_dropped": true}.
func normalizeDetails(raw json.RawMessage) (map[string]any, bool) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return map[string]any{}, false
	}
	m, err := DecodeDetails(raw)
	if err == nil {
		var b []byte
		b, err = marshalDetails(m)
		if err == nil && len(b) <= MaxDetailsBytes {
			return m, false
		}
	}
	return map[string]any{"details_dropped": true}, true
}

// DecodeDetails decodes a details object preserving number precision.
// Invalid UTF-8 inside strings is replaced by the JSON decoder.
func DecodeDetails(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errTrailing
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

type detailsError string

func (e detailsError) Error() string { return string(e) }

const errTrailing = detailsError("trailing data after details object")

func marshalDetails(m map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
