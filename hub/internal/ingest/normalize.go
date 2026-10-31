// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package ingest implements sensor event normalisation (§4.2) and the event
// pipeline (§6.5).
package ingest

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/domain"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/ids"
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
)

// Normalize converts a raw sensor event into a domain event. It never
// trusts sensor input: strings are made valid UTF-8, trimmed and clamped;
// details are re-serialised and size-limited; severities and timestamps are
// sanitised. code is non-empty when the event must be rejected.
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
	target := Clamp(r.Target)
	if target == "" {
		target = "Unknown"
	}
	raw, err := marshalDetails(details)
	if err != nil || len(raw) > MaxDetailsBytes {
		// Only reachable when sensor_time pushed details over the limit.
		fallback := map[string]any{"details_dropped": true}
		if st, ok := details["sensor_time"]; ok {
			fallback["sensor_time"] = st
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
		Target:     target,
		Details:    raw,
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
