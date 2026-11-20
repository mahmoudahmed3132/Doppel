// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package sensor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

// Severity is the event severity of contract v3.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Valid reports whether s is one of the five contract severities.
func (s Severity) Valid() bool {
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

// ParseSeverity converts a string into a Severity.
func ParseSeverity(v string) (Severity, error) {
	s := Severity(v)
	if !s.Valid() {
		return "", fmt.Errorf("invalid severity %q", v)
	}
	return s, nil
}

// Details is the sensor-specific payload of an event. Use Fields for an
// ordered object or Map for an unordered one. nil encodes as {}.
type Details interface {
	encodeDetails() ([]byte, error)
}

// Field is one key/value pair of an ordered Details object.
type Field struct {
	Key   string
	Value any
}

// F is shorthand for constructing a Field.
func F(key string, value any) Field { return Field{Key: key, Value: value} }

// Fields is an ordered Details object; keys keep the given order on the wire.
// A repeated key keeps its first position and its last value.
type Fields []Field

// Map is an unordered Details object.
type Map map[string]any

func (m Map) encodeDetails() ([]byte, error) {
	if m == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(map[string]any(m))
}

func (f Fields) encodeDetails() ([]byte, error) {
	idx := make(map[string]int, len(f))
	keys := make([]string, 0, len(f))
	vals := make([]any, 0, len(f))
	for _, kv := range f {
		if i, ok := idx[kv.Key]; ok {
			vals[i] = kv.Value
			continue
		}
		idx[kv.Key] = len(keys)
		keys = append(keys, kv.Key)
		vals = append(vals, kv.Value)
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		vb, err := json.Marshal(vals[i])
		if err != nil {
			return nil, fmt.Errorf("details field %q: %w", k, err)
		}
		buf.Write(kb)
		buf.WriteByte(':')
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func encodeDetails(d Details) (json.RawMessage, error) {
	if d == nil {
		return json.RawMessage("{}"), nil
	}
	b, err := d.encodeDetails()
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

// Per-event limits of contract v3 (§4.2), applied before an event is queued.
// The Hub enforces the same limits; applying them in the SDK also bounds the
// queue's memory: at most QueueSize events of at most MaxDetailsBytes of
// details plus two MaxFieldBytes fields each (about 66 MiB worst case for the
// default 1000-event queue, a few hundred KiB for typical events).
const (
	MaxFieldBytes   = 256      // source and target, in bytes
	MaxDetailsBytes = 64 << 10 // encoded details object
)

// clampField truncates s to MaxFieldBytes on a UTF-8 rune boundary.
func clampField(s string) string {
	if len(s) <= MaxFieldBytes {
		return s
	}
	cut := MaxFieldBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// maxBatchBytes is the encoded-size budget of one event batch. The Hub
// refuses request bodies over 256 KiB with 413 body_too_large, which is not
// retryable; the 16 KiB margin covers the {"events":[...]} envelope.
const maxBatchBytes = 240 << 10

// eventOverhead bounds the encoded size of an event's fixed parts: key names
// and punctuation (about 110 bytes), event_id (36), severity (at most 8),
// occurred_at (at most 35) and the comma separating it from the next event.
const eventOverhead = 256

// wireSize is an upper bound on the encoded size of e inside a batch.
//
// Details is already encoded JSON (compact and HTML-escaped by encoding/json
// in build), so the client re-emits it byte for byte and it counts at its
// length. The string fields are counted at six times their length because
// json.Marshal can expand a single byte to six (\u003c for <, > and &, control
// bytes, invalid UTF-8; U+2028/U+2029 go from 3 bytes to 6). Source and target
// often carry attacker-supplied text, so a len()-only estimate could be pushed
// past the Hub limit on purpose, getting a whole batch refused and dropped.
func (e *wireEvent) wireSize() int {
	return eventOverhead + len(e.Details) + 6*(len(e.SensorID)+len(e.Trigger)+len(e.Source)+len(e.Target))
}

// wireEvent is the contract v3 event object (§4.2).
type wireEvent struct {
	EventID    string          `json:"event_id"`
	SensorID   string          `json:"sensor_id"`
	Trigger    string          `json:"trigger"`
	Severity   Severity        `json:"severity"`
	OccurredAt string          `json:"occurred_at"`
	Source     string          `json:"source"`
	Target     string          `json:"target"`
	Details    json.RawMessage `json:"details"`
}

type eventBatch struct {
	Events []wireEvent `json:"events"`
}

type heartbeatBody struct {
	SensorID       string `json:"sensor_id"`
	ConfigRevision string `json:"config_revision"`
	SDKVersion     string `json:"sdk_version"`
	DroppedEvents  uint64 `json:"dropped_events,omitempty"`
}

type stoppingBody struct {
	SensorID string `json:"sensor_id"`
	Reason   string `json:"reason"`
}

// ingestResponse is the Hub's reply to an event batch.
type ingestResponse struct {
	OK         bool   `json:"ok"`
	Error      string `json:"error"`
	Message    string `json:"message"`
	Accepted   int    `json:"accepted"`
	Duplicates int    `json:"duplicates"`
	Rejected   []struct {
		Index int    `json:"index"`
		Error string `json:"error"`
	} `json:"rejected"`
}
