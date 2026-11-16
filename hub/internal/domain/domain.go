// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package domain holds the Hub's core types. It has no dependencies on
// storage, transport or the PORTED modules.
package domain

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

// Severity is the event severity enum used everywhere.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Severities lists all severities from lowest to highest.
var Severities = []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

// Valid reports whether s is a known severity.
func (s Severity) Valid() bool { return s.Rank() >= 0 }

// Rank orders severities: info=0 … critical=4, unknown=-1.
func (s Severity) Rank() int {
	for i, v := range Severities {
		if v == s {
			return i
		}
	}
	return -1
}

// Triggers that only the Hub may raise.
const (
	TriggerHoneytokenUsed      = "honeytoken_used"
	TriggerSensorStopped       = "sensor_stopped"
	TriggerSensorHeartbeatLost = "sensor_heartbeat_lost"
	TriggerSensorRecovered     = "sensor_recovered"
	TriggerBeaconTriggered     = "beacon_triggered"
	// TriggerNodeApplyFailed: a node could not apply its desired revision
	// (rolled back or failed), so its decoys may not run as configured.
	TriggerNodeApplyFailed = "node_apply_failed"
)

// IsReservedTrigger reports whether a sensor is forbidden to emit t.
func IsReservedTrigger(t string) bool {
	switch t {
	case TriggerHoneytokenUsed, TriggerSensorStopped, TriggerSensorHeartbeatLost, TriggerSensorRecovered, TriggerNodeApplyFailed:
		return true
	}
	return false
}

// HubSource is the source of Hub-raised liveness events.
const HubSource = "truesignal-hub"

var (
	nodeIDRE   = regexp.MustCompile(`^node-[0-9a-f]{8}$`)
	sensorIDRE = regexp.MustCompile(`^ts-sensor-[a-z0-9]+(-[a-z0-9]+)*$`)
	triggerRE  = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)
)

// ValidNodeID reports whether id has the form node-xxxxxxxx.
func ValidNodeID(id string) bool { return nodeIDRE.MatchString(id) }

// ValidSensorID reports whether id has the form ts-sensor-<kebab-name>.
func ValidSensorID(id string) bool { return len(id) <= 128 && sensorIDRE.MatchString(id) }

// ValidTrigger reports whether t is a snake_case trigger name.
func ValidTrigger(t string) bool { return len(t) <= 64 && triggerRE.MatchString(t) }

// Event is an immutable evidence record plus Hub-owned flags.
type Event struct {
	Seq          int64           `json:"seq"`
	EventID      string          `json:"event_id"`
	NodeID       string          `json:"node_id"`
	SensorID     string          `json:"sensor_id"`
	Trigger      string          `json:"trigger"`
	Severity     Severity        `json:"severity"`
	OccurredAt   time.Time       `json:"occurred_at"`
	ReceivedAt   time.Time       `json:"received_at"`
	Source       string          `json:"source"`
	Target       string          `json:"target"`
	Details      json.RawMessage `json:"details"`
	Read         bool            `json:"read"`
	Archived     bool            `json:"archived"`
	Whitelisted  bool            `json:"whitelisted"`
	KnownScanner bool            `json:"known_scanner"`
	HubRaised    bool            `json:"-"`
}

// Node is a managed host.
type Node struct {
	ID              string     `json:"id"`
	Alias           string     `json:"alias"`
	Tags            []string   `json:"tags"`
	KeyHash         []byte     `json:"-"`
	CreatedAt       time.Time  `json:"created_at"`
	LastSeenAt      *time.Time `json:"last_seen_at"`
	DesiredRevision string     `json:"desired_revision"`
	AppliedRevision string     `json:"applied_revision"`
}

// SensorStatus is the liveness state of a sensor instance.
type SensorStatus string

const (
	StatusPending SensorStatus = "pending"
	StatusOnline  SensorStatus = "online"
	StatusOffline SensorStatus = "offline"
)

// Sensor is a sensor instance on one node.
type Sensor struct {
	NodeID          string            `json:"node_id"`
	ID              string            `json:"id"`
	CatalogueName   string            `json:"catalogue_name"`
	Version         string            `json:"version"`
	Config          map[string]string `json:"config"`
	Silenced        bool              `json:"silenced"`
	Status          SensorStatus      `json:"status"`
	StatusChangedAt *time.Time        `json:"status_changed_at"`
	LastHeartbeatAt *time.Time        `json:"last_heartbeat_at"`
	LastActivityAt  *time.Time        `json:"last_activity_at"`
	EverOnline      bool              `json:"-"`
	StoppedAt       *time.Time        `json:"-"`
	OutageAlertedAt *time.Time        `json:"-"`
	SDKVersion      string            `json:"sdk_version"`
	CreatedAt       time.Time         `json:"created_at"`
}

// ErrNotFound is returned by stores when a record does not exist.
var ErrNotFound = fmt.Errorf("not found")

// ErrConflict is returned by stores on uniqueness violations.
var ErrConflict = fmt.Errorf("conflict")
