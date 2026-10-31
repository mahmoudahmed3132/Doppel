// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

package domain

import "time"

// Location is the GeoIP enrichment of a source (PORTED GeoIP module).
type Location struct {
	CountryCode string  `json:"country_code"`
	Country     string  `json:"country"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Basis       string  `json:"basis"` // "source" | "client_subnet"
	Address     string  `json:"address"`
}

// AssetMatch is the asset-inventory enrichment of a source.
type AssetMatch struct {
	Name        string `json:"name"`
	Criticality string `json:"criticality"`
}

// Technique is one ATT&CK technique reference.
type Technique struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Tactics []string `json:"tactics"`
}

// AttackMapping is the ATT&CK enrichment of a trigger.
type AttackMapping struct {
	Primary   Technique   `json:"primary"`
	Secondary []Technique `json:"secondary,omitempty"`
}

// Enrichment is computed on every read; it is never stored.
type Enrichment struct {
	Attack   *AttackMapping `json:"attack,omitempty"`
	Asset    *AssetMatch    `json:"source_asset,omitempty"`
	Location *Location      `json:"location,omitempty"`
}

// EnrichedEvent is an event with output-only enrichment and display names.
type EnrichedEvent struct {
	Event
	NodeAlias  string     `json:"node_alias"`
	Enrichment Enrichment `json:"enrichment"`
}

// AuditRecord describes one administrative action (§6.10).
type AuditRecord struct {
	Time    time.Time `json:"time"`
	Action  string    `json:"action"`
	Method  string    `json:"method"`
	Route   string    `json:"route"`
	Path    string    `json:"path"`
	Status  int       `json:"status"`
	Outcome string    `json:"outcome"`
	ActorIP string    `json:"actor_ip"`
}

// HoneytokenInventory is the SIEM inventory record of a planted token.
// It never contains the secret.
type HoneytokenInventory struct {
	Time            time.Time `json:"time"`
	HoneytokenID    string    `json:"honeytoken_id"`
	Username        string    `json:"username"`
	PlantedNodeID   string    `json:"planted_node_id"`
	PlantedSensorID string    `json:"planted_sensor_id"`
	CreatedAt       time.Time `json:"created_at"`
	Status          string    `json:"status"`
}

// HubHeartbeat is the periodic SIEM-only Hub health record (§6.6).
type HubHeartbeat struct {
	Time           time.Time `json:"time"`
	Version        string    `json:"version"`
	UptimeSeconds  int64     `json:"uptime_seconds"`
	NodesTotal     int       `json:"nodes_total"`
	NodesOnline    int       `json:"nodes_online"`
	SensorsTotal   int       `json:"sensors_total"`
	SensorsOnline  int       `json:"sensors_online"`
	SIEMQueueDepth int       `json:"siem_queue_depth"`
	SIEMDropped    uint64    `json:"siem_dropped"`
}

// RecordKind discriminates SIEM records.
type RecordKind int

const (
	RecordEvent RecordKind = iota + 1
	RecordAudit
	RecordHoneytoken
	RecordHeartbeat
)

// Record is one unit of SIEM output. Exactly one payload field is set.
type Record struct {
	Kind       RecordKind
	Event      *EnrichedEvent
	Audit      *AuditRecord
	Honeytoken *HoneytokenInventory
	Heartbeat  *HubHeartbeat
}
