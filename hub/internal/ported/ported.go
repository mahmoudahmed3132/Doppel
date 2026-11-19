// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package ported declares the integration seams for the modules marked
// PORTED in specification §12. The owner supplies the implementations; this
// repository contains only the interfaces, minimal test stubs (package
// ported/stub) and the wiring around them.
//
// Implementations must be safe for concurrent use.
package ported

import (
	"context"
	"encoding/json"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
)

// ManifestVerifier verifies the detached Sigstore bundle of a sensor
// manifest. It is configured with the signer repository and an optional
// trusted-root file. A nil error means the manifest bytes are authentic for
// that sensor name and version and may be parsed.
type ManifestVerifier interface {
	Verify(manifest, bundle []byte, sensorName, version string) error
}

// GeoLocator resolves a source to a location. details is the event's
// decoded details object (DNS beacons carry details.client_subnet).
// Locate returns nil when no location is known.
type GeoLocator interface {
	Enabled() bool
	Locate(source string, details map[string]any) *domain.Location
}

// AssetInventory validates the asset inventory and builds lookup indexes.
// The inventory is stored as one JSON settings value.
type AssetInventory interface {
	// Validate returns the normalised inventory or a validation error
	// suitable for an API response.
	Validate(raw json.RawMessage) (json.RawMessage, error)
	// Index builds a lookup index over a normalised inventory.
	Index(normalised json.RawMessage) (AssetIndex, error)
}

// AssetIndex looks up the asset a source belongs to.
type AssetIndex interface {
	Lookup(source string) *domain.AssetMatch
}

// AttackMapper maps triggers to MITRE ATT&CK.
type AttackMapper interface {
	For(trigger string) *domain.AttackMapping
	// NavigatorLayer renders an ATT&CK Navigator layer for the events.
	NavigatorLayer(events []domain.EnrichedEvent) (json.RawMessage, error)
}

// SourceListParser parses a whitelist or known-scanner list (one IP, CIDR
// or exact name per entry).
type SourceListParser interface {
	Parse(entries []string) (SourceMatcher, error)
}

// SourceMatcher reports whether a source matches a parsed list.
type SourceMatcher interface {
	Match(source string) bool
}

// TOTP is the RFC 6238 and recovery-code core.
type TOTP interface {
	// GenerateSecret returns a new base32 secret and its otpauth URI.
	GenerateSecret(accountName, issuer string) (secret, otpauthURI string, err error)
	// Verify checks code against secret at now. lastStep is the last
	// accepted time step; a code for a step ≤ lastStep must be refused
	// (replay protection). On success it returns the accepted step.
	Verify(secret, code string, lastStep int64, now time.Time) (step int64, ok bool)
	// GenerateRecoveryCodes returns n codes in clear (shown once) and
	// their hashed forms (stored).
	GenerateRecoveryCodes(n int) (plain, hashed []string, err error)
	// ConsumeRecoveryCode verifies code against hashed codes. On success
	// it returns the remaining hashed codes without the consumed one.
	ConsumeRecoveryCode(hashed []string, code string) (remaining []string, ok bool)
}

// Beacon is a token embedded in a DNS name, web bug or kubeconfig.
type Beacon struct {
	ID         string     `json:"id"`
	Token      string     `json:"-"`
	Type       string     `json:"type"`
	Name       string     `json:"name"`
	Memo       string     `json:"memo"`
	Domain     string     `json:"domain"`
	CreatedAt  time.Time  `json:"created_at"`
	UseCount   int64      `json:"use_count"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

// BeaconStore is the persistence the beacon service needs; the Hub
// implements it.
type BeaconStore interface {
	InsertBeacon(ctx context.Context, b Beacon) error
	BeaconByToken(ctx context.Context, token string) (*Beacon, error) // nil, nil when unknown
	ListBeacons(ctx context.Context) ([]Beacon, error)
	DeleteBeacon(ctx context.Context, id string) error
	IncrementBeaconUse(ctx context.Context, id string, at time.Time) error
}

// BeaconArtefact is a downloadable file for a beacon.
type BeaconArtefact struct {
	Filename    string
	ContentType string
	Body        []byte
}

// BeaconService is the PORTED beacon logic. It is constructed with a
// BeaconStore and the beacon master key from settings.
type BeaconService interface {
	Create(ctx context.Context, typ, name, memo string) (Beacon, error)
	Artefact(ctx context.Context, id string) (BeaconArtefact, error)
	Resolve(ctx context.Context, token string) (*Beacon, error) // nil, nil when unknown
	RecordUse(ctx context.Context, id string, at time.Time) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context) ([]Beacon, error)
}

// Honeytoken is a fabricated credential planted by one File Canary.
type Honeytoken struct {
	ID              string     `json:"id"`
	Username        string     `json:"username"`
	Secret          string     `json:"-"`
	PlantedNodeID   string     `json:"planted_node_id"`
	PlantedSensorID string     `json:"planted_sensor_id"`
	Status          string     `json:"status"`
	CreatedAt       time.Time  `json:"created_at"`
	UseCount        int64      `json:"use_count"`
	LastUsedAt      *time.Time `json:"last_used_at"`
}

// HoneytokenStore is the persistence the honeytoken service needs.
type HoneytokenStore interface {
	InsertHoneytoken(ctx context.Context, h Honeytoken) error
	HoneytokenForSensor(ctx context.Context, nodeID, sensorID string) (*Honeytoken, error) // nil, nil when none
	ListHoneytokens(ctx context.Context) ([]Honeytoken, error)
	IncrementHoneytokenUse(ctx context.Context, id string, at time.Time) error
}

// HoneytokenMatch is one honeytoken credential seen in an event.
type HoneytokenMatch struct {
	Token     Honeytoken
	MatchedOn string // e.g. "username", "password_hmac"
	Protocol  string
	DstPort   int
}

// CaptureKeyFunc derives the per-node capture hash key.
type CaptureKeyFunc func(nodeID string) []byte

// HoneytokenService is the PORTED honeytoken logic, constructed with a
// HoneytokenStore and a CaptureKeyFunc.
type HoneytokenService interface {
	// Ensure returns the credential for a File Canary instance, creating
	// it on first call.
	Ensure(ctx context.Context, nodeID, sensorID string) (Honeytoken, error)
	Match(ctx context.Context, ev *domain.Event) ([]HoneytokenMatch, error)
	RecordUse(ctx context.Context, id string, at time.Time) error
	List(ctx context.Context) ([]Honeytoken, error)
	Inventory(ctx context.Context, now time.Time) ([]domain.HoneytokenInventory, error)
}

// SendOutcome classifies a SIEM delivery attempt.
type SendOutcome int

const (
	SendSuccess SendOutcome = iota
	SendTransient
	SendTerminal
)

// ECSRenderer renders SIEM records as ECS JSON objects. The field contract
// is owned by the PORTED renderer and published in docs/siem-integration.md.
type ECSRenderer interface {
	Render(rec domain.Record) (map[string]any, error)
}

// HTTPSIEMTransport delivers one ECS document to an HTTP SIEM
// ("elastic" or "logscale"). It must use https only and never follow
// redirects.
type HTTPSIEMTransport interface {
	Send(ctx context.Context, protocol, address, token string, document []byte) (SendOutcome, error)
}

// Projection is one PORTED analytics projection (insights, sources, ATT&CK
// matrix, attack path, geo map, report).
type Projection interface {
	Name() string
	Build(ctx context.Context, events []domain.EnrichedEvent, params map[string]string) (any, error)
}

type windowDaysKey struct{}

// WithWindowDays attaches the Hub's projection window length (in days) to ctx
// so projections can report the window without adding "days" to pass-through
// query parameters.
func WithWindowDays(ctx context.Context, days int) context.Context {
	return context.WithValue(ctx, windowDaysKey{}, days)
}

// WindowDays returns the Hub's projection window length in days from ctx, or 0
// when not set.
func WindowDays(ctx context.Context) int {
	if ctx == nil {
		return 0
	}
	days, _ := ctx.Value(windowDaysKey{}).(int)
	return days
}
