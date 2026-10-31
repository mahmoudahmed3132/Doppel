// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

// Package stub provides deliberately minimal stand-ins for the PORTED
// modules, for tests and for running the Hub before the real modules are
// imported. They are NOT production implementations: matching is exact,
// there is no cryptography beyond what tests need, and no GeoIP data.
package stub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/domain"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/ported"
)

// ExactSourceList matches sources by exact string equality, ignoring a
// ":port" suffix on IPv4 sources.
type ExactSourceList struct{}

type exactMatcher map[string]bool

func (m exactMatcher) Match(source string) bool {
	if m[source] {
		return true
	}
	if i := strings.LastIndexByte(source, ':'); i > 0 && strings.Count(source, ":") == 1 {
		return m[source[:i]]
	}
	return false
}

// Parse implements ported.SourceListParser.
func (ExactSourceList) Parse(entries []string) (ported.SourceMatcher, error) {
	m := exactMatcher{}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			return nil, errors.New("empty entry")
		}
		m[e] = true
	}
	return m, nil
}

// TOTP accepts the code fmt.Sprintf("%06d", step%1e6) for the current
// 30-second step (and ±1). Recovery codes are stored as SHA-256 hex.
type TOTP struct{}

func (TOTP) GenerateSecret(account, issuer string) (string, string, error) {
	return "STUBSECRET", fmt.Sprintf("otpauth://totp/%s:%s?secret=STUBSECRET&issuer=%s", issuer, account, issuer), nil
}

// CodeAt returns the stub code for t.
func (TOTP) CodeAt(t time.Time) string { return fmt.Sprintf("%06d", (t.Unix()/30)%1000000) }

func (TOTP) Verify(_ string, code string, lastStep int64, now time.Time) (int64, bool) {
	cur := now.Unix() / 30
	for _, s := range []int64{cur - 1, cur, cur + 1} {
		if fmt.Sprintf("%06d", s%1000000) == code && s > lastStep {
			return s, true
		}
	}
	return 0, false
}

func hashCode(c string) string { h := sha256.Sum256([]byte(c)); return hex.EncodeToString(h[:]) }

func (TOTP) GenerateRecoveryCodes(n int) ([]string, []string, error) {
	var plain, hashed []string
	for i := 0; i < n; i++ {
		c := fmt.Sprintf("recovery-%02d-%d", i, time.Now().UnixNano())
		plain = append(plain, c)
		hashed = append(hashed, hashCode(c))
	}
	return plain, hashed, nil
}

func (TOTP) ConsumeRecoveryCode(hashed []string, code string) ([]string, bool) {
	h := hashCode(code)
	for i, v := range hashed {
		if v == h {
			return append(append([]string{}, hashed[:i]...), hashed[i+1:]...), true
		}
	}
	return hashed, false
}

// Beacons is an in-memory beacon service resolving tokens exactly.
type Beacons struct {
	mu   sync.Mutex
	byID map[string]*ported.Beacon
}

func NewBeacons() *Beacons { return &Beacons{byID: map[string]*ported.Beacon{}} }

// Add registers a beacon (test helper).
func (b *Beacons) Add(bc ported.Beacon) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.byID[bc.ID] = &bc
}

func (b *Beacons) Create(_ context.Context, typ, name, memo string) (ported.Beacon, error) {
	bc := ported.Beacon{ID: fmt.Sprintf("bcn_%d", time.Now().UnixNano()), Token: fmt.Sprintf("tok%d", time.Now().UnixNano()), Type: typ, Name: name, Memo: memo, CreatedAt: time.Now()}
	b.Add(bc)
	return bc, nil
}

func (b *Beacons) Artefact(_ context.Context, id string) (ported.BeaconArtefact, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	bc, ok := b.byID[id]
	if !ok {
		return ported.BeaconArtefact{}, domain.ErrNotFound
	}
	return ported.BeaconArtefact{Filename: bc.ID + ".txt", ContentType: "text/plain", Body: []byte(bc.Token)}, nil
}

func (b *Beacons) Resolve(_ context.Context, token string) (*ported.Beacon, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, bc := range b.byID {
		if bc.Token == token {
			c := *bc
			return &c, nil
		}
	}
	return nil, nil
}

func (b *Beacons) RecordUse(_ context.Context, id string, at time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if bc, ok := b.byID[id]; ok {
		bc.UseCount++
		bc.LastUsedAt = &at
		return nil
	}
	return domain.ErrNotFound
}

func (b *Beacons) Delete(_ context.Context, id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.byID, id)
	return nil
}

func (b *Beacons) List(context.Context) ([]ported.Beacon, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []ported.Beacon
	for _, bc := range b.byID {
		out = append(out, *bc)
	}
	return out, nil
}

// Honeytokens matches when details.username equals a token's username.
type Honeytokens struct {
	mu     sync.Mutex
	tokens []ported.Honeytoken
}

func (h *Honeytokens) Add(t ported.Honeytoken) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tokens = append(h.tokens, t)
}

func (h *Honeytokens) Ensure(_ context.Context, nodeID, sensorID string) (ported.Honeytoken, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, t := range h.tokens {
		if t.PlantedNodeID == nodeID && t.PlantedSensorID == sensorID {
			return t, nil
		}
	}
	t := ported.Honeytoken{ID: fmt.Sprintf("ht_%d", len(h.tokens)+1), Username: "svc_backup", Secret: "stub-secret",
		PlantedNodeID: nodeID, PlantedSensorID: sensorID, Status: "active", CreatedAt: time.Now()}
	h.tokens = append(h.tokens, t)
	return t, nil
}

func (h *Honeytokens) Match(_ context.Context, ev *domain.Event) ([]ported.HoneytokenMatch, error) {
	var d map[string]any
	if err := json.Unmarshal(ev.Details, &d); err != nil {
		return nil, nil
	}
	user, _ := d["username"].(string)
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []ported.HoneytokenMatch
	for _, t := range h.tokens {
		if user != "" && user == t.Username {
			out = append(out, ported.HoneytokenMatch{Token: t, MatchedOn: "username"})
		}
	}
	return out, nil
}

func (h *Honeytokens) RecordUse(context.Context, string, time.Time) error { return nil }

func (h *Honeytokens) List(context.Context) ([]ported.Honeytoken, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]ported.Honeytoken{}, h.tokens...), nil
}

func (h *Honeytokens) Inventory(_ context.Context, now time.Time) ([]domain.HoneytokenInventory, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []domain.HoneytokenInventory
	for _, t := range h.tokens {
		out = append(out, domain.HoneytokenInventory{Time: now, HoneytokenID: t.ID, Username: t.Username,
			PlantedNodeID: t.PlantedNodeID, PlantedSensorID: t.PlantedSensorID, CreatedAt: t.CreatedAt, Status: t.Status})
	}
	return out, nil
}

// ECS renders a flat JSON object. It does NOT implement the ECS contract.
type ECS struct{}

func (ECS) Render(rec domain.Record) (map[string]any, error) {
	var v any
	switch rec.Kind {
	case domain.RecordEvent:
		v = rec.Event
	case domain.RecordAudit:
		v = rec.Audit
	case domain.RecordHoneytoken:
		v = rec.Honeytoken
	case domain.RecordHeartbeat:
		v = rec.Heartbeat
	default:
		return nil, errors.New("unknown record kind")
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	err = json.Unmarshal(b, &m)
	return m, err
}

// RejectAllVerifier refuses every manifest (fail closed).
type RejectAllVerifier struct{}

func (RejectAllVerifier) Verify([]byte, []byte, string, string) error {
	return errors.New("manifest verifier not installed")
}

// AcceptAllVerifier accepts every manifest. Tests only.
type AcceptAllVerifier struct{}

func (AcceptAllVerifier) Verify([]byte, []byte, string, string) error { return nil }

// ---- GeoIP --------------------------------------------------------------------

// Geo locates sources from a fixed table keyed by IP (a ":port" suffix is
// ignored). No GeoIP data is shipped; the real module (§12) is PORTED.
type Geo struct {
	Table    map[string]domain.Location
	Disabled bool
}

func (g Geo) Enabled() bool { return !g.Disabled }

func (g Geo) Locate(source string, _ map[string]any) *domain.Location {
	ip := hostOnly(source)
	l, ok := g.Table[ip]
	if !ok {
		return nil
	}
	l.Basis, l.Address = "source", ip
	return &l
}

func hostOnly(s string) string {
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i > 0 {
			return s[1:i]
		}
	}
	if strings.Count(s, ":") == 1 {
		return s[:strings.IndexByte(s, ':')]
	}
	return s
}

// ---- Asset inventory ------------------------------------------------------------

// Assets accepts a JSON array of {"match": "<exact source>", "name", "criticality"}
// and matches sources exactly. The real inventory module (§12) is PORTED.
type Assets struct{}

type stubAsset struct {
	Match       string `json:"match"`
	Name        string `json:"name"`
	Criticality string `json:"criticality"`
}

func (Assets) Validate(raw json.RawMessage) (json.RawMessage, error) {
	var list []stubAsset
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&list); err != nil {
		return nil, fmt.Errorf("assets: %w", err)
	}
	for i, a := range list {
		if strings.TrimSpace(a.Match) == "" || strings.TrimSpace(a.Name) == "" {
			return nil, fmt.Errorf("assets[%d]: match and name are required", i)
		}
		switch a.Criticality {
		case "low", "medium", "high", "critical":
		default:
			return nil, fmt.Errorf("assets[%d]: criticality must be low, medium, high or critical", i)
		}
	}
	if list == nil {
		list = []stubAsset{}
	}
	return json.Marshal(list)
}

func (Assets) Index(norm json.RawMessage) (ported.AssetIndex, error) {
	var list []stubAsset
	if err := json.Unmarshal(norm, &list); err != nil {
		return nil, err
	}
	ix := assetIndex{}
	for _, a := range list {
		ix[a.Match] = domain.AssetMatch{Name: a.Name, Criticality: a.Criticality}
	}
	return ix, nil
}

type assetIndex map[string]domain.AssetMatch

func (ix assetIndex) Lookup(source string) *domain.AssetMatch {
	if a, ok := ix[hostOnly(source)]; ok {
		return &a
	}
	return nil
}

// ---- ATT&CK -------------------------------------------------------------------

// Attack maps triggers from a fixed table and exports a minimal layer
// (technique id → event count). The real mapping module (§12) is PORTED.
type Attack struct {
	Map map[string]domain.AttackMapping
}

func (a Attack) For(trigger string) *domain.AttackMapping {
	m, ok := a.Map[trigger]
	if !ok {
		return nil
	}
	return &m
}

func (a Attack) NavigatorLayer(events []domain.EnrichedEvent) (json.RawMessage, error) {
	counts := map[string]int{}
	for _, ev := range events {
		if m := a.For(ev.Trigger); m != nil {
			counts[m.Primary.ID]++
		}
	}
	type tech struct {
		TechniqueID string `json:"techniqueID"`
		Score       int    `json:"score"`
	}
	layer := struct {
		Name       string `json:"name"`
		Techniques []tech `json:"techniques"`
	}{Name: "truesignal (stub)", Techniques: []tech{}}
	for id, n := range counts {
		layer.Techniques = append(layer.Techniques, tech{id, n})
	}
	return json.Marshal(layer)
}

// ---- Analytics projection -------------------------------------------------------

// Projection counts the events it was given and echoes its parameters, so
// tests can check mounting, windowing and parameter pass-through.
type Projection struct{ N string }

func (p Projection) Name() string { return p.N }

func (p Projection) Build(_ context.Context, events []domain.EnrichedEvent, params map[string]string) (any, error) {
	return map[string]any{"events": len(events), "params": params}, nil
}

// ---- HTTP SIEM transport ----------------------------------------------------------

// HTTPTransport records documents and returns a scripted outcome.
type HTTPTransport struct {
	mu      sync.Mutex
	Outcome ported.SendOutcome
	Err     error
	Sent    [][]byte
}

func (h *HTTPTransport) Send(_ context.Context, _, _, _ string, document []byte) (ported.SendOutcome, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Sent = append(h.Sent, append([]byte(nil), document...))
	return h.Outcome, h.Err
}

// Every PORTED seam has a stub (§15).
var (
	_ ported.ManifestVerifier  = RejectAllVerifier{}
	_ ported.ManifestVerifier  = AcceptAllVerifier{}
	_ ported.GeoLocator        = Geo{}
	_ ported.AssetInventory    = Assets{}
	_ ported.AttackMapper      = Attack{}
	_ ported.SourceListParser  = ExactSourceList{}
	_ ported.TOTP              = TOTP{}
	_ ported.BeaconService     = (*Beacons)(nil)
	_ ported.HoneytokenService = (*Honeytokens)(nil)
	_ ported.ECSRenderer       = ECS{}
	_ ported.HTTPSIEMTransport = (*HTTPTransport)(nil)
	_ ported.Projection        = Projection{}
)
