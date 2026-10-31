// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

// Package fleet manages nodes and their sensor instances (§6.4 Nodes and
// Sensors). Every change to a node's sensor set is rendered by the compose
// compiler before it is saved (§6.12 rule 11): an invalid change is
// refused, never stored, and the node's desired revision always matches
// the saved sensor set.
package fleet

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/domain"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/ids"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/nodekey"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/semver"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/store"
)

// Limits on admin input.
const (
	MaxAliasRunes   = 64
	MaxTags         = 32
	MaxTagBytes     = 32
	MaxConfigKeys   = 64
	MaxConfigValue  = 4096
	NodeOnlineAfter = 90 * time.Second // three SDK heartbeat intervals
)

// Rendered is the compose compiler's output for one node.
type Rendered struct {
	Compose  []byte
	Revision string
	Warnings []string
}

// RenderOptions control rendering.
type RenderOptions struct {
	// Redact replaces injected secrets (node key, capture key, honeytoken,
	// beacon key) with placeholders. Admin previews are always redacted;
	// only the node-authenticated fetch by the CLI gets real values. The
	// revision does not depend on this option.
	Redact bool
}

// Compiler renders a node's compose file from its sensor instances (§6.12).
// It returns a *RenderError for every rule violation.
type Compiler interface {
	Render(ctx context.Context, node domain.Node, sensors []domain.Sensor, opts RenderOptions) (Rendered, error)
}

// RenderError is a compose rule violation. Status is 422, or 409 for
// port conflicts.
type RenderError struct {
	Status   int
	Code     string
	Message  string
	SensorID string
}

func (e *RenderError) Error() string { return e.Code + ": " + e.Message }

// Catalogue answers questions about available sensor manifests (§6.7).
type Catalogue interface {
	// Latest returns the newest non-deprecated version of a sensor.
	Latest(ctx context.Context, name string) (string, bool)
	// SecretKeys returns the configuration keys a manifest marks secret;
	// ok is false when the manifest is unknown or unverified.
	SecretKeys(ctx context.Context, name, version string) (keys []string, ok bool)
}

// KeyCache is the node-key authentication cache.
type KeyCache interface {
	Invalidate(nodeID string)
}

// Errors.
var (
	ErrInvalid              = errors.New("invalid request")
	ErrCompilerUnavailable  = errors.New("compose compiler not available")
	ErrCatalogueUnavailable = errors.New("sensor catalogue not available")
	ErrSensorExists         = errors.New("a sensor with this id already exists on the node")
)

// InputError carries a field-level validation message.
type InputError struct{ Message string }

func (e *InputError) Error() string { return e.Message }
func (e *InputError) Unwrap() error { return ErrInvalid }

func invalid(format string, a ...any) error { return &InputError{Message: fmt.Sprintf(format, a...)} }

// Store is the persistence fleet needs.
type Store interface {
	CreateNode(ctx context.Context, n *domain.Node) error
	Node(ctx context.Context, id string) (*domain.Node, error)
	Nodes(ctx context.Context) ([]domain.Node, error)
	UpdateNodeMeta(ctx context.Context, id, alias string, tags []string) error
	SetNodeKeyHash(ctx context.Context, id string, hash []byte) error
	DeleteNode(ctx context.Context, id string) error
	Sensor(ctx context.Context, nodeID, id string) (*domain.Sensor, error)
	Sensors(ctx context.Context, nodeID string) ([]domain.Sensor, error)
	SetSensorSilenced(ctx context.Context, nodeID, id string, v bool) error
	ApplySensorChanges(ctx context.Context, nodeID string, c store.SensorChanges) error
}

// Service is the fleet service.
type Service struct {
	Store     Store
	Compiler  Compiler  // nil until the compose compiler is installed
	Catalogue Catalogue // nil until the catalogue is installed
	Keys      KeyCache
	Log       *slog.Logger
	Now       func() time.Time

	mu sync.Mutex // serialises read-render-save of sensor sets
}

// --- validation ---------------------------------------------------------

var (
	tagRE       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]*$`)
	kebabRE     = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	configKeyRE = regexp.MustCompile(`^TS_[A-Z0-9]+(_[A-Z0-9]+)*$`)
)

func validAlias(a string) (string, error) {
	a = strings.TrimSpace(a)
	if a == "" || !utf8.ValidString(a) || utf8.RuneCountInString(a) > MaxAliasRunes {
		return "", invalid("alias must be 1 to %d characters", MaxAliasRunes)
	}
	for _, r := range a {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return "", invalid("alias must not contain control characters")
		}
	}
	return a, nil
}

func validTags(tags []string) ([]string, error) {
	if len(tags) > MaxTags {
		return nil, invalid("at most %d tags", MaxTags)
	}
	seen := map[string]bool{}
	out := []string{}
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if len(t) == 0 || len(t) > MaxTagBytes || !tagRE.MatchString(t) {
			return nil, invalid("tag %q must be 1 to %d characters of A-Z a-z 0-9 _ . : -", truncate(t, 40), MaxTagBytes)
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}

// validConfig checks the shape of user configuration. Whether a key is
// declared by the manifest, reserved, or valid for its type is decided by
// the compose compiler.
func validConfig(cfg map[string]string) error {
	if len(cfg) > MaxConfigKeys {
		return invalid("at most %d configuration keys", MaxConfigKeys)
	}
	for k, v := range cfg {
		if !configKeyRE.MatchString(k) || len(k) > 64 {
			return invalid("configuration key %q must match TS_[A-Z0-9_]+", truncate(k, 70))
		}
		if len(v) > MaxConfigValue || !utf8.ValidString(v) || strings.ContainsRune(v, 0) {
			return invalid("configuration value of %s must be valid UTF-8 of at most %d bytes", k, MaxConfigValue)
		}
	}
	return nil
}

// SensorIDFor builds the instance id from an instance name.
func SensorIDFor(name string) string { return "ts-sensor-" + name }

// --- nodes --------------------------------------------------------------

// NodeHealth summarises a node for lists.
type NodeHealth struct {
	Online         bool `json:"online"`
	InSync         bool `json:"in_sync"`
	SensorsTotal   int  `json:"sensors_total"`
	SensorsOnline  int  `json:"sensors_online"`
	SensorsOffline int  `json:"sensors_offline"`
	SensorsPending int  `json:"sensors_pending"`
}

// NodeSummary is a node with its health.
type NodeSummary struct {
	domain.Node
	Health NodeHealth `json:"health"`
}

func (s *Service) health(n domain.Node, sensors []domain.Sensor) NodeHealth {
	h := NodeHealth{
		Online:       n.LastSeenAt != nil && s.Now().Sub(*n.LastSeenAt) <= NodeOnlineAfter,
		InSync:       n.DesiredRevision != "" && n.DesiredRevision == n.AppliedRevision,
		SensorsTotal: len(sensors),
	}
	for _, sn := range sensors {
		switch sn.Status {
		case domain.StatusOnline:
			h.SensorsOnline++
		case domain.StatusOffline:
			h.SensorsOffline++
		default:
			h.SensorsPending++
		}
	}
	return h
}

// ListNodes returns all nodes with health summaries.
func (s *Service) ListNodes(ctx context.Context) ([]NodeSummary, error) {
	nodes, err := s.Store.Nodes(ctx)
	if err != nil {
		return nil, err
	}
	all, err := s.Store.Sensors(ctx, "")
	if err != nil {
		return nil, err
	}
	byNode := map[string][]domain.Sensor{}
	for _, sn := range all {
		byNode[sn.NodeID] = append(byNode[sn.NodeID], sn)
	}
	out := make([]NodeSummary, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, NodeSummary{Node: n, Health: s.health(n, byNode[n.ID])})
	}
	return out, nil
}

// SensorView is a sensor instance as shown to the admin: secret values are
// masked and update availability is computed from the catalogue.
type SensorView struct {
	domain.Sensor
	ConfigMasked    []string `json:"config_masked"`
	LatestVersion   string   `json:"latest_version,omitempty"`
	UpdateAvailable bool     `json:"update_available"`
}

// MaskedValue replaces secret configuration values in responses.
const MaskedValue = "********"

func (s *Service) view(ctx context.Context, sn domain.Sensor) SensorView {
	v := SensorView{Sensor: sn, ConfigMasked: []string{}}
	cfg := make(map[string]string, len(sn.Config))
	var secret map[string]bool
	allSecret := true
	if s.Catalogue != nil {
		if keys, ok := s.Catalogue.SecretKeys(ctx, sn.CatalogueName, sn.Version); ok {
			allSecret = false
			secret = map[string]bool{}
			for _, k := range keys {
				secret[k] = true
			}
		}
		if latest, ok := s.Catalogue.Latest(ctx, sn.CatalogueName); ok {
			v.LatestVersion = latest
			v.UpdateAvailable = semverLess(sn.Version, latest)
		}
	}
	for k, val := range sn.Config {
		// Without a verified manifest we cannot tell secrets apart: mask all.
		if allSecret || secret[k] {
			cfg[k] = MaskedValue
			v.ConfigMasked = append(v.ConfigMasked, k)
		} else {
			cfg[k] = val
		}
	}
	sort.Strings(v.ConfigMasked)
	v.Config = cfg
	return v
}

// NodeDetail is one node with its sensors.
type NodeDetail struct {
	NodeSummary
	Sensors []SensorView `json:"sensors"`
}

// GetNode returns a node with its sensors.
func (s *Service) GetNode(ctx context.Context, id string) (*NodeDetail, error) {
	n, err := s.Store.Node(ctx, id)
	if err != nil {
		return nil, err
	}
	sensors, err := s.Store.Sensors(ctx, id)
	if err != nil {
		return nil, err
	}
	d := &NodeDetail{NodeSummary: NodeSummary{Node: *n, Health: s.health(*n, sensors)}, Sensors: []SensorView{}}
	for _, sn := range sensors {
		d.Sensors = append(d.Sensors, s.view(ctx, sn))
	}
	return d, nil
}

// CreateNode creates a node and returns it with its key (shown once).
func (s *Service) CreateNode(ctx context.Context, alias string, tags []string) (*domain.Node, string, error) {
	alias, err := validAlias(alias)
	if err != nil {
		return nil, "", err
	}
	if tags, err = validTags(tags); err != nil {
		return nil, "", err
	}
	for attempt := 0; attempt < 5; attempt++ {
		key, hash := nodekey.Generate()
		n := &domain.Node{ID: ids.NodeID(), Alias: alias, Tags: tags, KeyHash: hash, CreatedAt: s.Now().UTC()}
		err := s.Store.CreateNode(ctx, n)
		if errors.Is(err, domain.ErrConflict) {
			continue // id collision (32-bit space): retry with a new id
		}
		if err != nil {
			return nil, "", err
		}
		return n, key, nil
	}
	return nil, "", errors.New("could not allocate a unique node id")
}

// UpdateNode changes alias and/or tags; nil leaves a field unchanged.
func (s *Service) UpdateNode(ctx context.Context, id string, alias *string, tags *[]string) (*domain.Node, error) {
	n, err := s.Store.Node(ctx, id)
	if err != nil {
		return nil, err
	}
	a, t := n.Alias, n.Tags
	if alias != nil {
		if a, err = validAlias(*alias); err != nil {
			return nil, err
		}
	}
	if tags != nil {
		if t, err = validTags(*tags); err != nil {
			return nil, err
		}
	}
	if err := s.Store.UpdateNodeMeta(ctx, id, a, t); err != nil {
		return nil, err
	}
	return s.Store.Node(ctx, id)
}

// RotateKey replaces the node key. The old key stops working immediately.
func (s *Service) RotateKey(ctx context.Context, id string) (string, error) {
	key, hash := nodekey.Generate()
	if err := s.Store.SetNodeKeyHash(ctx, id, hash); err != nil {
		return "", err
	}
	s.Keys.Invalidate(id) // after the database change; see nodekey
	return key, nil
}

// DeleteNode removes the node and its sensor instances; events are kept.
// The node key stops working immediately.
func (s *Service) DeleteNode(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.Store.DeleteNode(ctx, id); err != nil {
		return err
	}
	s.Keys.Invalidate(id)
	return nil
}

// --- sensors ------------------------------------------------------------

// SensorSpec is an admin request to add a sensor.
type SensorSpec struct {
	Name          string // instance name (kebab); default: catalogue name
	CatalogueName string
	Version       string
	Config        map[string]string
}

func (s *Service) render(ctx context.Context, n domain.Node, sensors []domain.Sensor) (Rendered, error) {
	if s.Compiler == nil {
		return Rendered{}, ErrCompilerUnavailable
	}
	sort.Slice(sensors, func(i, j int) bool { return sensors[i].ID < sensors[j].ID })
	return s.Compiler.Render(ctx, n, sensors, RenderOptions{Redact: true})
}

// plan loads a node and its sensors, applies mutate to a copy, renders the
// result and, unless dryRun, saves changes and the new revision atomically.
func (s *Service) plan(ctx context.Context, nodeID string, dryRun bool,
	mutate func(current map[string]domain.Sensor) (store.SensorChanges, error)) (Rendered, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.Store.Node(ctx, nodeID)
	if err != nil {
		return Rendered{}, err
	}
	list, err := s.Store.Sensors(ctx, nodeID)
	if err != nil {
		return Rendered{}, err
	}
	current := make(map[string]domain.Sensor, len(list))
	for _, sn := range list {
		current[sn.ID] = sn
	}
	changes, err := mutate(current)
	if err != nil {
		return Rendered{}, err
	}
	next := make(map[string]domain.Sensor, len(current))
	for id, sn := range current {
		next[id] = sn
	}
	for _, id := range changes.Delete {
		delete(next, id)
	}
	for _, sn := range append(append([]domain.Sensor{}, changes.Create...), changes.Update...) {
		next[sn.ID] = sn
	}
	set := make([]domain.Sensor, 0, len(next))
	for _, sn := range next {
		set = append(set, sn)
	}
	r, err := s.render(ctx, *n, set)
	if err != nil {
		return Rendered{}, err
	}
	if dryRun {
		return r, nil
	}
	changes.Desired = r.Revision
	if err := s.Store.ApplySensorChanges(ctx, nodeID, changes); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return Rendered{}, ErrSensorExists
		}
		return Rendered{}, err
	}
	return r, nil
}

func (s *Service) newSensor(nodeID string, spec SensorSpec) (domain.Sensor, error) {
	name := strings.TrimSpace(spec.Name)
	if name == "" {
		name = spec.CatalogueName
	}
	if !kebabRE.MatchString(spec.CatalogueName) || len(spec.CatalogueName) > 64 {
		return domain.Sensor{}, invalid("catalogue_name must be a kebab-case sensor name")
	}
	if !kebabRE.MatchString(name) || len(name) > 64 {
		return domain.Sensor{}, invalid("name must be kebab-case, at most 64 characters")
	}
	if !semver.Valid(spec.Version) {
		return domain.Sensor{}, invalid("version must be a semantic version")
	}
	if err := validConfig(spec.Config); err != nil {
		return domain.Sensor{}, err
	}
	cfg := map[string]string{}
	for k, v := range spec.Config {
		cfg[k] = v
	}
	return domain.Sensor{NodeID: nodeID, ID: SensorIDFor(name), CatalogueName: spec.CatalogueName, Version: spec.Version,
		Config: cfg, Status: domain.StatusPending, CreatedAt: s.Now().UTC()}, nil
}

// AddSensor validates, renders and saves a new sensor instance.
func (s *Service) AddSensor(ctx context.Context, nodeID string, spec SensorSpec) (*SensorView, Rendered, error) {
	sn, err := s.newSensor(nodeID, spec)
	if err != nil {
		return nil, Rendered{}, err
	}
	r, err := s.plan(ctx, nodeID, false, func(cur map[string]domain.Sensor) (store.SensorChanges, error) {
		if _, exists := cur[sn.ID]; exists {
			return store.SensorChanges{}, ErrSensorExists
		}
		return store.SensorChanges{Create: []domain.Sensor{sn}}, nil
	})
	if err != nil {
		return nil, Rendered{}, err
	}
	v := s.view(ctx, sn)
	return &v, r, nil
}

// ConfigPatch replaces a sensor's configuration: a nil value keeps the
// current value of that key (so masked secrets need not be re-sent), an
// absent key is removed.
type ConfigPatch map[string]*string

func applyPatch(current map[string]string, patch ConfigPatch) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range patch {
		if v == nil {
			old, ok := current[k]
			if !ok {
				return nil, invalid("configuration key %q has no current value to keep", truncate(k, 70))
			}
			out[k] = old
			continue
		}
		out[k] = *v
	}
	return out, validConfig(out)
}

// UpdateSensorConfig replaces a sensor's configuration after rendering.
func (s *Service) UpdateSensorConfig(ctx context.Context, nodeID, sensorID string, patch ConfigPatch) (*SensorView, Rendered, error) {
	var updated domain.Sensor
	r, err := s.plan(ctx, nodeID, false, func(cur map[string]domain.Sensor) (store.SensorChanges, error) {
		sn, ok := cur[sensorID]
		if !ok {
			return store.SensorChanges{}, domain.ErrNotFound
		}
		cfg, err := applyPatch(sn.Config, patch)
		if err != nil {
			return store.SensorChanges{}, err
		}
		sn.Config = cfg
		updated = sn
		return store.SensorChanges{Update: []domain.Sensor{sn}}, nil
	})
	if err != nil {
		return nil, Rendered{}, err
	}
	v := s.view(ctx, updated)
	return &v, r, nil
}

// UpgradeSensor changes a sensor's version after rendering. An empty
// version means the catalogue's latest.
func (s *Service) UpgradeSensor(ctx context.Context, nodeID, sensorID, version string) (*SensorView, Rendered, error) {
	var updated domain.Sensor
	r, err := s.plan(ctx, nodeID, false, func(cur map[string]domain.Sensor) (store.SensorChanges, error) {
		sn, ok := cur[sensorID]
		if !ok {
			return store.SensorChanges{}, domain.ErrNotFound
		}
		v := version
		if v == "" {
			if s.Catalogue == nil {
				return store.SensorChanges{}, ErrCatalogueUnavailable
			}
			latest, ok := s.Catalogue.Latest(ctx, sn.CatalogueName)
			if !ok {
				return store.SensorChanges{}, invalid("no available version of %s in the catalogue", sn.CatalogueName)
			}
			v = latest
		}
		if !semver.Valid(v) {
			return store.SensorChanges{}, invalid("version must be a semantic version")
		}
		sn.Version = v
		updated = sn
		return store.SensorChanges{Update: []domain.Sensor{sn}}, nil
	})
	if err != nil {
		return nil, Rendered{}, err
	}
	v := s.view(ctx, updated)
	return &v, r, nil
}

// UpgradeNode moves every sensor of a node to its latest catalogue version
// in one rendered, atomic change. It returns the ids that changed.
func (s *Service) UpgradeNode(ctx context.Context, nodeID string) ([]string, Rendered, error) {
	if s.Catalogue == nil {
		return nil, Rendered{}, ErrCatalogueUnavailable
	}
	var changed []string
	r, err := s.plan(ctx, nodeID, false, func(cur map[string]domain.Sensor) (store.SensorChanges, error) {
		var c store.SensorChanges
		for _, sn := range cur {
			latest, ok := s.Catalogue.Latest(ctx, sn.CatalogueName)
			if ok && semverLess(sn.Version, latest) {
				sn.Version = latest
				c.Update = append(c.Update, sn)
				changed = append(changed, sn.ID)
			}
		}
		return c, nil
	})
	sort.Strings(changed)
	return changed, r, err
}

// DeleteSensor removes a sensor instance; its events are kept.
func (s *Service) DeleteSensor(ctx context.Context, nodeID, sensorID string) (Rendered, error) {
	r, err := s.plan(ctx, nodeID, false, func(cur map[string]domain.Sensor) (store.SensorChanges, error) {
		if _, ok := cur[sensorID]; !ok {
			return store.SensorChanges{}, domain.ErrNotFound
		}
		return store.SensorChanges{Delete: []string{sensorID}}, nil
	})
	if errors.Is(err, ErrCompilerUnavailable) {
		// Removing a decoy must always be possible; the desired revision
		// becomes unknown until the compiler can render again.
		s.mu.Lock()
		defer s.mu.Unlock()
		if _, err := s.Store.Sensor(ctx, nodeID, sensorID); err != nil {
			return Rendered{}, err
		}
		return Rendered{}, s.Store.ApplySensorChanges(ctx, nodeID, store.SensorChanges{Delete: []string{sensorID}})
	}
	return r, err
}

// SetSilenced toggles webhook silencing; the compose file is unaffected.
func (s *Service) SetSilenced(ctx context.Context, nodeID, sensorID string, v bool) error {
	return s.Store.SetSensorSilenced(ctx, nodeID, sensorID, v)
}

// Deploy renders the node's compose file with real secrets. It is served
// only to the node itself (node-key authenticated), never to the admin API.
func (s *Service) Deploy(ctx context.Context, nodeID string) (Rendered, error) {
	if s.Compiler == nil {
		return Rendered{}, ErrCompilerUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.Store.Node(ctx, nodeID)
	if err != nil {
		return Rendered{}, err
	}
	list, err := s.Store.Sensors(ctx, nodeID)
	if err != nil {
		return Rendered{}, err
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	return s.Compiler.Render(ctx, *n, list, RenderOptions{Redact: false})
}

// Compose renders the node's current compose file (read-only).
func (s *Service) Compose(ctx context.Context, nodeID string) (Rendered, error) {
	return s.plan(ctx, nodeID, true, func(map[string]domain.Sensor) (store.SensorChanges, error) {
		return store.SensorChanges{}, nil
	})
}

// PreviewChange renders the node with an unsaved add (spec) or config edit
// (sensorID + patch) applied. Nothing is stored.
func (s *Service) PreviewChange(ctx context.Context, nodeID string, add *SensorSpec, sensorID string, patch ConfigPatch) (Rendered, error) {
	return s.plan(ctx, nodeID, true, func(cur map[string]domain.Sensor) (store.SensorChanges, error) {
		switch {
		case add != nil:
			sn, err := s.newSensor(nodeID, *add)
			if err != nil {
				return store.SensorChanges{}, err
			}
			if _, exists := cur[sn.ID]; exists {
				return store.SensorChanges{}, ErrSensorExists
			}
			return store.SensorChanges{Create: []domain.Sensor{sn}}, nil
		case sensorID != "":
			sn, ok := cur[sensorID]
			if !ok {
				return store.SensorChanges{}, domain.ErrNotFound
			}
			cfg, err := applyPatch(sn.Config, patch)
			if err != nil {
				return store.SensorChanges{}, err
			}
			sn.Config = cfg
			return store.SensorChanges{Update: []domain.Sensor{sn}}, nil
		}
		return store.SensorChanges{}, invalid("preview needs either a sensor to add or a sensor edit")
	})
}

func semverLess(a, b string) bool { return semver.Less(a, b) }
