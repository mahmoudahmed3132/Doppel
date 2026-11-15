// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package compose renders a node's Docker Compose file from its sensor
// instances and their verified manifests (§6.12). It is a security
// boundary: manifests and user values are untrusted, every rule violation
// rejects the whole render with a precise code, and no decoy is ever
// silently dropped.
//
// Output is JSON (a subset of YAML that Docker Compose accepts): no YAML
// quoting or injection issues, and deterministic key order.
package compose

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/fleet"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/manifest"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
)

// Defaults applied to every container.
const (
	DefaultUser     = "65532:65532"
	DefaultMemoryMB = 256
	PidsLimit       = 256
	TmpfsBytes      = 16 << 20
	Redacted        = "REDACTED"
	// BeaconKeyLabel is the fixed HMAC label of the Token Receiver key.
	BeaconKeyLabel = "truesignal/beacon-receiver/v1"
	// SettingEndpoint holds the Hub public endpoint (set during setup).
	SettingEndpoint = "public_endpoint"
)

// ErrManifestUnavailable is returned by ManifestSource for a sensor
// version that is unknown, unsigned or failed verification.
var ErrManifestUnavailable = errors.New("manifest unavailable")

// ManifestSource returns verified, parsed manifests (the catalogue).
type ManifestSource interface {
	Manifest(ctx context.Context, name, version string) (*manifest.Manifest, error)
}

// Settings reads Hub settings.
type Settings interface {
	Setting(ctx context.Context, key string) (string, bool, error)
}

// MasterKeys provides Hub-held master keys; they never leave the Hub.
type MasterKeys interface {
	CaptureMasterKey(ctx context.Context) ([]byte, error)
	BeaconMasterKey(ctx context.Context) ([]byte, error)
}

// Compiler implements fleet.Compiler.
type Compiler struct {
	Manifests   ManifestSource
	Settings    Settings
	Keys        MasterKeys
	Honeytokens ported.HoneytokenService // nil: File Canary renders fail unless redacted
	Options     manifest.Options
	Log         *slog.Logger
}

var _ fleet.Compiler = (*Compiler)(nil)

func reject(sensorID, code, format string, a ...any) error {
	return &fleet.RenderError{Status: 422, Code: code, Message: fmt.Sprintf(format, a...), SensorID: sensorID}
}

func fromRule(sensorID string, err error) error {
	var re *manifest.RuleError
	if errors.As(err, &re) {
		return reject(sensorID, re.Code, "%s", re.Msg)
	}
	return reject(sensorID, "invalid_manifest", "%v", err)
}

// Revision is "rev_" + the first 8 hex digits of SHA-256 over the sorted
// list of (sensor id, version, sorted config). It does not depend on
// secrets, manifests or the Hub endpoint.
func Revision(sensors []domain.Sensor) string {
	type entry struct {
		ID      string      `json:"id"`
		Version string      `json:"version"`
		Config  [][2]string `json:"config"`
	}
	list := make([]entry, 0, len(sensors))
	for _, s := range sensors {
		e := entry{ID: s.ID, Version: s.Version, Config: [][2]string{}}
		keys := make([]string, 0, len(s.Config))
		for k := range s.Config {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			e.Config = append(e.Config, [2]string{k, s.Config[k]})
		}
		list = append(list, e)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	b, _ := json.Marshal(list)
	sum := sha256.Sum256(b)
	return "rev_" + hex.EncodeToString(sum[:])[:8]
}

// Document is the rendered compose file.
type Document struct {
	Name     string              `json:"name"`
	Meta     Meta                `json:"x-truesignal"`
	Services map[string]*Service `json:"services"`
}

// Meta is the x-truesignal extension block (ignored by Docker Compose).
type Meta struct {
	NodeID   string `json:"node_id"`
	Revision string `json:"revision"`
	// NodeKeyEnv names the variable the CLI must add to every service from
	// its local configuration; the Hub stores only the key's hash.
	NodeKeyEnv string `json:"node_key_env"`
	// HostPaths lists the host paths (lure files) the sensors use, so the
	// CLI can re-check them and list them on uninstall (they are kept).
	HostPaths []string `json:"host_paths"`
}

// Service is one compose service.
type Service struct {
	Image         string               `json:"image"`
	ContainerName string               `json:"container_name"`
	User          string               `json:"user"`
	ReadOnly      bool                 `json:"read_only"`
	CapDrop       []string             `json:"cap_drop"`
	CapAdd        []string             `json:"cap_add,omitempty"`
	SecurityOpt   []string             `json:"security_opt"`
	NetworkMode   string               `json:"network_mode"`
	Restart       string               `json:"restart"`
	Command       []string             `json:"command,omitempty"`
	Environment   map[string]string    `json:"environment"`
	Volumes       []Volume             `json:"volumes"`
	Ports         []Port               `json:"ports,omitempty"`
	DependsOn     map[string]Condition `json:"depends_on,omitempty"`
	PidsLimit     int                  `json:"pids_limit"`
	MemLimit      string               `json:"mem_limit"`
	Logging       Logging              `json:"logging"`
	Labels        map[string]string    `json:"labels"`
}

// Volume is a long-syntax mount (no "src:dst:mode" string parsing).
type Volume struct {
	Type     string    `json:"type"`
	Source   string    `json:"source,omitempty"`
	Target   string    `json:"target"`
	ReadOnly bool      `json:"read_only,omitempty"`
	Bind     *BindOpts `json:"bind,omitempty"`
	Tmpfs    *TmpfsOpt `json:"tmpfs,omitempty"`
}

// BindOpts disables bind-source creation: a missing path is an error on
// the node instead of an empty directory created by Docker as root.
type BindOpts struct {
	CreateHostPath bool `json:"create_host_path"`
}

// TmpfsOpt sizes a tmpfs mount.
type TmpfsOpt struct {
	Size int `json:"size"`
}

// Port is a long-syntax published port (bridge network only).
type Port struct {
	Target    int    `json:"target"`
	Published string `json:"published"`
	Protocol  string `json:"protocol"`
}

// Condition is a depends_on condition.
type Condition struct {
	Condition string `json:"condition"`
}

// Logging bounds container logs on the node.
type Logging struct {
	Driver  string            `json:"driver"`
	Options map[string]string `json:"options"`
}

type portClaim struct {
	sensorID string
	proto    string
}

// Render implements fleet.Compiler.
func (c *Compiler) Render(ctx context.Context, node domain.Node, sensors []domain.Sensor, opts fleet.RenderOptions) (fleet.Rendered, error) {
	endpoint, ok, err := c.Settings.Setting(ctx, SettingEndpoint)
	if err != nil {
		return fleet.Rendered{}, err
	}
	if !ok || endpoint == "" {
		return fleet.Rendered{}, reject("", "hub_endpoint_unset", "the Hub public endpoint is not configured")
	}
	sorted := append([]domain.Sensor(nil), sensors...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	rev := Revision(sorted)

	doc := Document{
		Name:     "truesignal",
		Meta:     Meta{NodeID: node.ID, Revision: rev, NodeKeyEnv: manifest.EnvNodeKey, HostPaths: []string{}},
		Services: map[string]*Service{},
	}
	var warnings []string
	ports := map[int]portClaim{}

	for _, sn := range sorted {
		svcs, warn, err := c.renderSensor(ctx, node, sn, endpoint, rev, opts, ports, &doc.Meta.HostPaths)
		if err != nil {
			return fleet.Rendered{}, err
		}
		warnings = append(warnings, warn...)
		for name, s := range svcs {
			if _, dup := doc.Services[name]; dup {
				return fleet.Rendered{}, reject(sn.ID, "duplicate_service", "service name %s is used twice", name)
			}
			doc.Services[name] = s
		}
	}

	sort.Strings(doc.Meta.HostPaths)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fleet.Rendered{}, err
	}
	return fleet.Rendered{Compose: buf.Bytes(), Revision: rev, Warnings: warnings}, nil
}

func (c *Compiler) renderSensor(ctx context.Context, node domain.Node, sn domain.Sensor, endpoint, rev string,
	opts fleet.RenderOptions, ports map[int]portClaim, hostPaths *[]string) (map[string]*Service, []string, error) {

	if !domain.ValidSensorID(sn.ID) {
		return nil, nil, reject(sn.ID, "invalid_sensor_id", "invalid sensor id")
	}
	if c.Manifests == nil {
		return nil, nil, reject(sn.ID, "manifest_unavailable", "no verified manifest for %s %s (catalogue not available)", sn.CatalogueName, sn.Version)
	}
	m, err := c.Manifests.Manifest(ctx, sn.CatalogueName, sn.Version)
	if err != nil {
		if errors.Is(err, ErrManifestUnavailable) {
			return nil, nil, reject(sn.ID, "manifest_unavailable", "no verified manifest for %s %s", sn.CatalogueName, sn.Version)
		}
		return nil, nil, err
	}
	// Defence in depth: re-validate even though the catalogue did.
	if err := m.Validate(c.Options); err != nil {
		return nil, nil, fromRule(sn.ID, err)
	}
	if m.Name != sn.CatalogueName || m.Version != sn.Version {
		return nil, nil, reject(sn.ID, "manifest_mismatch", "manifest is %s %s, instance wants %s %s", m.Name, m.Version, sn.CatalogueName, sn.Version)
	}

	// Rule 6: effective configuration.
	var warnings []string
	cfg := map[string]string{}
	userKeys := make([]string, 0, len(sn.Config))
	for k := range sn.Config {
		userKeys = append(userKeys, k)
	}
	sort.Strings(userKeys)
	for _, k := range userKeys {
		decl := m.Key(k)
		switch {
		case manifest.IsReserved(k):
			warnings = append(warnings, fmt.Sprintf("%s: %s is set by the Hub; the supplied value was ignored", sn.ID, k))
		case decl == nil:
			warnings = append(warnings, fmt.Sprintf("%s: %s is not declared by the manifest and was dropped", sn.ID, k))
		}
	}
	for i := range m.Config {
		k := &m.Config[i]
		if k.HubReserved {
			continue
		}
		v, given := sn.Config[k.Name]
		if !given {
			switch {
			case k.Default != nil && !manifest.IsTemplate(*k.Default):
				v = *k.Default
			case k.Required || k.Default != nil:
				return nil, nil, reject(sn.ID, "missing_config", "%s is required", k.Name)
			default:
				continue
			}
		}
		if err := manifest.CheckValue(k, v); err != nil {
			return nil, nil, fromRuleOr(sn.ID, "invalid_config", fmt.Sprintf("%s: %v", k.Name, err), err)
		}
		cfg[k.Name] = v
	}

	// Rule 7: port conflicts across sensors of the node, any protocol.
	for _, lp := range m.Runtime.ListenPorts {
		for _, p := range portsOf(cfg[lp.ConfigKey]) {
			if prev, taken := ports[p]; taken && prev.sensorID != sn.ID {
				return nil, nil, &fleet.RenderError{Status: 409, Code: "port_conflict", SensorID: sn.ID,
					Message: fmt.Sprintf("port %d (%s) is already used by %s (%s)", p, lp.Protocol, prev.sensorID, prev.proto)}
			}
			ports[p] = portClaim{sensorID: sn.ID, proto: lp.Protocol}
		}
	}

	// Rule 4: bind mounts derived from config values.
	mounts := map[string][]Volume{} // config key -> mounts
	for _, hp := range m.Runtime.HostPaths {
		raw := cfg[hp.ConfigKey]
		if raw == "" {
			continue
		}
		seen := map[string]bool{}
		for _, p := range manifest.SplitList(raw) {
			if err := manifest.CheckMountSource(p); err != nil {
				return nil, nil, fromRule(sn.ID, err)
			}
			*hostPaths = append(*hostPaths, p)
			src := p
			if hp.Mount == "parent" {
				src = path.Dir(p)
				if err := manifest.CheckMountSource(src); err != nil {
					return nil, nil, fromRule(sn.ID, err)
				}
			}
			if seen[src] {
				continue
			}
			seen[src] = true
			mounts[hp.ConfigKey] = append(mounts[hp.ConfigKey], Volume{Type: "bind", Source: src, Target: src,
				ReadOnly: hp.ReadOnly, Bind: &BindOpts{CreateHostPath: false}})
		}
	}

	// Environment: reserved values always come from the Hub.
	env := map[string]string{}
	for k, v := range cfg {
		env[k] = v
	}
	env[manifest.EnvHubEndpoint] = endpoint
	env[manifest.EnvSensorID] = sn.ID
	env[manifest.EnvConfigRevision] = rev
	env[manifest.EnvTestMode] = "false"
	for i := range m.Config {
		k := &m.Config[i]
		if !k.HubReserved {
			continue
		}
		v, err := c.secret(ctx, node, sn, k.Name, opts.Redact)
		if err != nil {
			return nil, nil, err
		}
		env[k.Name] = v
	}
	for k, v := range env {
		env[k] = strings.ReplaceAll(v, "$", "$$") // rule 5
	}

	// Rules 1-3, 8: main service.
	ref, err := m.Image.Ref(c.Options)
	if err != nil {
		return nil, nil, fromRule(sn.ID, err)
	}
	user := m.Runtime.User
	if user == "" {
		user = DefaultUser
	}
	mem := m.Runtime.MemoryMB
	if mem == 0 {
		mem = DefaultMemoryMB
	}
	main := &Service{
		Image: ref, ContainerName: sn.ID, User: user, ReadOnly: true,
		CapDrop: []string{"ALL"}, CapAdd: sortedCopy(m.Runtime.CapAdd),
		SecurityOpt: []string{"no-new-privileges:true"}, NetworkMode: m.Runtime.NetworkMode,
		Restart: "unless-stopped", Environment: env,
		Volumes:   []Volume{{Type: "tmpfs", Target: "/tmp", Tmpfs: &TmpfsOpt{Size: TmpfsBytes}}},
		PidsLimit: PidsLimit, MemLimit: strconv.Itoa(mem) + "m",
		Logging: Logging{Driver: "json-file", Options: map[string]string{"max-size": "10m", "max-file": "3"}},
		Labels:  map[string]string{"io.truesignal.sensor": sn.ID, "io.truesignal.node": node.ID, "io.truesignal.role": "sensor"},
	}
	for _, hp := range m.Runtime.HostPaths {
		main.Volumes = append(main.Volumes, mounts[hp.ConfigKey]...)
	}
	if m.Runtime.NetworkMode == "bridge" {
		for _, lp := range m.Runtime.ListenPorts {
			for _, p := range portsOf(cfg[lp.ConfigKey]) {
				target := p
				if lp.ContainerPort != 0 {
					target = lp.ContainerPort
				}
				main.Ports = append(main.Ports, Port{Target: target, Published: strconv.Itoa(p), Protocol: lp.Protocol})
			}
		}
	}
	out := map[string]*Service{sn.ID: main}

	if in := m.Init; in != nil {
		iref, err := in.Image.Ref(c.Options)
		if err != nil {
			return nil, nil, fromRule(sn.ID, err)
		}
		iuser := in.User
		if iuser == "" {
			iuser = user
		}
		name := sn.ID + "-init"
		init := &Service{
			Image: iref, ContainerName: name, User: iuser, ReadOnly: true,
			CapDrop: []string{"ALL"}, CapAdd: sortedCopy(in.CapAdd),
			SecurityOpt: []string{"no-new-privileges:true"}, NetworkMode: "none", // rule 2
			Restart: "no", Command: append([]string(nil), in.Command...), Environment: env,
			Volumes:   []Volume{{Type: "tmpfs", Target: "/tmp", Tmpfs: &TmpfsOpt{Size: TmpfsBytes}}},
			PidsLimit: PidsLimit, MemLimit: strconv.Itoa(DefaultMemoryMB) + "m",
			Logging: main.Logging,
			Labels:  map[string]string{"io.truesignal.sensor": sn.ID, "io.truesignal.node": node.ID, "io.truesignal.role": "init"},
		}
		for _, key := range in.WritableHostPaths {
			for _, v := range mounts[key] {
				v.ReadOnly = false
				init.Volumes = append(init.Volumes, v)
			}
		}
		out[name] = init
		main.DependsOn = map[string]Condition{name: {Condition: "service_completed_successfully"}}
	}
	return out, warnings, nil
}

func fromRuleOr(sensorID, code, msg string, err error) error {
	var re *manifest.RuleError
	if errors.As(err, &re) {
		return reject(sensorID, re.Code, "%s", msg)
	}
	return reject(sensorID, code, "%s", msg)
}

// secret returns the value of a hub_reserved secret (rule 9).
func (c *Compiler) secret(ctx context.Context, node domain.Node, sn domain.Sensor, name string, redact bool) (string, error) {
	if redact {
		return Redacted, nil
	}
	switch name {
	case manifest.EnvCaptureKey:
		mk, err := c.Keys.CaptureMasterKey(ctx)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(CaptureKey(mk, node.ID)), nil
	case manifest.EnvBeaconKey:
		mk, err := c.Keys.BeaconMasterKey(ctx)
		if err != nil {
			return "", err
		}
		return BeaconReceiverKey(mk), nil
	case manifest.EnvHoneytoken:
		if c.Honeytokens == nil {
			return "", reject(sn.ID, "honeytoken_unavailable", "the honeytoken module is not installed")
		}
		ht, err := c.Honeytokens.Ensure(ctx, node.ID, sn.ID)
		if err != nil {
			return "", err
		}
		b, err := json.Marshal(map[string]string{"id": ht.ID, "username": ht.Username, "secret": ht.Secret})
		return string(b), err
	}
	return "", fmt.Errorf("unknown hub secret %s", name)
}

// BeaconReceiverKey is TS_BEACON_KEY, shared by every Token Receiver:
// hex HMAC-SHA256(beacon master key, BeaconKeyLabel).
func BeaconReceiverKey(master []byte) string {
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte(BeaconKeyLabel))
	return hex.EncodeToString(mac.Sum(nil))
}

// CaptureKey derives the per-node capture hash key:
// HMAC-SHA256(capture master key, node id).
func CaptureKey(master []byte, nodeID string) []byte {
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte(nodeID))
	return mac.Sum(nil)
}

func portsOf(v string) []int {
	var out []int
	for _, it := range manifest.SplitList(v) {
		if n, err := strconv.Atoi(it); err == nil && n >= 1 && n <= 65535 {
			out = append(out, n)
		}
	}
	return out
}

func sortedCopy(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}
