// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package manifest defines sensor manifest schema v3 (§9): strict decoding,
// structural validation and the static compose rules of §6.12 that apply to
// manifest content. Manifests are untrusted input; Decode must only be
// called on bytes the signing module has already verified.
package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/semver"
)

// SchemaVersion is the only schema version this Hub accepts.
const SchemaVersion = 3

// HubMajor is the Hub major version manifests must target.
const HubMajor = 3

// MaxSize is the largest manifest accepted (§6.7).
const MaxSize = 256 << 10

// Manifest describes one sensor version.
type Manifest struct {
	SchemaVersion int           `json:"schema_version"`
	Name          string        `json:"name"`
	DisplayName   string        `json:"display_name"`
	Version       string        `json:"version"`
	Description   string        `json:"description"`
	Category      string        `json:"category"`
	Author        string        `json:"author"`
	Documentation string        `json:"documentation"`
	Image         Image         `json:"image"`
	Runtime       Runtime       `json:"runtime"`
	Init          *Init         `json:"init,omitempty"`
	Config        []ConfigKey   `json:"config"`
	Discovery     *Discovery    `json:"discovery,omitempty"`
	Triggers      []Trigger     `json:"triggers"`
	Compatibility Compatibility `json:"compatibility"`
	// Status is set by the registry index, never by the author; a value in
	// the manifest itself is ignored and overwritten from the index.
	Status string `json:"status,omitempty"`
}

// Image references a container image. Digest is filled by CI.
type Image struct {
	Repository string   `json:"repository"`
	Tag        string   `json:"tag"`
	Digest     string   `json:"digest"`
	Platforms  []string `json:"platforms"`
}

// Runtime describes how the main container runs. read_only is not
// configurable: every container is read-only.
type Runtime struct {
	User        string       `json:"user,omitempty"`
	NetworkMode string       `json:"network_mode"`
	CapAdd      []string     `json:"cap_add,omitempty"`
	MemoryMB    int          `json:"memory_mb,omitempty"`
	ListenPorts []ListenPort `json:"listen_ports,omitempty"`
	HostPaths   []HostPath   `json:"host_paths,omitempty"`
}

// ListenPort names a config key holding a port (type port) or a list of
// ports (type list of port) the sensor binds.
type ListenPort struct {
	ConfigKey string `json:"config_key"`
	Protocol  string `json:"protocol"` // tcp | udp
	// ContainerPort (bridge only, single-port key): the sensor listens on
	// this fixed port inside the container and the config value is the
	// published host port. Lets an unprivileged sensor appear on port 80.
	ContainerPort int `json:"container_port,omitempty"`
	// EnabledKey (optional) names a declared bool config key. While its
	// effective value is "false" the port is neither conflict-checked nor
	// published, so a protocol a multi-protocol decoy has switched off does
	// not hold its default port.
	EnabledKey string `json:"enabled_key,omitempty"`
}

// HostPath derives bind mounts from a config key of type path or list of
// path. Mount "self" mounts the path itself, "parent" its parent directory
// (needed to observe delete/recreate of files). Container path = host path.
type HostPath struct {
	ConfigKey string `json:"config_key"`
	Mount     string `json:"mount"` // self | parent
	ReadOnly  bool   `json:"read_only"`
}

// Init is an optional hardened init container (no network).
type Init struct {
	Image             Image    `json:"image"`
	Command           []string `json:"command"`
	CapAdd            []string `json:"cap_add,omitempty"`
	WritableHostPaths []string `json:"writable_host_paths,omitempty"` // config keys from runtime.host_paths
	User              string   `json:"user,omitempty"`
}

// ConfigKey declares one configuration variable.
type ConfigKey struct {
	Name        string      `json:"name"`
	Type        string      `json:"type"` // string int bool enum list port path
	ItemType    string      `json:"item_type,omitempty"`
	Default     *string     `json:"default,omitempty"`
	Required    bool        `json:"required,omitempty"`
	Secret      bool        `json:"secret,omitempty"`
	HubReserved bool        `json:"hub_reserved,omitempty"`
	Description string      `json:"description"`
	Validation  *Validation `json:"validation,omitempty"`
}

// Validation constrains a config value.
type Validation struct {
	Pattern  string   `json:"pattern,omitempty"`
	Min      *int64   `json:"min,omitempty"`
	Max      *int64   `json:"max,omitempty"`
	Enum     []string `json:"enum,omitempty"`
	MaxItems int      `json:"max_items,omitempty"`
	MaxLen   int      `json:"max_length,omitempty"`
}

// Discovery holds the CLI heuristics (§8 discover).
type Discovery struct {
	ProcessNames   []string          `json:"process_names,omitempty"`
	ListeningPorts []int             `json:"listening_ports,omitempty"`
	Files          []string          `json:"files,omitempty"`
	Defaults       map[string]string `json:"defaults,omitempty"`
}

// Trigger documents an event the sensor can emit.
type Trigger struct {
	Name            string `json:"name"`
	DefaultSeverity string `json:"default_severity"`
	Description     string `json:"description"`
}

// Compatibility states the required Hub major version.
type Compatibility struct {
	HubMajor int `json:"hub_major"`
}

// Decode strictly decodes a manifest (unknown fields refused) and validates
// it.
func Decode(b []byte, opts Options) (*Manifest, error) {
	if len(b) > MaxSize {
		return nil, fmt.Errorf("manifest exceeds %d bytes", MaxSize)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if dec.More() {
		return nil, errors.New("manifest: trailing data")
	}
	if err := m.Validate(opts); err != nil {
		return nil, err
	}
	return &m, nil
}

// Options relax development-only rules.
type Options struct {
	AllowUnpinned bool // TS_DEV_ALLOW_UNPINNED_IMAGES
}

// Hub-reserved environment variables (§6.12 rule 6).
const (
	EnvHubEndpoint    = "TS_HUB_ENDPOINT"
	EnvNodeKey        = "TS_NODE_KEY"
	EnvSensorID       = "TS_SENSOR_ID"
	EnvConfigRevision = "TS_CONFIG_REVISION"
	EnvTestMode       = "TS_TEST_MODE"
	EnvCaptureKey     = "TS_CAPTURE_KEY"
	EnvHoneytoken     = "TS_HONEYTOKEN"
	EnvBeaconKey      = "TS_BEACON_KEY"
)

// AlwaysReserved are set by the Hub for every sensor.
var AlwaysReserved = []string{EnvHubEndpoint, EnvNodeKey, EnvSensorID, EnvConfigRevision, EnvTestMode}

// OptionalSecrets are set only when a manifest declares them hub_reserved.
var OptionalSecrets = []string{EnvCaptureKey, EnvHoneytoken, EnvBeaconKey}

// IsReserved reports whether a variable is set by the Hub.
func IsReserved(name string) bool {
	for _, r := range AlwaysReserved {
		if r == name {
			return true
		}
	}
	for _, r := range OptionalSecrets {
		if r == name {
			return true
		}
	}
	return false
}

// AllowedCaps is the capability allow-list (§6.12 rule 3).
var AllowedCaps = map[string]bool{"NET_RAW": true, "NET_BIND_SERVICE": true, "DAC_OVERRIDE": true}

// AllowedNetworkModes (§6.12 rule 3).
var AllowedNetworkModes = map[string]bool{"host": true, "bridge": true, "none": true}

var (
	kebabRE     = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	configKeyRE = regexp.MustCompile(`^TS_[A-Z0-9]+(_[A-Z0-9]+)*$`)
	digestRE    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	repoRE      = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(:[0-9]+)?(/[a-z0-9]+([._-][a-z0-9]+)*)+$`)
	tagRE       = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	userRE      = regexp.MustCompile(`^[0-9]{1,10}(:[0-9]{1,10})?$`)
	platformRE  = regexp.MustCompile(`^linux/(amd64|arm64)$`)
	templateRE  = regexp.MustCompile(`^(free_port\(([0-9]{1,5})\)|random_choice\(([^()]*)\)|hostname\(\))$`)
)

var severities = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}

// ConfigTypes accepted in manifests.
var ConfigTypes = map[string]bool{"string": true, "int": true, "bool": true, "enum": true, "list": true, "port": true, "path": true}

// HasInterpolation reports `$` or `{{` (§6.12 rule 5).
func HasInterpolation(s string) bool { return strings.Contains(s, "$") || strings.Contains(s, "{{") }

// IsTemplate reports whether a default is a discovery template.
func IsTemplate(s string) bool { return templateRE.MatchString(s) }

// ImageRef returns the pinned reference repository[:tag]@digest, or with
// AllowUnpinned and no digest, repository:tag (§6.12 rule 1).
func (im Image) Ref(opts Options) (string, error) {
	if !repoRE.MatchString(im.Repository) || HasInterpolation(im.Repository) {
		return "", fmt.Errorf("invalid image repository %q", trunc(im.Repository))
	}
	if im.Tag != "" && !tagRE.MatchString(im.Tag) {
		return "", fmt.Errorf("invalid image tag %q", trunc(im.Tag))
	}
	if im.Digest == "" {
		if !opts.AllowUnpinned {
			return "", &RuleError{Code: "image_not_pinned", Msg: fmt.Sprintf("image %s has no @sha256 digest", im.Repository)}
		}
		if im.Tag == "" {
			return "", fmt.Errorf("unpinned image %s has no tag", im.Repository)
		}
		return im.Repository + ":" + im.Tag, nil
	}
	if !digestRE.MatchString(im.Digest) {
		return "", &RuleError{Code: "image_not_pinned", Msg: fmt.Sprintf("image %s digest is not sha256:<64 hex>", im.Repository)}
	}
	if im.Tag != "" {
		return im.Repository + ":" + im.Tag + "@" + im.Digest, nil
	}
	return im.Repository + "@" + im.Digest, nil
}

// RuleError is a §6.12 rule violation with a stable code.
type RuleError struct {
	Code string
	Msg  string
}

func (e *RuleError) Error() string { return e.Code + ": " + e.Msg }

func trunc(s string) string {
	if len(s) > 80 {
		return strings.ToValidUTF8(s[:80], "") + "…"
	}
	return s
}

func checkCaps(caps []string, where string) error {
	seen := map[string]bool{}
	for _, c := range caps {
		if !AllowedCaps[c] {
			return &RuleError{Code: "capability_not_allowed", Msg: fmt.Sprintf("%s: capability %q is not in the allow-list (NET_RAW, NET_BIND_SERVICE, DAC_OVERRIDE)", where, trunc(c))}
		}
		if seen[c] {
			return fmt.Errorf("%s: duplicate capability %s", where, c)
		}
		seen[c] = true
	}
	return nil
}

// Key returns the declaration of a config key.
func (m *Manifest) Key(name string) *ConfigKey {
	for i := range m.Config {
		if m.Config[i].Name == name {
			return &m.Config[i]
		}
	}
	return nil
}

// Validate checks structure and the static §6.12 rules.
func (m *Manifest) Validate(opts Options) error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if m.SchemaVersion != SchemaVersion {
		add("schema_version must be %d", SchemaVersion)
	}
	if !kebabRE.MatchString(m.Name) || len(m.Name) > 64 {
		add("name must be kebab-case (≤ 64)")
	}
	if !semver.Valid(m.Version) {
		add("version must be SemVer")
	}
	if strings.TrimSpace(m.DisplayName) == "" || len(m.DisplayName) > 128 {
		add("display_name required (≤ 128)")
	}
	if strings.TrimSpace(m.Description) == "" || len(m.Description) > 2048 {
		add("description required (≤ 2048)")
	}
	if !kebabRE.MatchString(m.Category) {
		add("category must be kebab-case")
	}
	if strings.TrimSpace(m.Author) == "" || len(m.Author) > 128 {
		add("author required (≤ 128)")
	}
	if len(m.Documentation) > 64<<10 {
		add("documentation exceeds 64 KiB")
	}
	if m.Compatibility.HubMajor != HubMajor {
		errs = append(errs, &RuleError{Code: "incompatible_manifest", Msg: fmt.Sprintf("compatibility.hub_major must be %d", HubMajor)})
	}
	if _, err := m.Image.Ref(opts); err != nil {
		errs = append(errs, err)
	}
	if len(m.Image.Platforms) == 0 {
		add("image.platforms required")
	}
	for _, p := range m.Image.Platforms {
		if !platformRE.MatchString(p) {
			add("unsupported platform %q", trunc(p))
		}
	}

	// Runtime.
	rt := m.Runtime
	if !AllowedNetworkModes[rt.NetworkMode] {
		errs = append(errs, &RuleError{Code: "network_mode_not_allowed", Msg: fmt.Sprintf("network_mode %q (host, bridge or none)", trunc(rt.NetworkMode))})
	}
	if rt.User != "" && !userRE.MatchString(rt.User) {
		add("runtime.user must be uid[:gid]")
	}
	if rt.MemoryMB < 0 || rt.MemoryMB > 4096 {
		add("runtime.memory_mb must be 0..4096")
	}
	if err := checkCaps(rt.CapAdd, "runtime"); err != nil {
		errs = append(errs, err)
	}

	// Config keys.
	names := map[string]bool{}
	for _, k := range m.Config {
		if !configKeyRE.MatchString(k.Name) || len(k.Name) > 64 {
			add("config key %q must match TS_[A-Z0-9_]+", trunc(k.Name))
			continue
		}
		if names[k.Name] {
			add("duplicate config key %s", k.Name)
		}
		names[k.Name] = true
		if !ConfigTypes[k.Type] {
			add("%s: unknown type %q", k.Name, k.Type)
		}
		if k.Type == "list" {
			if !ConfigTypes[k.ItemType] || k.ItemType == "list" || k.ItemType == "bool" {
				add("%s: list needs item_type string, int, enum, port or path", k.Name)
			}
		} else if k.ItemType != "" {
			add("%s: item_type only applies to lists", k.Name)
		}
		if k.HubReserved {
			isOpt := false
			for _, o := range OptionalSecrets {
				isOpt = isOpt || o == k.Name
			}
			if !isOpt {
				add("%s: hub_reserved is only valid for %s", k.Name, strings.Join(OptionalSecrets, ", "))
			}
			if k.Default != nil || k.Required {
				add("%s: hub_reserved keys take no default and are not user-required", k.Name)
			}
		} else if IsReserved(k.Name) {
			add("%s is reserved for the Hub; declare it with hub_reserved: true or not at all", k.Name)
		}
		if strings.TrimSpace(k.Description) == "" {
			add("%s: description required", k.Name)
		}
		if v := k.Validation; v != nil {
			if v.Pattern != "" {
				if len(v.Pattern) > 512 {
					add("%s: pattern too long", k.Name)
				} else if _, err := regexp.Compile("^(?:" + v.Pattern + ")$"); err != nil {
					add("%s: invalid pattern", k.Name)
				}
			}
			if v.Min != nil && v.Max != nil && *v.Min > *v.Max {
				add("%s: min > max", k.Name)
			}
			if (k.Type == "enum" || k.ItemType == "enum") && len(v.Enum) == 0 {
				add("%s: enum needs validation.enum", k.Name)
			}
		} else if k.Type == "enum" || k.ItemType == "enum" {
			add("%s: enum needs validation.enum", k.Name)
		}
		if k.Default != nil && !IsTemplate(*k.Default) {
			if err := CheckValue(&k, *k.Default); err != nil {
				add("%s: default: %v", k.Name, err)
			}
		}
	}

	// Listen ports and host paths must reference declared keys of the
	// right type.
	for _, lp := range rt.ListenPorts {
		k := m.Key(lp.ConfigKey)
		if k == nil || !(k.Type == "port" || (k.Type == "list" && k.ItemType == "port")) {
			add("listen_ports: %s must be a declared port or list of port key", trunc(lp.ConfigKey))
		}
		if lp.Protocol != "tcp" && lp.Protocol != "udp" {
			add("listen_ports: protocol must be tcp or udp")
		}
		if lp.EnabledKey != "" {
			if ek := m.Key(lp.EnabledKey); ek == nil || ek.Type != "bool" {
				add("listen_ports: enabled_key %s must be a declared bool key", trunc(lp.EnabledKey))
			}
		}
		if lp.ContainerPort != 0 {
			if lp.ContainerPort < 1 || lp.ContainerPort > 65535 {
				add("listen_ports: container_port must be 1..65535")
			}
			if rt.NetworkMode != "bridge" {
				add("listen_ports: container_port requires network_mode bridge")
			}
			if k != nil && k.Type != "port" {
				add("listen_ports: container_port requires a single port key")
			}
		}
	}
	hostKeys := map[string]bool{}
	for _, hp := range rt.HostPaths {
		k := m.Key(hp.ConfigKey)
		if k == nil || !(k.Type == "path" || (k.Type == "list" && k.ItemType == "path")) {
			add("host_paths: %s must be a declared path or list of path key", trunc(hp.ConfigKey))
		}
		if hp.Mount != "self" && hp.Mount != "parent" {
			add("host_paths: mount must be self or parent")
		}
		hostKeys[hp.ConfigKey] = true
	}

	if in := m.Init; in != nil {
		if _, err := in.Image.Ref(opts); err != nil {
			errs = append(errs, fmt.Errorf("init: %w", err))
		}
		if len(in.Command) == 0 || len(in.Command) > 32 {
			add("init.command needs 1..32 elements")
		}
		for _, c := range in.Command {
			if HasInterpolation(c) {
				errs = append(errs, &RuleError{Code: "interpolation", Msg: "init.command must not contain $ or {{"})
				break
			}
			if len(c) > 1024 || strings.ContainsRune(c, 0) {
				add("init.command element too long or contains NUL")
			}
		}
		if err := checkCaps(in.CapAdd, "init"); err != nil {
			errs = append(errs, err)
		}
		if in.User != "" && !userRE.MatchString(in.User) {
			add("init.user must be uid[:gid]")
		}
		for _, w := range in.WritableHostPaths {
			if !hostKeys[w] {
				add("init.writable_host_paths: %s is not in runtime.host_paths", trunc(w))
			}
		}
	}

	// Discovery templates use a fixed function set only.
	if d := m.Discovery; d != nil {
		for k, v := range d.Defaults {
			if m.Key(k) == nil {
				add("discovery.defaults: %s is not a declared key", trunc(k))
			}
			if !IsTemplate(v) && HasInterpolation(v) {
				add("discovery.defaults: %s uses an unsupported expression", k)
			}
		}
		for _, p := range d.ListeningPorts {
			if p < 1 || p > 65535 {
				add("discovery.listening_ports: %d out of range", p)
			}
		}
	}

	if len(m.Triggers) == 0 {
		add("at least one trigger required")
	}
	for _, t := range m.Triggers {
		if !domain.ValidTrigger(t.Name) {
			add("trigger %q must be snake_case", trunc(t.Name))
		}
		if !severities[t.DefaultSeverity] {
			add("trigger %s: default_severity invalid", t.Name)
		}
	}
	return errors.Join(errs...)
}
