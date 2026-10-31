// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

// Package catalogue maintains the sensor catalogue from the signed registry
// (§6.7). Every manifest is verified by the PORTED signing module before it
// is parsed; unverified manifests are listed as unavailable with a reason.
// Verified manifests are cached in the database and re-verified on load,
// so a registry outage does not prevent rendering deployed sensors.
package catalogue

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/compose"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/fleet"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/manifest"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/ported"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/semver"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/store"
)

// Settings keys.
const (
	SettingRegistryURL  = "registry_url"
	SettingRefreshHours = "catalogue_refresh_hours"
	DefaultRefresh      = 24 * time.Hour
)

// Reason codes for unavailable versions.
const (
	ReasonUnsigned         = "unsigned"
	ReasonSignatureInvalid = "signature_invalid"
	ReasonFetchFailed      = "fetch_failed"
	ReasonInvalidManifest  = "invalid_manifest"
	ReasonManifestMismatch = "manifest_mismatch"
)

// Store is the cache persistence.
type Store interface {
	PutCachedManifest(ctx context.Context, m store.CachedManifest) error
	CachedManifests(ctx context.Context) ([]store.CachedManifest, error)
}

// Settings reads Hub settings.
type Settings interface {
	Setting(ctx context.Context, key string) (string, bool, error)
}

// Version describes one sensor version in the catalogue.
type Version struct {
	Version    string `json:"version"`
	Available  bool   `json:"available"`
	Verified   bool   `json:"verified"`
	Deprecated bool   `json:"deprecated"`
	Listed     bool   `json:"listed"` // present in the current index
	Reason     string `json:"reason,omitempty"`

	m *manifest.Manifest
}

// Sensor groups the versions of one sensor.
type Sensor struct {
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name"`
	Category    string    `json:"category"`
	Description string    `json:"description"`
	Latest      string    `json:"latest"`
	Versions    []Version `json:"versions"`
}

// Status describes the last refresh.
type Status struct {
	RegistryURL string     `json:"registry_url"`
	LastRefresh *time.Time `json:"last_refresh"`
	LastError   string     `json:"last_error,omitempty"`
}

type snapshot struct {
	versions map[string]map[string]*Version // name -> version -> info
	status   Status
}

// Catalogue implements compose.ManifestSource and fleet.Catalogue.
type Catalogue struct {
	Store         Store
	Settings      Settings
	Verifier      ported.ManifestVerifier
	Fetcher       Fetcher
	DefaultURL    string
	AllowHTTP     bool // development only
	AllowUnsigned bool // TS_DEV_ALLOW_UNSIGNED_MANIFESTS
	Options       manifest.Options
	Log           *slog.Logger
	Now           func() time.Time

	refreshMu sync.Mutex
	state     atomic.Pointer[snapshot]
}

var (
	_ compose.ManifestSource = (*Catalogue)(nil)
	_ fleet.Catalogue        = (*Catalogue)(nil)
)

func (c *Catalogue) snap() *snapshot {
	if s := c.state.Load(); s != nil {
		return s
	}
	return &snapshot{versions: map[string]map[string]*Version{}}
}

// verifyAndParse runs verification before parsing (§6.7) and checks the
// manifest identity against the expected name and version.
func (c *Catalogue) verifyAndParse(name, version string, mb, bundle []byte) (m *manifest.Manifest, verified bool, reason string) {
	verr := c.Verifier.Verify(mb, bundle, name, version)
	if verr != nil {
		if !c.AllowUnsigned {
			if len(bundle) == 0 {
				return nil, false, ReasonUnsigned
			}
			return nil, false, ReasonSignatureInvalid
		}
		c.Log.Warn("DEVELOPMENT: accepting an unverified manifest", "sensor", name, "version", version, "error", verr.Error())
	}
	// Parsed only after verification (or the explicit dev override).
	m, err := manifest.Decode(mb, c.Options)
	if err != nil {
		return nil, false, ReasonInvalidManifest
	}
	if m.Name != name || m.Version != version {
		return nil, false, ReasonManifestMismatch
	}
	return m, verr == nil, ""
}

// Load fills the catalogue from the database cache, re-verifying every
// entry. Call it once at start before serving.
func (c *Catalogue) Load(ctx context.Context) error {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	cached, err := c.Store.CachedManifests(ctx)
	if err != nil {
		return err
	}
	next := &snapshot{versions: map[string]map[string]*Version{}}
	for _, cm := range cached {
		m, verified, reason := c.verifyAndParse(cm.Name, cm.Version, cm.Manifest, cm.Bundle)
		v := &Version{Version: cm.Version, Available: m != nil, Verified: verified, Reason: reason, m: m}
		if m == nil {
			c.Log.Warn("cached manifest failed re-verification; not loaded", "sensor", cm.Name, "version", cm.Version, "reason", reason)
		}
		if next.versions[cm.Name] == nil {
			next.versions[cm.Name] = map[string]*Version{}
		}
		next.versions[cm.Name][cm.Version] = v
	}
	if old := c.state.Load(); old != nil {
		next.status = old.status
	}
	c.state.Store(next)
	return nil
}

func (c *Catalogue) registryBase(ctx context.Context) (*url.URL, error) {
	raw := c.DefaultURL
	if v, ok, err := c.Settings.Setting(ctx, SettingRegistryURL); err != nil {
		return nil, err
	} else if ok && v != "" {
		raw = v
	}
	if raw == "" {
		return nil, errors.New("registry URL not configured")
	}
	return ParseBase(raw, c.AllowHTTP)
}

// Refresh fetches the index and any versions not yet verified. On index
// failure the current catalogue is kept and the error recorded.
func (c *Catalogue) Refresh(ctx context.Context) error {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	cur := c.snap()
	now := c.Now().UTC()
	fail := func(err error, base string) error {
		next := &snapshot{versions: cur.versions, status: cur.status}
		next.status.LastError = err.Error()
		next.status.RegistryURL = base
		c.state.Store(next)
		c.Log.Warn("catalogue refresh failed; keeping the current catalogue", "error", err.Error())
		return err
	}

	base, err := c.registryBase(ctx)
	if err != nil {
		return fail(err, "")
	}
	ib, err := c.Fetcher.Get(ctx, resolve(base, "index.json"), MaxIndexBytes)
	if err != nil {
		return fail(fmt.Errorf("fetching index: %w", err), base.String())
	}
	ix, err := ParseIndex(ib)
	if err != nil {
		return fail(err, base.String())
	}

	next := &snapshot{versions: map[string]map[string]*Version{}}
	// Versions known before but no longer listed stay renderable for
	// deployed instances, flagged unlisted (treated as deprecated).
	for name, vs := range cur.versions {
		next.versions[name] = map[string]*Version{}
		for ver, v := range vs {
			cp := *v
			cp.Listed = false
			next.versions[name][ver] = &cp
		}
	}
	for name, e := range ix.Sensors {
		if next.versions[name] == nil {
			next.versions[name] = map[string]*Version{}
		}
		for ver, iv := range e.Versions {
			if v := next.versions[name][ver]; v != nil && v.Available {
				// Versions are immutable (§10): no refetch, only status.
				v.Listed, v.Deprecated = true, iv.Deprecated
				continue
			}
			next.versions[name][ver] = c.fetchVersion(ctx, base, name, ver, iv, now)
		}
	}
	next.status = Status{RegistryURL: base.String(), LastRefresh: &now}
	c.state.Store(next)
	return nil
}

func (c *Catalogue) fetchVersion(ctx context.Context, base *url.URL, name, ver string, iv IndexVersion, now time.Time) *Version {
	v := &Version{Version: ver, Listed: true, Deprecated: iv.Deprecated}
	mb, err := c.Fetcher.Get(ctx, resolve(base, iv.Manifest), MaxManifestBytes)
	if err != nil {
		v.Reason = ReasonFetchFailed
		c.Log.Warn("fetching manifest failed", "sensor", name, "version", ver, "error", err.Error())
		return v
	}
	bundle, err := c.Fetcher.Get(ctx, resolve(base, iv.Manifest+BundleSuffix), MaxBundleBytes)
	if err != nil && !errors.Is(err, ErrNotFound) {
		v.Reason = ReasonFetchFailed
		c.Log.Warn("fetching manifest bundle failed", "sensor", name, "version", ver, "error", err.Error())
		return v
	}
	m, verified, reason := c.verifyAndParse(name, ver, mb, bundle)
	if m == nil {
		v.Reason = reason
		c.Log.Warn("manifest unavailable", "sensor", name, "version", ver, "reason", reason)
		return v
	}
	if err := c.Store.PutCachedManifest(ctx, store.CachedManifest{Name: name, Version: ver, Manifest: mb, Bundle: bundle,
		Verified: verified, FetchedAt: now}); err != nil {
		c.Log.Warn("caching manifest failed", "sensor", name, "version", ver, "error", err.Error())
	}
	v.Available, v.Verified, v.m = true, verified, m
	return v
}

// Manifest implements compose.ManifestSource. Deprecated and unlisted
// versions remain renderable so deployed decoys are never dropped.
func (c *Catalogue) Manifest(_ context.Context, name, version string) (*manifest.Manifest, error) {
	v := c.snap().versions[name][version]
	if v == nil || !v.Available {
		return nil, compose.ErrManifestUnavailable
	}
	m := *v.m
	m.Status = "active"
	if v.Deprecated || !v.Listed {
		m.Status = "deprecated"
	}
	return &m, nil
}

// Latest implements fleet.Catalogue: the highest available, listed,
// non-deprecated version.
func (c *Catalogue) Latest(_ context.Context, name string) (string, bool) {
	best := ""
	for ver, v := range c.snap().versions[name] {
		if v.Available && v.Listed && !v.Deprecated && (best == "" || semver.Less(best, ver)) {
			best = ver
		}
	}
	return best, best != ""
}

// SecretKeys implements fleet.Catalogue.
func (c *Catalogue) SecretKeys(_ context.Context, name, version string) ([]string, bool) {
	v := c.snap().versions[name][version]
	if v == nil || !v.Available {
		return nil, false
	}
	keys := []string{}
	for _, k := range v.m.Config {
		if k.Secret || k.HubReserved {
			keys = append(keys, k.Name)
		}
	}
	return keys, true
}

// List returns the catalogue for the admin API, newest versions first.
func (c *Catalogue) List(ctx context.Context) ([]Sensor, Status) {
	s := c.snap()
	out := make([]Sensor, 0, len(s.versions))
	for name, vs := range s.versions {
		sn := Sensor{Name: name, Versions: []Version{}}
		sn.Latest, _ = c.Latest(ctx, name)
		var newest *manifest.Manifest
		for _, v := range vs {
			sn.Versions = append(sn.Versions, *v)
			if v.Available && (newest == nil || semver.Less(newest.Version, v.Version)) {
				newest = v.m
			}
		}
		if newest != nil {
			sn.DisplayName, sn.Category, sn.Description = newest.DisplayName, newest.Category, newest.Description
		}
		sort.Slice(sn.Versions, func(i, j int) bool { return semver.Less(sn.Versions[j].Version, sn.Versions[i].Version) })
		out = append(out, sn)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, s.status
}

// Details returns one version with its manifest (nil when unavailable).
func (c *Catalogue) Details(_ context.Context, name, version string) (*Version, *manifest.Manifest, bool) {
	v := c.snap().versions[name][version]
	if v == nil {
		return nil, nil, false
	}
	cp := *v
	if !v.Available {
		return &cp, nil, true
	}
	m := *v.m
	return &cp, &m, true
}

func (c *Catalogue) interval(ctx context.Context) time.Duration {
	v, ok, err := c.Settings.Setting(ctx, SettingRefreshHours)
	if err != nil || !ok {
		return DefaultRefresh
	}
	h, err := strconv.Atoi(v)
	if err != nil || h < 1 || h > 168 {
		return DefaultRefresh
	}
	return time.Duration(h) * time.Hour
}

// Run refreshes at start and then periodically until ctx ends.
func (c *Catalogue) Run(ctx context.Context) {
	for {
		if err := c.Refresh(ctx); err == nil {
			c.Log.Info("catalogue refreshed")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(c.interval(ctx)):
		}
	}
}
