// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package registrytool implements the sensor publish and rollback steps of
// §10 on a checkout of the registry branch: pinning a manifest to the pushed
// image digest, regenerating index.json and deprecating a version. It reuses
// the Hub's own strict manifest and index decoders, so the publish pipeline
// cannot write something the Hub would refuse.
package registrytool

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/catalogue"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/manifest"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/semver"
)

var (
	nameRE   = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// FillSpec says which image a manifest must be pinned to.
type FillSpec struct {
	Name, Version string // must equal the manifest's name and version (from the tag)
	Repository    string // expected image repository
	Tag, Digest   string // pushed tag and digest
}

// Fill pins the manifest's image (and an init image built from the same
// repository) to the pushed tag and digest, then re-validates the result
// with production rules (digest required). The manifest's identity and
// repository must match the tag being published.
func Fill(raw []byte, s FillSpec) ([]byte, error) {
	if !nameRE.MatchString(s.Name) || !semver.Valid(s.Version) || !digestRE.MatchString(s.Digest) || s.Tag == "" {
		return nil, errors.New("fill: invalid name, version, tag or digest")
	}
	m, err := manifest.Decode(raw, manifest.Options{AllowUnpinned: true})
	if err != nil {
		return nil, fmt.Errorf("fill: source manifest: %w", err)
	}
	if m.Name != s.Name || m.Version != s.Version {
		return nil, fmt.Errorf("fill: manifest is %s@%s, tag is %s@%s", m.Name, m.Version, s.Name, s.Version)
	}
	if m.Image.Repository != s.Repository {
		return nil, fmt.Errorf("fill: manifest image repository %q, expected %q", m.Image.Repository, s.Repository)
	}
	if m.Image.Tag != s.Tag {
		return nil, fmt.Errorf("fill: manifest image tag %q, pushed tag %q", m.Image.Tag, s.Tag)
	}
	m.Image.Digest = s.Digest
	if m.Init != nil && m.Init.Image.Repository == s.Repository {
		m.Init.Image.Tag, m.Init.Image.Digest = s.Tag, s.Digest
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	if _, err := manifest.Decode(buf.Bytes(), manifest.Options{}); err != nil {
		return nil, fmt.Errorf("fill: pinned manifest fails production validation: %w", err)
	}
	return buf.Bytes(), nil
}

// ManifestPath is the registry-relative path of a version's manifest.
func ManifestPath(name, version string) string {
	return path.Join("sensors", name, version, "manifest.json")
}

// Published reports whether a version is already in the registry checkout.
func Published(dir, name, version string) bool {
	_, err := os.Stat(filepath.Join(dir, filepath.FromSlash(ManifestPath(name, version))))
	return err == nil
}

// LoadIndex reads dir/index.json; a missing file yields an empty index.
func LoadIndex(dir string) (*catalogue.Index, error) {
	b, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if errors.Is(err, os.ErrNotExist) {
		return &catalogue.Index{SchemaVersion: catalogue.IndexSchemaVersion, Sensors: map[string]catalogue.IndexEntry{}}, nil
	}
	if err != nil {
		return nil, err
	}
	return catalogue.ParseIndex(b)
}

// Build regenerates the index from the manifests present in dir, carrying
// deprecation flags over from prev. Every listed manifest must decode with
// production rules, match its directory and have a Sigstore bundle.
func Build(dir string, prev *catalogue.Index, now time.Time) (*catalogue.Index, error) {
	ix := &catalogue.Index{SchemaVersion: catalogue.IndexSchemaVersion, GeneratedAt: now.UTC().Format(time.RFC3339), Sensors: map[string]catalogue.IndexEntry{}}
	names, err := os.ReadDir(filepath.Join(dir, "sensors"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, n := range names {
		if !n.IsDir() {
			continue
		}
		name := n.Name()
		if !nameRE.MatchString(name) {
			return nil, fmt.Errorf("index: invalid sensor directory %q", name)
		}
		vers, err := os.ReadDir(filepath.Join(dir, "sensors", name))
		if err != nil {
			return nil, err
		}
		e := catalogue.IndexEntry{Versions: map[string]catalogue.IndexVersion{}}
		for _, v := range vers {
			if !v.IsDir() {
				continue
			}
			ver := v.Name()
			if !semver.Valid(ver) {
				return nil, fmt.Errorf("index: %s: invalid version directory %q", name, ver)
			}
			rel := ManifestPath(name, ver)
			mp := filepath.Join(dir, filepath.FromSlash(rel))
			b, err := os.ReadFile(mp)
			if err != nil {
				return nil, fmt.Errorf("index: %s@%s: %w", name, ver, err)
			}
			m, err := manifest.Decode(b, manifest.Options{})
			if err != nil {
				return nil, fmt.Errorf("index: %s@%s: %w", name, ver, err)
			}
			if m.Name != name || m.Version != ver {
				return nil, fmt.Errorf("index: %s holds %s@%s", rel, m.Name, m.Version)
			}
			if _, err := os.Stat(mp + catalogue.BundleSuffix); err != nil {
				return nil, fmt.Errorf("index: %s@%s has no Sigstore bundle", name, ver)
			}
			dep := false
			if prev != nil {
				dep = prev.Sensors[name].Versions[ver].Deprecated
			}
			e.Versions[ver] = catalogue.IndexVersion{Manifest: rel, Deprecated: dep}
		}
		if len(e.Versions) == 0 {
			continue
		}
		e.Latest = latest(e)
		ix.Sensors[name] = e
	}
	if _, err := catalogue.ParseIndex(Marshal(ix)); err != nil {
		return nil, fmt.Errorf("generated index rejected by the Hub decoder: %w", err)
	}
	return ix, nil
}

// latest is the highest non-deprecated version, or "" if all are deprecated.
func latest(e catalogue.IndexEntry) string {
	best := ""
	for v, iv := range e.Versions {
		if !iv.Deprecated && (best == "" || semver.Less(best, v)) {
			best = v
		}
	}
	return best
}

// Deprecate marks the latest non-deprecated version of a sensor deprecated
// (§10 registry rollback) and returns it.
func Deprecate(ix *catalogue.Index, name string) (string, error) {
	e, ok := ix.Sensors[name]
	if !ok {
		return "", fmt.Errorf("sensor %q is not in the registry", name)
	}
	v := latest(e)
	if v == "" {
		return "", fmt.Errorf("every version of %s is already deprecated", name)
	}
	iv := e.Versions[v]
	iv.Deprecated = true
	e.Versions[v] = iv
	e.Latest = latest(e)
	ix.Sensors[name] = e
	return v, nil
}

// Marshal renders an index deterministically (sorted keys, indented).
func Marshal(ix *catalogue.Index) []byte {
	b, _ := json.MarshalIndent(ix, "", "  ") // maps marshal with sorted keys
	return append(b, '\n')
}

// Versions lists a sensor's versions in ascending precedence (for logs).
func Versions(e catalogue.IndexEntry) []string {
	out := make([]string, 0, len(e.Versions))
	for v := range e.Versions {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return semver.Less(out[i], out[j]) })
	return out
}
