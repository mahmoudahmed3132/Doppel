// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package catalogue

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Registry limits (§6.7).
const (
	MaxIndexBytes    = 1 << 20
	MaxManifestBytes = 256 << 10
	MaxBundleBytes   = 256 << 10
	MaxSensors       = 500
	MaxVersions      = 200
)

// IndexSchemaVersion is the registry index format version.
const IndexSchemaVersion = 1

// BundleSuffix names the detached Sigstore bundle next to a manifest.
const BundleSuffix = ".sigstore.json"

// Index is the registry's index.json.
type Index struct {
	SchemaVersion int                   `json:"schema_version"`
	GeneratedAt   string                `json:"generated_at,omitempty"`
	Sensors       map[string]IndexEntry `json:"sensors"`
}

// IndexEntry lists the published versions of one sensor. Latest is
// advisory: the Hub computes the latest verified, non-deprecated version.
type IndexEntry struct {
	Latest   string                  `json:"latest"`
	Versions map[string]IndexVersion `json:"versions"`
}

// IndexVersion locates one manifest.
type IndexVersion struct {
	Manifest   string `json:"manifest"` // path relative to the registry base
	Deprecated bool   `json:"deprecated"`
}

var (
	kebabRE  = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	semverRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$`)
	relRE    = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$`)
)

// ParseIndex strictly decodes and validates an index.
func ParseIndex(b []byte) (*Index, error) {
	if len(b) > MaxIndexBytes {
		return nil, fmt.Errorf("index exceeds %d bytes", MaxIndexBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var ix Index
	if err := dec.Decode(&ix); err != nil {
		return nil, fmt.Errorf("index: %w", err)
	}
	if dec.More() {
		return nil, errors.New("index: trailing data")
	}
	if ix.SchemaVersion != IndexSchemaVersion {
		return nil, fmt.Errorf("index: schema_version must be %d", IndexSchemaVersion)
	}
	if len(ix.Sensors) > MaxSensors {
		return nil, fmt.Errorf("index: more than %d sensors", MaxSensors)
	}
	for name, e := range ix.Sensors {
		if !kebabRE.MatchString(name) || len(name) > 64 {
			return nil, errors.New("index: sensor name is not kebab-case")
		}
		if len(e.Versions) == 0 || len(e.Versions) > MaxVersions {
			return nil, fmt.Errorf("index: %s must list 1..%d versions", name, MaxVersions)
		}
		if e.Latest != "" && !semverRE.MatchString(e.Latest) {
			return nil, fmt.Errorf("index: %s latest is not SemVer", name)
		}
		for v, iv := range e.Versions {
			if !semverRE.MatchString(v) {
				return nil, fmt.Errorf("index: %s has a non-SemVer version", name)
			}
			if !safeRelPath(iv.Manifest) {
				return nil, fmt.Errorf("index: %s %s manifest path is not a safe relative path", name, v)
			}
		}
	}
	return &ix, nil
}

// safeRelPath accepts relative paths of plain segments only: no scheme,
// no leading slash, no "." or ".." segments, no query or fragment.
func safeRelPath(p string) bool {
	if len(p) == 0 || len(p) > 512 || !relRE.MatchString(p) {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}
