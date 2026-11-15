// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package registrytool

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/catalogue"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/manifest"
)

const digest = "sha256:" + "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12"

func repoManifests(t *testing.T) map[string][]byte {
	t.Helper()
	paths, _ := filepath.Glob("../../../sensors/*/manifest.json")
	if len(paths) < 5 {
		t.Fatalf("found %d sensor manifests", len(paths))
	}
	out := map[string][]byte{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.Base(filepath.Dir(p))] = b
	}
	return out
}

func spec(t *testing.T, raw []byte) FillSpec {
	m, err := manifest.Decode(raw, manifest.Options{AllowUnpinned: true})
	if err != nil {
		t.Fatal(err)
	}
	return FillSpec{Name: m.Name, Version: m.Version, Repository: m.Image.Repository, Tag: m.Image.Tag, Digest: digest}
}

// Every sensor in the repository can be pinned and then passes the Hub's
// production validation (digest required), including file-canary's init
// image built from the same repository.
func TestFillAllRepositoryManifests(t *testing.T) {
	for dir, raw := range repoManifests(t) {
		s := spec(t, raw)
		if s.Name != dir {
			t.Errorf("%s: manifest name %s", dir, s.Name)
		}
		if !strings.HasPrefix(s.Repository, "ghcr.io/mahmoudahmed3132/ts-sensor-") {
			t.Errorf("%s: image repository %s outside the project namespace (Q60)", dir, s.Repository)
		}
		out, err := Fill(raw, s)
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		m, err := manifest.Decode(out, manifest.Options{})
		if err != nil || m.Image.Digest != digest {
			t.Fatalf("%s: %v", dir, err)
		}
		if m.Init != nil && m.Init.Image.Repository == s.Repository && m.Init.Image.Digest != digest {
			t.Errorf("%s: init image not pinned", dir)
		}
	}
}

func TestFillRefusesMismatch(t *testing.T) {
	raw := repoManifests(t)["tcp-tarpit"]
	good := spec(t, raw)
	for name, mut := range map[string]func(*FillSpec){
		"version":    func(s *FillSpec) { s.Version = "9.9.9" },
		"name":       func(s *FillSpec) { s.Name = "icmp-canary" },
		"repository": func(s *FillSpec) { s.Repository = "ghcr.io/evil/x" },
		"tag":        func(s *FillSpec) { s.Tag = "latest" },
		"digest":     func(s *FillSpec) { s.Digest = "sha256:short" },
	} {
		s := good
		mut(&s)
		if _, err := Fill(raw, s); err == nil {
			t.Errorf("%s mismatch accepted", name)
		}
	}
}

// publish writes a pinned manifest (and optionally its bundle) the way the
// workflow does.
func publish(t *testing.T, dir, version string, bundle bool) {
	t.Helper()
	raw := repoManifests(t)["tcp-tarpit"]
	var m map[string]any
	json.Unmarshal(raw, &m)
	m["version"] = version
	m["image"].(map[string]any)["tag"] = version
	raw, _ = json.Marshal(m)
	s := spec(t, raw)
	out, err := Fill(raw, s)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, filepath.FromSlash(ManifestPath("tcp-tarpit", version)))
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, out, 0o644)
	if bundle {
		os.WriteFile(p+catalogue.BundleSuffix, []byte(`{}`), 0o644)
	}
}

func TestIndexLatestDeprecateAndRollback(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
	publish(t, dir, "1.0.0", true)
	publish(t, dir, "1.10.0", true)
	publish(t, dir, "1.2.0", true)
	if !Published(dir, "tcp-tarpit", "1.2.0") || Published(dir, "tcp-tarpit", "2.0.0") {
		t.Fatal("Published")
	}
	ix, err := Build(dir, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if ix.Sensors["tcp-tarpit"].Latest != "1.10.0" {
		t.Fatalf("latest %q (SemVer, not lexical)", ix.Sensors["tcp-tarpit"].Latest)
	}
	// Rollback deprecates the latest; the next highest becomes latest.
	v, err := Deprecate(ix, "tcp-tarpit")
	if err != nil || v != "1.10.0" || ix.Sensors["tcp-tarpit"].Latest != "1.2.0" {
		t.Fatalf("%s %v %q", v, err, ix.Sensors["tcp-tarpit"].Latest)
	}
	os.WriteFile(filepath.Join(dir, "index.json"), Marshal(ix), 0o644)
	// A later publish keeps the deprecation.
	publish(t, dir, "1.3.0", true)
	prev, err := LoadIndex(dir)
	if err != nil {
		t.Fatal(err)
	}
	ix, err = Build(dir, prev, now)
	if err != nil {
		t.Fatal(err)
	}
	e := ix.Sensors["tcp-tarpit"]
	if !e.Versions["1.10.0"].Deprecated || e.Latest != "1.3.0" {
		t.Fatalf("%+v", e)
	}
	for range 3 {
		Deprecate(ix, "tcp-tarpit")
	}
	if _, err := Deprecate(ix, "tcp-tarpit"); err == nil || ix.Sensors["tcp-tarpit"].Latest != "" {
		t.Fatal("all deprecated must leave latest empty and refuse further rollback")
	}
	if _, err := catalogue.ParseIndex(Marshal(ix)); err != nil {
		t.Fatalf("Hub refuses the index: %v", err)
	}
	if _, err := Deprecate(ix, "nope"); err == nil {
		t.Fatal("unknown sensor")
	}
	// Deterministic output.
	if string(Marshal(ix)) != string(Marshal(ix)) {
		t.Fatal("non-deterministic")
	}
}

func TestIndexRefusesUnsignedOrMisplaced(t *testing.T) {
	dir := t.TempDir()
	publish(t, dir, "1.0.0", false)
	if _, err := Build(dir, nil, time.Now()); err == nil || !strings.Contains(err.Error(), "Sigstore bundle") {
		t.Fatalf("unsigned version indexed: %v", err)
	}
	dir = t.TempDir()
	publish(t, dir, "1.0.0", true)
	os.Rename(filepath.Join(dir, "sensors/tcp-tarpit/1.0.0"), filepath.Join(dir, "sensors/tcp-tarpit/1.0.1"))
	if _, err := Build(dir, nil, time.Now()); err == nil {
		t.Fatal("manifest in the wrong version directory indexed")
	}
	dir = t.TempDir()
	publish(t, dir, "1.0.0", true)
	p := filepath.Join(dir, "sensors/tcp-tarpit/1.0.0/manifest.json")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.Replace(string(b), digest, "", 1)), 0o644)
	if _, err := Build(dir, nil, time.Now()); err == nil {
		t.Fatal("unpinned manifest indexed")
	}
}
