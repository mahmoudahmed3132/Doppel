// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package catalogue

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/manifest"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/signing"
)

// published registry content: the registry branch as the publish-sensor.yml
// workflow of this repository wrote it for the five 1.0.0 releases.
const publishedRegistry = "../signing/testdata/registry"

// productionCatalogue serves dir over TLS and builds a catalogue the way a
// production Hub does: real Sigstore verifier (embedded root, this
// repository's identity), https only, no unsigned or unpinned allowances.
func productionCatalogue(t *testing.T, dir string) *Catalogue {
	t.Helper()
	srv := httptest.NewTLSServer(http.StripPrefix("/registry/", http.FileServer(http.Dir(dir))))
	t.Cleanup(srv.Close)
	tm, err := signing.TrustedRoot("")
	if err != nil {
		t.Fatal(err)
	}
	v, err := signing.New(tm, signing.DefaultSignerRepo)
	if err != nil {
		t.Fatal(err)
	}
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Catalogue{Store: openDB(t), Settings: settings{}, Verifier: v, Fetcher: &HTTPFetcher{Client: client},
		DefaultURL: srv.URL + "/registry/", AllowHTTP: false, AllowUnsigned: false, Options: manifest.Options{},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: time.Now}
}

func available(c *Catalogue) map[string]Version {
	sensors, _ := c.List(context.Background())
	out := map[string]Version{}
	for _, s := range sensors {
		for _, v := range s.Versions {
			out[s.Name+"@"+v.Version] = v
		}
	}
	return out
}

// Step-1 acceptance: a production Hub lists the five published 1.0.0 sensors
// from the registry branch, verified, and survives a restart (cache
// re-verified on load).
func TestProductionHubListsPublishedSensors(t *testing.T) {
	c := productionCatalogue(t, publishedRegistry)
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := available(c)
	want := []string{"file-canary@1.0.0", "icmp-canary@1.0.0", "network-scan-detector@1.0.0", "tcp-tarpit@1.0.0", "web-router-decoy@1.0.0"}
	var keys []string
	for k, v := range got {
		if !v.Available || !v.Verified {
			t.Errorf("%s not available/verified: %+v", k, v)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) != len(want) {
		t.Fatalf("listed %v, want %v", keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("listed %v, want %v", keys, want)
		}
	}
	for _, n := range []string{"tcp-tarpit", "web-router-decoy"} {
		if _, ok := c.Latest(context.Background(), n); !ok {
			t.Errorf("%s has no latest version", n)
		}
	}
	// Restart: a new catalogue on the same database re-verifies the cache.
	c2 := &Catalogue{Store: c.Store, Settings: c.Settings, Verifier: c.Verifier, Fetcher: c.Fetcher,
		DefaultURL: c.DefaultURL, Log: c.Log, Now: time.Now}
	if err := c2.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(available(c2)); n != 5 {
		t.Fatalf("after reload %d versions listed", n)
	}
}

// One modified byte in one published manifest makes exactly that version
// unavailable; the others stay usable.
func TestProductionHubRefusesTamperedManifest(t *testing.T) {
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(publishedRegistry)); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "sensors/tcp-tarpit/1.0.0/manifest.json")
	b, _ := os.ReadFile(p)
	if err := os.WriteFile(p, append(b, ' '), 0o644); err != nil {
		t.Fatal(err)
	}
	c := productionCatalogue(t, dir)
	c.Refresh(context.Background())
	got := available(c)
	if v := got["tcp-tarpit@1.0.0"]; v.Available || v.Verified {
		t.Fatalf("tampered manifest accepted: %+v", v)
	}
	if v := got["icmp-canary@1.0.0"]; !v.Available {
		t.Fatalf("untouched sensor lost: %+v", v)
	}
	if _, ok := c.Latest(context.Background(), "tcp-tarpit"); ok {
		t.Fatal("tampered sensor still offered as latest")
	}
}
