// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package catalogue

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/compose"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/fleet"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported/stub"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/secrets"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
)

// sig binds a signature to the exact bytes and identity (stand-in for
// Sigstore: the real verifier checks the certificate identity per §6.7).
func sig(manifest []byte, name, version string) string {
	h := sha256.Sum256(append(append(append([]byte{}, manifest...), name...), version...))
	return "sig:" + hex.EncodeToString(h[:])
}

type fakeVerifier struct {
	mu    sync.Mutex
	calls int
}

func (v *fakeVerifier) Verify(m, bundle []byte, name, version string) error {
	v.mu.Lock()
	v.calls++
	v.mu.Unlock()
	if string(bundle) != sig(m, name, version) {
		return errors.New("bad signature")
	}
	return nil
}

const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func manifestJSON(name, version string, extra string) []byte {
	return []byte(fmt.Sprintf(`{
 "schema_version": 3, "name": %q, "display_name": "Tarpit", "version": %q, "description": "d", "category": "network", "author": "a",
 "image": {"repository": "ghcr.io/example/truesignal-%s", "tag": %q, "digest": %q, "platforms": ["linux/amd64"]},
 "runtime": {"network_mode": "host", "listen_ports": [{"config_key": "TS_PORTS", "protocol": "tcp"}]},
 "config": [
  {"name": "TS_PORTS", "type": "list", "item_type": "port", "required": true, "description": "ports"},
  {"name": "TS_API_TOKEN", "type": "string", "secret": true, "description": "token"}
 ],
 "triggers": [{"name": "tcp_connection", "default_severity": "medium", "description": "x"}],
 "compatibility": {"hub_major": 3}%s}`, name, version, name, version, digest, extra))
}

type registry struct {
	mu    sync.Mutex
	files map[string][]byte
	down  bool
	srv   *httptest.Server
}

func newRegistry(t *testing.T) *registry {
	r := &registry{files: map[string][]byte{}}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.down {
			w.WriteHeader(503)
			return
		}
		if req.URL.Path == "/reg/redirect/index.json" {
			http.Redirect(w, req, "/reg/index.json", http.StatusFound)
			return
		}
		b, ok := r.files[strings.TrimPrefix(req.URL.Path, "/reg/")]
		if !ok {
			w.WriteHeader(404)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *registry) put(path string, b []byte) { r.mu.Lock(); r.files[path] = b; r.mu.Unlock() }

// publish adds a signed manifest; bundle "" = unsigned, "bad" = wrong signature.
func (r *registry) publish(name, version, bundle string, body []byte) string {
	p := fmt.Sprintf("sensors/%s/%s/manifest.json", name, version)
	r.put(p, body)
	switch bundle {
	case "":
	case "bad":
		r.put(p+BundleSuffix, []byte("sig:forged"))
	default:
		r.put(p+BundleSuffix, []byte(sig(body, name, version)))
	}
	return p
}

func (r *registry) index(entries map[string]IndexEntry) {
	b, _ := json.Marshal(Index{SchemaVersion: 1, Sensors: entries})
	r.put("index.json", b)
}

type settings map[string]string

func (s settings) Setting(_ context.Context, k string) (string, bool, error) {
	v, ok := s[k]
	return v, ok, nil
}

func newCatalogue(t *testing.T, r *registry, db *store.DB, v *fakeVerifier) *Catalogue {
	t.Helper()
	return &Catalogue{Store: db, Settings: settings{}, Verifier: v, Fetcher: NewHTTPFetcher(),
		DefaultURL: r.srv.URL + "/reg/", AllowHTTP: true, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: time.Now}
}

func openDB(t *testing.T) *store.DB {
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "ts.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func versionOf(t *testing.T, c *Catalogue, name, ver string) Version {
	t.Helper()
	v, _, ok := c.Details(context.Background(), name, ver)
	if !ok {
		t.Fatalf("%s %s not in catalogue", name, ver)
	}
	return *v
}

func setupRegistry(r *registry) {
	good := r.publish("tcp-tarpit", "1.0.0", "ok", manifestJSON("tcp-tarpit", "1.0.0", ""))
	good2 := r.publish("tcp-tarpit", "1.1.0", "ok", manifestJSON("tcp-tarpit", "1.1.0", ""))
	unsigned := r.publish("tcp-tarpit", "1.2.0", "", manifestJSON("tcp-tarpit", "1.2.0", ""))
	forged := r.publish("tcp-tarpit", "1.3.0", "bad", []byte(`this is not even JSON`))
	// Signed, but its content claims another version.
	mismatch := r.publish("tcp-tarpit", "1.4.0", "ok", nil)
	body := manifestJSON("tcp-tarpit", "9.9.9", "")
	r.put(mismatch, body)
	r.put(mismatch+BundleSuffix, []byte(sig(body, "tcp-tarpit", "1.4.0")))
	invalid := r.publish("tcp-tarpit", "1.5.0", "ok", manifestJSON("tcp-tarpit", "1.5.0", `, "privileged": true`))
	deprecated := r.publish("tcp-tarpit", "2.0.0", "ok", manifestJSON("tcp-tarpit", "2.0.0", ""))
	r.index(map[string]IndexEntry{"tcp-tarpit": {Latest: "1.2.0", Versions: map[string]IndexVersion{
		"1.0.0": {Manifest: good}, "1.1.0": {Manifest: good2}, "1.2.0": {Manifest: unsigned}, "1.3.0": {Manifest: forged},
		"1.4.0": {Manifest: mismatch}, "1.5.0": {Manifest: invalid}, "2.0.0": {Manifest: deprecated, Deprecated: true},
		"1.6.0": {Manifest: "sensors/tcp-tarpit/1.6.0/missing.json"},
	}}})
}

func TestRefreshVerifiesBeforeParsing(t *testing.T) {
	r := newRegistry(t)
	setupRegistry(r)
	c := newCatalogue(t, r, openDB(t), &fakeVerifier{})
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"1.0.0": "", "1.1.0": "", "1.2.0": ReasonUnsigned, "1.3.0": ReasonSignatureInvalid,
		"1.4.0": ReasonManifestMismatch, "1.5.0": ReasonInvalidManifest, "2.0.0": "", "1.6.0": ReasonFetchFailed}
	for ver, reason := range want {
		v := versionOf(t, c, "tcp-tarpit", ver)
		if v.Reason != reason || v.Available != (reason == "") {
			t.Errorf("%s: %+v, want reason %q", ver, v, reason)
		}
	}
	// 1.3.0 is garbage but signature-invalid, proving verification ran first.
	ctx := context.Background()
	// Latest ignores the index's "1.2.0" (unsigned) and the deprecated 2.0.0.
	if l, ok := c.Latest(ctx, "tcp-tarpit"); !ok || l != "1.1.0" {
		t.Fatalf("latest %q", l)
	}
	if _, err := c.Manifest(ctx, "tcp-tarpit", "1.2.0"); !errors.Is(err, compose.ErrManifestUnavailable) {
		t.Fatal("unsigned manifest served")
	}
	m, err := c.Manifest(ctx, "tcp-tarpit", "2.0.0")
	if err != nil || m.Status != "deprecated" {
		t.Fatalf("deprecated version must stay renderable, marked deprecated: %v %v", m, err)
	}
	keys, ok := c.SecretKeys(ctx, "tcp-tarpit", "1.0.0")
	if !ok || strings.Join(keys, ",") != "TS_API_TOKEN" {
		t.Fatalf("secret keys %v", keys)
	}
	list, st := c.List(ctx)
	if len(list) != 1 || list[0].Latest != "1.1.0" || list[0].Versions[0].Version != "2.0.0" || st.LastRefresh == nil || st.LastError != "" {
		t.Fatalf("list %+v %+v", list, st)
	}
}

func TestRefreshFailuresKeepCatalogue(t *testing.T) {
	r := newRegistry(t)
	setupRegistry(r)
	c := newCatalogue(t, r, openDB(t), &fakeVerifier{})
	ctx := context.Background()
	c.Refresh(ctx)

	r.mu.Lock()
	r.down = true
	r.mu.Unlock()
	if err := c.Refresh(ctx); err == nil {
		t.Fatal("outage not reported")
	}
	if _, err := c.Manifest(ctx, "tcp-tarpit", "1.0.0"); err != nil {
		t.Fatal("outage dropped the catalogue")
	}
	if _, st := c.List(ctx); st.LastError == "" {
		t.Fatal("last error not recorded")
	}
	r.mu.Lock()
	r.down = false
	r.mu.Unlock()

	// Redirects are not followed.
	c.Settings = settings{SettingRegistryURL: r.srv.URL + "/reg/redirect/"}
	if err := c.Refresh(ctx); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("redirect followed: %v", err)
	}
	c.Settings = settings{}

	// Oversized index; traversal in a manifest path.
	r.put("index.json", []byte(`{"schema_version":1,"sensors":{},"pad":"`+strings.Repeat("a", MaxIndexBytes)+`"}`))
	if err := c.Refresh(ctx); err == nil {
		t.Fatal("oversized index accepted")
	}
	r.index(map[string]IndexEntry{"evil": {Versions: map[string]IndexVersion{"1.0.0": {Manifest: "../../etc/passwd"}}}})
	if err := c.Refresh(ctx); err == nil {
		t.Fatal("path traversal accepted")
	}
	for _, p := range []string{"/abs.json", "https://evil/x.json", "a/./b.json", "a//b.json", "a/b.json?x=1"} {
		if safeRelPath(p) {
			t.Errorf("%q accepted", p)
		}
	}
	if _, err := ParseBase("http://registry.example/", false); err == nil {
		t.Fatal("plain http registry accepted outside development")
	}
}

func TestUnlistedVersionsStayRenderable(t *testing.T) {
	r := newRegistry(t)
	setupRegistry(r)
	c := newCatalogue(t, r, openDB(t), &fakeVerifier{})
	ctx := context.Background()
	c.Refresh(ctx)
	p := r.publish("tcp-tarpit", "1.1.0", "ok", manifestJSON("tcp-tarpit", "1.1.0", ""))
	r.index(map[string]IndexEntry{"tcp-tarpit": {Versions: map[string]IndexVersion{"1.1.0": {Manifest: p}}}})
	c.Refresh(ctx)
	if m, err := c.Manifest(ctx, "tcp-tarpit", "1.0.0"); err != nil || m.Status != "deprecated" {
		t.Fatalf("removed version not renderable: %v", err)
	}
	if l, _ := c.Latest(ctx, "tcp-tarpit"); l != "1.1.0" {
		t.Fatalf("latest %s", l)
	}
}

func TestCacheReverifiedOnLoad(t *testing.T) {
	r := newRegistry(t)
	setupRegistry(r)
	db := openDB(t)
	v := &fakeVerifier{}
	newCatalogue(t, r, db, v).Refresh(context.Background())
	r.srv.Close() // registry gone

	ctx := context.Background()
	c := newCatalogue(t, r, db, &fakeVerifier{})
	if err := c.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Manifest(ctx, "tcp-tarpit", "1.0.0"); err != nil {
		t.Fatal("cached manifest not available offline")
	}
	// A verifier that now rejects (revoked identity / no module) unloads it.
	c = newCatalogue(t, r, db, nil)
	c.Verifier = stub.RejectAllVerifier{}
	c.Load(ctx)
	if _, err := c.Manifest(ctx, "tcp-tarpit", "1.0.0"); err == nil {
		t.Fatal("cache served without passing re-verification")
	}
}

func TestDevUnsignedFlag(t *testing.T) {
	r := newRegistry(t)
	setupRegistry(r)
	c := newCatalogue(t, r, openDB(t), &fakeVerifier{})
	c.AllowUnsigned = true
	c.Refresh(context.Background())
	v := versionOf(t, c, "tcp-tarpit", "1.2.0")
	if !v.Available || v.Verified {
		t.Fatalf("dev unsigned: %+v", v)
	}
	// Still never parses garbage, and still enforces identity.
	if versionOf(t, c, "tcp-tarpit", "1.3.0").Available || versionOf(t, c, "tcp-tarpit", "1.4.0").Available {
		t.Fatal("dev flag accepted invalid or mismatched manifest")
	}
	if !versionOf(t, c, "tcp-tarpit", "1.0.0").Verified {
		t.Fatal("signed manifest not marked verified")
	}
}

// End to end: catalogue -> compiler -> fleet.
func TestCatalogueDrivesFleet(t *testing.T) {
	r := newRegistry(t)
	setupRegistry(r)
	db := openDB(t)
	ctx := context.Background()
	ep := "https://hub.example.com"
	db.PutSettings(ctx, map[string]*string{compose.SettingEndpoint: &ep})
	c := newCatalogue(t, r, db, &fakeVerifier{})
	c.Refresh(ctx)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	comp := &compose.Compiler{Manifests: c, Settings: db, Keys: &secrets.Keys{Store: db}, Log: log}
	svc := &fleet.Service{Store: db, Compiler: comp, Catalogue: c, Keys: noopKeys{}, Log: log, Now: time.Now}
	n, _, _ := svc.CreateNode(ctx, "n", nil)

	v, _, err := svc.AddSensor(ctx, n.ID, fleet.SensorSpec{CatalogueName: "tcp-tarpit", Version: "1.0.0",
		Config: map[string]string{"TS_PORTS": "22", "TS_API_TOKEN": "s3cret"}})
	if err != nil {
		t.Fatal(err)
	}
	if v.Config["TS_PORTS"] != "22" || v.Config["TS_API_TOKEN"] != fleet.MaskedValue || !v.UpdateAvailable || v.LatestVersion != "1.1.0" {
		t.Fatalf("view %+v", v)
	}
	if _, _, err := svc.AddSensor(ctx, n.ID, fleet.SensorSpec{Name: "x", CatalogueName: "tcp-tarpit", Version: "1.2.0",
		Config: map[string]string{"TS_PORTS": "23"}}); err == nil {
		t.Fatal("unsigned version deployable")
	}
	changed, _, err := svc.UpgradeNode(ctx, n.ID)
	if err != nil || len(changed) != 1 {
		t.Fatalf("upgrade %v %v", changed, err)
	}
	s, _ := db.Sensor(ctx, n.ID, "ts-sensor-tcp-tarpit")
	if s.Version != "1.1.0" {
		t.Fatalf("upgraded to %s, want 1.1.0 (not deprecated 2.0.0, not unsigned 1.2.0)", s.Version)
	}
	_ = domain.StatusPending
}

type noopKeys struct{}

func (noopKeys) Invalidate(string) {}
