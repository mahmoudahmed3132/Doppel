// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/auth"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/fleet"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ingest"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/liveness"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/nodekey"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported/stub"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ratelimit"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
)

// noCatalogue reports no sensor as known: secrets cannot be told apart (all
// masked) and no update is ever available.
type noCatalogue struct{}

func (noCatalogue) Latest(context.Context, string) (string, bool)               { return "", false }
func (noCatalogue) SecretKeys(context.Context, string, string) ([]string, bool) { return nil, false }

// portCompiler refuses duplicate TS_PORT values and emits a secret marker
// unless redaction is requested.
type portCompiler struct{}

func (portCompiler) Render(_ context.Context, n domain.Node, sensors []domain.Sensor, o fleet.RenderOptions) (fleet.Rendered, error) {
	seen := map[string]string{}
	var b strings.Builder
	for _, s := range sensors {
		if p := s.Config["TS_PORT"]; p != "" {
			if other, dup := seen[p]; dup {
				return fleet.Rendered{}, &fleet.RenderError{Status: 409, Code: "port_conflict", Message: other + " vs " + s.ID, SensorID: s.ID}
			}
			seen[p] = s.ID
		}
		secret := "tsk_REAL_SECRET"
		if o.Redact {
			secret = "<redacted>"
		}
		fmt.Fprintf(&b, "%s %s key=%s\n", s.ID, s.Version, secret)
	}
	return fleet.Rendered{Compose: []byte(b.String()), Revision: fmt.Sprintf("rev_%08x", len(b.String()))}, nil
}

type fleetHub struct {
	srv   *httptest.Server
	audit *auditLog
	c     *client
}

func newFleetHub(t *testing.T) *fleetHub {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "ts.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc, _ := auth.New(auth.Options{Store: db, Hasher: auth.NewHasher(auth.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1}, 4),
		TOTP: stub.TOTP{}, Log: log, Now: time.Now, SessionTTL: time.Hour, SessionIdle: time.Hour})
	tok, _ := svc.Init(ctx)

	keys := nodekey.NewAuthenticator(db)
	al := &auditLog{}
	admin := &Admin{Auth: svc, Settings: db, Audit: al, Log: log, Now: time.Now, Development: true}
	(&Fleet{Svc: &fleet.Service{Store: db, Compiler: portCompiler{}, Catalogue: noCatalogue{}, Keys: keys, Log: log, Now: time.Now}, Settings: db, Log: log}).Register(admin)

	pipe := &ingest.Pipeline{Store: db, Log: log, Now: time.Now}
	mux := http.NewServeMux()
	mux.Handle("/api/v3/", admin.Handler())
	(&Ingest{Auth: keys, Limiter: ratelimit.NewKeyed(100, 100), Store: db, Pipeline: pipe,
		Liveness: &liveness.Service{Store: db, Raiser: pipe, Log: log, Now: time.Now}, Log: log, Now: time.Now}).Register(mux)
	srv := httptest.NewServer(SecurityHeaders(Network{}, mux))
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	c := &client{t: t, http: &http.Client{Jar: jar}, base: srv.URL, origin: srv.URL}
	if code, out, _ := c.do("POST", "/api/v3/setup", map[string]string{"setup_token": tok, "password": adminPW, "public_endpoint": srv.URL}); code != 200 {
		t.Fatalf("setup %d %v", code, out)
	}
	if code, _, _ := c.do("POST", "/api/v3/session/login", map[string]string{"password": adminPW}); code != 200 {
		t.Fatal("login")
	}
	return &fleetHub{srv: srv, audit: al, c: c}
}

func (h *fleetHub) heartbeat(t *testing.T, key, sensor string) int {
	t.Helper()
	req, _ := http.NewRequest("POST", h.srv.URL+"/v3/ingest/heartbeats",
		strings.NewReader(`{"sensor_id":"`+sensor+`","config_revision":"rev_00000000","sdk_version":"3.0.0"}`))
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestFleetNodeKeyLifecycleEndToEnd(t *testing.T) {
	h := newFleetHub(t)
	code, out, _ := h.c.do("POST", "/api/v3/nodes", map[string]any{"alias": "dmz-1", "tags": []string{"pci"}})
	if code != 201 {
		t.Fatalf("%d %v", code, out)
	}
	key := out["node_key"].(string)
	nodeID := out["node"].(map[string]any)["id"].(string)
	link := out["link"].(map[string]any)
	if !strings.Contains(link["command"].(string), "TS_NODE_KEY='"+key+"' truesignal link '"+h.srv.URL+"'") {
		t.Fatalf("link command %v", link["command"])
	}
	if _, has := out["node"].(map[string]any)["key_hash"]; has {
		t.Fatal("key hash exposed")
	}

	// The key is never shown again.
	_, got, _ := h.c.do("GET", "/api/v3/nodes/"+nodeID, nil)
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), key) || strings.Contains(string(raw), key[4:]) {
		t.Fatal("node key returned by GET")
	}
	_, list, _ := h.c.do("GET", "/api/v3/nodes", nil)
	raw, _ = json.Marshal(list)
	if strings.Contains(string(raw), key) {
		t.Fatal("node key returned by list")
	}

	if code, out, _ := h.c.do("POST", "/api/v3/nodes/"+nodeID+"/sensors", map[string]any{"catalogue_name": "tcp-tarpit", "version": "1.0.0", "name": "ssh", "config": map[string]string{"TS_PORT": "22"}}); code != 201 {
		t.Fatalf("%d %v", code, out)
	}
	if c := h.heartbeat(t, key, "ts-sensor-ssh"); c != 200 {
		t.Fatalf("heartbeat with fresh key: %d", c)
	}

	code, out, _ = h.c.do("POST", "/api/v3/nodes/"+nodeID+"/key", nil)
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	newKey := out["node_key"].(string)
	if c := h.heartbeat(t, key, "ts-sensor-ssh"); c != 401 {
		t.Fatalf("old key after rotation: %d", c)
	}
	if c := h.heartbeat(t, newKey, "ts-sensor-ssh"); c != 200 {
		t.Fatalf("new key: %d", c)
	}

	if code, _, _ := h.c.do("DELETE", "/api/v3/nodes/"+nodeID, nil); code != 200 {
		t.Fatal("delete node")
	}
	if c := h.heartbeat(t, newKey, "ts-sensor-ssh"); c != 401 {
		t.Fatalf("deleted node's key: %d", c)
	}

	// Keys never reach the audit trail.
	h.audit.mu.Lock()
	b, _ := json.Marshal(h.audit.recs)
	h.audit.mu.Unlock()
	if strings.Contains(string(b), key[4:20]) || strings.Contains(string(b), newKey[4:20]) {
		t.Fatal("node key in audit records")
	}
	acts := strings.Join(h.audit.actions(), " ")
	for _, a := range []string{"node.create:201", "sensor.create:201", "node.rotate_key:200", "node.delete:200"} {
		if !strings.Contains(acts, a) {
			t.Errorf("missing audit %s in %s", a, acts)
		}
	}
}

func TestFleetSensorAPI(t *testing.T) {
	h := newFleetHub(t)
	_, out, _ := h.c.do("POST", "/api/v3/nodes", map[string]any{"alias": "n"})
	nodeID := out["node"].(map[string]any)["id"].(string)
	base := "/api/v3/nodes/" + nodeID

	add := func(name, port string) (int, map[string]any) {
		code, out, _ := h.c.do("POST", base+"/sensors", map[string]any{"catalogue_name": "tcp-tarpit", "version": "1.0.0", "name": name,
			"config": map[string]string{"TS_PORT": port, "TS_TOKEN": "hunter2"}})
		return code, out
	}
	code, out := add("a", "22")
	if code != 201 || out["sensor"].(map[string]any)["config"].(map[string]any)["TS_TOKEN"] != fleet.MaskedValue {
		t.Fatalf("%d %v", code, out)
	}
	code, out = add("b", "22")
	if code != 409 || out["error"] != "port_conflict" || out["sensor_id"] != "ts-sensor-b" {
		t.Fatalf("port conflict: %d %v", code, out)
	}
	if code, out := add("a", "23"); code != 409 || out["error"] != "sensor_exists" {
		t.Fatalf("duplicate: %d %v", code, out)
	}

	// Edit with null keeps the masked secret.
	code, out, _ = h.c.do("PATCH", base+"/sensors/ts-sensor-a", map[string]any{"config": map[string]any{"TS_PORT": "2222", "TS_TOKEN": nil}})
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	code, out, _ = h.c.do("GET", base+"/compose", nil)
	if code != 200 || out["redacted"] != true || strings.Contains(out["compose"].(string), "REAL_SECRET") {
		t.Fatalf("compose: %d %v", code, out)
	}
	code, out, _ = h.c.do("POST", base+"/compose/preview", map[string]any{"add": map[string]any{"catalogue_name": "tcp-tarpit", "version": "1.0.0", "name": "c", "config": map[string]string{"TS_PORT": "443"}}})
	if code != 200 || !strings.Contains(out["compose"].(string), "ts-sensor-c") {
		t.Fatalf("preview: %d %v", code, out)
	}
	_, nd, _ := h.c.do("GET", base, nil)
	if n := len(nd["node"].(map[string]any)["sensors"].([]any)); n != 1 {
		t.Fatalf("preview saved: %d sensors", n)
	}
	raw, _ := json.Marshal(nd)
	if strings.Contains(string(raw), "hunter2") {
		t.Fatal("secret config value returned")
	}

	if code, out, _ := h.c.do("POST", base+"/sensors/ts-sensor-a/silence", nil); code != 200 || out["silenced"] != true {
		t.Fatal("silence")
	}
	if code, out, _ := h.c.do("POST", base+"/sensors/ts-sensor-a/upgrade", map[string]string{"version": "1.1.0"}); code != 200 ||
		out["sensor"].(map[string]any)["version"] != "1.1.0" {
		t.Fatalf("upgrade: %d %v", code, out)
	}
	if code, out, _ := h.c.do("POST", base+"/sensors/ts-sensor-a/upgrade", map[string]string{}); code != 400 || out["error"] != "invalid_request" {
		t.Fatalf("upgrade to latest without catalogue: %d %v", code, out)
	}
	if code, _, _ := h.c.do("DELETE", base+"/sensors/ts-sensor-a", nil); code != 200 {
		t.Fatal("delete sensor")
	}

	// Path and body validation.
	for _, p := range []string{"/api/v3/nodes/node-XYZ", "/api/v3/nodes/../etc", base + "/sensors/evil_name/silence"} {
		method := "GET"
		if strings.HasSuffix(p, "silence") {
			method = "POST"
		}
		if code, _, _ := h.c.do(method, p, nil); code != 404 {
			t.Errorf("%s %s: %d", method, p, code)
		}
	}
	if code, out, _ := h.c.do("POST", "/api/v3/nodes", map[string]any{"alias": "x", "key": "tsk_mine"}); code != 400 || out["error"] != "unknown_field" {
		t.Fatalf("caller-chosen key: %d %v", code, out)
	}
}

func TestFleetRequiresFullSession(t *testing.T) {
	h := newFleetHub(t)
	anon := &client{t: t, http: &http.Client{}, base: h.srv.URL, origin: h.srv.URL}
	if code, _, _ := anon.do("GET", "/api/v3/nodes", nil); code != 401 {
		t.Fatal("nodes reachable without session")
	}
	h.c.origin = "https://evil.example"
	if code, _, _ := h.c.do("POST", "/api/v3/nodes", map[string]any{"alias": "x"}); code != 403 {
		t.Fatal("cross-origin node creation")
	}
}
