// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/cli/internal/config"
	"github.com/mahmoudahmed3132/Doppel/cli/internal/discover"
)

const key = "tsk_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// fakeHub implements the node endpoints.
type fakeHub struct {
	mu       sync.Mutex
	major    string // required CLI major; "" = accept
	compose  string
	applied  []string
	versions []string
	srv      *httptest.Server
}

func newHub(t *testing.T) *fakeHub {
	h := &fakeHub{}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.versions = append(h.versions, r.Header.Get("X-TrueSignal-CLI-Version"))
		w.Header().Set("Content-Type", "application/json")
		if h.major != "" && !strings.HasPrefix(r.Header.Get("X-TrueSignal-CLI-Version"), h.major+".") {
			w.WriteHeader(426)
			io.WriteString(w, `{"ok":false,"error":"version_mismatch","required_major":`+h.major+`,"message":"x"}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+key {
			w.WriteHeader(401)
			io.WriteString(w, `{"ok":false,"error":"unauthorized","message":"invalid node key"}`)
			return
		}
		switch r.URL.Path {
		case "/v3/node/identity":
			io.WriteString(w, `{"ok":true,"node_id":"node-0000000a","alias":"dmz-1","desired_revision":"rev_00000001","applied_revision":"","hub_version":"3.0.0"}`)
		case "/v3/node/compose":
			io.WriteString(w, `{"ok":true,"revision":"rev_00000001","compose":`+h.compose+`,"warnings":[]}`)
		case "/v3/node/applied":
			var b map[string]string
			json.NewDecoder(r.Body).Decode(&b)
			h.applied = append(h.applied, b["result"])
			io.WriteString(w, `{"ok":true}`)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(h.srv.Close)
	return h
}

// fakeRunner records docker invocations.
type fakeRunner struct {
	mu    sync.Mutex
	calls []string
	ps    string
	names string
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, c)
	switch {
	case strings.Contains(c, " ps --all --format json"):
		return []byte(f.ps), nil
	case strings.HasPrefix(c, "docker ps --filter"):
		return []byte(f.names), nil
	}
	return nil, nil
}

func newApp(t *testing.T, env map[string]string) (*App, *bytes.Buffer, *bytes.Buffer, *fakeRunner) {
	t.Helper()
	dir := t.TempDir()
	var out, errb bytes.Buffer
	r := &fakeRunner{ps: `{"Service":"ts-sensor-a","State":"running","Status":"Up 3 seconds"}` + "\n"}
	exe := filepath.Join(dir, "bin", "truesignal")
	os.MkdirAll(filepath.Dir(exe), 0o755)
	os.WriteFile(exe, []byte("binary"), 0o755)
	a := &App{
		Version: "3.0.0", Paths: config.Paths{ConfigFile: filepath.Join(dir, "etc", "config.json"), WorkDir: filepath.Join(dir, "opt")},
		Getenv: func(k string) string { return env[k] }, Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb,
		Runner: r, Arch: "amd64", ProcRoot: dir, Exe: func() (string, error) { return exe, nil }, Settle: time.Millisecond,
	}
	return a, &out, &errb, r
}

func TestLinkSavesConfig0600(t *testing.T) {
	h := newHub(t)
	a, out, errb, _ := newApp(t, map[string]string{"TS_NODE_KEY": key})
	if code := a.Run(context.Background(), []string{"link", h.srv.URL}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	st, _ := os.Stat(a.Paths.ConfigFile)
	dst, _ := os.Stat(filepath.Dir(a.Paths.ConfigFile))
	if st.Mode().Perm() != 0o600 || dst.Mode().Perm() != 0o700 {
		t.Fatalf("modes %v %v", st.Mode().Perm(), dst.Mode().Perm())
	}
	cfg, err := config.Load(a.Paths)
	if err != nil || cfg.NodeID != "node-0000000a" || cfg.NodeKey != key {
		t.Fatalf("%+v %v", cfg, err)
	}
	if !strings.Contains(out.String(), "linked as node-0000000a (dmz-1)") || strings.Contains(out.String(), key) {
		t.Fatalf("output: %s", out)
	}
	if !strings.Contains(errb.String(), "plain HTTP") {
		t.Fatal("no warning for plain HTTP")
	}
	for _, v := range h.versions {
		if v != "3.0.0" {
			t.Fatalf("version header %q", v)
		}
	}

	// Wrong key: not saved.
	b, _, _, _ := newApp(t, map[string]string{"TS_NODE_KEY": "tsk_" + strings.Repeat("f", 64)})
	if code := b.Run(context.Background(), []string{"link", h.srv.URL}); code == 0 {
		t.Fatal("bad key linked")
	}
	if _, err := os.Stat(b.Paths.ConfigFile); err == nil {
		t.Fatal("config written for a rejected key")
	}
	c, _, _, _ := newApp(t, nil)
	if code := c.Run(context.Background(), []string{"link", h.srv.URL}); code == 0 {
		t.Fatal("link without key succeeded")
	}
}

func TestConfigWithLoosePermissionsRefused(t *testing.T) {
	a, _, errb, _ := newApp(t, nil)
	config.Save(a.Paths, &config.Config{HubEndpoint: "https://hub", NodeID: "node-0000000a", NodeKey: key})
	os.Chmod(a.Paths.ConfigFile, 0o644)
	if code := a.Run(context.Background(), []string{"apply"}); code == 0 || !strings.Contains(errb.String(), "chmod 600") {
		t.Fatalf("world-readable key accepted: %s", errb)
	}
}

func linked(t *testing.T, h *fakeHub, env map[string]string) (*App, *bytes.Buffer, *bytes.Buffer, *fakeRunner) {
	a, out, errb, r := newApp(t, env)
	if err := config.Save(a.Paths, &config.Config{HubEndpoint: h.srv.URL, NodeID: "node-0000000a", NodeKey: key}); err != nil {
		t.Fatal(err)
	}
	return a, out, errb, r
}

func TestVersionMismatchMessage(t *testing.T) {
	h := newHub(t)
	h.major = "4"
	a, _, errb, _ := linked(t, h, nil)
	if code := a.Run(context.Background(), []string{"apply"}); code == 0 {
		t.Fatal("apply succeeded against a newer Hub")
	}
	if !strings.Contains(errb.String(), "requires doppel CLI major version 4") || !strings.Contains(errb.String(), "This CLI is version 3.0.0") {
		t.Fatalf("unclear message: %s", errb)
	}
}

func TestApplyAndUninstallKeepsLures(t *testing.T) {
	h := newHub(t)
	lureDir := t.TempDir()
	lure := filepath.Join(lureDir, "passwords.xlsx")
	os.WriteFile(lure, []byte("bait"), 0o644)
	h.compose = `{"name":"truesignal","x-truesignal":{"node_id":"node-0000000a","revision":"rev_00000001","node_key_env":"TS_NODE_KEY","host_paths":["` + lure + `"]},
	 "services":{"ts-sensor-a":{"container_name":"ts-sensor-a","image":"x","environment":{},"volumes":[{"type":"bind","source":"` + lureDir + `","target":"` + lureDir + `","read_only":true}]}}}`
	a, out, errb, r := linked(t, h, nil)
	if code := a.Run(context.Background(), []string{"apply"}); code != 0 {
		t.Fatalf("apply: %s", errb)
	}
	if code := a.Run(context.Background(), []string{"apply"}); code != 0 || !strings.Contains(out.String(), "nothing to do") {
		t.Fatalf("second apply not a no-op: %s", out)
	}
	if strings.Join(h.applied, ",") != "applied,unchanged" {
		t.Fatalf("reports %v", h.applied)
	}

	// Uninstall needs confirmation.
	if code := a.Run(context.Background(), []string{"uninstall"}); code == 0 {
		t.Fatal("uninstall without confirmation")
	}
	out.Reset()
	a.Stdin = strings.NewReader("yes\n")
	if code := a.Run(context.Background(), []string{"uninstall"}); code != 0 {
		t.Fatalf("uninstall: %s", errb)
	}
	if _, err := os.Stat(lure); err != nil {
		t.Fatal("lure file removed")
	}
	if !strings.Contains(out.String(), lure) || !strings.Contains(out.String(), "delete node-0000000a in the Hub") {
		t.Fatalf("uninstall output: %s", out)
	}
	for _, p := range []string{a.Paths.WorkDir, a.Paths.ConfigFile} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("%s not removed", p)
		}
	}
	exe, _ := a.Exe()
	if _, err := os.Stat(exe); err == nil {
		t.Fatal("binary not removed")
	}
	last := r.calls[len(r.calls)-1]
	if !strings.HasPrefix(last, "docker compose -p truesignal -f ") || !strings.HasSuffix(last, "down --remove-orphans") {
		t.Fatalf("down call: %q", last)
	}
}

func TestArchGuard(t *testing.T) {
	h := newHub(t)
	a, _, errb, _ := linked(t, h, nil)
	a.Arch = "arm64"
	if code := a.Run(context.Background(), []string{"apply"}); code == 0 || !strings.Contains(errb.String(), "TS_ALLOW_NON_AMD64") {
		t.Fatalf("arm64 apply allowed: %s", errb)
	}
	h.compose = `{"x-truesignal":{"node_id":"node-0000000a"},"services":{}}`
	b, _, _, _ := linked(t, h, map[string]string{"TS_ALLOW_NON_AMD64": "true"})
	b.Arch = "arm64"
	if code := b.Run(context.Background(), []string{"apply"}); code != 0 {
		t.Fatal("override ignored")
	}
}

func TestStatusJSONAndFiredrill(t *testing.T) {
	h := newHub(t)
	h.compose = `{"x-truesignal":{"node_id":"node-0000000a","revision":"rev_00000001"},"services":{"ts-sensor-a":{"container_name":"ts-sensor-a","image":"x"}}}`
	a, out, _, r := linked(t, h, nil)
	a.Run(context.Background(), []string{"apply"})
	out.Reset()
	if code := a.Run(context.Background(), []string{"status", "--json"}); code != 0 {
		t.Fatal("status failed")
	}
	var st Status
	if err := json.Unmarshal(out.Bytes(), &st); err != nil {
		t.Fatalf("not JSON: %s", out)
	}
	if !st.HubReachable || st.NodeID != "node-0000000a" || !st.InSync || len(st.Containers) != 1 || strings.Contains(out.String(), key) {
		t.Fatalf("%+v", st)
	}

	r.names = "ts-sensor-a\nts-sensor-b\n"
	out.Reset()
	if code := a.Run(context.Background(), []string{"firedrill"}); code != 0 {
		t.Fatal("firedrill failed")
	}
	var kills []string
	for _, c := range r.calls {
		if strings.HasPrefix(c, "docker kill") {
			kills = append(kills, c)
		}
	}
	if strings.Join(kills, ";") != "docker kill --signal SIGUSR1 ts-sensor-a;docker kill --signal SIGUSR1 ts-sensor-b" {
		t.Fatalf("%v", kills)
	}
}

func TestDiscoverPlanJSONAndApply(t *testing.T) {
	var mu sync.Mutex
	var registered []map[string]any
	applied := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v3/session/login":
			http.SetCookie(w, &http.Cookie{Name: "ts_session", Value: "demo-sess", Path: "/"})
			io.WriteString(w, `{"ok":true}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v3/session/logout":
			io.WriteString(w, `{"ok":true}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v3/catalogue":
			io.WriteString(w, `{"ok":true,"sensors":[
				{"name":"remote-access-decoy","latest":"1.0.0"},
				{"name":"database-decoy","latest":"1.0.0"}
			]}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v3/catalogue/remote-access-decoy/1.0.0":
			io.WriteString(w, `{"ok":true,"manifest":{
				"name":"remote-access-decoy","display_name":"Remote access decoy","version":"1.0.0",
				"runtime":{"listen_ports":[{"config_key":"TS_SSH_PORT","protocol":"tcp","enabled_key":"TS_ENABLE_SSH"}]},
				"config":[
					{"name":"TS_ENABLE_SSH","type":"bool","default":"true"},
					{"name":"TS_SSH_PORT","type":"port","default":"22"}
				],
				"discovery":{"process_names":["sshd"],"listening_ports":[22],"defaults":{"TS_SSH_PORT":"free_port(2222)"}}
			}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v3/catalogue/database-decoy/1.0.0":
			io.WriteString(w, `{"ok":true,"manifest":{
				"name":"database-decoy","display_name":"Database decoy","version":"1.0.0",
				"runtime":{"listen_ports":[{"config_key":"TS_POSTGRES_PORT","protocol":"tcp","enabled_key":"TS_ENABLE_POSTGRES"}]},
				"config":[
					{"name":"TS_ENABLE_POSTGRES","type":"bool","default":"true"},
					{"name":"TS_POSTGRES_PORT","type":"port","default":"5432"}
				],
				"discovery":{"process_names":["postgres"],"listening_ports":[5432],"defaults":{"TS_POSTGRES_PORT":"free_port(5432)"}}
			}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v3/nodes/node-0000000a":
			io.WriteString(w, `{"ok":true,"node":{"sensors":[]}}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v3/nodes/node-0000000a/sensors":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			registered = append(registered, body)
			io.WriteString(w, `{"ok":true,"sensor":{"id":"ts-sensor-new"}}`)
		case r.URL.Path == "/v3/node/compose":
			io.WriteString(w, `{"ok":true,"revision":"rev_00000002","compose":{"name":"truesignal","x-truesignal":{"node_id":"node-0000000a","revision":"rev_00000002","node_key_env":"TS_NODE_KEY"},"services":{}},"warnings":[]}`)
		case r.URL.Path == "/v3/node/applied":
			applied = true
			io.WriteString(w, `{"ok":true}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	// Build fake /proc with sshd on tcp/22 and no postgres.
	procDir := t.TempDir()
	os.MkdirAll(filepath.Join(procDir, "net"), 0o755)
	os.MkdirAll(filepath.Join(procDir, "100/fd"), 0o755)
	os.WriteFile(filepath.Join(procDir, "net/tcp"), []byte(
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
			"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0\n"), 0o644)
	os.WriteFile(filepath.Join(procDir, "100/comm"), []byte("sshd\n"), 0o644)
	os.Symlink("socket:[1001]", filepath.Join(procDir, "100/fd/3"))

	newDiscoverApp := func(stdin string) (*App, *bytes.Buffer, *bytes.Buffer) {
		a, out, errb, _ := newApp(t, map[string]string{"TS_ADMIN_PASSWORD": "pw"})
		config.Save(a.Paths, &config.Config{HubEndpoint: srv.URL, NodeID: "node-0000000a", NodeKey: key})
		a.ProcRoot = procDir
		a.Stdin = strings.NewReader(stdin)
		a.DiscoverEnv = &discover.Env{
			FileExists: func(string) bool { return false },
			BindFree:   func(_ string, port int) bool { return port != 22 },
			Hostname:   func() (string, error) { return "demo-host", nil },
		}
		return a, out, errb
	}

	// 1. --plan + --apply must fail with exit 2.
	a0, _, err0 := newDiscoverApp("")
	if code := a0.Run(context.Background(), []string{"discover", "--plan", "--apply"}); code != 2 {
		t.Fatalf("--plan --apply exit = %d, want 2: %s", code, err0)
	}

	// 2. --json outputs clean JSON plan and does not register anything.
	a1, out1, err1 := newDiscoverApp("")
	if code := a1.Run(context.Background(), []string{"discover", "--json"}); code != 0 {
		t.Fatalf("discover --json exit %d: %s", code, err1)
	}
	var plan discover.Plan
	if err := json.Unmarshal(out1.Bytes(), &plan); err != nil {
		t.Fatalf("discover --json invalid JSON: %v\n%s", err, out1)
	}
	if len(plan.Proposals) != 2 || plan.Proposals[0].Name != "remote-access-decoy" || plan.Proposals[0].Config["TS_SSH_PORT"] != "2222" {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if plan.Proposals[1].Name != "database-decoy" || plan.Proposals[1].Config["TS_POSTGRES_PORT"] != "5432" {
		t.Fatalf("unexpected second proposal: %+v", plan.Proposals[1])
	}
	if len(registered) != 0 || applied {
		t.Fatalf("--json mutated Hub: registered=%d applied=%v", len(registered), applied)
	}

	// 3. --plan prints human summary and does not register anything.
	a2, out2, err2 := newDiscoverApp("")
	if code := a2.Run(context.Background(), []string{"discover", "--plan"}); code != 0 {
		t.Fatalf("discover --plan exit %d: %s", code, err2)
	}
	if !strings.Contains(out2.String(), "doppel discover --apply") || !strings.Contains(out2.String(), "tcp/2222") {
		t.Fatalf("unexpected --plan output: %s", out2)
	}
	if len(registered) != 0 || applied {
		t.Fatalf("--plan mutated Hub")
	}

	// 4. --apply with interactive confirmation ("y\nn\n") deploys only the confirmed sensor and runs apply.
	a3, out3, err3 := newDiscoverApp("y\nn\n")
	if code := a3.Run(context.Background(), []string{"discover", "--apply"}); code != 0 {
		t.Fatalf("discover --apply exit %d: %s\nout: %s", code, err3, out3)
	}
	if len(registered) != 1 || registered[0]["catalogue_name"] != "remote-access-decoy" || !applied {
		t.Fatalf("registered=%v applied=%v", registered, applied)
	}
}
