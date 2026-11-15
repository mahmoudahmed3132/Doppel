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
