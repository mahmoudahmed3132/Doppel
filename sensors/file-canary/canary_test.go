// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

var ht = Honeytoken{ID: "ht_1", Username: "svc_backup", Secret: "S3cr3t-honey"}

func TestCreateLuresNeverOverwritesOrFollowsLinks(t *testing.T) {
	dir := t.TempDir()
	fresh := filepath.Join(dir, "passwords.txt")
	existing := filepath.Join(dir, "existing.env")
	os.WriteFile(existing, []byte("real data"), 0o600)
	target := filepath.Join(dir, "shadow")
	os.WriteFile(target, []byte("victim"), 0o600)
	link := filepath.Join(dir, "planted.cfg")
	os.Symlink(target, link)
	missing := filepath.Join(dir, "nodir", "x.txt")

	var log bytes.Buffer
	created, err := CreateLures([]string{fresh, existing, link, missing}, ht, stubLures{}, &log)
	if err == nil || !strings.Contains(err.Error(), "parent directory missing") {
		t.Fatalf("missing parent not reported: %v", err)
	}
	if len(created) != 1 || created[0] != fresh {
		t.Fatalf("created %v", created)
	}
	b, _ := os.ReadFile(fresh)
	if !strings.Contains(string(b), "svc_backup") || !strings.Contains(string(b), "S3cr3t-honey") {
		t.Fatal("honeytoken not embedded")
	}
	if b, _ := os.ReadFile(existing); string(b) != "real data" {
		t.Fatal("existing file overwritten")
	}
	if b, _ := os.ReadFile(target); string(b) != "victim" {
		t.Fatal("symlink followed")
	}
}

func TestInitModeRequiresHoneytoken(t *testing.T) {
	dir := t.TempDir()
	env := map[string]string{"TS_LURES": filepath.Join(dir, "a.txt")}
	var errb bytes.Buffer
	if code := runInit(func(k string) string { return env[k] }, &errb); code == 0 {
		t.Fatal("init without honeytoken succeeded")
	}
	b, _ := json.Marshal(ht)
	env["TS_HONEYTOKEN"] = string(b)
	if code := runInit(func(k string) string { return env[k] }, &errb); code != 0 {
		t.Fatalf("init failed: %s", errb.String())
	}
	if _, err := os.Stat(env["TS_LURES"]); err != nil {
		t.Fatal("lure not created")
	}
	for _, bad := range []string{"relative/path", "/a/../b", ""} {
		if _, err := LurePaths(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

type rec struct {
	mu  sync.Mutex
	ev  []map[string]any
	cfg map[string]string
}

func (r *rec) ReportSeverity(sev sensor.Severity, trig, src, _ string, d sensor.Details) {
	m := map[string]any{"_trigger": trig, "_severity": string(sev), "_source": src}
	for _, f := range d.(sensor.Fields) {
		m[f.Key] = f.Value
	}
	r.mu.Lock()
	r.ev = append(r.ev, m)
	r.mu.Unlock()
}
func (r *rec) Setting(k string) (string, bool) { v, ok := r.cfg[k]; return v, ok }
func (r *rec) actions() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, e := range r.ev {
		out = append(out, e["action"].(string))
	}
	return out
}

func waitAction(t *testing.T, r *rec, action string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		for _, e := range r.ev {
			if e["action"] == action {
				r.mu.Unlock()
				return e
			}
		}
		r.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no %q event; got %v", action, r.actions())
	return nil
}

func TestTestModeAgainstMockHub(t *testing.T) {
	var got []map[string]any
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b struct{ Events []map[string]any }
		json.NewDecoder(r.Body).Decode(&b)
		got = append(got, b.Events...)
		io.WriteString(w, `{"ok":true,"accepted":1,"duplicates":0,"rejected":[]}`)
	}))
	defer hub.Close()
	env := map[string]string{"TS_HUB_ENDPOINT": hub.URL, "TS_TEST_MODE": "true", "TS_DEV_ALLOW_HTTP": "true"}
	if code := sensor.Run(context.Background(), spec, sensor.Options{Getenv: func(k string) string { return env[k] },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}); code != 0 || len(got) != 1 || got[0]["trigger"] != TriggerAccessed {
		t.Fatalf("%d %v", code, got)
	}
}
