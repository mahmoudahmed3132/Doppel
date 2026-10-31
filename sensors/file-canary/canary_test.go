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

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/sdk/go/sensor"
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

func TestWatcherWithRealInotify(t *testing.T) {
	dir := t.TempDir()
	lure := filepath.Join(dir, "passwords.xlsx")
	other := filepath.Join(dir, "unrelated.txt")
	os.WriteFile(lure, []byte("bait"), 0o644)
	os.WriteFile(other, []byte("x"), 0o644)

	r := &rec{cfg: map[string]string{"TS_LURES": lure, "TS_ACCESS_COOLDOWN_SEC": "3600", "TS_TAMPER_COOLDOWN_SEC": "0"}}
	w, err := NewWatcher(r, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	w.RewatchPeriod = 50 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)

	os.ReadFile(other) // not a lure: ignored
	os.ReadFile(lure)
	e := waitAction(t, r, "open")
	if e["_trigger"] != TriggerAccessed || e["_severity"] != "high" || e["_source"] != "local" || e["category"] != "document" {
		t.Fatalf("%v", e)
	}
	os.ReadFile(lure) // within access cooldown: suppressed
	os.WriteFile(lure, []byte("changed"), 0o644)
	m := waitAction(t, r, "modify")
	if m["_trigger"] != TriggerTampered || m["_severity"] != "critical" {
		t.Fatalf("%v", m)
	}
	os.Chmod(lure, 0o600)
	waitAction(t, r, "attrib")
	os.Rename(lure, lure+".bak")
	waitAction(t, r, "rename")
	// Recreated lure stays covered (directory watch), then deleted.
	os.WriteFile(lure, []byte("again"), 0o644)
	os.Remove(lure)
	waitAction(t, r, "delete")

	// The directory itself disappears and comes back: the watch is re-armed.
	os.RemoveAll(dir)
	time.Sleep(100 * time.Millisecond)
	os.MkdirAll(dir, 0o755)
	time.Sleep(200 * time.Millisecond)
	r.mu.Lock()
	r.ev = nil
	r.mu.Unlock()
	os.WriteFile(lure, []byte("x"), 0o644)
	waitAction(t, r, "modify")

	for _, a := range r.actions() {
		if a == "" {
			t.Fatal("empty action")
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAccessAlertsCanBeDisabled(t *testing.T) {
	r := &rec{cfg: map[string]string{"TS_LURES": "/srv/x.txt", "TS_ACCESS_ALERTS": "false"}}
	w, _ := NewWatcher(r, func(string, ...any) {})
	w.access, w.tamper = sensor.NewSourceLimiter(0, 0), sensor.NewSourceLimiter(0, 0)
	w.event("/srv/x.txt", 0x20) // IN_OPEN
	w.event("/srv/x.txt", 0x02) // IN_MODIFY
	if a := r.actions(); len(a) != 1 || a[0] != "modify" {
		t.Fatalf("%v", a)
	}
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
	env := map[string]string{"TS_HUB_ENDPOINT": hub.URL, "TS_TEST_MODE": "true"}
	if code := sensor.Run(context.Background(), spec, sensor.Options{Getenv: func(k string) string { return env[k] },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}); code != 0 || len(got) != 1 || got[0]["trigger"] != TriggerAccessed {
		t.Fatalf("%d %v", code, got)
	}
}
