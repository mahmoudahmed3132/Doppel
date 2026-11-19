// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

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
