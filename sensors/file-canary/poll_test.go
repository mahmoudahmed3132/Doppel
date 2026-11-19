// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The polling backend is the default off Linux; it is exercised here on every
// platform so Linux CI covers the macOS code path.
func TestPollingWatcher(t *testing.T) {
	dir := t.TempDir()
	lure := filepath.Join(dir, "passwords.xlsx")
	os.WriteFile(lure, []byte("bait"), 0o644)
	// Backdate atime/mtime so the first read advances atime under relatime
	// and noatime-free mounts, independent of timestamp granularity.
	old := time.Now().Add(-48 * time.Hour)
	os.Chtimes(lure, old, old)

	r := &rec{cfg: map[string]string{"TS_LURES": lure, "TS_ACCESS_COOLDOWN_SEC": "0", "TS_TAMPER_COOLDOWN_SEC": "0"}}
	w, err := NewWatcher(r, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	w.PollPeriod = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.runPoll(ctx) }()
	time.Sleep(60 * time.Millisecond)

	if _, ok := accessTime(mustStat(t, lure)); ok {
		// Only assert read detection where the platform exposes atime and the
		// mount updates it (not noatime).
		before := statLure(lure).atime
		os.ReadFile(lure)
		if statLure(lure).atime.After(before) {
			e := waitAction(t, r, "read")
			if e["_trigger"] != TriggerAccessed || e["_severity"] != "high" {
				t.Fatalf("%v", e)
			}
		} else {
			t.Log("atime not updated on this mount; read detection skipped")
		}
	}
	os.WriteFile(lure, []byte("changed!"), 0o644)
	if m := waitAction(t, r, "modify"); m["_trigger"] != TriggerTampered || m["_severity"] != "critical" {
		t.Fatalf("%v", m)
	}
	os.Chmod(lure, 0o600)
	waitAction(t, r, "attrib")
	os.Rename(lure, lure+".bak")
	waitAction(t, r, "delete")
	os.Rename(lure+".bak", lure)
	os.Remove(lure)
	os.WriteFile(lure, []byte("replacement"), 0o644)
	time.Sleep(60 * time.Millisecond)
	tmp := lure + ".tmp"
	os.WriteFile(tmp, []byte("replacement"), 0o644)
	os.Rename(tmp, lure) // same size and maybe mtime, different inode
	waitAction(t, r, "rename")

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func mustStat(t *testing.T, p string) os.FileInfo {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi
}
