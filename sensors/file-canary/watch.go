// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"path/filepath"
	"sort"
	"time"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

// Triggers.
const (
	TriggerAccessed = "decoy_file_accessed"
	TriggerTampered = "decoy_file_tampered"
)

// Watcher reports access to and tampering with lure files. It watches
// the parent directories, so a lure that is deleted and recreated stays
// covered, and re-adds a directory watch that disappears.
type Watcher struct {
	Lures         map[string]bool // absolute lure paths
	AccessAlerts  bool
	AccessCool    time.Duration
	TamperCool    time.Duration
	R             sensor.Reporter
	Gen           LureGenerator
	Log           func(msg string, args ...any)
	RewatchPeriod time.Duration
	PollPeriod    time.Duration // stat polling interval (non-Linux backend)

	access *sensor.SourceLimiter
	tamper *sensor.SourceLimiter
	fd     int
	wds    map[int32]string // watch descriptor -> directory (inotify backend)
}

// dirs returns the distinct parent directories of the lures.
func (w *Watcher) dirs() []string {
	set := map[string]bool{}
	for p := range w.Lures {
		set[filepath.Dir(p)] = true
	}
	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// init applies defaults and builds the cooldown limiters.
func (w *Watcher) init() {
	if w.RewatchPeriod == 0 {
		w.RewatchPeriod = 5 * time.Second
	}
	if w.PollPeriod == 0 {
		w.PollPeriod = time.Second
	}
	w.access = sensor.NewSourceLimiter(w.AccessCool, 0)
	w.tamper = sensor.NewSourceLimiter(w.TamperCool, 0)
}

// report emits one access or tamper event, subject to the cooldowns.
func (w *Watcher) report(path, action string, tamper bool) {
	trig, sev, lim, key := TriggerAccessed, sensor.SeverityHigh, w.access, path
	if tamper {
		trig, sev, lim, key = TriggerTampered, sensor.SeverityCritical, w.tamper, path+"|"+action
	} else if !w.AccessAlerts {
		return
	}
	allowed, suppressed := lim.Allow(key)
	if !allowed {
		return
	}
	// The sensor cannot see the actor; the SOC correlates with EDR.
	w.R.ReportSeverity(sev, trig, "local", path, sensor.Fields{
		sensor.F("path", path), sensor.F("action", action), sensor.F("category", w.Gen.Category(path)),
		sensor.F("suppressed_since_last", suppressed),
	})
}
