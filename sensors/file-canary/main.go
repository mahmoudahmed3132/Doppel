// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Command file-canary plants lure files and reports access to and
// tampering with them (§11.4). `file-canary init` runs in the init
// container (no network) and creates missing lures; without arguments it
// is the sensor that watches them read-only.
package main

import (
	"context"
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

// lures is the content generator; replaced by the PORTED module on import.
var lures LureGenerator = generatedLures{}

var spec = sensor.Spec{
	Drill: sensor.Drill{
		Trigger: TriggerAccessed, Target: "/fire-drill/lure", Severity: sensor.SeverityHigh,
		Details: sensor.Fields{sensor.F("path", "/fire-drill/lure"), sensor.F("action", "open"), sensor.F("category", "drill")},
	},
	Run: run,
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		os.Exit(runInit(os.Getenv, os.Stderr))
	}
	sensor.Main(spec)
}

func seconds(r sensor.Reporter, k string, def int) (time.Duration, error) {
	v, ok := r.Setting(k)
	if !ok {
		return time.Duration(def) * time.Second, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 86400 {
		return 0, errors.New(k + " must be 0..86400")
	}
	return time.Duration(n) * time.Second, nil
}

// NewWatcher builds a watcher from the configuration.
func NewWatcher(r sensor.Reporter, log func(string, ...any)) (*Watcher, error) {
	raw, _ := r.Setting("TS_LURES")
	paths, err := LurePaths(raw)
	if err != nil {
		return nil, err
	}
	w := &Watcher{Lures: map[string]bool{}, AccessAlerts: true, R: r, Gen: lures, Log: log}
	for _, p := range paths {
		w.Lures[p] = true
	}
	if v, ok := r.Setting("TS_ACCESS_ALERTS"); ok {
		w.AccessAlerts = v != "false"
	}
	if w.AccessCool, err = seconds(r, "TS_ACCESS_COOLDOWN_SEC", 60); err != nil {
		return nil, err
	}
	if w.TamperCool, err = seconds(r, "TS_TAMPER_COOLDOWN_SEC", 1); err != nil {
		return nil, err
	}
	return w, nil
}

func run(ctx context.Context, s *sensor.Sensor) error {
	sensor.LogPrivileges(s.Logger())
	w, err := NewWatcher(s, func(m string, a ...any) { s.Logger().Warn(m, a...) })
	if err != nil {
		return err
	}
	s.Logger().Info("watching lure files", "count", len(w.Lures), "access_alerts", w.AccessAlerts)
	return w.Run(ctx)
}
