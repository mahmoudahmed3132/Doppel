// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package apply converges the node to the Hub's desired compose file (§8):
// fetch, inject the node key, re-check host paths on this host, compare
// semantically, back up, deploy, verify, and roll back on failure.
package apply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/mahmoudahmed3132/Doppel/cli/internal/config"
	"github.com/mahmoudahmed3132/Doppel/cli/internal/docker"
	"github.com/mahmoudahmed3132/Doppel/cli/internal/hub"
)

// Results reported to the Hub.
const (
	ResultApplied    = "applied"
	ResultUnchanged  = "unchanged"
	ResultRolledBack = "rolled_back"
	ResultFailed     = "failed"
)

// SettleTime is how long after `up` service states are checked (§8: 3 s).
const SettleTime = 3 * time.Second

// Hub is the part of the Hub client apply needs.
type Hub interface {
	Compose(ctx context.Context) (*hub.Rendered, error)
	ReportApplied(ctx context.Context, revision, result, message string) error
}

// Engine is the part of Docker apply needs.
type Engine interface {
	Pull(ctx context.Context, file string) error
	Up(ctx context.Context, file string) error
	Down(ctx context.Context, file string) error
	PS(ctx context.Context, file string) ([]docker.Container, error)
}

// Applier performs one apply.
type Applier struct {
	Paths  config.Paths
	Config *config.Config
	Hub    Hub
	Docker Engine
	Settle time.Duration // default SettleTime
	Sleep  func(context.Context, time.Duration) error
	Warn   func(format string, a ...any)
}

// Result describes the outcome.
type Result struct {
	Revision string
	Outcome  string // one of the Result* constants
	Message  string
	Warnings []string
}

// forbidden mirrors the Hub's mount rule (§6.12.4). The Hub cannot see
// symlinks on this host, so the CLI re-checks resolved paths.
var forbidden = []string{
	"/run", "/var/run", "/proc", "/sys", "/dev", "/boot", "/etc", "/root", "/usr", "/bin", "/sbin",
	"/lib", "/lib32", "/lib64", "/libx32", "/var/lib/docker", "/var/lib/containerd", "/var/lib/kubelet",
}

func forbiddenPath(p string) bool {
	if p == "/" {
		return true
	}
	for _, f := range forbidden {
		if p == f || strings.HasPrefix(p, f+"/") || strings.HasPrefix(f, p+"/") {
			return true
		}
	}
	return false
}

// Lock takes an exclusive, non-blocking lock so two applies cannot race.
func Lock(p config.Paths) (func(), error) {
	if err := os.MkdirAll(p.WorkDir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p.Lock(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("another doppel apply is running")
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

type document = map[string]any

func services(doc document) (map[string]any, error) {
	s, ok := doc["services"].(map[string]any)
	if !ok {
		return nil, errors.New("compose file has no services object")
	}
	return s, nil
}

// prepare injects the node key and validates what the CLI is responsible
// for on this host. It returns the host paths (lure files) of the document.
func (a *Applier) prepare(raw json.RawMessage) (document, []string, []string, error) {
	var doc document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, nil, fmt.Errorf("Hub sent an invalid compose file: %w", err)
	}
	meta, _ := doc["x-truesignal"].(map[string]any)
	if meta == nil || meta["node_id"] != a.Config.NodeID {
		return nil, nil, nil, errors.New("Hub sent a compose file for another node; refusing")
	}
	keyEnv, _ := meta["node_key_env"].(string)
	if keyEnv == "" {
		keyEnv = "TS_NODE_KEY"
	}
	svcs, err := services(doc)
	if err != nil {
		return nil, nil, nil, err
	}
	var warnings []string
	for name, raw := range svcs {
		svc, ok := raw.(map[string]any)
		if !ok {
			return nil, nil, nil, fmt.Errorf("service %s is malformed", name)
		}
		if !strings.HasPrefix(name, "ts-sensor-") || svc["container_name"] != name {
			return nil, nil, nil, fmt.Errorf("unexpected service %q; refusing", name)
		}
		env, _ := svc["environment"].(map[string]any)
		if env == nil {
			env = map[string]any{}
			svc["environment"] = env
		}
		env[keyEnv] = a.Config.NodeKey
		vols, _ := svc["volumes"].([]any)
		for _, v := range vols {
			vm, _ := v.(map[string]any)
			if vm["type"] != "bind" {
				continue
			}
			src, _ := vm["source"].(string)
			if err := checkHostPath(src); err != nil {
				return nil, nil, nil, fmt.Errorf("service %s: %w", name, err)
			}
		}
	}
	var hostPaths []string
	if hp, ok := meta["host_paths"].([]any); ok {
		for _, p := range hp {
			s, _ := p.(string)
			if s == "" {
				continue
			}
			hostPaths = append(hostPaths, s)
			if st, err := os.Lstat(s); err == nil && st.Mode()&fs.ModeSymlink != 0 {
				warnings = append(warnings, fmt.Sprintf("lure path %s is a symbolic link; it will not be replaced", s))
			}
		}
	}
	sort.Strings(hostPaths)
	return doc, hostPaths, warnings, nil
}

// checkHostPath requires a bind source to exist, to be a directory or file
// reached without symbolic links, and to resolve outside forbidden trees.
func checkHostPath(src string) error {
	if !filepath.IsAbs(src) || filepath.Clean(src) != src {
		return fmt.Errorf("bind source %q is not an absolute clean path", src)
	}
	resolved, err := filepath.EvalSymlinks(src)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("host path %s does not exist; create it before applying", src)
	}
	if err != nil {
		return fmt.Errorf("host path %s: %v", src, err)
	}
	if resolved != src {
		return fmt.Errorf("host path %s resolves through a symbolic link to %s; refusing", src, resolved)
	}
	if forbiddenPath(resolved) {
		return fmt.Errorf("host path %s is not allowed", resolved)
	}
	return nil
}

func readDoc(path string) (document, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d document
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	return d, nil
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return config.WriteSecret(dst, b)
}

// failedServices returns services that are not healthy after `up`. Init
// services (suffix "-init") that exited 0 are expected.
func failedServices(cs []docker.Container) []string {
	var bad []string
	for _, c := range cs {
		state := strings.ToLower(c.State)
		isInit := strings.HasSuffix(c.Service, "-init")
		switch {
		case isInit && state == "exited" && c.ExitCode == 0:
		case state == "running":
		case state == "exited", state == "restarting", state == "dead", state == "removing":
			bad = append(bad, fmt.Sprintf("%s (%s, exit %d)", c.Service, state, c.ExitCode))
		case state == "created" && !isInit:
			bad = append(bad, fmt.Sprintf("%s (never started)", c.Service))
		}
	}
	sort.Strings(bad)
	return bad
}

// Run performs the apply.
func (a *Applier) Run(ctx context.Context) (*Result, error) {
	if a.Settle == 0 {
		a.Settle = SettleTime
	}
	if a.Sleep == nil {
		a.Sleep = func(ctx context.Context, d time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(d):
				return nil
			}
		}
	}
	r, err := a.Hub.Compose(ctx)
	if err != nil {
		return nil, err
	}
	res := &Result{Revision: r.Revision, Warnings: append([]string{}, r.Warnings...)}
	report := func(outcome, msg string) {
		res.Outcome, res.Message = outcome, msg
		if err := a.Hub.ReportApplied(ctx, r.Revision, outcome, msg); err != nil && a.Warn != nil {
			a.Warn("could not report the result to the Hub: %v", err)
		}
	}

	doc, _, warns, err := a.prepare(r.Compose)
	res.Warnings = append(res.Warnings, warns...)
	if err != nil {
		report(ResultFailed, err.Error())
		return res, err
	}

	file, backup := a.Paths.Compose(), a.Paths.Backup()
	current, err := readDoc(file)
	hadCurrent := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return res, fmt.Errorf("reading %s: %w", file, err)
	}
	if hadCurrent && reflect.DeepEqual(current, doc) {
		report(ResultUnchanged, "")
		return res, nil
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return res, err
	}
	if hadCurrent {
		if err := copyFile(file, backup); err != nil {
			return res, fmt.Errorf("backing up %s: %w", file, err)
		}
	}
	if err := config.WriteSecret(file, append(out, '\n')); err != nil {
		return res, err
	}

	// Pull before touching running containers: a failed pull changes nothing.
	if err := a.Docker.Pull(ctx, file); err != nil {
		a.restoreFile(hadCurrent, file, backup)
		report(ResultFailed, "image pull failed: "+err.Error())
		return res, fmt.Errorf("image pull failed (nothing changed): %w", err)
	}

	failure := ""
	if err := a.Docker.Up(ctx, file); err != nil {
		failure = "docker compose up failed: " + err.Error()
	} else {
		if err := a.Sleep(ctx, a.Settle); err != nil {
			return res, err
		}
		cs, err := a.Docker.PS(ctx, file)
		switch {
		case err != nil:
			failure = "cannot read container states: " + err.Error()
		case len(failedServices(cs)) > 0:
			failure = "services failed to start: " + strings.Join(failedServices(cs), ", ")
		}
	}
	if failure == "" {
		report(ResultApplied, "")
		return res, nil
	}

	// Roll back.
	rbErr := a.rollback(ctx, hadCurrent, file, backup)
	if rbErr != nil {
		report(ResultFailed, failure+"; rollback failed: "+rbErr.Error())
		return res, fmt.Errorf("%s; rollback FAILED: %v", failure, rbErr)
	}
	report(ResultRolledBack, failure)
	return res, fmt.Errorf("%s; rolled back to the previous configuration", failure)
}

func (a *Applier) restoreFile(hadCurrent bool, file, backup string) {
	if hadCurrent {
		_ = copyFile(backup, file)
	} else {
		_ = os.Remove(file)
	}
}

func (a *Applier) rollback(ctx context.Context, hadCurrent bool, file, backup string) error {
	if !hadCurrent {
		// First deploy: nothing to return to.
		err := a.Docker.Down(ctx, file)
		_ = os.Remove(file)
		return err
	}
	if err := copyFile(backup, file); err != nil {
		return err
	}
	return a.Docker.Up(ctx, file)
}

// HostPaths returns the lure paths listed in a compose file.
func HostPaths(path string) ([]string, error) {
	doc, err := readDoc(path)
	if err != nil {
		return nil, err
	}
	meta, _ := doc["x-truesignal"].(map[string]any)
	var out []string
	if hp, ok := meta["host_paths"].([]any); ok {
		for _, p := range hp {
			if s, _ := p.(string); s != "" {
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}
