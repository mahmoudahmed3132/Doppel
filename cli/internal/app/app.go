// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package app implements the doppel commands (§8).
package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/mahmoudahmed3132/Doppel/cli/internal/apply"
	"github.com/mahmoudahmed3132/Doppel/cli/internal/config"
	"github.com/mahmoudahmed3132/Doppel/cli/internal/discover"
	"github.com/mahmoudahmed3132/Doppel/cli/internal/docker"
	"github.com/mahmoudahmed3132/Doppel/cli/internal/hub"
)

// App holds the command environment (injectable for tests).
type App struct {
	Version  string
	Paths    config.Paths
	Getenv   func(string) string
	Stdin    io.Reader
	Stdout   io.Writer
	Stderr   io.Writer
	Runner   docker.Runner
	Arch     string
	ProcRoot string
	Exe      func() (string, error)
	Settle   time.Duration
	Color    bool
	// ReadSecret reads a secret without echo (default: terminal).
	ReadSecret  func(prompt string) (string, error)
	DiscoverEnv *discover.Env
}

// New returns an App for the real environment.
func New(version string) *App {
	genv := config.OSGetenv() // DOPPEL_* wins; TS_* still accepted with a warning (F-004)
	a := &App{
		Version: version, Paths: config.PathsFromEnv(genv), Getenv: genv,
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Runner: docker.Exec{},
		Arch: runtime.GOARCH, ProcRoot: "/proc", Exe: os.Executable,
		Color: term.IsTerminal(int(os.Stdout.Fd())) && os.Getenv("NO_COLOR") == "",
	}
	a.ReadSecret = func(prompt string) (string, error) {
		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			return "", errors.New("no terminal for the prompt; set the environment variable instead")
		}
		defer tty.Close()
		fmt.Fprint(tty, prompt)
		b, err := term.ReadPassword(int(tty.Fd()))
		fmt.Fprintln(tty)
		return string(b), err
	}
	return a
}

func (a *App) paint(code, s string) string {
	if !a.Color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (a *App) ok(format string, v ...any) {
	fmt.Fprintln(a.Stdout, a.paint("32", "✔ ")+fmt.Sprintf(format, v...))
}
func (a *App) info(format string, v ...any) { fmt.Fprintf(a.Stdout, format+"\n", v...) }
func (a *App) warn(format string, v ...any) {
	fmt.Fprintln(a.Stderr, a.paint("33", "warning: ")+fmt.Sprintf(format, v...))
}
func (a *App) fail(err error) int {
	fmt.Fprintln(a.Stderr, a.paint("31", "error: ")+err.Error())
	if hub.IsVersionMismatch(err) {
		fmt.Fprintln(a.Stderr, "  This CLI is version "+a.Version+". Download the matching release and rerun.")
	}
	return 1
}

const usage = `doppel — Doppel node agent

Usage:
  doppel link <hub-url>    link this node (node key from TS_NODE_KEY)
  doppel apply             deploy the Hub's desired configuration
  doppel discover [--plan] [--json] [--apply] [--yes]
                           propose a conflict-free decoy mix and deploy it
  doppel firedrill         make every sensor send its synthetic event
  doppel status [--json]   show node, Hub and container status
  doppel uninstall [--yes] remove Doppel from this node (lure files are kept)
  doppel version
`

// Run executes args (without the program name) and returns the exit code.
func (a *App) Run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.Stderr, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "link":
		return a.link(ctx, rest)
	case "apply":
		return a.apply(ctx, rest)
	case "discover":
		return a.discover(ctx, rest)
	case "firedrill":
		return a.firedrill(ctx, rest)
	case "status":
		return a.status(ctx, rest)
	case "uninstall":
		return a.uninstall(ctx, rest)
	case "version", "--version":
		a.info("doppel %s (%s/%s)", a.Version, runtime.GOOS, a.Arch)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(a.Stdout, usage)
		return 0
	}
	fmt.Fprintf(a.Stderr, "unknown command %q\n\n%s", cmd, usage)
	return 2
}

func (a *App) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	return fs
}

func (a *App) allowHTTP() bool {
	switch strings.ToLower(strings.TrimSpace(a.Getenv("TS_DEV_ALLOW_HTTP"))) {
	case "true", "1", "yes":
		return true
	}
	return false
}

func (a *App) client(cfg *config.Config) (*hub.Client, error) {
	u, err := hub.ParseEndpoint(cfg.HubEndpoint, a.allowHTTP())
	if err != nil {
		return nil, err
	}
	return hub.New(u, cfg.NodeKey, a.Version), nil
}

// --- link ---------------------------------------------------------------

func (a *App) link(ctx context.Context, args []string) int {
	fs := a.flags("link")
	keyFlag := fs.String("key", "", "node key (visible in ps; prefer TS_NODE_KEY)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(a.Stderr, "usage: TS_NODE_KEY=tsk_… doppel link <hub-url>")
		return 2
	}
	key := a.Getenv("TS_NODE_KEY")
	if *keyFlag != "" {
		a.warn("--key is visible to other users in the process list; prefer TS_NODE_KEY")
		key = *keyFlag
	}
	if !config.ValidKey(key) {
		return a.fail(errors.New("set TS_NODE_KEY to the node key shown when the node was created (tsk_ + 64 hex)"))
	}
	u, err := hub.ParseEndpoint(fs.Arg(0), a.allowHTTP())
	if err != nil {
		return a.fail(err)
	}
	if u.Scheme == "http" {
		a.warn("TS_DEV_ALLOW_HTTP is active: plain HTTP sends the node key unencrypted; do not use in production")
	}
	c := hub.New(u, key, a.Version)
	id, err := c.Identity(ctx)
	if err != nil {
		return a.fail(fmt.Errorf("verifying the node key: %w", err))
	}
	if err := config.Save(a.Paths, &config.Config{HubEndpoint: u.String(), NodeID: id.NodeID, NodeKey: key}); err != nil {
		return a.fail(err)
	}
	a.ok("linked as %s (%s) to %s", id.NodeID, id.Alias, u.String())
	a.info("Next: doppel apply   (or: doppel discover)")
	return 0
}

// --- apply --------------------------------------------------------------

func (a *App) archOK() error {
	if a.Arch == "amd64" || a.Getenv("TS_ALLOW_NON_AMD64") == "true" {
		return nil
	}
	return fmt.Errorf("sensor images are built for linux/amd64; this host is %s (set TS_ALLOW_NON_AMD64=true to override)", a.Arch)
}

func (a *App) apply(ctx context.Context, _ []string) int {
	cfg, err := config.Load(a.Paths)
	if err != nil {
		return a.fail(err)
	}
	if err := a.archOK(); err != nil {
		return a.fail(err)
	}
	c, err := a.client(cfg)
	if err != nil {
		return a.fail(err)
	}
	unlock, err := apply.Lock(a.Paths)
	if err != nil {
		return a.fail(err)
	}
	defer unlock()
	ap := &apply.Applier{Paths: a.Paths, Config: cfg, Hub: c, Docker: docker.Docker{R: a.Runner}, Settle: a.Settle, Warn: a.warn}
	res, err := ap.Run(ctx)
	if res != nil {
		for _, w := range res.Warnings {
			a.warn("%s", w)
		}
	}
	if err != nil {
		return a.fail(err)
	}
	switch res.Outcome {
	case apply.ResultUnchanged:
		a.ok("already at %s; nothing to do", res.Revision)
	default:
		a.ok("applied %s", res.Revision)
	}
	return 0
}

// --- firedrill ----------------------------------------------------------

func (a *App) firedrill(ctx context.Context, _ []string) int {
	d := docker.Docker{R: a.Runner}
	names, err := d.SensorContainers(ctx)
	if err != nil {
		return a.fail(err)
	}
	if len(names) == 0 {
		return a.fail(errors.New("no running Doppel sensors"))
	}
	failed := 0
	for _, n := range names {
		if err := d.Signal(ctx, n, "SIGUSR1"); err != nil {
			a.warn("%s: %v", n, err)
			failed++
			continue
		}
		a.ok("%s: fire drill triggered (source \"Fire drill\")", n)
	}
	if failed > 0 {
		return 1
	}
	a.info("Check the Hub's event list and your SIEM for the synthetic events.")
	return 0
}

// --- status -------------------------------------------------------------

// Status is the --json output of `doppel status`.
type Status struct {
	CLIVersion      string             `json:"cli_version"`
	NodeID          string             `json:"node_id"`
	Alias           string             `json:"alias,omitempty"`
	HubEndpoint     string             `json:"hub_endpoint"`
	HubReachable    bool               `json:"hub_reachable"`
	HubVersion      string             `json:"hub_version,omitempty"`
	HubError        string             `json:"hub_error,omitempty"`
	DesiredRevision string             `json:"desired_revision,omitempty"`
	AppliedRevision string             `json:"applied_revision,omitempty"`
	LocalRevision   string             `json:"local_revision,omitempty"`
	InSync          bool               `json:"in_sync"`
	Containers      []docker.Container `json:"containers"`
	DockerError     string             `json:"docker_error,omitempty"`
}

func localRevision(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var d struct {
		Meta struct {
			Revision string `json:"revision"`
		} `json:"x-truesignal"`
	}
	json.Unmarshal(b, &d)
	return d.Meta.Revision
}

func (a *App) status(ctx context.Context, args []string) int {
	fs := a.flags("status")
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(a.Paths)
	if err != nil {
		return a.fail(err)
	}
	st := Status{CLIVersion: a.Version, NodeID: cfg.NodeID, HubEndpoint: cfg.HubEndpoint, Containers: []docker.Container{},
		LocalRevision: localRevision(a.Paths.Compose())}
	if c, err := a.client(cfg); err == nil {
		if id, err := c.Identity(ctx); err != nil {
			st.HubError = err.Error()
		} else {
			st.HubReachable, st.HubVersion, st.Alias = true, id.HubVersion, id.Alias
			st.DesiredRevision, st.AppliedRevision = id.DesiredRevision, id.AppliedRevision
			st.InSync = id.DesiredRevision != "" && id.DesiredRevision == st.LocalRevision
		}
	}
	if _, err := os.Stat(a.Paths.Compose()); err == nil {
		cs, err := docker.Docker{R: a.Runner}.PS(ctx, a.Paths.Compose())
		if err != nil {
			st.DockerError = err.Error()
		} else if cs != nil {
			st.Containers = cs
		}
	}
	if *asJSON {
		enc := json.NewEncoder(a.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(st)
		if !st.HubReachable {
			return 1
		}
		return 0
	}
	a.info("Node      %s %s", st.NodeID, st.Alias)
	if st.HubReachable {
		a.info("Hub       %s (%s) %s", st.HubEndpoint, st.HubVersion, a.paint("32", "reachable"))
	} else {
		a.info("Hub       %s %s: %s", st.HubEndpoint, a.paint("31", "unreachable"), st.HubError)
	}
	sync := a.paint("33", "out of sync — run doppel apply")
	if st.InSync {
		sync = a.paint("32", "in sync")
	}
	a.info("Revision  desired %s, local %s (%s)", orDash(st.DesiredRevision), orDash(st.LocalRevision), sync)
	if st.DockerError != "" {
		a.info("Containers %s", a.paint("31", st.DockerError))
	}
	for _, c := range st.Containers {
		a.info("  %-40s %s", c.Service, c.Status)
	}
	if !st.HubReachable {
		return 1
	}
	return 0
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// --- uninstall ------------------------------------------------------------

func (a *App) confirm(prompt string) bool {
	fmt.Fprint(a.Stdout, prompt+" [y/N] ")
	line, _ := bufio.NewReader(a.Stdin).ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(line), "y") || strings.EqualFold(strings.TrimSpace(line), "yes")
}

func (a *App) uninstall(ctx context.Context, args []string) int {
	fs := a.flags("uninstall")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !*yes && !a.confirm("Remove all Doppel sensors, configuration and the CLI from this node?") {
		a.info("aborted")
		return 1
	}
	lures, _ := apply.HostPaths(a.Paths.Compose())
	file := ""
	if _, err := os.Stat(a.Paths.Compose()); err == nil {
		file = a.Paths.Compose()
	}
	if err := (docker.Docker{R: a.Runner}).Down(ctx, file); err != nil {
		a.warn("stopping containers: %v", err)
	} else {
		a.ok("containers and network removed")
	}
	if err := os.RemoveAll(a.Paths.WorkDir); err != nil {
		a.warn("removing %s: %v", a.Paths.WorkDir, err)
	} else {
		a.ok("removed %s", a.Paths.WorkDir)
	}
	cfg, _ := config.Load(a.Paths)
	if err := os.Remove(a.Paths.ConfigFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		a.warn("removing %s: %v", a.Paths.ConfigFile, err)
	} else {
		os.Remove(filepath.Dir(a.Paths.ConfigFile)) // only if empty
		a.ok("removed %s (node key)", a.Paths.ConfigFile)
	}
	if exe, err := a.Exe(); err == nil && (filepath.Base(exe) == "doppel" || filepath.Base(exe) == "truesignal") {
		// The installer's compatibility link next to the binary (Q66).
		if link := filepath.Join(filepath.Dir(exe), "truesignal"); link != exe {
			if t, err := os.Readlink(link); err == nil && (t == "doppel" || t == exe) {
				os.Remove(link)
			}
		}
		if err := os.Remove(exe); err != nil {
			a.warn("removing %s: %v", exe, err)
		} else {
			a.ok("removed %s", exe)
		}
	}
	if len(lures) > 0 {
		a.info("\nLure files were left in place (they may still be referenced by attackers or honeytokens):")
		sort.Strings(lures)
		for _, l := range lures {
			a.info("  %s", l)
		}
	}
	node := "this node"
	if cfg != nil {
		node = cfg.NodeID
	}
	a.info("\nNow delete %s in the Hub (Fleet → node → Delete) so its key is revoked.", node)
	return 0
}
