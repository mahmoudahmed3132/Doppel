// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package docker drives the Docker CLI for the node agent. All arguments
// are passed as an argv list (never through a shell).
package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// Project is the compose project name (§8).
const Project = "truesignal"

// Runner executes a command and returns its standard output.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Exec runs real commands.
type Exec struct{}

// Run implements Runner. Stderr is included in the error.
func (Exec) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 2000 {
			msg = msg[len(msg)-2000:]
		}
		return stdout.Bytes(), fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, msg)
	}
	return stdout.Bytes(), nil
}

// Docker wraps the compose commands the agent needs.
type Docker struct {
	R Runner
}

func (d Docker) compose(ctx context.Context, file string, args ...string) ([]byte, error) {
	base := []string{"compose", "-p", Project}
	if file != "" {
		base = append(base, "-f", file)
	}
	return d.R.Run(ctx, "docker", append(base, args...)...)
}

// Pull pulls the images of a compose file.
func (d Docker) Pull(ctx context.Context, file string) error {
	_, err := d.compose(ctx, file, "pull", "--quiet")
	return err
}

// Up starts the project and removes orphans.
func (d Docker) Up(ctx context.Context, file string) error {
	_, err := d.compose(ctx, file, "up", "-d", "--remove-orphans")
	return err
}

// Down stops and removes the project's containers and network.
func (d Docker) Down(ctx context.Context, file string) error {
	_, err := d.compose(ctx, file, "down", "--remove-orphans")
	return err
}

// Container is one container of the project.
type Container struct {
	Name     string `json:"Name"`
	Service  string `json:"Service"`
	State    string `json:"State"`
	Status   string `json:"Status"`
	ExitCode int    `json:"ExitCode"`
}

// PS lists the project's containers, including stopped ones. It accepts
// both output styles of `docker compose ps --format json` (one JSON array,
// or one object per line).
func (d Docker) PS(ctx context.Context, file string) ([]Container, error) {
	out, err := d.compose(ctx, file, "ps", "--all", "--format", "json")
	if err != nil {
		return nil, err
	}
	out = bytes.TrimSpace(out)
	if len(out) == 0 {
		return nil, nil
	}
	if out[0] == '[' {
		var cs []Container
		if err := json.Unmarshal(out, &cs); err != nil {
			return nil, fmt.Errorf("parsing docker compose ps: %w", err)
		}
		return cs, nil
	}
	var cs []Container
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var c Container
		if err := json.Unmarshal(line, &c); err != nil {
			return nil, fmt.Errorf("parsing docker compose ps: %w", err)
		}
		cs = append(cs, c)
	}
	return cs, sc.Err()
}

// SensorContainers lists running TrueSignal sensor containers by label.
func (d Docker) SensorContainers(ctx context.Context) ([]string, error) {
	out, err := d.R.Run(ctx, "docker", "ps", "--filter", "label=io.truesignal.role=sensor", "--format", "{{.Names}}")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			names = append(names, l)
		}
	}
	return names, nil
}

// Signal sends a signal to a container.
func (d Docker) Signal(ctx context.Context, name, signal string) error {
	_, err := d.R.Run(ctx, "docker", "kill", "--signal", signal, name)
	return err
}
