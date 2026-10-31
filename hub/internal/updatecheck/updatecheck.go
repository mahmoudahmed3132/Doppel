// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

// Package updatecheck periodically reads the product's public releases and
// reports the newest Hub and CLI versions (§6.11). It is the Hub's only
// call home; failures are logged and otherwise silent.
package updatecheck

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/semver"
)

// DefaultURL lists the product's releases.
const DefaultURL = "https://api.github.com/repos/mahmoudahmed3132/TrueSignal-Rewrite/releases?per_page=100"

const maxBody = 2 << 20

// State is the last check's outcome.
type State struct {
	LatestHub string     `json:"latest_hub"`
	LatestCLI string     `json:"latest_cli"`
	LastCheck *time.Time `json:"last_check"`
	LastError string     `json:"last_error,omitempty"`
}

// Checker performs update checks.
type Checker struct {
	URL      string
	Client   *http.Client
	Interval func(ctx context.Context) time.Duration // 0 disables
	Log      *slog.Logger
	Now      func() time.Time

	mu    sync.Mutex
	state State
}

var tagRE = regexp.MustCompile(`^(hub|cli)/v([0-9]+\.[0-9]+\.[0-9]+)$`)

func (c *Checker) client() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// Check queries the releases once.
func (c *Checker) Check(ctx context.Context) State {
	hub, cli, err := c.fetch(ctx)
	now := c.Now().UTC()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state.LastCheck = &now
	if err != nil {
		c.state.LastError = err.Error()
		c.Log.Info("update check failed", "error", err.Error())
	} else {
		c.state.LatestHub, c.state.LatestCLI, c.state.LastError = hub, cli, ""
	}
	return c.state
}

func (c *Checker) fetch(ctx context.Context) (hub, cli string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "truesignal-hub")
	resp, err := c.client().Do(req)
	if err != nil {
		return "", "", errors.New("releases unreachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("releases answered %d", resp.StatusCode)
	}
	var rel []struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&rel); err != nil {
		return "", "", errors.New("unexpected releases response")
	}
	for _, r := range rel {
		m := tagRE.FindStringSubmatch(r.Tag)
		if m == nil || r.Draft || r.Prerelease {
			continue
		}
		dst := &hub
		if m[1] == "cli" {
			dst = &cli
		}
		if *dst == "" || semver.Less(*dst, m[2]) {
			*dst = m[2]
		}
	}
	return hub, cli, nil
}

// State returns the last outcome.
func (c *Checker) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// Run checks at start and then every interval (re-read each time; 0 =
// disabled, re-evaluated hourly).
func (c *Checker) Run(ctx context.Context) {
	for {
		wait := c.Interval(ctx)
		if wait > 0 {
			c.Check(ctx)
		} else {
			wait = time.Hour
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}
