// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package hub is the node agent's Hub client. Node calls authenticate with
// the node key; discover additionally uses a short-lived admin session.
// Every request carries the CLI version header (§4.4).
package hub

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// VersionHeader is sent with every request.
const VersionHeader = "X-TrueSignal-CLI-Version"

const maxResponse = 4 << 20

// Client talks to one Hub.
type Client struct {
	base    *url.URL
	key     string
	version string
	http    *http.Client
}

// ParseEndpoint validates a Hub URL. Plain HTTP is accepted for lab use
// (§4.1); the caller should warn.
func ParseEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("hub URL must be https://host[:port][/path] (http:// only for lab use)")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u, nil
}

// New returns a client. key may be empty for unauthenticated calls.
func New(base *url.URL, key, cliVersion string) *Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &Client{base: base, key: key, version: cliVersion, http: &http.Client{
		Transport: tr,
		Timeout:   60 * time.Second,
		// Never follow redirects: they could carry the node key elsewhere.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Origin returns scheme://host of the Hub (sent on admin calls for CSRF).
func (c *Client) Origin() string { return c.base.Scheme + "://" + c.base.Host }

// Error is a Hub error envelope.
type Error struct {
	Status        int
	Code          string
	Message       string
	SensorID      string
	RequiredMajor int
}

func (e *Error) Error() string {
	if e.Status == http.StatusUpgradeRequired {
		return fmt.Sprintf("the Hub requires truesignal CLI major version %d; install the matching CLI release", e.RequiredMajor)
	}
	msg := e.Message
	if e.SensorID != "" {
		msg += " (sensor " + e.SensorID + ")"
	}
	if e.Code != "" {
		return fmt.Sprintf("hub refused (%d %s): %s", e.Status, e.Code, msg)
	}
	return fmt.Sprintf("hub answered %d", e.Status)
}

// IsVersionMismatch reports a 426 answer.
func IsVersionMismatch(err error) bool {
	var he *Error
	return errors.As(err, &he) && he.Status == http.StatusUpgradeRequired
}

func (c *Client) do(ctx context.Context, method, path string, auth bool, origin bool, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	u := *c.base
	u.Path += path
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return err
	}
	req.Header.Set(VersionHeader, c.version)
	req.Header.Set("User-Agent", "truesignal-cli/"+c.version)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	if origin {
		req.Header.Set("Origin", c.Origin())
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			return fmt.Errorf("cannot reach the Hub at %s: %v", c.Origin(), ue.Err)
		}
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		he := &Error{Status: resp.StatusCode}
		var env struct {
			Error         string `json:"error"`
			Message       string `json:"message"`
			SensorID      string `json:"sensor_id"`
			RequiredMajor int    `json:"required_major"`
		}
		if json.Unmarshal(data, &env) == nil {
			he.Code, he.Message, he.SensorID, he.RequiredMajor = env.Error, env.Message, env.SensorID, env.RequiredMajor
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			he.Message = "the Hub answered a redirect; check the Hub URL (redirects are not followed)"
		}
		return he
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("unexpected Hub response: %w", err)
		}
	}
	return nil
}

// Version is the Hub's /v3/version answer.
type Version struct {
	Product  string `json:"product"`
	Version  string `json:"version"`
	Contract int    `json:"contract"`
}

// HubVersion calls the unauthenticated version endpoint.
func (c *Client) HubVersion(ctx context.Context) (*Version, error) {
	var v Version
	return &v, c.do(ctx, http.MethodGet, "/v3/version", false, false, nil, &v)
}

// Identity describes this node as the Hub sees it.
type Identity struct {
	NodeID          string   `json:"node_id"`
	Alias           string   `json:"alias"`
	Tags            []string `json:"tags"`
	DesiredRevision string   `json:"desired_revision"`
	AppliedRevision string   `json:"applied_revision"`
	HubVersion      string   `json:"hub_version"`
}

// Identity verifies the node key.
func (c *Client) Identity(ctx context.Context) (*Identity, error) {
	var id Identity
	return &id, c.do(ctx, http.MethodGet, "/v3/node/identity", true, false, nil, &id)
}

// Rendered is the node's compose file from the Hub (contains secrets).
type Rendered struct {
	Revision string          `json:"revision"`
	Compose  json.RawMessage `json:"compose"`
	Warnings []string        `json:"warnings"`
}

// Compose fetches the node's rendered compose file.
func (c *Client) Compose(ctx context.Context) (*Rendered, error) {
	var r Rendered
	return &r, c.do(ctx, http.MethodGet, "/v3/node/compose", true, false, nil, &r)
}

// ReportApplied tells the Hub the outcome of an apply.
func (c *Client) ReportApplied(ctx context.Context, revision, result, message string) error {
	return c.do(ctx, http.MethodPost, "/v3/node/applied", true, false,
		map[string]string{"revision": revision, "result": result, "message": message}, nil)
}

// --- admin session (discover) --------------------------------------------

// Admin is a short-lived admin session. Credentials are never stored.
type Admin struct {
	c *Client
}

// ErrMFARequired means the login needs a TOTP or recovery code.
var ErrMFARequired = errors.New("an MFA code is required")

// Login opens an admin session.
func (c *Client) Login(ctx context.Context, password, code string) (*Admin, error) {
	jar, _ := cookiejar.New(nil)
	ac := *c
	hc := *c.http
	hc.Jar = jar
	ac.http = &hc
	err := ac.do(ctx, http.MethodPost, "/api/v3/session/login", false, true, map[string]string{"password": password, "code": code}, nil)
	var he *Error
	if errors.As(err, &he) && he.Code == "mfa_required" {
		return nil, ErrMFARequired
	}
	if errors.As(err, &he) && he.Code == "origin_mismatch" {
		return nil, fmt.Errorf("the Hub refused the login origin %s; link this node with the Hub's public URL", c.Origin())
	}
	if err != nil {
		return nil, err
	}
	return &Admin{c: &ac}, nil
}

// Logout ends the session (best effort).
func (a *Admin) Logout(ctx context.Context) {
	_ = a.c.do(ctx, http.MethodPost, "/api/v3/session/logout", false, true, nil, nil)
}

// Get performs an admin GET.
func (a *Admin) Get(ctx context.Context, path string, out any) error {
	return a.c.do(ctx, http.MethodGet, path, false, true, nil, out)
}

// Post performs an admin POST.
func (a *Admin) Post(ctx context.Context, path string, body, out any) error {
	return a.c.do(ctx, http.MethodPost, path, false, true, body, out)
}
