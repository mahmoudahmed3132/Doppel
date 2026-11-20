// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package sensor

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

// SDKVersion is the contract-compatible SDK version reported in heartbeats.
const SDKVersion = "3.0.0"

const (
	pathEvents     = "/v3/ingest/events"
	pathHeartbeats = "/v3/ingest/heartbeats"
	pathStopping   = "/v3/ingest/stopping"
	pathVersion    = "/v3/version"

	// capDrill is the Hub capability for the event drill flag.
	capDrill = "event.drill"

	maxResponseBytes = 64 << 10
	requestTimeout   = 15 * time.Second
)

// hubClient performs authenticated JSON requests against the Hub.
type hubClient struct {
	base *url.URL
	key  string
	http *http.Client
}

func newHubClient(cfg *Config) (*hubClient, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if cfg.CABundlePath != "" {
		pem, err := os.ReadFile(cfg.CABundlePath)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", EnvCABundle, err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: no certificates found in %s", EnvCABundle, cfg.CABundlePath)
		}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &hubClient{
		base: cfg.HubEndpoint,
		key:  cfg.NodeKey,
		http: &http.Client{
			Transport: tr,
			Timeout:   requestTimeout,
			// The Hub never redirects ingest calls; following one could leak
			// the node key to another origin.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// hubError is a non-2xx answer from the Hub.
type hubError struct {
	Status     int
	Code       string
	Message    string
	RetryAfter time.Duration
}

func (e *hubError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("hub answered %d %s: %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("hub answered %d", e.Status)
}

// retryable reports whether err is transient: network errors, 408, 429, 5xx.
func retryable(err error) bool {
	var he *hubError
	if !errors.As(err, &he) {
		return true
	}
	return he.Status == http.StatusRequestTimeout || he.Status == http.StatusTooManyRequests || he.Status >= 500
}

// hubVersion is the part of the Hub's /v3/version answer the SDK uses.
type hubVersion struct {
	Contract     int      `json:"contract"`
	Capabilities []string `json:"capabilities"`
}

// capabilities fetches the Hub's advertised contract capabilities.
func (c *hubClient) capabilities(ctx context.Context) (map[string]bool, error) {
	var v hubVersion
	if err := c.do(ctx, http.MethodGet, pathVersion, nil, &v); err != nil {
		return nil, err
	}
	caps := make(map[string]bool, len(v.Capabilities))
	for _, s := range v.Capabilities {
		caps[s] = true
	}
	return caps, nil
}

// post sends body as JSON and decodes a 2xx reply into out (may be nil).
func (c *hubClient) post(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, path, b, out)
}

// do performs one request (body nil: no body) and decodes a 2xx reply into
// out (may be nil).
func (c *hubClient) do(ctx context.Context, method, path string, b []byte, out any) error {
	u := *c.base
	u.Path += path
	var rd io.Reader
	if b != nil {
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return err
	}
	if b != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "truesignal-sdk-go/"+SDKVersion)
	if c.key != "" {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		he := &hubError{Status: resp.StatusCode}
		var env struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &env) == nil {
			he.Code, he.Message = env.Error, env.Message
		}
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
			he.RetryAfter = time.Duration(s) * time.Second
		}
		return he
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decoding hub response: %w", err)
		}
	}
	return nil
}
