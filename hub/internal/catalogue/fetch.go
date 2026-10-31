// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package catalogue

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrNotFound is returned for a 404 from the registry.
var ErrNotFound = errors.New("not found in registry")

// Fetcher retrieves registry files.
type Fetcher interface {
	Get(ctx context.Context, u *url.URL, limit int64) ([]byte, error)
}

// HTTPFetcher fetches over HTTPS without following redirects.
type HTTPFetcher struct {
	Client *http.Client
}

// NewHTTPFetcher returns a fetcher with timeouts, TLS ≥ 1.2 and no redirects.
func NewHTTPFetcher() *HTTPFetcher {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	tr.ResponseHeaderTimeout = 20 * time.Second
	return &HTTPFetcher{Client: &http.Client{
		Transport:     tr,
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Get fetches u, refusing bodies larger than limit.
func (f *HTTPFetcher) Get(ctx context.Context, u *url.URL, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "truesignal-hub-catalogue")
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrNotFound
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return nil, fmt.Errorf("registry answered a redirect (%d); redirects are not followed", resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("registry answered %d", resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return b, nil
}

// ParseBase validates the registry base URL. Plain HTTP is accepted only
// when allowHTTP (development).
func ParseBase(raw string, allowHTTP bool) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("registry URL must be an absolute https URL without credentials, query or fragment")
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return nil, errors.New("registry URL must use https")
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	return u, nil
}

// resolve joins a validated relative path to the base; the result always
// stays under the base (relative paths contain no "..").
func resolve(base *url.URL, rel string) *url.URL {
	u := *base
	u.Path = base.Path + rel
	u.RawPath = ""
	return &u
}
