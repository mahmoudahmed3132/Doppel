// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package siemhttp is the HTTP SIEM transport behind
// ported.HTTPSIEMTransport. Both outputs send one ECS document per request
// over HTTPS:
//
//   - elastic: POST <address>/_bulk where address is the cluster URL plus the
//     target data stream, e.g. https://es.example:9200/logs-truesignal-default.
//     Each document is a `create` action (required for data streams).
//     Authorization: ApiKey <encoded API key>.
//   - logscale: POST <address> where address is the HEC endpoint, e.g.
//     https://cloud.us.humio.com/api/v1/ingest/hec. Authorization: Bearer
//     <ingest token>.
//
// Deception alerts are low volume, and per-event delivery keeps the retry
// position exact. Retries and backoff belong to the Hub's SIEM service; this
// package only classifies each attempt.
//
// Imported from TrueSignal (see PROVENANCE.md): request building and outcome
// classification are that module's; the retry loop is not imported.
package siemhttp

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
	"strings"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
)

const (
	ProtocolElastic  = "elastic"
	ProtocolLogScale = "logscale"

	maxHTTPResponse = 64 << 10
	requestTimeout  = 10 * time.Second
)

// Transport implements ported.HTTPSIEMTransport.
type Transport struct {
	Client *http.Client
}

var _ ported.HTTPSIEMTransport = (*Transport)(nil)

// New returns a transport that trusts the system roots plus the PEM bundle
// at caBundle (when set) and never follows redirects, so a token is never
// sent to another host.
func New(caBundle string) (*Transport, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if caBundle != "" {
		pem, err := os.ReadFile(caBundle)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: no PEM certificates", caBundle)
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	return &Transport{Client: &http.Client{Transport: tr, CheckRedirect: noRedirect}}, nil
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// httpRequestBody builds the request body for one ECS document.
func httpRequestBody(protocol string, docJSON []byte) ([]byte, string, error) {
	if !json.Valid(docJSON) {
		return nil, "", errors.New("document is not JSON")
	}
	switch protocol {
	case ProtocolElastic:
		var b bytes.Buffer
		b.WriteString(`{"create":{}}` + "\n")
		b.Write(docJSON)
		b.WriteByte('\n')
		return b.Bytes(), "application/x-ndjson", nil
	default: // logscale (HEC)
		var head struct {
			Timestamp string `json:"@timestamp"`
			Host      struct {
				Name string `json:"name"`
			} `json:"host"`
		}
		_ = json.Unmarshal(docJSON, &head)
		ts, _ := time.Parse(time.RFC3339Nano, head.Timestamp)
		body, err := json.Marshal(map[string]any{
			"time":       float64(ts.UnixNano()) / 1e9,
			"host":       head.Host.Name,
			"source":     "truesignal-hub",
			"sourcetype": "truesignal",
			"event":      json.RawMessage(docJSON),
		})
		return body, "application/json", err
	}
}

func httpEndpoint(protocol, address string) string {
	if protocol == ProtocolElastic {
		return strings.TrimRight(address, "/") + "/_bulk"
	}
	return address
}

func authHeader(protocol, token string) string {
	if token == "" {
		return ""
	}
	if protocol == ProtocolElastic {
		return "ApiKey " + token
	}
	return "Bearer " + token
}

// Send delivers one document and classifies the outcome. Network errors,
// 5xx and 429 are transient; other non-2xx responses (redirects included)
// and Elastic per-item errors are terminal for that document (a retry would
// fail the same way).
func (t *Transport) Send(ctx context.Context, protocol, address, token string, document []byte) (ported.SendOutcome, error) {
	if protocol != ProtocolElastic && protocol != ProtocolLogScale {
		return ported.SendTerminal, fmt.Errorf("unknown HTTP protocol %q", protocol)
	}
	if u, err := url.Parse(address); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return ported.SendTerminal, errors.New("address must be an https:// URL without credentials")
	}
	body, contentType, err := httpRequestBody(protocol, document)
	if err != nil {
		return ported.SendTerminal, err
	}
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, httpEndpoint(protocol, address), bytes.NewReader(body))
	if err != nil {
		return ported.SendTerminal, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "TrueSignal-Hub")
	if h := authHeader(protocol, token); h != "" {
		req.Header.Set("Authorization", h)
	}

	resp, err := t.Client.Do(req)
	if err != nil {
		return ported.SendTransient, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponse))

	switch {
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return ported.SendTransient, fmt.Errorf("HTTP %d", resp.StatusCode)
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return ported.SendTerminal, fmt.Errorf("HTTP %d: %s", resp.StatusCode, snippet(respBody))
	}

	if protocol == ProtocolElastic {
		var bulk struct {
			Errors bool `json:"errors"`
			Items  []map[string]struct {
				Status int             `json:"status"`
				Error  json.RawMessage `json:"error"`
			} `json:"items"`
		}
		if json.Unmarshal(respBody, &bulk) == nil && bulk.Errors {
			for _, item := range bulk.Items {
				for _, r := range item {
					if r.Status == http.StatusTooManyRequests {
						return ported.SendTransient, errors.New("bulk item HTTP 429")
					}
					return ported.SendTerminal, fmt.Errorf("bulk item HTTP %d: %s", r.Status, snippet(r.Error))
				}
			}
			return ported.SendTerminal, errors.New("bulk request reported errors")
		}
	}
	return ported.SendSuccess, nil
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}
