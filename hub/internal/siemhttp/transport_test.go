// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package siemhttp

// Adapted from TrueSignal's HTTP output tests (PROVENANCE.md).

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
)

const doc = `{"@timestamp":"2026-10-24T08:00:00Z","event":{"action":"ldap_login"},"host":{"name":"node-0a1b2c3d"}}`

type capture struct {
	mu   sync.Mutex
	reqs []*http.Request
	body []string
}

func (c *capture) add(r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	c.reqs = append(c.reqs, r)
	c.body = append(c.body, string(b))
	c.mu.Unlock()
}

func forServer(ts *httptest.Server) *Transport {
	c := ts.Client()
	c.CheckRedirect = noRedirect
	return &Transport{Client: c}
}

func TestElasticBulkOutput(t *testing.T) {
	var got capture
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.add(r)
		w.Write([]byte(`{"errors":false,"items":[{"create":{"status":201}}]}`))
	}))
	defer ts.Close()
	out, err := forServer(ts).Send(context.Background(), ProtocolElastic, ts.URL+"/logs-truesignal-default", "ZW5jb2RlZA==", []byte(doc))
	if out != ported.SendSuccess || err != nil || len(got.reqs) != 1 {
		t.Fatal(out, err, len(got.reqs))
	}
	r := got.reqs[0]
	if r.URL.Path != "/logs-truesignal-default/_bulk" || r.Header.Get("Authorization") != "ApiKey ZW5jb2RlZA==" ||
		r.Header.Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("request = %s auth=%q ct=%q", r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type"))
	}
	lines := strings.Split(strings.TrimRight(got.body[0], "\n"), "\n")
	if len(lines) != 2 || lines[0] != `{"create":{}}` || lines[1] != doc {
		t.Fatalf("bulk body = %q", got.body[0])
	}
}

func TestLogScaleHECOutput(t *testing.T) {
	var got capture
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.add(r)
		w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer ts.Close()
	if out, err := forServer(ts).Send(context.Background(), ProtocolLogScale, ts.URL+"/api/v1/ingest/hec", "ingest-token", []byte(doc)); out != ported.SendSuccess {
		t.Fatal(err)
	}
	r := got.reqs[0]
	if r.URL.Path != "/api/v1/ingest/hec" || r.Header.Get("Authorization") != "Bearer ingest-token" {
		t.Fatalf("request = %s auth=%q", r.URL.Path, r.Header.Get("Authorization"))
	}
	var hec map[string]any
	if err := json.Unmarshal([]byte(got.body[0]), &hec); err != nil {
		t.Fatal(err)
	}
	ev, _ := hec["event"].(map[string]any)
	if hec["sourcetype"] != "truesignal" || hec["host"] != "node-0a1b2c3d" || ev["event"].(map[string]any)["action"] != "ldap_login" {
		t.Fatalf("hec = %v", hec)
	}
	if ts, _ := hec["time"].(float64); int64(ts) != time.Date(2026, 10, 24, 8, 0, 0, 0, time.UTC).Unix() {
		t.Fatalf("hec time = %v", hec["time"])
	}
}

func TestHTTPOutcomeClassification(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   ported.SendOutcome
	}{
		{"ok", 200, `{}`, ported.SendSuccess},
		{"unavailable", 503, ``, ported.SendTransient},
		{"throttled", 429, ``, ported.SendTransient},
		{"bad token", 401, `{"error":"unauthorized"}`, ported.SendTerminal},
		{"mapping error", 200, `{"errors":true,"items":[{"create":{"status":400,"error":{"type":"document_parsing_exception"}}}]}`, ported.SendTerminal},
		{"bulk item throttled", 200, `{"errors":true,"items":[{"create":{"status":429}}]}`, ported.SendTransient},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer ts.Close()
			out, err := forServer(ts).Send(context.Background(), ProtocolElastic, ts.URL+"/logs-x", "k", []byte(doc))
			if out != tc.want || (out == ported.SendSuccess) != (err == nil) {
				t.Fatalf("outcome = %v, %v", out, err)
			}
		})
	}
	// Unreachable: transient.
	dead := httptest.NewTLSServer(http.NotFoundHandler())
	tr := forServer(dead)
	dead.Close()
	if out, _ := tr.Send(context.Background(), ProtocolElastic, dead.URL+"/logs-x", "k", []byte(doc)); out != ported.SendTransient {
		t.Fatalf("unreachable = %v", out)
	}
}

func TestHTTPOutputDoesNotFollowRedirects(t *testing.T) {
	var leaked bool
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization") != ""
	}))
	defer other.Close()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer ts.Close()
	tr, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	tr.Client.Transport = ts.Client().Transport // trust the test CA, keep the redirect policy
	out, _ := tr.Send(context.Background(), ProtocolLogScale, ts.URL+"/hec", "secret", []byte(doc))
	if out != ported.SendTerminal {
		t.Fatalf("redirect should be terminal, got %v", out)
	}
	if leaked {
		t.Fatal("token followed the redirect")
	}
}

func TestRefusesNonHTTPSAndBadInput(t *testing.T) {
	tr := &Transport{Client: http.DefaultClient}
	for _, c := range []struct{ proto, addr, doc string }{
		{ProtocolElastic, "http://es:9200/logs-x", doc},
		{ProtocolElastic, "https://user:pw@es:9200/logs-x", doc},
		{"splunk", "https://x/", doc},
		{ProtocolLogScale, "https://x/hec", "not json"},
	} {
		if out, _ := tr.Send(context.Background(), c.proto, c.addr, "t", []byte(c.doc)); out != ported.SendTerminal {
			t.Errorf("%v accepted: %v", c, out)
		}
	}
	if _, err := New("/nonexistent/ca.pem"); err == nil {
		t.Fatal("missing CA bundle accepted")
	}
}
