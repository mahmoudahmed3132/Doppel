// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

type rec struct {
	mu  sync.Mutex
	ev  []map[string]any
	cfg map[string]string
}

func (r *rec) ReportSeverity(sev sensor.Severity, trig, src, _ string, d sensor.Details) {
	m := map[string]any{"_trigger": trig, "_severity": string(sev)}
	for _, f := range d.(sensor.Fields) {
		m[f.Key] = f.Value
	}
	r.mu.Lock()
	r.ev = append(r.ev, m)
	r.mu.Unlock()
}
func (r *rec) Setting(k string) (string, bool) { v, ok := r.cfg[k]; return v, ok }
func (r *rec) of(trig string) []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []map[string]any
	for _, e := range r.ev {
		if e["_trigger"] == trig {
			out = append(out, e)
		}
	}
	return out
}

var key = strings.Repeat("ab", 32)

func newServer(t *testing.T, cfg map[string]string) (*httptest.Server, *rec) {
	t.Helper()
	if cfg == nil {
		cfg = map[string]string{}
	}
	if _, ok := cfg["TS_CAPTURE_KEY"]; !ok {
		cfg["TS_CAPTURE_KEY"] = key
	}
	r := &rec{cfg: cfg}
	d, _, err := NewFromSettings(r)
	if err != nil {
		t.Fatal(err)
	}
	d.FailDelay = func() time.Duration { return 0 }
	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)
	return srv, r
}

func TestLoginCapturedAsHMACAndAlwaysFails(t *testing.T) {
	srv, r := newServer(t, nil)
	form := url.Values{"username": {"admin"}, "password": {"hunter2"}, "csrf-Token": {"x"}, "remember.me": {"1"}, "<script>": {"y"}}
	resp, err := http.PostForm(srv.URL+"/login", form)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "Invalid username or password") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	ev := r.of(TriggerLogin)
	if len(ev) != 1 {
		t.Fatalf("%v", r.ev)
	}
	e := ev[0]
	k, _ := hex.DecodeString(key)
	if e["username"] != "admin" || e["password_hmac"] != PasswordHMAC(k, "hunter2") || e["auth"] != "form" || e["_severity"] != "critical" {
		t.Fatalf("%v", e)
	}
	if _, has := e["password"]; has {
		t.Fatal("plaintext password captured under hash policy")
	}
	if e["form_csrf_token"] != "x" || e["form_remember_me"] != "1" || e["form_script"] != "y" {
		t.Fatalf("form fields: %v", e)
	}
	if strings.Contains(string(body), "hunter2") {
		t.Fatal("password reflected")
	}
}

func TestBasicAuthAndPolicies(t *testing.T) {
	srv, r := newServer(t, map[string]string{"TS_PASSWORD_CAPTURE": "plain"})
	req, _ := http.NewRequest("GET", srv.URL+"/cgi-bin/admin", nil)
	req.SetBasicAuth("root", "toor")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 401 || resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
	e := r.of(TriggerLogin)[0]
	if e["auth"] != "basic" || e["username"] != "root" || e["password"] != "toor" {
		t.Fatalf("%v", e)
	}
	srv2, r2 := newServer(t, map[string]string{"TS_PASSWORD_CAPTURE": "none"})
	http.PostForm(srv2.URL+"/login", url.Values{"username": {"a"}, "password": {"b"}})
	e = r2.of(TriggerLogin)[0]
	if _, has := e["password"]; has {
		t.Fatal("password captured under none")
	}
	if _, has := e["password_hmac"]; has {
		t.Fatal("hmac captured under none")
	}
	if _, _, err := NewFromSettings(&rec{cfg: map[string]string{}}); err == nil {
		t.Fatal("hash capture without a capture key accepted")
	}
}

func TestProbesViewsEscaping(t *testing.T) {
	srv, r := newServer(t, map[string]string{"TS_PROBE_COOLDOWN_SEC": "3600"})
	resp, _ := http.Get(srv.URL + "/")
	resp.Body.Close()
	resp, _ = http.Get(srv.URL + "/")
	resp.Body.Close()
	if n := len(r.of(TriggerPageView)); n != 1 {
		t.Fatalf("page views %d", n)
	}
	resp, _ = http.Get(srv.URL + "/<script>alert(1)</script>/../../etc/passwd")
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 404 || strings.Contains(string(body), "<script>alert") {
		t.Fatalf("%d reflected: %s", resp.StatusCode, body)
	}
	http.Get(srv.URL + "/wp-admin")
	p := r.of(TriggerProbe)
	if len(p) != 1 || !strings.Contains(p[0]["path"].(string), "script") {
		t.Fatalf("probes %v", p)
	}
	// Oversized body is refused but still answered with a failure page.
	big := strings.NewReader("username=a&password=" + strings.Repeat("x", 20<<10))
	resp, _ = http.Post(srv.URL+"/login", "application/x-www-form-urlencoded", big)
	if resp.StatusCode != 200 {
		t.Fatalf("%d", resp.StatusCode)
	}
}

func TestTestModeAgainstMockHub(t *testing.T) {
	var got []map[string]any
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b struct{ Events []map[string]any }
		json.NewDecoder(r.Body).Decode(&b)
		got = append(got, b.Events...)
		io.WriteString(w, `{"ok":true,"accepted":1,"duplicates":0,"rejected":[]}`)
	}))
	defer hub.Close()
	env := map[string]string{"TS_HUB_ENDPOINT": hub.URL, "TS_TEST_MODE": "true", "TS_DEV_ALLOW_HTTP": "true"}
	if code := sensor.Run(context.Background(), spec, sensor.Options{Getenv: func(k string) string { return env[k] },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}); code != 0 || len(got) != 1 || got[0]["trigger"] != TriggerLogin {
		t.Fatalf("%d %v", code, got)
	}
}
