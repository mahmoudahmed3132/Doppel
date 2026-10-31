// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/auth"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/domain"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/ported/stub"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/store"
)

const adminPW = "a sufficiently long password"

type auditLog struct {
	mu   sync.Mutex
	recs []domain.AuditRecord
}

func (l *auditLog) Record(_ context.Context, r domain.AuditRecord) {
	l.mu.Lock()
	l.recs = append(l.recs, r)
	l.mu.Unlock()
}

func (l *auditLog) actions() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, r := range l.recs {
		out = append(out, fmt.Sprintf("%s:%d", r.Action, r.Status))
	}
	return out
}

type adminFixture struct {
	srv   *httptest.Server
	token string
	audit *auditLog
	svc   *auth.Service
	now   *time.Time
	mu    *sync.Mutex
}

func newAdmin(t *testing.T, requireMFA bool) *adminFixture {
	t.Helper()
	ctx := context.Background()
	mu := &sync.Mutex{}
	now := time.Now().UTC()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "ts.db"), store.Options{Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc, err := auth.New(auth.Options{Store: db, Hasher: auth.NewHasher(auth.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1}, 4),
		TOTP: stub.TOTP{}, Log: log, Now: clock, SessionTTL: 12 * time.Hour, SessionIdle: 15 * time.Minute, RequireMFA: requireMFA})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := svc.Init(ctx)
	if err != nil {
		t.Fatal(err)
	}
	al := &auditLog{}
	a := &Admin{Auth: svc, Settings: db, Audit: al, Log: log, Now: clock, Development: true}
	srv := httptest.NewServer(SecurityHeaders(Network{}, a.Handler()))
	t.Cleanup(srv.Close)
	return &adminFixture{srv: srv, token: tok, audit: al, svc: svc, now: &now, mu: mu}
}

func (f *adminFixture) advance(d time.Duration) { f.mu.Lock(); *f.now = f.now.Add(d); f.mu.Unlock() }
func (f *adminFixture) code() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return stub.TOTP{}.CodeAt(*f.now)
}

type client struct {
	t      *testing.T
	http   *http.Client
	base   string
	origin string
	xff    string
}

func (f *adminFixture) client(t *testing.T) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, http: &http.Client{Jar: jar}, base: f.srv.URL, origin: f.srv.URL}
}

func (c *client) do(method, path string, body any) (int, map[string]any, *http.Response) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	if c.origin != "" {
		req.Header.Set("Origin", c.origin)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, resp
}

func (f *adminFixture) doSetup(t *testing.T) {
	t.Helper()
	c := f.client(t)
	code, out, _ := c.do("POST", "/api/v3/setup", map[string]string{"setup_token": f.token, "password": adminPW, "public_endpoint": f.srv.URL})
	if code != 200 {
		t.Fatalf("setup: %d %v", code, out)
	}
}

func TestAdminSetupFlow(t *testing.T) {
	f := newAdmin(t, false)
	c := f.client(t)

	code, out, resp := c.do("GET", "/api/v3/setup", nil)
	if code != 200 || out["setup_completed"] != false {
		t.Fatalf("%d %v", code, out)
	}
	for h, want := range map[string]string{"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY"} {
		if resp.Header.Get(h) != want {
			t.Errorf("header %s = %q", h, resp.Header.Get(h))
		}
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Error("CSP missing")
	}
	if resp.Header.Get("Strict-Transport-Security") != "" {
		t.Error("HSTS over plain HTTP")
	}

	code, out, _ = c.do("POST", "/api/v3/setup", map[string]string{"setup_token": "nope", "password": adminPW, "public_endpoint": f.srv.URL})
	if code != 403 || out["error"] != "invalid_setup_token" {
		t.Fatalf("%d %v", code, out)
	}
	code, out, _ = c.do("POST", "/api/v3/setup", map[string]string{"setup_token": f.token, "password": "elevenchars", "public_endpoint": f.srv.URL})
	if code != 400 || out["error"] != "weak_password" {
		t.Fatalf("%d %v", code, out)
	}
	f.doSetup(t)
	code, out, _ = c.do("POST", "/api/v3/setup", map[string]string{"setup_token": f.token, "password": adminPW, "public_endpoint": f.srv.URL})
	if code != 409 || out["error"] != "setup_completed" {
		t.Fatalf("second setup: %d %v", code, out)
	}
	acts := strings.Join(f.audit.actions(), " ")
	if !strings.Contains(acts, "setup.complete:403") || !strings.Contains(acts, "setup.complete:200") || !strings.Contains(acts, "setup.complete:409") {
		t.Fatalf("setup attempts not audited: %s", acts)
	}
}

func TestAdminCSRF(t *testing.T) {
	f := newAdmin(t, false)
	f.doSetup(t)
	for _, origin := range []string{"", "https://evil.example", "null"} {
		c := f.client(t)
		c.origin = origin
		code, out, _ := c.do("POST", "/api/v3/session/login", map[string]string{"password": adminPW})
		if code != 403 || out["error"] != "origin_mismatch" {
			t.Fatalf("origin %q: %d %v", origin, code, out)
		}
	}
	// Referer fallback with the right origin is accepted.
	jar, _ := cookiejar.New(nil)
	req, _ := http.NewRequest("POST", f.srv.URL+"/api/v3/session/login", strings.NewReader(`{"password":"`+adminPW+`"}`))
	req.Header.Set("Referer", f.srv.URL+"/login")
	resp, err := (&http.Client{Jar: jar}).Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("referer fallback: %v %v", resp.StatusCode, err)
	}
}

func TestAdminLoginCookieAndLockout(t *testing.T) {
	f := newAdmin(t, false)
	f.doSetup(t)
	c := f.client(t)

	code, out, resp := c.do("POST", "/api/v3/session/login", map[string]string{"password": adminPW})
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	var sc *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == SessionCookie {
			sc = ck
		}
	}
	if sc == nil || !sc.HttpOnly || sc.SameSite != http.SameSiteStrictMode || sc.Path != "/" || len(sc.Value) < 40 {
		t.Fatalf("cookie %+v", sc)
	}
	if code, _, _ := c.do("GET", "/api/v3/session", nil); code != 200 {
		t.Fatal("session not usable")
	}
	if code, _, _ := c.do("POST", "/api/v3/session/logout", nil); code != 200 {
		t.Fatal("logout")
	}
	if code, _, _ := c.do("GET", "/api/v3/session", nil); code != 401 {
		t.Fatal("session usable after logout")
	}

	bad := f.client(t)
	for i := 0; i < 5; i++ {
		if code, _, _ := bad.do("POST", "/api/v3/session/login", map[string]string{"password": "wrong password!"}); code != 401 {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	code, out, resp = bad.do("POST", "/api/v3/session/login", map[string]string{"password": adminPW})
	if code != 429 || out["error"] != "locked" || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("lockout: %d %v", code, out)
	}
	if !strings.Contains(strings.Join(f.audit.actions(), " "), "session.login:429") {
		t.Fatal("locked login not audited")
	}
}

func TestAdminMFAOverHTTP(t *testing.T) {
	f := newAdmin(t, false)
	f.doSetup(t)
	c := f.client(t)
	c.do("POST", "/api/v3/session/login", map[string]string{"password": adminPW})

	code, out, _ := c.do("POST", "/api/v3/mfa/enrolment", map[string]string{"password": adminPW})
	if code != 200 || out["secret"] == "" || !strings.HasPrefix(out["otpauth_uri"].(string), "otpauth://") {
		t.Fatalf("%d %v", code, out)
	}
	code, out, _ = c.do("POST", "/api/v3/mfa/enrolment/confirm", map[string]string{"code": f.code()})
	if code != 200 || len(out["recovery_codes"].([]any)) != 10 {
		t.Fatalf("%d %v", code, out)
	}
	recovery := out["recovery_codes"].([]any)[0].(string)
	if code, _, _ := c.do("GET", "/api/v3/session", nil); code != 401 {
		t.Fatal("session survived enrolment")
	}

	code, out, _ = c.do("POST", "/api/v3/session/login", map[string]string{"password": adminPW})
	if code != 401 || out["error"] != "mfa_required" {
		t.Fatalf("%d %v", code, out)
	}
	code, out, _ = c.do("POST", "/api/v3/session/login", map[string]string{"password": adminPW, "code": f.code()})
	if code != 401 || out["error"] != "invalid_code" {
		t.Fatalf("replayed enrolment code: %d %v", code, out)
	}
	code, _, _ = c.do("POST", "/api/v3/session/login", map[string]string{"password": adminPW, "code": recovery})
	if code != 200 {
		t.Fatal("recovery login refused")
	}
	c2 := f.client(t)
	if code, _, _ := c2.do("POST", "/api/v3/session/login", map[string]string{"password": adminPW, "code": recovery}); code != 401 {
		t.Fatal("recovery code reused")
	}

	// Audit records must not contain secrets or codes.
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	b, _ := json.Marshal(f.audit.recs)
	if strings.Contains(string(b), recovery) || strings.Contains(string(b), adminPW) {
		t.Fatal("secret material in audit records")
	}
}

func TestRequireMFAEnrolOnlySession(t *testing.T) {
	f := newAdmin(t, true)
	f.doSetup(t)
	c := f.client(t)
	code, out, _ := c.do("POST", "/api/v3/session/login", map[string]string{"password": adminPW})
	if code != 200 || out["session"].(map[string]any)["enrol_only"] != true {
		t.Fatalf("%d %v", code, out)
	}
	if code, out, _ := c.do("GET", "/api/v3/session", nil); code != 403 || out["error"] != "mfa_enrolment_required" {
		t.Fatalf("full route reachable: %d %v", code, out)
	}
	if code, _, _ := c.do("POST", "/api/v3/system/password", map[string]string{"current_password": adminPW, "new_password": "something else long"}); code != 403 {
		t.Fatal("password change reachable from enrol-only session")
	}
	if code, _, _ := c.do("GET", "/api/v3/mfa", nil); code != 200 {
		t.Fatal("MFA status unreachable")
	}
	if code, _, _ := c.do("POST", "/api/v3/mfa/enrolment", map[string]string{"password": adminPW}); code != 200 {
		t.Fatal("enrolment unreachable")
	}
	if code, _, _ := c.do("POST", "/api/v3/mfa/enrolment/confirm", map[string]string{"code": f.code()}); code != 200 {
		t.Fatal("confirm unreachable")
	}
	f.advance(30 * time.Second)
	code, out, _ = c.do("POST", "/api/v3/session/login", map[string]string{"password": adminPW, "code": f.code()})
	if code != 200 || out["session"].(map[string]any)["enrol_only"] != false {
		t.Fatalf("%d %v", code, out)
	}
	f.advance(30 * time.Second)
	code, out, _ = c.do("POST", "/api/v3/mfa/disable", map[string]string{"password": adminPW, "code": f.code()})
	if code != 403 || out["error"] != "mfa_mandatory" {
		t.Fatalf("disable in require-MFA mode: %d %v", code, out)
	}
}

func TestStrictAdminBodies(t *testing.T) {
	f := newAdmin(t, false)
	c := f.client(t)
	code, out, _ := c.do("POST", "/api/v3/session/login", map[string]any{"password": "x", "admin": true})
	if code != 400 || out["error"] != "unknown_field" {
		t.Fatalf("%d %v", code, out)
	}
}

func TestClientIP(t *testing.T) {
	n := Network{Trusted: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	mk := func(remote string, xff ...string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		for _, v := range xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		return r
	}
	cases := []struct {
		r    *http.Request
		want string
	}{
		{mk("203.0.113.5:1234", "1.2.3.4"), "203.0.113.5"},             // untrusted peer: header ignored
		{mk("10.0.0.2:1234", "1.2.3.4"), "1.2.3.4"},                    // trusted proxy
		{mk("10.0.0.2:1234", "6.6.6.6, 1.2.3.4, 10.0.0.9"), "1.2.3.4"}, // spoofed left entry ignored
		{mk("10.0.0.2:1234", "6.6.6.6", "1.2.3.4"), "1.2.3.4"},         // multiple headers
		{mk("10.0.0.2:1234", "garbage, 10.0.0.3"), "10.0.0.3"},         // malformed: stop
		{mk("10.0.0.2:1234"), "10.0.0.2"},                              // no header
		{mk("[::ffff:203.0.113.7]:1"), "203.0.113.7"},                  // mapped v4
	}
	for i, c := range cases {
		if got := n.ClientIP(c.r); got != c.want {
			t.Errorf("case %d: %s want %s", i, got, c.want)
		}
	}
	r := mk("10.0.0.2:1", "1.2.3.4")
	r.Header.Set("X-Forwarded-Proto", "https")
	if !n.IsHTTPS(r) {
		t.Fatal("trusted proto ignored")
	}
	r = mk("203.0.113.5:1")
	r.Header.Set("X-Forwarded-Proto", "https")
	if n.IsHTTPS(r) {
		t.Fatal("untrusted proto believed")
	}
}

func TestClearCookieSecureOutsideDevelopment(t *testing.T) {
	for _, dev := range []bool{false, true} {
		w := httptest.NewRecorder()
		(&Admin{Development: dev}).clearCookie(w)
		c := w.Result().Cookies()
		if len(c) != 1 || c[0].Secure == dev || !c[0].HttpOnly || c[0].MaxAge >= 0 || c[0].SameSite != http.SameSiteStrictMode {
			t.Fatalf("development=%v: %+v", dev, c)
		}
	}
}
