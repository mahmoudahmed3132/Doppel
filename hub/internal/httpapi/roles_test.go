// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/auth"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported/stub"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
)

type roleFixture struct {
	srv   *httptest.Server
	db    *store.DB
	svc   *auth.Service
	audit *auditLog
	toks  map[string]string // role/name -> session token
}

func newRoleFixture(t *testing.T) *roleFixture {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "ts.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc, err := auth.New(auth.Options{Store: db, Hasher: auth.NewHasher(auth.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1}, 4),
		TOTP: stub.TOTP{}, Log: log, SessionTTL: time.Hour, SessionIdle: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	setup, _ := svc.Init(ctx)
	if err := svc.Setup(ctx, "10.0.0.1", setup, adminPW, "https://hub.example.com"); err != nil {
		t.Fatal(err)
	}
	al := &auditLog{}
	a := &Admin{Auth: svc, Settings: db, Audit: al, Users: db, Log: log, Now: time.Now, Development: true}
	// One probe route per privilege level, registered the way every module
	// registers its routes.
	ok := func(w http.ResponseWriter, r *http.Request) { OK(w, nil) }
	a.RouteFull("GET /api/v3/probe/viewer", "", needViewer, ok)
	a.RouteFull("POST /api/v3/probe/analyst", "probe.analyst", needAnalyst, ok)
	a.RouteFull("POST /api/v3/probe/admin", "probe.admin", needAdmin, ok)
	srv := httptest.NewServer(SecurityHeaders(Network{}, a.Handler()))
	t.Cleanup(srv.Close)

	f := &roleFixture{srv: srv, db: db, svc: svc, audit: al, toks: map[string]string{}}
	for _, u := range []store.User{
		{ID: "usr_a", Username: "alice", Role: store.RoleAdmin, Source: store.SourceOIDC},
		{ID: "usr_n", Username: "nadia", Role: store.RoleAnalyst, Source: store.SourceOIDC},
		{ID: "usr_v", Username: "victor", Role: store.RoleViewer, Source: store.SourceOIDC},
	} {
		if err := db.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
		uu, _ := db.UserByID(ctx, u.ID)
		s, err := svc.NewUserSession(ctx, uu)
		if err != nil {
			t.Fatal(err)
		}
		f.toks[u.ID] = s.Token
	}
	boot, err := svc.Login(ctx, "10.0.0.1", adminPW, "")
	if err != nil {
		t.Fatal(err)
	}
	f.toks[store.BootstrapUserID] = boot.Token
	return f
}

func (f *roleFixture) call(tok, method, path, body string) (int, string) {
	req, _ := http.NewRequest(method, f.srv.URL+path, strings.NewReader(body))
	req.Header.Set("Origin", "https://hub.example.com") // the public endpoint set at setup
	req.Header.Set("Content-Type", "application/json")
	if tok != "" {
		req.AddCookie(&http.Cookie{Name: SessionCookie, Value: tok})
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestRoleMatrix(t *testing.T) {
	f := newRoleFixture(t)
	type probe struct{ method, path string }
	probes := map[string]probe{"viewer": {"GET", "/api/v3/probe/viewer"}, "analyst": {"POST", "/api/v3/probe/analyst"}, "admin": {"POST", "/api/v3/probe/admin"}}
	// who -> allowed levels
	allowed := map[string]map[string]bool{
		"usr_v":     {"viewer": true},
		"usr_n":     {"viewer": true, "analyst": true},
		"usr_a":     {"viewer": true, "analyst": true, "admin": true},
		"usr_admin": {"viewer": true, "analyst": true, "admin": true},
	}
	for who, levels := range allowed {
		for level, p := range probes {
			code, body := f.call(f.toks[who], p.method, p.path, "")
			want := http.StatusForbidden
			if levels[level] {
				want = http.StatusOK
			}
			if code != want {
				t.Errorf("%s -> %s probe: %d want %d (%s)", who, level, code, want, body)
			}
		}
	}
	if code, _ := f.call("", "GET", "/api/v3/probe/viewer", ""); code != http.StatusUnauthorized {
		t.Errorf("no session: %d", code)
	}
}

func TestLocalAccountRoutesAreBootstrapOnly(t *testing.T) {
	f := newRoleFixture(t)
	// An SSO administrator is still not the local account: it cannot touch
	// the local password or MFA.
	for _, p := range []struct{ m, path string }{{"POST", "/api/v3/system/password"}, {"POST", "/api/v3/mfa/disable"}, {"POST", "/api/v3/mfa/recovery-codes"},
		{"POST", "/api/v3/mfa/enrolment"}, {"GET", "/api/v3/mfa"}} {
		if code, body := f.call(f.toks["usr_a"], p.m, p.path, "{}"); code != http.StatusForbidden {
			t.Errorf("SSO admin on %s %s: %d (%s)", p.m, p.path, code, body)
		}
	}
	if code, _ := f.call(f.toks[store.BootstrapUserID], "GET", "/api/v3/mfa", ""); code != http.StatusOK {
		t.Errorf("bootstrap admin on /mfa: %d", code)
	}
}

func TestUsersAPIAndProtections(t *testing.T) {
	f := newRoleFixture(t)
	adm := f.toks["usr_a"]
	// Only admins reach the users API.
	for _, who := range []string{"usr_n", "usr_v"} {
		if code, _ := f.call(f.toks[who], "GET", "/api/v3/users", ""); code != http.StatusForbidden {
			t.Errorf("%s listed users: %d", who, code)
		}
	}
	if code, body := f.call(adm, "GET", "/api/v3/users", ""); code != 200 || !strings.Contains(body, `"usr_admin"`) || !strings.Contains(body, `"nadia"`) {
		t.Fatalf("list: %d %s", code, body)
	}
	// The bootstrap administrator cannot be changed, disabled or deleted.
	for _, c := range []struct{ m, body string }{{"PATCH", `{"role":"viewer"}`}, {"PATCH", `{"disabled":true}`}, {"DELETE", ""}} {
		if code, body := f.call(adm, c.m, "/api/v3/users/usr_admin", c.body); code != http.StatusForbidden || !strings.Contains(body, "protected_user") {
			t.Errorf("bootstrap %s %s: %d %s", c.m, c.body, code, body)
		}
	}
	// Demotion takes effect on the very next request (role is read per request).
	if code, _ := f.call(f.toks["usr_n"], "POST", "/api/v3/probe/analyst", ""); code != 200 {
		t.Fatal("analyst should pass before demotion")
	}
	if code, body := f.call(adm, "PATCH", "/api/v3/users/usr_n", `{"role":"viewer"}`); code != 200 {
		t.Fatalf("demote: %d %s", code, body)
	}
	if code, _ := f.call(f.toks["usr_n"], "POST", "/api/v3/probe/analyst", ""); code != http.StatusForbidden {
		t.Errorf("demoted analyst still passes: %d", code)
	}
	// Disabling ends sessions at once.
	if code, _ := f.call(adm, "PATCH", "/api/v3/users/usr_v", `{"disabled":true}`); code != 200 {
		t.Fatal("disable")
	}
	if code, _ := f.call(f.toks["usr_v"], "GET", "/api/v3/probe/viewer", ""); code != http.StatusUnauthorized {
		t.Errorf("disabled user still has a session: %d", code)
	}
	// Deleting removes the user and the session with it.
	if code, _ := f.call(adm, "DELETE", "/api/v3/users/usr_n", ""); code != 200 {
		t.Fatal("delete")
	}
	if code, _ := f.call(f.toks["usr_n"], "GET", "/api/v3/probe/viewer", ""); code != http.StatusUnauthorized {
		t.Errorf("deleted user still has a session: %d", code)
	}
	if code, _ := f.call(adm, "PATCH", "/api/v3/users/nobody", `{"role":"viewer"}`); code != http.StatusNotFound {
		t.Errorf("unknown user: %d", code)
	}
	if code, _ := f.call(adm, "PATCH", "/api/v3/users/usr_a", `{"role":"root"}`); code != http.StatusUnprocessableEntity {
		t.Errorf("bad role: %d", code)
	}
	// Audit records name the actor.
	var named bool
	f.audit.mu.Lock()
	for _, r := range f.audit.recs {
		if r.Action == "user.update" && r.Actor == "alice" && r.ActorID == "usr_a" {
			named = true
		}
	}
	f.audit.mu.Unlock()
	if !named {
		t.Error("user.update audit record does not carry the actor")
	}
}

func TestLastAdminCannotBeRemoved(t *testing.T) {
	f := newRoleFixture(t)
	adm := f.toks["usr_a"]
	// usr_a is an administrator, and so is the bootstrap one; the bootstrap
	// admin counts as an enabled administrator, so demoting usr_a is allowed.
	if code, body := f.call(adm, "PATCH", "/api/v3/users/usr_a", `{"role":"viewer"}`); code != 200 {
		t.Fatalf("self-demotion with another admin present: %d %s", code, body)
	}
	// Make a second SSO admin and remove the bootstrap from the equation by
	// checking the store rule directly: with only one enabled admin (usr_b),
	// demoting, disabling and deleting must all be refused.
	ctx := context.Background()
	f.db.CreateUser(ctx, store.User{ID: "usr_b", Username: "bob", Role: store.RoleAdmin, Source: store.SourceOIDC})
	// bootstrap is protected and counts: two admins exist (usr_admin, usr_b)
	if err := f.db.SetUserRole(ctx, "usr_b", store.RoleViewer); err != nil {
		t.Fatalf("usr_b demotion with bootstrap present: %v", err)
	}
	f.db.SetUserRole(ctx, "usr_b", store.RoleAdmin)
	// Remove the bootstrap admin's standing by disabling it directly in SQL,
	// as only a host-side action could, then the guard must hold for usr_b.
	f.db.TestExec(t, `UPDATE users SET disabled = 1 WHERE id = 'usr_admin'`)
	for name, fn := range map[string]func() error{
		"demote":  func() error { return f.db.SetUserRole(ctx, "usr_b", store.RoleAnalyst) },
		"disable": func() error { return f.db.SetUserDisabled(ctx, "usr_b", true) },
		"delete":  func() error { return f.db.DeleteUser(ctx, "usr_b") },
	} {
		if err := fn(); err != store.ErrLastAdmin {
			t.Errorf("%s the last admin: %v", name, err)
		}
	}
}
