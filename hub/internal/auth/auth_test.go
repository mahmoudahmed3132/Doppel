// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported/stub"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
)

const pw = "correct horse battery"

var cheap = Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type fixture struct {
	svc *Service
	db  *store.DB
	clk *clock
	tok string
}

func newFixture(t *testing.T, mod func(*Options)) *fixture {
	t.Helper()
	clk := &clock{t: time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)}
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "ts.db"), store.Options{Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	o := Options{Store: db, Hasher: NewHasher(cheap, 2), TOTP: stub.TOTP{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: clk.now, SessionTTL: 12 * time.Hour, SessionIdle: 15 * time.Minute}
	if mod != nil {
		mod(&o)
	}
	svc, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := svc.Init(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{svc: svc, db: db, clk: clk, tok: tok}
}

func (f *fixture) setup(t *testing.T) {
	t.Helper()
	if err := f.svc.Setup(context.Background(), "10.0.0.1", f.tok, pw, "https://hub.example.com/"); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordHashRoundTrip(t *testing.T) {
	h := NewHasher(cheap, 1)
	enc, err := h.Hash(context.Background(), pw)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := h.Verify(context.Background(), pw, enc); !ok {
		t.Fatal("correct password refused")
	}
	if ok, _ := h.Verify(context.Background(), pw+"x", enc); ok {
		t.Fatal("wrong password accepted")
	}
	if _, err := h.Verify(context.Background(), pw, "$2a$12$bcrypt"); err == nil {
		t.Fatal("foreign hash format accepted")
	}
	enc2, _ := h.Hash(context.Background(), pw)
	if enc == enc2 {
		t.Fatal("salt not random")
	}
}

func TestSetup(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	if len(f.tok) < 43 {
		t.Fatalf("setup token too short: %q", f.tok)
	}
	if err := f.svc.Setup(ctx, "ip", "wrong", pw, "https://hub"); !errors.Is(err, ErrInvalidSetupToken) {
		t.Fatalf("wrong token: %v", err)
	}
	if err := f.svc.Setup(ctx, "ip", f.tok, "short pw", "https://hub"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("short password: %v", err)
	}
	if err := f.svc.Setup(ctx, "ip", f.tok, pw, "ftp://hub"); !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("bad endpoint: %v", err)
	}
	f.setup(t)
	if v, _, _ := f.db.Setting(ctx, SettingEndpoint); v != "https://hub.example.com" {
		t.Fatalf("endpoint %q", v)
	}
	if err := f.svc.Setup(ctx, "ip", f.tok, pw, "https://hub"); !errors.Is(err, ErrSetupCompleted) {
		t.Fatalf("second setup: %v", err)
	}
	// A restarted Hub must not mint a new token once setup is complete.
	if tok, _ := f.svc.Init(ctx); tok != "" {
		t.Fatal("token generated after setup")
	}
}

func TestSetupTokenOverrideAndPasswordOverride(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.SetupTokenOverride = "operator-supplied-token-0123456789abcdef" })
	if f.tok != "" {
		t.Fatal("override token must not be returned for printing")
	}
	if err := f.svc.Setup(context.Background(), "ip", "operator-supplied-token-0123456789abcdef", pw, "https://h"); err != nil {
		t.Fatal(err)
	}

	g := newFixture(t, func(o *Options) { o.PasswordOverride = "env-managed-password" })
	ctx := context.Background()
	if done, _ := g.svc.SetupCompleted(ctx); !done {
		t.Fatal("override must create the admin")
	}
	if _, err := g.svc.Login(ctx, "ip", "env-managed-password", ""); err != nil {
		t.Fatal(err)
	}
	if err := g.svc.ChangePassword(ctx, "ip", "env-managed-password", "another long password"); !errors.Is(err, ErrPasswordManaged) {
		t.Fatalf("change with override: %v", err)
	}
}

func TestLoginLockouts(t *testing.T) {
	f := newFixture(t, nil)
	f.setup(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if _, err := f.svc.Login(ctx, "198.51.100.1", "wrong", ""); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	var le *LockedError
	if _, err := f.svc.Login(ctx, "198.51.100.1", pw, ""); !errors.As(err, &le) {
		t.Fatalf("IP not locked after 5 failures: %v", err)
	}
	if _, err := f.svc.Login(ctx, "198.51.100.2", pw, ""); err != nil {
		t.Fatalf("other IP locked: %v", err)
	}

	// Account-wide: 10 failures across IPs lock everyone.
	for i := 0; i < 10; i++ {
		f.svc.Login(ctx, fmt.Sprintf("203.0.113.%d", i), "wrong", "")
	}
	if _, err := f.svc.Login(ctx, "192.0.2.77", pw, ""); !errors.As(err, &le) || le.RetryAfter <= 0 {
		t.Fatalf("account not locked: %v", err)
	}
	f.clk.advance(15*time.Minute + time.Second)
	if _, err := f.svc.Login(ctx, "192.0.2.77", pw, ""); err != nil {
		t.Fatalf("lock did not expire: %v", err)
	}
}

func TestMFAFlow(t *testing.T) {
	f := newFixture(t, nil)
	f.setup(t)
	ctx := context.Background()
	totp := stub.TOTP{}

	sess, err := f.svc.Login(ctx, "ip", pw, "")
	if err != nil || sess.EnrolOnly {
		t.Fatal(sess, err)
	}
	if _, _, err := f.svc.BeginEnrolment(ctx, "ip", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("enrolment without password")
	}
	secret, uri, err := f.svc.BeginEnrolment(ctx, "ip", pw)
	if err != nil || secret == "" || uri == "" {
		t.Fatal(err)
	}
	if _, err := f.svc.ConfirmEnrolment(ctx, "ip", "000000"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("bad confirm code: %v", err)
	}
	codes, err := f.svc.ConfirmEnrolment(ctx, "ip", totp.CodeAt(f.clk.now()))
	if err != nil || len(codes) != RecoveryCodeCount {
		t.Fatal(len(codes), err)
	}
	if _, err := f.svc.Authenticate(ctx, sess.Token); !errors.Is(err, ErrSessionInvalid) {
		t.Fatal("session survived MFA enrolment")
	}

	// Password alone now asks for a code.
	if _, err := f.svc.Login(ctx, "ip", pw, ""); !errors.Is(err, ErrMFARequired) {
		t.Fatalf("expected mfa_required: %v", err)
	}
	// The enrolment code's step is consumed: replay refused.
	if _, err := f.svc.Login(ctx, "ip", pw, totp.CodeAt(f.clk.now())); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("TOTP replay accepted: %v", err)
	}
	f.clk.advance(30 * time.Second)
	code := totp.CodeAt(f.clk.now())
	if _, err := f.svc.Login(ctx, "ip", pw, code); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Login(ctx, "ip2", pw, code); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("same TOTP accepted twice")
	}

	// Recovery code: single use.
	if _, err := f.svc.Login(ctx, "ip", pw, codes[3]); err != nil {
		t.Fatalf("recovery code refused: %v", err)
	}
	if _, err := f.svc.Login(ctx, "ip", pw, codes[3]); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("recovery code reused")
	}
	st, _ := f.svc.MFAStatus(ctx)
	if st.RecoveryCodesRemaining != 9 || !st.Enabled {
		t.Fatalf("%+v", st)
	}

	// Regenerate: password + current code; keeps the current session only.
	f.clk.advance(30 * time.Second)
	cur, _ := f.svc.Login(ctx, "ip", pw, codes[0])
	other, _ := f.svc.Login(ctx, "ip", pw, codes[1])
	if _, err := f.svc.RegenerateRecoveryCodes(ctx, "ip", pw, codes[2], cur); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("regenerate accepted a recovery code instead of a current TOTP code")
	}
	newCodes, err := f.svc.RegenerateRecoveryCodes(ctx, "ip", pw, totp.CodeAt(f.clk.now()), cur)
	if err != nil || len(newCodes) != RecoveryCodeCount {
		t.Fatal(err)
	}
	if _, err := f.svc.Authenticate(ctx, cur.Token); err != nil {
		t.Fatal("current session dropped by regenerate")
	}
	if _, err := f.svc.Authenticate(ctx, other.Token); err == nil {
		t.Fatal("other session kept by regenerate")
	}
	if _, err := f.svc.Login(ctx, "ip", pw, codes[4]); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("old recovery code still valid")
	}

	// Disable: password + current code.
	f.clk.advance(30 * time.Second)
	if err := f.svc.DisableMFA(ctx, "ip", pw, totp.CodeAt(f.clk.now())); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Login(ctx, "ip", pw, ""); err != nil {
		t.Fatal("login after disable")
	}
}

func TestConcurrentRecoveryCodeUse(t *testing.T) {
	f := newFixture(t, nil)
	f.setup(t)
	ctx := context.Background()
	f.svc.BeginEnrolment(ctx, "ip", pw)
	codes, _ := f.svc.ConfirmEnrolment(ctx, "ip", stub.TOTP{}.CodeAt(f.clk.now()))

	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := f.svc.Login(ctx, fmt.Sprintf("10.9.9.%d", i), pw, codes[0]); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("recovery code accepted %d times", wins)
	}
}

func TestRequireMFAMode(t *testing.T) {
	if _, err := New(Options{RequireMFA: true}); err == nil {
		t.Fatal("require-MFA without TOTP module accepted")
	}
	f := newFixture(t, func(o *Options) { o.RequireMFA = true })
	f.setup(t)
	ctx := context.Background()
	sess, err := f.svc.Login(ctx, "ip", pw, "")
	if err != nil || !sess.EnrolOnly {
		t.Fatalf("expected enrol-only session: %+v %v", sess, err)
	}
	f.svc.BeginEnrolment(ctx, "ip", pw)
	f.svc.ConfirmEnrolment(ctx, "ip", stub.TOTP{}.CodeAt(f.clk.now()))
	f.clk.advance(30 * time.Second)
	full, err := f.svc.Login(ctx, "ip", pw, stub.TOTP{}.CodeAt(f.clk.now()))
	if err != nil || full.EnrolOnly {
		t.Fatal(full, err)
	}
	f.clk.advance(30 * time.Second)
	if err := f.svc.DisableMFA(ctx, "ip", pw, stub.TOTP{}.CodeAt(f.clk.now())); !errors.Is(err, ErrMFAMandatory) {
		t.Fatalf("disable in require-MFA mode: %v", err)
	}
}

func TestSessionExpiry(t *testing.T) {
	f := newFixture(t, nil)
	f.setup(t)
	ctx := context.Background()
	s, _ := f.svc.Login(ctx, "ip", pw, "")

	// Idle timeout refreshed by activity.
	for i := 0; i < 5; i++ {
		f.clk.advance(14 * time.Minute)
		if _, err := f.svc.Authenticate(ctx, s.Token); err != nil {
			t.Fatalf("active session expired at step %d", i)
		}
	}
	f.clk.advance(15 * time.Minute)
	if _, err := f.svc.Authenticate(ctx, s.Token); !errors.Is(err, ErrSessionInvalid) {
		t.Fatal("idle timeout not enforced")
	}

	// Absolute TTL despite activity.
	s, _ = f.svc.Login(ctx, "ip", pw, "")
	for elapsed := time.Duration(0); elapsed < 12*time.Hour-10*time.Minute; elapsed += 10 * time.Minute {
		f.clk.advance(10 * time.Minute)
		f.svc.Authenticate(ctx, s.Token)
	}
	f.clk.advance(11 * time.Minute)
	if _, err := f.svc.Authenticate(ctx, s.Token); !errors.Is(err, ErrSessionInvalid) {
		t.Fatal("absolute TTL not enforced")
	}

	// Logout and password change invalidate.
	s1, _ := f.svc.Login(ctx, "ip", pw, "")
	s2, _ := f.svc.Login(ctx, "ip", pw, "")
	f.svc.Logout(ctx, s1)
	if _, err := f.svc.Authenticate(ctx, s1.Token); err == nil {
		t.Fatal("logout did not delete session")
	}
	if err := f.svc.ChangePassword(ctx, "ip", pw, "new password long enough"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Authenticate(ctx, s2.Token); err == nil {
		t.Fatal("password change kept sessions")
	}
	if _, err := f.svc.Login(ctx, "ip", "new password long enough", ""); err != nil {
		t.Fatal(err)
	}
}

// laxTOTP accepts the current stub code regardless of lastStep, modelling a
// TOTP module that leaves replay protection to the Hub.
type laxTOTP struct{ stub.TOTP }

func (laxTOTP) Verify(_ string, code string, _ int64, now time.Time) (int64, bool) {
	step := now.Unix() / 30
	return step, code == stub.TOTP{}.CodeAt(now)
}

func TestHubEnforcesTOTPReplayItself(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.TOTP = laxTOTP{} })
	f.setup(t)
	ctx := context.Background()
	f.svc.BeginEnrolment(ctx, "ip", pw)
	if _, err := f.svc.ConfirmEnrolment(ctx, "ip", stub.TOTP{}.CodeAt(f.clk.now())); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Login(ctx, "ip", pw, stub.TOTP{}.CodeAt(f.clk.now())); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("enrolment step replayed: %v", err)
	}
	f.clk.advance(30 * time.Second)
	code := stub.TOTP{}.CodeAt(f.clk.now())
	if _, err := f.svc.Login(ctx, "ip", pw, code); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Login(ctx, "ip", pw, code); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("TOTP replay accepted: %v", err)
	}
}
