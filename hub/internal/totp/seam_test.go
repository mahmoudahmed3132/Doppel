// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package totp_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/auth"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/totp"
)

// The real module behind ported.TOTP drives the Hub's MFA flows end to end:
// enrolment, login with a code, replay refusal, recovery-code login.
func TestModuleThroughAuthService(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 15, 8, 0, 0, 0, time.UTC)
	clk := func() time.Time { return now }
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "hub.db"), store.Options{Now: clk})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	svc, err := auth.New(auth.Options{Store: db, Hasher: auth.NewHasher(auth.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1}, 2),
		TOTP: totp.Module{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: clk,
		SessionTTL: 12 * time.Hour, SessionIdle: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := svc.Init(ctx)
	if err != nil {
		t.Fatal(err)
	}
	const pw = "correct horse battery"
	if err := svc.Setup(ctx, "10.0.0.1", tok, pw, "https://hub.example.com/"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Login(ctx, "ip", pw, ""); err != nil {
		t.Fatal(err)
	}
	secret, uri, err := svc.BeginEnrolment(ctx, "ip", pw)
	if err != nil || len(secret) != 32 || uri == "" {
		t.Fatal(secret, uri, err)
	}
	codes, err := svc.ConfirmEnrolment(ctx, "ip", totp.CodeAt(secret, now))
	if err != nil || len(codes) != auth.RecoveryCodeCount {
		t.Fatal(len(codes), err)
	}
	if _, err := svc.Login(ctx, "ip", pw, totp.CodeAt(secret, now)); !errors.Is(err, auth.ErrInvalidCode) {
		t.Fatalf("replayed enrolment code: %v", err)
	}
	now = now.Add(30 * time.Second)
	if _, err := svc.Login(ctx, "ip", pw, totp.CodeAt(secret, now)); err != nil {
		t.Fatalf("current code refused: %v", err)
	}
	if _, err := svc.Login(ctx, "ip2", pw, codes[0]); err != nil {
		t.Fatalf("recovery code refused: %v", err)
	}
	if _, err := svc.Login(ctx, "ip3", pw, codes[0]); !errors.Is(err, auth.ErrInvalidCode) {
		t.Fatalf("recovery code reused: %v", err)
	}
}
