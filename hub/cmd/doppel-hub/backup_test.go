// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/backup"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/config"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/seal"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
)

func TestCLIBackupScheduleFlag(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	if err := backupCmd(log, []string{"--schedule"}); err != nil {
		t.Fatalf("backup --schedule: %v", err)
	}
}

func TestCLIBackupVerifyRestoreDrill(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.DiscardHandler)

	dbDir := t.TempDir()
	dbPath := filepath.Join(dbDir, "hub.db")
	kekDir := t.TempDir()
	kekPath := filepath.Join(kekDir, "hub.kek")
	k, err := seal.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kekPath, []byte(k+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Populate a sealed database with a secret, node, and active session.
	db, err := store.Open(ctx, dbPath, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.EnableEncryption(ctx, seal.FileProvider{Path: kekPath}, nil); err != nil {
		t.Fatal(err)
	}
	_, _ = db.TakeCLIAudits(ctx)
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := db.CreateAdmin(ctx, "dummy-argon2-hash", map[string]string{
		"siem_token": "drill-token-xyz",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateNode(ctx, &domain.Node{ID: "n-drill", Alias: "drill-host", KeyHash: []byte("kh-drill"), CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateSession(ctx, store.Session{
		TokenHash: []byte("s-drill-hash"), UserID: store.BootstrapUserID, CreatedAt: now, LastSeenAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Generate age keypair for --encrypt-to / --identity.
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	idPath := filepath.Join(t.TempDir(), "backup.agekey")
	if err := os.WriteFile(idPath, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv(config.EnvDBPath, dbPath)
	t.Setenv(config.EnvKEKFile, kekPath)

	backupDir := filepath.Join(t.TempDir(), "snap")
	if err := backupCmd(log, []string{"--out", backupDir, "--encrypt-to", id.Recipient().String()}); err != nil {
		t.Fatalf("backupCmd: %v", err)
	}

	// Verify without identity (ciphertext checksum only) and with identity (full check).
	if err := verifyCmd(log, []string{"--from", backupDir}); err != nil {
		t.Fatalf("verifyCmd (no identity): %v", err)
	}
	if err := verifyCmd(log, []string{"--from", backupDir, "--identity", idPath}); err != nil {
		t.Fatalf("verifyCmd (with identity): %v", err)
	}

	// Wrong KEK must be rejected by restoreCmd.
	wrongKEKPath := filepath.Join(t.TempDir(), "wrong.kek")
	wk, _ := seal.GenerateKEK()
	if err := os.WriteFile(wrongKEKPath, []byte(wk+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restoreCmd(log, []string{"--from", backupDir, "--identity", idPath, "--kek-file", wrongKEKPath}); err == nil {
		t.Fatalf("expected restoreCmd with wrong KEK to fail")
	}

	// Wipe original DB and restore.
	_ = os.Remove(dbPath)
	_ = os.Remove(dbPath + "-wal")
	_ = os.Remove(dbPath + "-shm")

	if err := restoreCmd(log, []string{"--from", backupDir, "--identity", idPath}); err != nil {
		t.Fatalf("restoreCmd: %v", err)
	}

	// Open restored DB, check data, invalidated session, and queued system.restore_cli audit.
	restored, err := store.Open(ctx, dbPath, store.Options{})
	if err != nil {
		t.Fatalf("store.Open restored: %v", err)
	}
	defer restored.Close()
	if err := restored.EnableEncryption(ctx, seal.FileProvider{Path: kekPath}, nil); err != nil {
		t.Fatalf("EnableEncryption restored: %v", err)
	}
	tok, ok, err := restored.Setting(ctx, "siem_token")
	if err != nil || !ok || tok != "drill-token-xyz" {
		t.Fatalf("siem_token = (%q, %v, %v), want drill-token-xyz", tok, ok, err)
	}
	if s, err := restored.SessionByHash(ctx, []byte("s-drill-hash")); !errors.Is(err, domain.ErrNotFound) || s != nil {
		t.Fatalf("expected session s-drill-hash invalidated, got (%+v, %v)", s, err)
	}
	audits, err := restored.TakeCLIAudits(ctx)
	if err != nil {
		t.Fatalf("TakeCLIAudits: %v", err)
	}
	found := false
	for _, a := range audits {
		if a.Action == backup.RestoreAuditAction {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected %q in cli_audit, got %+v", backup.RestoreAuditAction, audits)
	}

	// Corrupt the archive and ensure verifyCmd fails.
	arc := filepath.Join(backupDir, backup.AgeDBFile)
	b, err := os.ReadFile(arc)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 0xff
	if err := os.WriteFile(arc, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyCmd(log, []string{"--from", backupDir, "--identity", idPath}); err == nil {
		t.Fatalf("expected verifyCmd on corrupted archive to fail")
	}
}
