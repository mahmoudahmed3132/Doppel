// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/seal"
)

var kek1 = seal.StaticProvider{Key: bytes.Repeat([]byte{1}, 32)}
var kek2 = seal.StaticProvider{Key: bytes.Repeat([]byte{2}, 32)}

func raw(t *testing.T, db *DB, q string, args ...any) string {
	t.Helper()
	var v string
	if err := db.sql.QueryRow(q, args...).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// seedPlaintext writes every kind of secret the way a pre-encryption Hub did.
func seedPlaintext(t *testing.T, db *DB) {
	t.Helper()
	ctx := context.Background()
	for k, v := range map[string]string{"siem_token": "TOKEN-PLAINTEXT-1", "webhook_url": "https://hooks.example.com/PLAINTEXT-2",
		"capture_master_key": strings.Repeat("ab", 32), "beacon_master_key": strings.Repeat("cd", 32), "public_endpoint": "https://hub.example.com"} {
		if _, err := db.sql.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?)`, k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.CreateAdmin(ctx, "hash", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.ExecContext(ctx, `UPDATE admin SET mfa_secret = 'MFASECRETPLAIN', mfa_pending_secret = 'PENDINGPLAIN', mfa_enabled = 1 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	seedNode(t, db, "n1")
	if err := db.InsertHoneytoken(ctx, ported.Honeytoken{ID: "ht_1", Username: "svc_x", Secret: "HONEYSECRET-PLAIN", PlantedNodeID: "n1", PlantedSensorID: "s1",
		CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

func TestEncryptionMigratesAndRoundTrips(t *testing.T) {
	ctx := context.Background()
	db, path := openTest(t)
	seedPlaintext(t, db)

	if err := db.EnableEncryption(ctx, kek1, nil); err != nil {
		t.Fatal(err)
	}
	if on, fp, _ := db.EncryptionState(ctx); !on || fp != seal.Fingerprint(kek1.Key) {
		t.Fatalf("state %v %q", on, fp)
	}
	for _, q := range []string{
		`SELECT value FROM settings WHERE key = 'siem_token'`, `SELECT value FROM settings WHERE key = 'webhook_url'`,
		`SELECT value FROM settings WHERE key = 'capture_master_key'`, `SELECT value FROM settings WHERE key = 'beacon_master_key'`,
		`SELECT mfa_secret FROM admin`, `SELECT mfa_pending_secret FROM admin`, `SELECT secret FROM honeytokens`,
	} {
		if v := raw(t, db, q); !seal.IsSealed(v) {
			t.Errorf("%s stored as %q", q, v)
		}
	}
	if v := raw(t, db, `SELECT value FROM settings WHERE key = 'public_endpoint'`); v != "https://hub.example.com" {
		t.Errorf("non-secret setting changed: %q", v)
	}
	// Reads still return plaintext through the API.
	if v, ok, err := db.Setting(ctx, "siem_token"); err != nil || !ok || v != "TOKEN-PLAINTEXT-1" {
		t.Fatalf("setting: %q %v %v", v, ok, err)
	}
	if all, _ := db.Settings(ctx); all["webhook_url"] != "https://hooks.example.com/PLAINTEXT-2" {
		t.Errorf("settings map: %v", all)
	}
	a, _ := db.Admin(ctx)
	if a.MFASecret != "MFASECRETPLAIN" || a.MFAPendingSecret != "PENDINGPLAIN" {
		t.Errorf("admin: %+v", a)
	}
	if h, _ := db.HoneytokenForSensor(ctx, "n1", "s1"); h == nil || h.Secret != "HONEYSECRET-PLAIN" {
		t.Errorf("honeytoken: %+v", h)
	}
	// New writes are sealed too, and create-once still returns the stored value.
	if err := db.PutSettings(ctx, map[string]*string{"siem_token": strPtr("NEW-TOKEN")}); err != nil {
		t.Fatal(err)
	}
	if v := raw(t, db, `SELECT value FROM settings WHERE key = 'siem_token'`); !seal.IsSealed(v) || strings.Contains(v, "NEW-TOKEN") {
		t.Errorf("new write: %q", v)
	}
	k1, _ := db.PutSettingIfAbsent(ctx, "capture_master_key", "ignored")
	if k1 != strings.Repeat("ab", 32) {
		t.Errorf("create-once changed value: %q", k1)
	}

	// No plaintext remains anywhere in the database file or its WAL.
	db.Close()
	for _, f := range []string{path, path + "-wal"} {
		b, _ := os.ReadFile(f)
		for _, needle := range []string{"TOKEN-PLAINTEXT-1", "PLAINTEXT-2", "MFASECRETPLAIN", "PENDINGPLAIN", "HONEYSECRET-PLAIN", strings.Repeat("ab", 32)} {
			if bytes.Contains(b, []byte(needle)) {
				t.Errorf("%s still contains %q", filepath.Base(f), needle)
			}
		}
	}

	// Second start is idempotent and still reads everything.
	db2, err := Open(ctx, path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	if err := db2.EnableEncryption(ctx, kek1, nil); err != nil {
		t.Fatal(err)
	}
	if v, _, _ := db2.Setting(ctx, "siem_token"); v != "NEW-TOKEN" {
		t.Errorf("after restart: %q", v)
	}
}

func strPtr(s string) *string { return &s }

func TestEncryptionRefusals(t *testing.T) {
	ctx := context.Background()
	db, path := openTest(t)
	seedPlaintext(t, db)
	if err := db.EnableEncryption(ctx, kek1, nil); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Wrong KEK: refuse, say so.
	db2, _ := Open(ctx, path, Options{})
	if err := db2.EnableEncryption(ctx, kek2, nil); !errors.Is(err, seal.ErrWrongKEK) {
		t.Errorf("wrong kek: %v", err)
	}
	db2.Close()

	// No KEK at all: reads of sealed values fail loudly, never return ciphertext.
	db3, _ := Open(ctx, path, Options{})
	if _, _, err := db3.Setting(ctx, "siem_token"); !errors.Is(err, ErrSealedNoKey) {
		t.Errorf("no kek: %v", err)
	}
	if _, err := db3.Admin(ctx); !errors.Is(err, ErrSealedNoKey) {
		t.Errorf("admin no kek: %v", err)
	}
	if on, _, _ := db3.EncryptionState(ctx); !on {
		t.Error("state should report encrypted so the caller can refuse to start")
	}
	db3.Close()

	// Ciphertext moved to another setting does not open (AAD binding), and a
	// plaintext secret written behind the Hub's back is refused (strict).
	db4, _ := Open(ctx, path, Options{})
	defer db4.Close()
	if err := db4.EnableEncryption(ctx, kek1, nil); err != nil {
		t.Fatal(err)
	}
	db4.sql.Exec(`UPDATE settings SET value = (SELECT value FROM settings WHERE key = 'siem_token') WHERE key = 'webhook_url'`)
	if _, _, err := db4.Setting(ctx, "webhook_url"); !errors.Is(err, seal.ErrOpen) {
		t.Errorf("moved ciphertext: %v", err)
	}
	db4.sql.Exec(`UPDATE settings SET value = 'attacker-plaintext' WHERE key = 'siem_token'`)
	if _, _, err := db4.Setting(ctx, "siem_token"); !errors.Is(err, seal.ErrNotSealed) {
		t.Errorf("planted plaintext: %v", err)
	}
}

func TestRotateKEK(t *testing.T) {
	ctx := context.Background()
	db, path := openTest(t)
	seedPlaintext(t, db)
	db.EnableEncryption(ctx, kek1, nil)
	if err := db.RotateKEK(ctx, kek2.Key, kek1.Key); !errors.Is(err, seal.ErrWrongKEK) {
		t.Errorf("rotate with wrong old key: %v", err)
	}
	if err := db.RotateKEK(ctx, kek1.Key, kek2.Key); err != nil {
		t.Fatal(err)
	}
	db.Close()
	db2, _ := Open(ctx, path, Options{})
	defer db2.Close()
	if err := db2.EnableEncryption(ctx, kek1, nil); !errors.Is(err, seal.ErrWrongKEK) {
		t.Errorf("old kek after rotation: %v", err)
	}
	if err := db2.EnableEncryption(ctx, kek2, nil); err != nil {
		t.Fatal(err)
	}
	if v, _, _ := db2.Setting(ctx, "siem_token"); v != "TOKEN-PLAINTEXT-1" {
		t.Errorf("value after rotation: %q", v)
	}
	plain, _ := Open(ctx, filepath.Join(t.TempDir(), "p.db"), Options{})
	defer plain.Close()
	if err := plain.RotateKEK(ctx, kek1.Key, kek2.Key); err == nil {
		t.Error("rotate on an unencrypted database succeeded")
	}
}

func TestMFAEnrolmentWithEncryption(t *testing.T) {
	ctx := context.Background()
	db, _ := openTest(t)
	if err := db.CreateAdmin(ctx, "hash", nil); err != nil {
		t.Fatal(err)
	}
	if err := db.EnableEncryption(ctx, kek1, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.SetPendingMFASecret(ctx, "SECRET-A"); err != nil {
		t.Fatal(err)
	}
	if v := raw(t, db, `SELECT mfa_pending_secret FROM admin`); !seal.IsSealed(v) {
		t.Fatalf("pending stored as %q", v)
	}
	if err := db.EnableMFA(ctx, "SECRET-B", 5, []string{"c"}); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("wrong pending secret accepted: %v", err)
	}
	if err := db.EnableMFA(ctx, "SECRET-A", 5, []string{"c"}); err != nil {
		t.Fatal(err)
	}
	a, _ := db.Admin(ctx)
	if !a.MFAEnabled || a.MFASecret != "SECRET-A" || a.MFAPendingSecret != "" {
		t.Errorf("admin after enrol: %+v", a)
	}
	if err := db.EnableMFA(ctx, "SECRET-A", 6, []string{"c"}); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("second enrol: %v", err)
	}
}

// A snapshot taken by the v2 -> v3 migration is plaintext by design (it is
// the rollback copy for a Hub without encryption). This pins that behaviour
// so a change to it is a deliberate decision (Q74).
func TestPreEncryptionSnapshotIsPlaintext(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ts.db")
	v2 := migrations[:2]
	db, err := Open(ctx, path, Options{Migrations: v2})
	if err != nil {
		t.Fatal(err)
	}
	db.sql.Exec(`INSERT INTO settings (key, value) VALUES ('siem_token', 'SNAPSHOT-PLAIN')`)
	db.Close()
	db, err = Open(ctx, path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	snaps, _ := filepath.Glob(path + ".pre-v3-*.bak")
	if len(snaps) != 1 {
		t.Fatalf("snapshots: %v", snaps)
	}
	if b, _ := os.ReadFile(snaps[0]); !bytes.Contains(b, []byte("SNAPSHOT-PLAIN")) {
		t.Error("expected the rollback snapshot to hold the pre-encryption data")
	}
}
