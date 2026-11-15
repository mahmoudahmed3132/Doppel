// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/seal"
)

// SecretSettingKeys are the settings sealed at rest. The list is literal
// because the packages that own the constants import this one; a test in
// internal/secrets pins it to those constants. beacons.token is deliberately
// not sealed: it is looked up by equality, is an identifier that is printed
// into artefacts left in the field, and carries no authority by itself.
var SecretSettingKeys = []string{
	"capture_master_key", // internal/secrets
	"beacon_master_key",  // internal/secrets
	"siem_token",         // internal/siem
	"webhook_url",        // internal/webhook
}

const aadMFA = "admin/mfa_secret" // both MFA columns, so SQL may move one into the other

func aadHoneytoken(id string) string { return "honeytokens/secret/" + id }
func aadSetting(key string) string   { return "settings/" + key }

func isSecretSetting(key string) bool {
	for _, k := range SecretSettingKeys {
		if k == key {
			return true
		}
	}
	return false
}

// ErrSealedNoKey is returned when the database holds sealed values but no
// key-encryption key was supplied.
var ErrSealedNoKey = errors.New("database holds encrypted secrets but no key-encryption key was provided (TS_KEK_FILE)")

func (db *DB) sealValue(aad, v string) (string, error) {
	if db.sealer == nil || v == "" {
		return v, nil
	}
	return db.sealer.Seal(aad, v)
}

func (db *DB) openValue(aad, v string) (string, error) {
	if db.sealer == nil {
		if seal.IsSealed(v) {
			return "", ErrSealedNoKey
		}
		return v, nil
	}
	out, err := db.sealer.Open(aad, v)
	if err != nil {
		return "", fmt.Errorf("opening %s: %w", aad, err)
	}
	return out, nil
}

func (db *DB) sealSetting(key, v string) (string, error) {
	if !isSecretSetting(key) {
		return v, nil
	}
	return db.sealValue(aadSetting(key), v)
}

func (db *DB) openSetting(key, v string) (string, error) {
	if !isSecretSetting(key) {
		return v, nil
	}
	return db.openValue(aadSetting(key), v)
}

// EncryptionState says whether the database already carries a wrapped data
// key, and the fingerprint of the key-encryption key that wrapped it.
func (db *DB) EncryptionState(ctx context.Context) (enabled bool, kekFingerprint string, err error) {
	err = db.sql.QueryRowContext(ctx, `SELECT kek_fingerprint FROM crypto_meta WHERE id = 1`).Scan(&kekFingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return false, "", nil
	}
	return err == nil, kekFingerprint, err
}

// EnableEncryption unwraps (or, on first use, creates) the data key with the
// provider's key-encryption key, seals every plaintext secret in place, then
// makes the sealer strict so a plaintext secret found later is refused. It is
// idempotent and safe to run at every start. After it, the plaintext left in
// freed pages and the WAL is removed (checkpoint and VACUUM).
func (db *DB) EnableEncryption(ctx context.Context, p seal.KeyProvider, log *slog.Logger) error {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	kek, err := p.KEK(ctx)
	if err != nil {
		return err
	}
	var wrapped string
	err = db.sql.QueryRowContext(ctx, `SELECT wrapped_dek FROM crypto_meta WHERE id = 1`).Scan(&wrapped)
	var dek []byte
	first := false
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if dek, err = seal.NewDEK(); err != nil {
			return err
		}
		if wrapped, err = seal.Wrap(kek, dek); err != nil {
			return err
		}
		if _, err = db.sql.ExecContext(ctx, `INSERT INTO crypto_meta (id, wrapped_dek, kek_fingerprint, created_at) VALUES (1, ?, ?, ?)`,
			wrapped, seal.Fingerprint(kek), ms(db.now())); err != nil {
			return err
		}
		first = true
	case err != nil:
		return err
	default:
		if dek, err = seal.Unwrap(kek, wrapped); err != nil {
			return err
		}
	}
	s, err := seal.New(dek)
	if err != nil {
		return err
	}
	db.sealer = s
	n, err := db.sealPlaintext(ctx)
	if err != nil {
		return err
	}
	s.SetStrict(true)
	if first || n > 0 {
		log.Info("secrets sealed at rest", "values_sealed", n, "key_source", p.Describe(), "kek_fingerprint", seal.Fingerprint(kek))
		if err := db.scrubFreePages(ctx); err != nil {
			return fmt.Errorf("removing plaintext remnants: %w", err)
		}
	}
	return nil
}

// sealPlaintext seals every secret still stored in plaintext, in one
// transaction, and returns how many values it sealed.
func (db *DB) sealPlaintext(ctx context.Context) (int, error) {
	n := 0
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		n = 0
		type upd struct{ query, aad, val, id string }
		var todo []upd
		collect := func(query, aad, val, id string) {
			if val != "" && !seal.IsSealed(val) {
				todo = append(todo, upd{query, aad, val, id})
			}
		}
		rows, err := tx.QueryContext(ctx, `SELECT key, value FROM settings`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var k, v string
			if err := rows.Scan(&k, &v); err != nil {
				rows.Close()
				return err
			}
			if isSecretSetting(k) {
				collect(`UPDATE settings SET value = ? WHERE key = ?`, aadSetting(k), v, k)
			}
		}
		rows.Close()
		var ms1, ms2 string
		switch err := tx.QueryRowContext(ctx, `SELECT mfa_secret, mfa_pending_secret FROM admin WHERE id = 1`).Scan(&ms1, &ms2); {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return err
		default:
			collect(`UPDATE admin SET mfa_secret = ? WHERE id = 1`, aadMFA, ms1, "-")
			collect(`UPDATE admin SET mfa_pending_secret = ? WHERE id = 1`, aadMFA, ms2, "-")
		}
		rows, err = tx.QueryContext(ctx, `SELECT id, secret FROM honeytokens`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id, v string
			if err := rows.Scan(&id, &v); err != nil {
				rows.Close()
				return err
			}
			collect(`UPDATE honeytokens SET secret = ? WHERE id = ?`, aadHoneytoken(id), v, id)
		}
		rows.Close()
		for _, u := range todo {
			sv, err := db.sealer.Seal(u.aad, u.val)
			if err != nil {
				return err
			}
			args := []any{sv}
			if u.id != "-" {
				args = append(args, u.id)
			}
			if _, err := tx.ExecContext(ctx, u.query, args...); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// scrubFreePages checkpoints and truncates the WAL, then VACUUMs, so sealed
// values replace (rather than sit beside) their plaintext in the file.
func (db *DB) scrubFreePages(ctx context.Context) error {
	if _, err := db.sql.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return err
	}
	if _, err := db.sql.ExecContext(ctx, `VACUUM`); err != nil {
		return err
	}
	_, err := db.sql.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

// RotateKEK re-wraps the data key under newKEK. Values are not re-encrypted.
// The old key must unwrap the stored data key.
func (db *DB) RotateKEK(ctx context.Context, oldKEK, newKEK []byte) error {
	return db.withTx(ctx, func(tx *sql.Tx) error {
		var wrapped string
		if err := tx.QueryRowContext(ctx, `SELECT wrapped_dek FROM crypto_meta WHERE id = 1`).Scan(&wrapped); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errors.New("secrets are not encrypted in this database; nothing to rotate")
			}
			return err
		}
		dek, err := seal.Unwrap(oldKEK, wrapped)
		if err != nil {
			return err
		}
		nw, err := seal.Wrap(newKEK, dek)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE crypto_meta SET wrapped_dek = ?, kek_fingerprint = ?, rotated_at = ? WHERE id = 1`,
			nw, seal.Fingerprint(newKEK), ms(db.now()))
		return err
	})
}
