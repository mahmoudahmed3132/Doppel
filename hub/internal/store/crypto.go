// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

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

// ErrPlaintextFound is returned when a database that was already sealed holds
// a plaintext secret: someone with file access planted it. Locations only, no values.
var ErrPlaintextFound = errors.New("secrets: plaintext value found in an encrypted database")

// EnableEncryption unwraps (or, on first use, creates) the data key with the
// provider's key-encryption key and seals every plaintext secret in place.
// Both steps are recorded (sealed_at, scrubbed_at) so an interrupted run
// resumes instead of leaving plaintext behind. Once sealed_at is set the
// sealer is strict from the first read, and a plaintext secret found at start
// is refused rather than adopted. It is safe to run at every start.
func (db *DB) EnableEncryption(ctx context.Context, p seal.KeyProvider, log *slog.Logger) error {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	kek, err := p.KEK(ctx)
	if err != nil {
		return err
	}
	var wrapped string
	var sealedAt, scrubbedAt sql.NullInt64
	err = db.sql.QueryRowContext(ctx, `SELECT wrapped_dek, sealed_at, scrubbed_at FROM crypto_meta WHERE id = 1`).Scan(&wrapped, &sealedAt, &scrubbedAt)
	var dek []byte
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
	adopt := !sealedAt.Valid
	s.SetStrict(!adopt)
	n, err := db.sealPlaintext(ctx, adopt)
	if err != nil {
		return err
	}
	s.SetStrict(true)
	if adopt {
		log.Info("secrets sealed at rest", "values_sealed", n, "key_source", p.Describe(), "kek_fingerprint", seal.Fingerprint(kek))
		if err := db.QueueCLIAudit(ctx, "secrets.sealed", "truesignal-hub serve (first start with TS_KEK_FILE)"); err != nil {
			return err
		}
	}
	if !scrubbedAt.Valid {
		if err := db.scrubFreePages(ctx); err != nil {
			return fmt.Errorf("removing plaintext remnants: %w", err)
		}
		if _, err := db.sql.ExecContext(ctx, `UPDATE crypto_meta SET scrubbed_at = ? WHERE id = 1`, ms(db.now())); err != nil {
			return err
		}
	}
	return nil
}

// sealPlaintext finds every secret stored in plaintext. With adopt it seals
// them and records sealed_at in the same transaction and returns how many it
// sealed; without adopt any finding is an error naming the locations.
func (db *DB) sealPlaintext(ctx context.Context, adopt bool) (int, error) {
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
		if !adopt && len(todo) > 0 {
			var where []string
			for _, u := range todo {
				where = append(where, u.aad)
			}
			return fmt.Errorf("%w: %s", ErrPlaintextFound, strings.Join(where, ", "))
		}
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
		if adopt {
			_, err = tx.ExecContext(ctx, `UPDATE crypto_meta SET sealed_at = ? WHERE id = 1 AND sealed_at IS NULL`, ms(db.now()))
		}
		return err
	})
	return n, err
}

// scrubFreePages checkpoints and truncates the WAL, then VACUUMs, so sealed
// values replace (rather than sit beside) their plaintext in the file. VACUUM
// builds a temporary copy of the database: SQLite's default temp locations
// (/tmp, /var/tmp, the working directory) are a small tmpfs or read-only in
// the production container, so the copy is placed next to the database.
func (db *DB) scrubFreePages(ctx context.Context) error {
	if _, err := db.sql.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return err
	}
	if db.path != "" {
		dir := strings.ReplaceAll(filepath.Dir(db.path), "'", "''")
		if _, err := db.sql.ExecContext(ctx, `PRAGMA temp_store_directory = '`+dir+`'`); err != nil {
			return err
		}
	}
	if _, err := db.sql.ExecContext(ctx, `VACUUM`); err != nil {
		return err
	}
	_, err := db.sql.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

// PlaintextSnapshots lists pre-migration snapshots next to the database. They
// are plaintext copies kept for rollback; they travel with every backup of
// the data directory.
func (db *DB) PlaintextSnapshots() []string {
	m, _ := filepath.Glob(db.path + ".pre-v*.bak")
	return m
}

// QueueCLIAudit records an action performed outside the running Hub (a host
// command, or the first sealing) so the next start audits it.
func (db *DB) QueueCLIAudit(ctx context.Context, action, route string) error {
	_, err := db.sql.ExecContext(ctx, `INSERT INTO cli_audit (action, route, at) VALUES (?, ?, ?)`, action, route, ms(db.now()))
	return err
}

// CLIAudit is one queued host-side action.
type CLIAudit struct {
	Action, Route string
	At            time.Time
}

// TakeCLIAudits returns and clears the queue.
func (db *DB) TakeCLIAudits(ctx context.Context) ([]CLIAudit, error) {
	var out []CLIAudit
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		out = nil
		rows, err := tx.QueryContext(ctx, `SELECT action, route, at FROM cli_audit ORDER BY id`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var a CLIAudit
			var at int64
			if err := rows.Scan(&a.Action, &a.Route, &at); err != nil {
				rows.Close()
				return err
			}
			a.At = fromMS(at)
			out = append(out, a)
		}
		rows.Close()
		_, err = tx.ExecContext(ctx, `DELETE FROM cli_audit`)
		return err
	})
	return out, err
}

// ResetSecrets is the break-glass for a lost KEK. It deletes the wrapped data
// key and everything sealed under it: the four secret settings (SIEM token,
// webhook URL, master keys), the admin MFA, and honeytoken secrets (tokens are
// re-minted when sensors are next rendered). Master keys are regenerated on
// demand, which orphans honeytokens and beacons already in the field. Hub stopped.
func (db *DB) ResetSecrets(ctx context.Context) error {
	return db.withTx(ctx, func(tx *sql.Tx) error {
		for _, k := range SecretSettingKeys {
			if _, err := tx.ExecContext(ctx, `DELETE FROM settings WHERE key = ?`, k); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE admin SET mfa_secret = '', mfa_pending_secret = '', mfa_enabled = 0,
			mfa_last_step = 0, recovery_codes = '[]', updated_at = ? WHERE id = 1`, ms(db.now())); err != nil {
			return err
		}
		for _, q := range []string{`DELETE FROM honeytokens`, `DELETE FROM sessions`, `DELETE FROM crypto_meta`} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO cli_audit (action, route, at) VALUES ('secrets.reset_cli', 'truesignal-hub secrets-reset', ?)`, ms(db.now()))
		return err
	})
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
		if _, err = tx.ExecContext(ctx, `UPDATE crypto_meta SET wrapped_dek = ?, kek_fingerprint = ?, rotated_at = ? WHERE id = 1`,
			nw, seal.Fingerprint(newKEK), ms(db.now())); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO cli_audit (action, route, at) VALUES ('secrets.kek_rotate_cli', 'truesignal-hub kek-rotate', ?)`, ms(db.now()))
		return err
	})
}
