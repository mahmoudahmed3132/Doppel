// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/domain"
)

// Admin is the single administrator account.
type Admin struct {
	PasswordHash     string
	MFASecret        string
	MFAPendingSecret string
	MFAEnabled       bool
	MFALastStep      int64
	RecoveryCodes    []string // hashed
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// CreateAdmin inserts the admin account. It returns domain.ErrConflict when
// one already exists, which makes setup single-use even under races.
func (db *DB) CreateAdmin(ctx context.Context, passwordHash string, settings map[string]string) error {
	return db.withTx(ctx, func(tx *sql.Tx) error {
		now := ms(db.now())
		_, err := tx.ExecContext(ctx, `INSERT INTO admin (id, password_hash, created_at, updated_at) VALUES (1, ?, ?, ?)`,
			passwordHash, now, now)
		if isUniqueViolation(err) {
			return domain.ErrConflict
		}
		if err != nil {
			return err
		}
		for k, v := range settings {
			if _, err := tx.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?)
				ON CONFLICT (key) DO UPDATE SET value = excluded.value`, k, v); err != nil {
				return err
			}
		}
		return nil
	})
}

// Admin returns the admin account or domain.ErrNotFound.
func (db *DB) Admin(ctx context.Context) (*Admin, error) {
	var (
		a                Admin
		enabled          int
		codes            string
		created, updated int64
	)
	err := db.sql.QueryRowContext(ctx, `SELECT password_hash, mfa_secret, mfa_pending_secret, mfa_enabled, mfa_last_step,
		recovery_codes, created_at, updated_at FROM admin WHERE id = 1`).
		Scan(&a.PasswordHash, &a.MFASecret, &a.MFAPendingSecret, &enabled, &a.MFALastStep, &codes, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(codes), &a.RecoveryCodes); err != nil {
		return nil, err
	}
	a.MFAEnabled = enabled != 0
	a.CreatedAt, a.UpdatedAt = fromMS(created), fromMS(updated)
	return &a, nil
}

// AdminExists reports whether setup has been completed.
func (db *DB) AdminExists(ctx context.Context) (bool, error) {
	var one int
	err := db.sql.QueryRowContext(ctx, `SELECT 1 FROM admin WHERE id = 1`).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// SetPasswordHash replaces the password hash and deletes all sessions.
func (db *DB) SetPasswordHash(ctx context.Context, hash string) error {
	return db.withTx(ctx, func(tx *sql.Tx) error {
		if err := affectedOne(tx.ExecContext(ctx, `UPDATE admin SET password_hash = ?, updated_at = ? WHERE id = 1`, hash, ms(db.now()))); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM sessions`)
		return err
	})
}

// SetPendingMFASecret stores the secret of an enrolment in progress.
func (db *DB) SetPendingMFASecret(ctx context.Context, secret string) error {
	return affectedOne(db.sql.ExecContext(ctx, `UPDATE admin SET mfa_pending_secret = ?, updated_at = ? WHERE id = 1`, secret, ms(db.now())))
}

// EnableMFA activates the pending secret, provided it still equals
// pendingSecret, stores hashed recovery codes and the accepted step, and
// deletes all sessions.
func (db *DB) EnableMFA(ctx context.Context, pendingSecret string, step int64, hashedCodes []string) error {
	codes, err := json.Marshal(hashedCodes)
	if err != nil {
		return err
	}
	return db.withTx(ctx, func(tx *sql.Tx) error {
		err := affectedOne(tx.ExecContext(ctx, `UPDATE admin SET mfa_secret = mfa_pending_secret, mfa_pending_secret = '',
			mfa_enabled = 1, mfa_last_step = ?, recovery_codes = ?, updated_at = ?
			WHERE id = 1 AND mfa_enabled = 0 AND mfa_pending_secret = ? AND mfa_pending_secret != ''`,
			step, string(codes), ms(db.now()), pendingSecret))
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM sessions`)
		return err
	})
}

// DisableMFA removes MFA and deletes all sessions.
func (db *DB) DisableMFA(ctx context.Context) error {
	return db.withTx(ctx, func(tx *sql.Tx) error {
		if err := affectedOne(tx.ExecContext(ctx, `UPDATE admin SET mfa_secret = '', mfa_pending_secret = '', mfa_enabled = 0,
			mfa_last_step = 0, recovery_codes = '[]', updated_at = ? WHERE id = 1`, ms(db.now()))); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM sessions`)
		return err
	})
}

// AdvanceMFAStep records an accepted TOTP step only if it is newer than the
// stored one. It returns false when another request already used the step
// (replay), so two concurrent logins with one code cannot both succeed.
func (db *DB) AdvanceMFAStep(ctx context.Context, step int64) (bool, error) {
	res, err := db.sql.ExecContext(ctx, `UPDATE admin SET mfa_last_step = ? WHERE id = 1 AND mfa_last_step < ?`, step, step)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// ReplaceRecoveryCodes swaps the hashed recovery codes if they still equal
// old (compare-and-swap); it returns false when they changed concurrently.
func (db *DB) ReplaceRecoveryCodes(ctx context.Context, old, replacement []string) (bool, error) {
	o, err := json.Marshal(nonNil(old))
	if err != nil {
		return false, err
	}
	n, err := json.Marshal(nonNil(replacement))
	if err != nil {
		return false, err
	}
	res, err := db.sql.ExecContext(ctx, `UPDATE admin SET recovery_codes = ?, updated_at = ? WHERE id = 1 AND recovery_codes = ?`,
		string(n), ms(db.now()), string(o))
	if err != nil {
		return false, err
	}
	c, err := res.RowsAffected()
	return c == 1, err
}

// ResetMFA removes MFA from the admin account, invalidates all sessions and
// sets the pending-audit marker (break-glass, §6.3).
func (db *DB) ResetMFA(ctx context.Context) error {
	return db.withTx(ctx, func(tx *sql.Tx) error {
		err := affectedOne(tx.ExecContext(ctx, `UPDATE admin SET mfa_secret = '', mfa_pending_secret = '', mfa_enabled = 0,
			mfa_last_step = 0, recovery_codes = '[]', mfa_reset_pending = 1, updated_at = ? WHERE id = 1`, ms(db.now())))
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM sessions`)
		return err
	})
}

// TakeMFAResetMarker clears the pending-audit marker and reports whether it
// was set.
func (db *DB) TakeMFAResetMarker(ctx context.Context) (bool, error) {
	res, err := db.sql.ExecContext(ctx, `UPDATE admin SET mfa_reset_pending = 0 WHERE id = 1 AND mfa_reset_pending = 1`)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// Session is a server-side browser session record.
type Session struct {
	TokenHash  []byte
	CreatedAt  time.Time
	LastSeenAt time.Time
	EnrolOnly  bool
}

// CreateSession stores a session.
func (db *DB) CreateSession(ctx context.Context, s Session) error {
	_, err := db.sql.ExecContext(ctx, `INSERT INTO sessions (token_hash, created_at, last_seen_at, enrol_only) VALUES (?, ?, ?, ?)`,
		s.TokenHash, ms(s.CreatedAt), ms(s.LastSeenAt), boolInt(s.EnrolOnly))
	return err
}

// SessionByHash returns a session or domain.ErrNotFound.
func (db *DB) SessionByHash(ctx context.Context, hash []byte) (*Session, error) {
	var (
		s             Session
		created, seen int64
		enrol         int
	)
	err := db.sql.QueryRowContext(ctx, `SELECT token_hash, created_at, last_seen_at, enrol_only FROM sessions WHERE token_hash = ?`, hash).
		Scan(&s.TokenHash, &created, &seen, &enrol)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	s.CreatedAt, s.LastSeenAt, s.EnrolOnly = fromMS(created), fromMS(seen), enrol != 0
	return &s, nil
}

// TouchSession updates a session's last-seen time.
func (db *DB) TouchSession(ctx context.Context, hash []byte, at time.Time) error {
	_, err := db.sql.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?`, ms(at), hash)
	return err
}

// DeleteSession removes one session.
func (db *DB) DeleteSession(ctx context.Context, hash []byte) error {
	_, err := db.sql.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, hash)
	return err
}

// DeleteSessionsExcept removes every session except keep (nil keeps none).
func (db *DB) DeleteSessionsExcept(ctx context.Context, keep []byte) error {
	_, err := db.sql.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash != ?`, nonNilBytes(keep))
	return err
}

// PurgeExpiredSessions removes sessions created before absBefore or idle
// since before idleBefore.
func (db *DB) PurgeExpiredSessions(ctx context.Context, absBefore, idleBefore time.Time) (int64, error) {
	res, err := db.sql.ExecContext(ctx, `DELETE FROM sessions WHERE created_at < ? OR last_seen_at < ?`, ms(absBefore), ms(idleBefore))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func nonNilBytes(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}
