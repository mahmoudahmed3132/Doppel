// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

package store

import (
	"context"
	"database/sql"
	"errors"
)

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

// AdminExists reports whether setup has been completed.
func (db *DB) AdminExists(ctx context.Context) (bool, error) {
	var one int
	err := db.sql.QueryRowContext(ctx, `SELECT 1 FROM admin WHERE id = 1`).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}
