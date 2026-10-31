// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

package store

import (
	"context"
	"database/sql"
	"errors"
)

// Setting returns a settings value; ok is false when unset.
func (db *DB) Setting(ctx context.Context, key string) (value string, ok bool, err error) {
	err = db.sql.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return value, err == nil, err
}

// Settings returns all settings.
func (db *DB) Settings(ctx context.Context) (map[string]string, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// PutSettings upserts several settings atomically; a nil value deletes.
func (db *DB) PutSettings(ctx context.Context, kv map[string]*string) error {
	return db.withTx(ctx, func(tx *sql.Tx) error {
		for k, v := range kv {
			var err error
			if v == nil {
				_, err = tx.ExecContext(ctx, `DELETE FROM settings WHERE key = ?`, k)
			} else {
				_, err = tx.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?)
					ON CONFLICT (key) DO UPDATE SET value = excluded.value`, k, *v)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// PutSettingIfAbsent stores value under key unless the key exists, and
// returns the value that is stored afterwards (race-safe create-once).
func (db *DB) PutSettingIfAbsent(ctx context.Context, key, value string) (string, error) {
	if _, err := db.sql.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO NOTHING`, key, value); err != nil {
		return "", err
	}
	v, ok, err := db.Setting(ctx, key)
	if err == nil && !ok {
		err = errors.New("setting vanished after insert")
	}
	return v, err
}
