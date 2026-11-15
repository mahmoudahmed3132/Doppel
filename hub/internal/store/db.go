// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package store persists Hub state in a single SQLite file (WAL mode,
// foreign keys on) through the pure-Go modernc.org/sqlite driver.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/seal"
	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// DB is the Hub database.
type DB struct {
	sql    *sql.DB
	now    func() time.Time
	sealer *seal.Sealer // nil until EnableEncryption
}

// Options configures Open.
type Options struct {
	Logger *slog.Logger
	Now    func() time.Time
	// Migrations overrides the built-in schema (tests only).
	Migrations []Migration
}

// ErrSchemaTooNew is returned when the database was written by a newer Hub.
var ErrSchemaTooNew = errors.New("database schema is newer than this Hub supports")

// Open opens (creating if needed) the database at path, snapshots it if
// migrations are pending, and migrates it to the current schema.
func Open(ctx context.Context, path string, opts Options) (*DB, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	migs := opts.Migrations
	if migs == nil {
		migs = migrations
	}

	q := url.Values{}
	for _, p := range []string{"foreign_keys(1)", "journal_mode(WAL)", "busy_timeout(10000)", "synchronous(NORMAL)"} {
		q.Add("_pragma", p)
	}
	q.Set("_txlock", "immediate")
	dsn := "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + q.Encode()
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection serialises writers and avoids SQLITE_BUSY between
	// connections of this process; the Hub's write rate is modest.
	sqldb.SetMaxOpenConns(1)
	sqldb.SetConnMaxLifetime(0)
	if err := sqldb.PingContext(ctx); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	db := &DB{sql: sqldb, now: opts.Now}
	if err := db.migrate(ctx, path, migs, opts.Logger); err != nil {
		sqldb.Close()
		return nil, err
	}
	return db, nil
}

// Close closes the database.
func (db *DB) Close() error { return db.sql.Close() }

// Migration is one schema step. Version numbers start at 1 and are dense.
type Migration struct {
	Version int
	SQL     string
}

func (db *DB) schemaVersion(ctx context.Context) (int, error) {
	var v int
	err := db.sql.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v)
	return v, err
}

func (db *DB) migrate(ctx context.Context, path string, migs []Migration, log *slog.Logger) error {
	for i, m := range migs {
		if m.Version != i+1 {
			return fmt.Errorf("migration list is not dense at index %d", i)
		}
	}
	latest := len(migs)
	cur, err := db.schemaVersion(ctx)
	if err != nil {
		return err
	}
	if cur > latest {
		return fmt.Errorf("%w: database is at v%d, this Hub knows up to v%d; upgrade the Hub or restore a backup", ErrSchemaTooNew, cur, latest)
	}
	if cur == latest {
		return nil
	}
	if cur > 0 {
		snap, err := db.snapshot(ctx, path, latest)
		if err != nil {
			return fmt.Errorf("pre-migration snapshot failed, refusing to migrate: %w", err)
		}
		log.Info("database snapshot written before migration", "path", snap, "from", cur, "to", latest)
	}
	for _, m := range migs[cur:] {
		if err := db.apply(ctx, m); err != nil {
			return fmt.Errorf("migration v%d: %w", m.Version, err)
		}
		log.Info("database migrated", "version", m.Version)
	}
	return nil
}

func (db *DB) apply(ctx context.Context, m Migration) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		return err
	}
	// PRAGMA does not accept bound parameters; Version is an int.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", m.Version)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "PRAGMA foreign_key_check"); err != nil {
		return err
	}
	return tx.Commit()
}

// snapshot writes a consistent copy of the database next to it, named
// <db>.pre-v<N>-<UTC timestamp>.bak, using VACUUM INTO.
func (db *DB) snapshot(ctx context.Context, path string, target int) (string, error) {
	name := fmt.Sprintf("%s.pre-v%d-%s.bak", path, target, db.now().UTC().Format("20060102T150405Z"))
	if _, err := os.Stat(name); err == nil {
		return "", fmt.Errorf("snapshot %s already exists", name)
	}
	if _, err := db.sql.ExecContext(ctx, "VACUUM INTO ?", name); err != nil {
		return "", err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return "", err
	}
	return name, nil
}

// ms converts a time to the stored representation (Unix milliseconds).
func ms(t time.Time) int64 { return t.UnixMilli() }

func fromMS(v int64) time.Time { return time.UnixMilli(v).UTC() }

func fromNullMS(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := fromMS(v.Int64)
	return &t
}

func nullMS(t *time.Time) sql.NullInt64 {
	if t == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: ms(*t), Valid: true}
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// withTx runs fn in a transaction.
func (db *DB) withTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}
