// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
)

// --- beacons (implements ported.BeaconStore) ------------------------------

var _ ported.BeaconStore = (*DB)(nil)
var _ ported.HoneytokenStore = (*DB)(nil)

const beaconCols = `id, token, type, name, memo, domain, created_at, use_count, last_used_at`

func scanBeacon(row interface{ Scan(...any) error }) (*ported.Beacon, error) {
	var (
		b       ported.Beacon
		created int64
		last    sql.NullInt64
	)
	if err := row.Scan(&b.ID, &b.Token, &b.Type, &b.Name, &b.Memo, &b.Domain, &created, &b.UseCount, &last); err != nil {
		return nil, err
	}
	b.CreatedAt, b.LastUsedAt = fromMS(created), fromNullMS(last)
	return &b, nil
}

// InsertBeacon stores a beacon.
func (db *DB) InsertBeacon(ctx context.Context, b ported.Beacon) error {
	_, err := db.sql.ExecContext(ctx, `INSERT INTO beacons (`+beaconCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL)`,
		b.ID, b.Token, b.Type, b.Name, b.Memo, b.Domain, ms(b.CreatedAt))
	if isUniqueViolation(err) {
		return domain.ErrConflict
	}
	return err
}

// BeaconByToken returns the beacon with token, or nil, nil.
func (db *DB) BeaconByToken(ctx context.Context, token string) (*ported.Beacon, error) {
	b, err := scanBeacon(db.sql.QueryRowContext(ctx, `SELECT `+beaconCols+` FROM beacons WHERE token = ?`, token))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return b, err
}

// ListBeacons returns all beacons, newest first.
func (db *DB) ListBeacons(ctx context.Context) ([]ported.Beacon, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT `+beaconCols+` FROM beacons ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ported.Beacon{}
	for rows.Next() {
		b, err := scanBeacon(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *b)
	}
	return out, rows.Err()
}

// DeleteBeacon removes a beacon.
func (db *DB) DeleteBeacon(ctx context.Context, id string) error {
	return affectedOne(db.sql.ExecContext(ctx, `DELETE FROM beacons WHERE id = ?`, id))
}

// IncrementBeaconUse records one use.
func (db *DB) IncrementBeaconUse(ctx context.Context, id string, at time.Time) error {
	return affectedOne(db.sql.ExecContext(ctx, `UPDATE beacons SET use_count = use_count + 1, last_used_at = ? WHERE id = ?`, ms(at), id))
}

// --- honeytokens (implements ported.HoneytokenStore) ----------------------

const honeytokenCols = `id, username, secret, planted_node_id, planted_sensor_id, status, created_at, use_count, last_used_at`

func (db *DB) scanHoneytoken(row interface{ Scan(...any) error }) (*ported.Honeytoken, error) {
	var (
		h       ported.Honeytoken
		created int64
		last    sql.NullInt64
	)
	if err := row.Scan(&h.ID, &h.Username, &h.Secret, &h.PlantedNodeID, &h.PlantedSensorID, &h.Status, &created, &h.UseCount, &last); err != nil {
		return nil, err
	}
	var err error
	if h.Secret, err = db.openValue(aadHoneytoken(h.ID), h.Secret); err != nil {
		return nil, err
	}
	h.CreatedAt, h.LastUsedAt = fromMS(created), fromNullMS(last)
	return &h, nil
}

// InsertHoneytoken stores a honeytoken.
func (db *DB) InsertHoneytoken(ctx context.Context, h ported.Honeytoken) error {
	status := h.Status
	if status == "" {
		status = "active"
	}
	sealed, err := db.sealValue(aadHoneytoken(h.ID), h.Secret)
	if err != nil {
		return err
	}
	_, err = db.sql.ExecContext(ctx, `INSERT INTO honeytokens (`+honeytokenCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL)`,
		h.ID, h.Username, sealed, h.PlantedNodeID, h.PlantedSensorID, status, ms(h.CreatedAt))
	if isUniqueViolation(err) {
		return domain.ErrConflict
	}
	return err
}

// HoneytokenForSensor returns the token planted by a sensor, or nil, nil.
func (db *DB) HoneytokenForSensor(ctx context.Context, nodeID, sensorID string) (*ported.Honeytoken, error) {
	h, err := db.scanHoneytoken(db.sql.QueryRowContext(ctx, `SELECT `+honeytokenCols+` FROM honeytokens
		WHERE planted_node_id = ? AND planted_sensor_id = ?`, nodeID, sensorID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return h, err
}

// ListHoneytokens returns all honeytokens (with secrets: callers must not
// expose them).
func (db *DB) ListHoneytokens(ctx context.Context) ([]ported.Honeytoken, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT `+honeytokenCols+` FROM honeytokens ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ported.Honeytoken{}
	for rows.Next() {
		h, err := db.scanHoneytoken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *h)
	}
	return out, rows.Err()
}

// IncrementHoneytokenUse records one use.
func (db *DB) IncrementHoneytokenUse(ctx context.Context, id string, at time.Time) error {
	return affectedOne(db.sql.ExecContext(ctx, `UPDATE honeytokens SET use_count = use_count + 1, last_used_at = ? WHERE id = ?`, ms(at), id))
}

// --- analytics -------------------------------------------------------------

// SeverityCounts counts unarchived events by severity since t.
func (db *DB) SeverityCounts(ctx context.Context, since time.Time) (map[domain.Severity]int64, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT severity, COUNT(*) FROM events WHERE received_at >= ? AND archived = 0 GROUP BY severity`, ms(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[domain.Severity]int64{}
	for _, s := range domain.Severities {
		out[s] = 0
	}
	for rows.Next() {
		var s string
		var n int64
		if err := rows.Scan(&s, &n); err != nil {
			return nil, err
		}
		out[domain.Severity(s)] = n
	}
	return out, rows.Err()
}

// Velocity counts unarchived events per bucket since t. Buckets without
// events are absent; the caller fills gaps.
func (db *DB) Velocity(ctx context.Context, since time.Time, bucket time.Duration) (map[int64]int64, error) {
	b := bucket.Milliseconds()
	if b <= 0 {
		return nil, errors.New("bucket must be positive")
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT (received_at / ?) * ? AS b, COUNT(*) FROM events
		WHERE received_at >= ? AND archived = 0 GROUP BY b`, b, b, ms(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int64{}
	for rows.Next() {
		var k, n int64
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, rows.Err()
}

// EventCounts returns total, unread and since-t counts of unarchived events.
func (db *DB) EventCounts(ctx context.Context, since time.Time) (total, unread, recent, recentCritical int64, err error) {
	err = db.sql.QueryRowContext(ctx, `SELECT COUNT(*),
		COALESCE(SUM(CASE WHEN is_read = 0 THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN received_at >= ? THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN received_at >= ? AND severity = 'critical' THEN 1 ELSE 0 END), 0)
		FROM events WHERE archived = 0`, ms(since), ms(since)).Scan(&total, &unread, &recent, &recentCritical)
	return
}

// --- factory reset ---------------------------------------------------------

// FactoryReset deletes admin, sessions, nodes and sensors, events, status
// history, settings and beacons in one transaction. Honeytokens are kept
// unless purgeHoneytokens (they may still be planted in lures). The
// catalogue cache is kept: it holds only signed public manifests.
func (db *DB) FactoryReset(ctx context.Context, purgeHoneytokens bool) error {
	return db.withTx(ctx, func(tx *sql.Tx) error {
		stmts := []string{
			`DELETE FROM sessions`, `DELETE FROM admin`, `DELETE FROM sensors`, `DELETE FROM nodes`,
			`DELETE FROM events`, `DELETE FROM sensor_status_history`, `DELETE FROM settings`, `DELETE FROM beacons`,
		}
		if purgeHoneytokens {
			stmts = append(stmts, `DELETE FROM honeytokens`)
		}
		for _, q := range stmts {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return err
			}
		}
		return nil
	})
}
