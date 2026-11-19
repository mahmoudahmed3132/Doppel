// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package store

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
)

const eventCols = `seq, event_id, node_id, sensor_id, trigger, severity, occurred_at, received_at, source, target,
	details, is_read, archived, whitelisted, known_scanner`

func scanEvent(row interface{ Scan(...any) error }) (*domain.Event, error) {
	var (
		e                       domain.Event
		sev, details            string
		occ, rec                int64
		read, arch, wl, scanner int
	)
	if err := row.Scan(&e.Seq, &e.EventID, &e.NodeID, &e.SensorID, &e.Trigger, &sev, &occ, &rec, &e.Source, &e.Target,
		&details, &read, &arch, &wl, &scanner); err != nil {
		return nil, err
	}
	e.Severity = domain.Severity(sev)
	e.OccurredAt, e.ReceivedAt = fromMS(occ), fromMS(rec)
	e.Details = []byte(details)
	e.Read, e.Archived, e.Whitelisted, e.KnownScanner = read != 0, arch != 0, wl != 0, scanner != 0
	return &e, nil
}

// InsertEvent stores e idempotently on (node_id, event_id). It sets e.Seq
// and returns false when the event was already stored.
func (db *DB) InsertEvent(ctx context.Context, e *domain.Event) (bool, error) {
	var seq int64
	err := db.sql.QueryRowContext(ctx, `INSERT INTO events (event_id, node_id, sensor_id, trigger, severity, occurred_at,
		received_at, source, target, details, is_read, archived, whitelisted, known_scanner)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (node_id, event_id) DO NOTHING RETURNING seq`,
		e.EventID, e.NodeID, e.SensorID, e.Trigger, string(e.Severity), ms(e.OccurredAt), ms(e.ReceivedAt),
		e.Source, e.Target, string(e.Details), boolInt(e.Read), boolInt(e.Archived), boolInt(e.Whitelisted),
		boolInt(e.KnownScanner)).Scan(&seq)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	e.Seq = seq
	return true, nil
}

// EventFilter selects events. Zero values mean "any".
type EventFilter struct {
	Archived   *bool
	NodeID     string
	SensorID   string
	Severities []domain.Severity
	Trigger    string
	From, To   time.Time // received_at range, To exclusive
	Text       string    // substring of source or target
	BeforeSeq  int64     // cursor: only seq < BeforeSeq
	Limit      int       // default 100, max 1000
}

func (f EventFilter) where() (string, []any) {
	var (
		conds []string
		args  []any
	)
	if f.Archived != nil {
		conds = append(conds, "archived = ?")
		args = append(args, boolInt(*f.Archived))
	}
	if f.NodeID != "" {
		conds = append(conds, "node_id = ?")
		args = append(args, f.NodeID)
	}
	if f.SensorID != "" {
		conds = append(conds, "sensor_id = ?")
		args = append(args, f.SensorID)
	}
	if len(f.Severities) > 0 {
		conds = append(conds, "severity IN ("+strings.TrimSuffix(strings.Repeat("?,", len(f.Severities)), ",")+")")
		for _, s := range f.Severities {
			args = append(args, string(s))
		}
	}
	if f.Trigger != "" {
		conds = append(conds, "trigger = ?")
		args = append(args, f.Trigger)
	}
	if !f.From.IsZero() {
		conds = append(conds, "received_at >= ?")
		args = append(args, ms(f.From))
	}
	if !f.To.IsZero() {
		conds = append(conds, "received_at < ?")
		args = append(args, ms(f.To))
	}
	if f.Text != "" {
		like := "%" + escapeLike(f.Text) + "%"
		conds = append(conds, `(source LIKE ? ESCAPE '\' OR target LIKE ? ESCAPE '\')`)
		args = append(args, like, like)
	}
	if f.BeforeSeq > 0 {
		conds = append(conds, "seq < ?")
		args = append(args, f.BeforeSeq)
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// Events lists events newest first. The next cursor is the Seq of the last
// returned event when len == limit.
func (db *DB) Events(ctx context.Context, f EventFilter) ([]domain.Event, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	if f.Limit > 1000 {
		f.Limit = 1000
	}
	w, args := f.where()
	rows, err := db.sql.QueryContext(ctx, `SELECT `+eventCols+` FROM events`+w+` ORDER BY seq DESC LIMIT ?`, append(args, f.Limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}

// Event returns one event by sequence number.
func (db *DB) Event(ctx context.Context, seq int64) (*domain.Event, error) {
	e, err := scanEvent(db.sql.QueryRowContext(ctx, `SELECT `+eventCols+` FROM events WHERE seq = ?`, seq))
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	return e, err
}

// UnreadCount counts unread, unarchived events.
func (db *DB) UnreadCount(ctx context.Context) (int64, error) {
	var n int64
	err := db.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE is_read = 0 AND archived = 0`).Scan(&n)
	return n, err
}

// MarkRead marks one event (seq > 0) or all events (seq == 0) read.
func (db *DB) MarkRead(ctx context.Context, seq int64) (int64, error) {
	return db.updateFlag(ctx, `UPDATE events SET is_read = 1 WHERE is_read = 0`, seq)
}

// Archive archives one event (seq > 0) or all events (seq == 0); archived
// events are also marked read.
func (db *DB) Archive(ctx context.Context, seq int64) (int64, error) {
	return db.updateFlag(ctx, `UPDATE events SET archived = 1, is_read = 1 WHERE archived = 0`, seq)
}

func (db *DB) updateFlag(ctx context.Context, q string, seq int64) (int64, error) {
	var args []any
	if seq > 0 {
		q += ` AND seq = ?`
		args = append(args, seq)
	}
	res, err := db.sql.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteAllEvents removes every event (danger zone).
func (db *DB) DeleteAllEvents(ctx context.Context) (int64, error) {
	res, err := db.sql.ExecContext(ctx, `DELETE FROM events`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ArchiveOlderThan archives unarchived events received before t.
func (db *DB) ArchiveOlderThan(ctx context.Context, t time.Time) (int64, error) {
	res, err := db.sql.ExecContext(ctx, `UPDATE events SET archived = 1, is_read = 1 WHERE archived = 0 AND received_at < ?`, ms(t))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PurgeArchivedOlderThan deletes archived events received before t.
func (db *DB) PurgeArchivedOlderThan(ctx context.Context, t time.Time) (int64, error) {
	res, err := db.sql.ExecContext(ctx, `DELETE FROM events WHERE archived = 1 AND received_at < ?`, ms(t))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
