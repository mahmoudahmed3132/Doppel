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

const nodeCols = `id, alias, tags, key_hash, created_at, last_seen_at, desired_revision, applied_revision, upgrade_requested`

func scanNode(row interface{ Scan(...any) error }) (*domain.Node, error) {
	var (
		n        domain.Node
		tags     string
		created  int64
		lastSeen sql.NullInt64
		upgrade  int
	)
	if err := row.Scan(&n.ID, &n.Alias, &tags, &n.KeyHash, &created, &lastSeen, &n.DesiredRevision, &n.AppliedRevision, &upgrade); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	if err := json.Unmarshal([]byte(tags), &n.Tags); err != nil {
		return nil, err
	}
	n.CreatedAt = fromMS(created)
	n.LastSeenAt = fromNullMS(lastSeen)
	n.UpgradeRequested = upgrade != 0
	return &n, nil
}

// CreateNode inserts a node. It returns domain.ErrConflict when the id or
// key hash already exists.
func (db *DB) CreateNode(ctx context.Context, n *domain.Node) error {
	tags, err := json.Marshal(nonNil(n.Tags))
	if err != nil {
		return err
	}
	_, err = db.sql.ExecContext(ctx, `INSERT INTO nodes (id, alias, tags, key_hash, created_at) VALUES (?, ?, ?, ?, ?)`,
		n.ID, n.Alias, string(tags), n.KeyHash, ms(n.CreatedAt))
	if isUniqueViolation(err) {
		return domain.ErrConflict
	}
	return err
}

// Node returns one node.
func (db *DB) Node(ctx context.Context, id string) (*domain.Node, error) {
	return scanNode(db.sql.QueryRowContext(ctx, `SELECT `+nodeCols+` FROM nodes WHERE id = ?`, id))
}

// NodeIDByKeyHash returns the id of the node owning a key hash.
func (db *DB) NodeIDByKeyHash(ctx context.Context, hash []byte) (string, error) {
	var id string
	err := db.sql.QueryRowContext(ctx, `SELECT id FROM nodes WHERE key_hash = ?`, hash).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", domain.ErrNotFound
	}
	return id, err
}

// Nodes lists all nodes ordered by alias.
func (db *DB) Nodes(ctx context.Context) ([]domain.Node, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT `+nodeCols+` FROM nodes ORDER BY alias, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *n)
	}
	return out, rows.Err()
}

// UpdateNodeMeta changes alias and tags.
func (db *DB) UpdateNodeMeta(ctx context.Context, id, alias string, tags []string) error {
	t, err := json.Marshal(nonNil(tags))
	if err != nil {
		return err
	}
	return affectedOne(db.sql.ExecContext(ctx, `UPDATE nodes SET alias = ?, tags = ? WHERE id = ?`, alias, string(t), id))
}

// SetNodeKeyHash replaces the node key hash (rotation).
func (db *DB) SetNodeKeyHash(ctx context.Context, id string, hash []byte) error {
	return affectedOne(db.sql.ExecContext(ctx, `UPDATE nodes SET key_hash = ? WHERE id = ?`, hash, id))
}

// DeleteNode removes a node and (by cascade) its sensor instances. Events,
// honeytokens and status history are kept.
func (db *DB) DeleteNode(ctx context.Context, id string) error {
	return affectedOne(db.sql.ExecContext(ctx, `DELETE FROM nodes WHERE id = ?`, id))
}

// TouchNode updates the node's last-seen time.
func (db *DB) TouchNode(ctx context.Context, id string, at time.Time) error {
	_, err := db.sql.ExecContext(ctx, `UPDATE nodes SET last_seen_at = MAX(COALESCE(last_seen_at, 0), ?) WHERE id = ?`, ms(at), id)
	return err
}

// SetNodeRevisions stores the desired and/or applied revision; empty
// arguments leave the column unchanged.
func (db *DB) SetNodeRevisions(ctx context.Context, id, desired, applied string) error {
	return affectedOne(db.sql.ExecContext(ctx, `UPDATE nodes SET
		desired_revision = CASE WHEN ? = '' THEN desired_revision ELSE ? END,
		applied_revision = CASE WHEN ? = '' THEN applied_revision ELSE ? END
		WHERE id = ?`, desired, desired, applied, applied, id))
}

// SetNodeUpgradeRequested flags or clears a pending "upgrade all sensors".
func (db *DB) SetNodeUpgradeRequested(ctx context.Context, id string, v bool) error {
	return affectedOne(db.sql.ExecContext(ctx, `UPDATE nodes SET upgrade_requested = ? WHERE id = ?`, boolInt(v), id))
}

func affectedOne(res sql.Result, err error) error {
	if err != nil {
		if isUniqueViolation(err) {
			return domain.ErrConflict
		}
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
