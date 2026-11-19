// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package store

import (
	"context"
	"time"
)

// CachedManifest is a manifest and its Sigstore bundle as fetched from the
// registry. The bytes are re-verified whenever they are loaded.
type CachedManifest struct {
	Name      string
	Version   string
	Manifest  []byte
	Bundle    []byte
	Verified  bool // false only when accepted under the dev unsigned flag
	FetchedAt time.Time
}

// PutCachedManifest stores or replaces a cached manifest.
func (db *DB) PutCachedManifest(ctx context.Context, m CachedManifest) error {
	_, err := db.sql.ExecContext(ctx, `INSERT INTO catalogue_cache (name, version, manifest, bundle, verified, fetched_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (name, version) DO UPDATE SET manifest = excluded.manifest, bundle = excluded.bundle,
			verified = excluded.verified, fetched_at = excluded.fetched_at`,
		m.Name, m.Version, m.Manifest, nonNilBytes(m.Bundle), boolInt(m.Verified), ms(m.FetchedAt))
	return err
}

// CachedManifests returns every cached manifest.
func (db *DB) CachedManifests(ctx context.Context) ([]CachedManifest, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT name, version, manifest, bundle, verified, fetched_at FROM catalogue_cache ORDER BY name, version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CachedManifest
	for rows.Next() {
		var (
			m  CachedManifest
			v  int
			at int64
		)
		if err := rows.Scan(&m.Name, &m.Version, &m.Manifest, &m.Bundle, &v, &at); err != nil {
			return nil, err
		}
		m.Verified, m.FetchedAt = v != 0, fromMS(at)
		out = append(out, m)
	}
	return out, rows.Err()
}
