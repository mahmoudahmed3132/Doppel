// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
)

const sensorCols = `node_id, id, catalogue_name, version, config, silenced, status, status_changed_at,
	last_heartbeat_at, last_activity_at, ever_online, stopped_at, outage_alerted_at, sdk_version, created_at`

func scanSensor(row interface{ Scan(...any) error }) (*domain.Sensor, error) {
	var (
		s                                       domain.Sensor
		cfg, status                             string
		silenced, everOnline                    int
		changed, hb, activity, stopped, alerted sql.NullInt64
		created                                 int64
	)
	err := row.Scan(&s.NodeID, &s.ID, &s.CatalogueName, &s.Version, &cfg, &silenced, &status, &changed,
		&hb, &activity, &everOnline, &stopped, &alerted, &s.SDKVersion, &created)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	if err := json.Unmarshal([]byte(cfg), &s.Config); err != nil {
		return nil, err
	}
	s.Silenced = silenced != 0
	s.Status = domain.SensorStatus(status)
	s.StatusChangedAt = fromNullMS(changed)
	s.LastHeartbeatAt = fromNullMS(hb)
	s.LastActivityAt = fromNullMS(activity)
	s.EverOnline = everOnline != 0
	s.StoppedAt = fromNullMS(stopped)
	s.OutageAlertedAt = fromNullMS(alerted)
	s.CreatedAt = fromMS(created)
	return &s, nil
}

// CreateSensor inserts a sensor instance in pending state.
func (db *DB) CreateSensor(ctx context.Context, s *domain.Sensor) error {
	cfg, err := json.Marshal(s.Config)
	if err != nil {
		return err
	}
	if s.Config == nil {
		cfg = []byte("{}")
	}
	_, err = db.sql.ExecContext(ctx, `INSERT INTO sensors (node_id, id, catalogue_name, version, config, silenced, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)`,
		s.NodeID, s.ID, s.CatalogueName, s.Version, string(cfg), boolInt(s.Silenced), ms(s.CreatedAt))
	if isUniqueViolation(err) {
		return domain.ErrConflict
	}
	return err
}

// Sensor returns one sensor instance.
func (db *DB) Sensor(ctx context.Context, nodeID, id string) (*domain.Sensor, error) {
	return scanSensor(db.sql.QueryRowContext(ctx, `SELECT `+sensorCols+` FROM sensors WHERE node_id = ? AND id = ?`, nodeID, id))
}

// Sensors lists sensor instances; nodeID "" lists all.
func (db *DB) Sensors(ctx context.Context, nodeID string) ([]domain.Sensor, error) {
	q := `SELECT ` + sensorCols + ` FROM sensors`
	var args []any
	if nodeID != "" {
		q += ` WHERE node_id = ?`
		args = append(args, nodeID)
	}
	rows, err := db.sql.QueryContext(ctx, q+` ORDER BY node_id, id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Sensor
	for rows.Next() {
		s, err := scanSensor(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

// SetSensorSilenced toggles webhook silencing.
func (db *DB) SetSensorSilenced(ctx context.Context, nodeID, id string, v bool) error {
	return affectedOne(db.sql.ExecContext(ctx, `UPDATE sensors SET silenced = ? WHERE node_id = ? AND id = ?`, boolInt(v), nodeID, id))
}

// DeleteSensor removes a sensor instance; its events are kept.
func (db *DB) DeleteSensor(ctx context.Context, nodeID, id string) error {
	return affectedOne(db.sql.ExecContext(ctx, `DELETE FROM sensors WHERE node_id = ? AND id = ?`, nodeID, id))
}

// SensorBelongsToNode reports whether the sensor id exists on the node.
func (db *DB) SensorBelongsToNode(ctx context.Context, nodeID, id string) (bool, error) {
	var one int
	err := db.sql.QueryRowContext(ctx, `SELECT 1 FROM sensors WHERE node_id = ? AND id = ?`, nodeID, id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// TouchSensorActivity records an event from the sensor (liveness input).
func (db *DB) TouchSensorActivity(ctx context.Context, nodeID, id string, at time.Time) error {
	_, err := db.sql.ExecContext(ctx, `UPDATE sensors SET last_activity_at = MAX(COALESCE(last_activity_at, 0), ?) WHERE node_id = ? AND id = ?`,
		ms(at), nodeID, id)
	return err
}

// SensorLiveness is the mutable liveness state written by the liveness
// service in one transaction with a status-history row.
type SensorLiveness struct {
	Status          domain.SensorStatus
	StatusChanged   bool
	LastHeartbeatAt *time.Time
	EverOnline      bool
	StoppedAt       *time.Time
	OutageAlertedAt *time.Time
	SDKVersion      string
}

// SaveSensorLiveness writes liveness state; when StatusChanged a history
// row is appended.
func (db *DB) SaveSensorLiveness(ctx context.Context, nodeID, id string, l SensorLiveness, at time.Time) error {
	return db.withTx(ctx, func(tx *sql.Tx) error {
		err := affectedOne(tx.ExecContext(ctx, `UPDATE sensors SET
			status = ?,
			status_changed_at = CASE WHEN ? THEN ? ELSE status_changed_at END,
			last_heartbeat_at = ?, ever_online = ?, stopped_at = ?, outage_alerted_at = ?,
			sdk_version = CASE WHEN ? = '' THEN sdk_version ELSE ? END
			WHERE node_id = ? AND id = ?`,
			string(l.Status), l.StatusChanged, ms(at), nullMS(l.LastHeartbeatAt), boolInt(l.EverOnline),
			nullMS(l.StoppedAt), nullMS(l.OutageAlertedAt), l.SDKVersion, l.SDKVersion, nodeID, id))
		if err != nil || !l.StatusChanged {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO sensor_status_history (node_id, sensor_id, status, at) VALUES (?, ?, ?, ?)`,
			nodeID, id, string(l.Status), ms(at))
		return err
	})
}

// StatusChange is one sensor status-history row.
type StatusChange struct {
	NodeID   string
	SensorID string
	Status   domain.SensorStatus
	At       time.Time
}

// StatusHistory returns history rows since a time, oldest first, plus the
// last row before since for every sensor (so uptime can be computed from
// the window start).
func (db *DB) StatusHistory(ctx context.Context, since time.Time) ([]StatusChange, error) {
	rows, err := db.sql.QueryContext(ctx, `
		SELECT node_id, sensor_id, status, at FROM sensor_status_history WHERE at >= ?
		UNION ALL
		SELECT h.node_id, h.sensor_id, h.status, h.at FROM sensor_status_history h
		WHERE h.id IN (SELECT MAX(id) FROM sensor_status_history WHERE at < ? GROUP BY node_id, sensor_id)
		ORDER BY at`, ms(since), ms(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StatusChange
	for rows.Next() {
		var c StatusChange
		var st string
		var at int64
		if err := rows.Scan(&c.NodeID, &c.SensorID, &st, &at); err != nil {
			return nil, err
		}
		c.Status, c.At = domain.SensorStatus(st), fromMS(at)
		out = append(out, c)
	}
	return out, rows.Err()
}

// PurgeStatusHistory deletes history rows older than before.
func (db *DB) PurgeStatusHistory(ctx context.Context, before time.Time) (int64, error) {
	res, err := db.sql.ExecContext(ctx, `DELETE FROM sensor_status_history WHERE at < ?`, ms(before))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// SensorChanges is one atomic change to a node's sensor set.
type SensorChanges struct {
	Create  []domain.Sensor // new instances (pending)
	Update  []domain.Sensor // version and config replaced
	Delete  []string        // sensor ids
	Desired string          // new desired revision of the node ("" = unknown)
}

// ApplySensorChanges applies c and stores the node's desired revision in
// one transaction. Liveness state of updated sensors is preserved.
func (db *DB) ApplySensorChanges(ctx context.Context, nodeID string, c SensorChanges) error {
	return db.withTx(ctx, func(tx *sql.Tx) error {
		for _, s := range c.Create {
			cfg, err := json.Marshal(nonNilMap(s.Config))
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO sensors (node_id, id, catalogue_name, version, config, silenced, status, created_at)
				VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)`,
				nodeID, s.ID, s.CatalogueName, s.Version, string(cfg), boolInt(s.Silenced), ms(s.CreatedAt))
			if isUniqueViolation(err) {
				return domain.ErrConflict
			}
			if err != nil {
				return err
			}
		}
		for _, s := range c.Update {
			cfg, err := json.Marshal(nonNilMap(s.Config))
			if err != nil {
				return err
			}
			if err := affectedOne(tx.ExecContext(ctx, `UPDATE sensors SET version = ?, config = ? WHERE node_id = ? AND id = ?`,
				s.Version, string(cfg), nodeID, s.ID)); err != nil {
				return err
			}
		}
		for _, id := range c.Delete {
			if err := affectedOne(tx.ExecContext(ctx, `DELETE FROM sensors WHERE node_id = ? AND id = ?`, nodeID, id)); err != nil {
				return err
			}
		}
		return affectedOne(tx.ExecContext(ctx, `UPDATE nodes SET desired_revision = ? WHERE id = ?`, c.Desired, nodeID))
	})
}

func nonNilMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
