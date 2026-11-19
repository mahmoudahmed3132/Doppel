// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package store

// migrations is the ordered schema history. Rules:
//   - never edit a released migration; append a new one;
//   - never drop and rebuild a table referenced with ON DELETE CASCADE;
//   - events, honeytokens and status history carry node/sensor ids as plain
//     values (no foreign key) so evidence survives node/sensor deletion.
//
// Timestamps are Unix milliseconds (INTEGER).
var migrations = []Migration{
	{Version: 1, SQL: `
CREATE TABLE settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

CREATE TABLE admin (
	id                 INTEGER PRIMARY KEY CHECK (id = 1),
	password_hash      TEXT    NOT NULL,
	mfa_secret         TEXT    NOT NULL DEFAULT '',
	mfa_pending_secret TEXT    NOT NULL DEFAULT '',
	mfa_enabled        INTEGER NOT NULL DEFAULT 0,
	mfa_last_step      INTEGER NOT NULL DEFAULT 0,
	recovery_codes     TEXT    NOT NULL DEFAULT '[]',
	mfa_reset_pending  INTEGER NOT NULL DEFAULT 0,
	created_at         INTEGER NOT NULL,
	updated_at         INTEGER NOT NULL
);

CREATE TABLE sessions (
	token_hash   BLOB    PRIMARY KEY,
	created_at   INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL,
	enrol_only   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE nodes (
	id                TEXT    PRIMARY KEY,
	alias             TEXT    NOT NULL,
	tags              TEXT    NOT NULL DEFAULT '[]',
	key_hash          BLOB    NOT NULL UNIQUE,
	created_at        INTEGER NOT NULL,
	last_seen_at      INTEGER,
	desired_revision  TEXT    NOT NULL DEFAULT '',
	applied_revision  TEXT    NOT NULL DEFAULT '',
	upgrade_requested INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE sensors (
	node_id           TEXT    NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
	id                TEXT    NOT NULL,
	catalogue_name    TEXT    NOT NULL,
	version           TEXT    NOT NULL,
	config            TEXT    NOT NULL DEFAULT '{}',
	silenced          INTEGER NOT NULL DEFAULT 0,
	status            TEXT    NOT NULL DEFAULT 'pending',
	status_changed_at INTEGER,
	last_heartbeat_at INTEGER,
	last_activity_at  INTEGER,
	ever_online       INTEGER NOT NULL DEFAULT 0,
	stopped_at        INTEGER,
	outage_alerted_at INTEGER,
	sdk_version       TEXT    NOT NULL DEFAULT '',
	created_at        INTEGER NOT NULL,
	PRIMARY KEY (node_id, id)
);

CREATE TABLE sensor_status_history (
	id        INTEGER PRIMARY KEY,
	node_id   TEXT    NOT NULL,
	sensor_id TEXT    NOT NULL,
	status    TEXT    NOT NULL,
	at        INTEGER NOT NULL
);
CREATE INDEX sensor_status_history_sensor ON sensor_status_history (node_id, sensor_id, at);
CREATE INDEX sensor_status_history_at ON sensor_status_history (at);

CREATE TABLE events (
	seq           INTEGER PRIMARY KEY AUTOINCREMENT,
	event_id      TEXT    NOT NULL,
	node_id       TEXT    NOT NULL,
	sensor_id     TEXT    NOT NULL,
	trigger       TEXT    NOT NULL,
	severity      TEXT    NOT NULL,
	occurred_at   INTEGER NOT NULL,
	received_at   INTEGER NOT NULL,
	source        TEXT    NOT NULL,
	target        TEXT    NOT NULL,
	details       TEXT    NOT NULL,
	is_read       INTEGER NOT NULL DEFAULT 0,
	archived      INTEGER NOT NULL DEFAULT 0,
	whitelisted   INTEGER NOT NULL DEFAULT 0,
	known_scanner INTEGER NOT NULL DEFAULT 0,
	UNIQUE (node_id, event_id)
);
CREATE INDEX events_received ON events (archived, received_at);
CREATE INDEX events_unread ON events (is_read) WHERE is_read = 0;
CREATE INDEX events_sensor ON events (node_id, sensor_id, received_at);

CREATE TABLE honeytokens (
	id                TEXT    PRIMARY KEY,
	username          TEXT    NOT NULL,
	secret            TEXT    NOT NULL,
	planted_node_id   TEXT    NOT NULL,
	planted_sensor_id TEXT    NOT NULL,
	status            TEXT    NOT NULL DEFAULT 'active',
	created_at        INTEGER NOT NULL,
	use_count         INTEGER NOT NULL DEFAULT 0,
	last_used_at      INTEGER,
	UNIQUE (planted_node_id, planted_sensor_id)
);

CREATE TABLE beacons (
	id           TEXT    PRIMARY KEY,
	token        TEXT    NOT NULL UNIQUE,
	type         TEXT    NOT NULL,
	name         TEXT    NOT NULL,
	memo         TEXT    NOT NULL DEFAULT '',
	domain       TEXT    NOT NULL DEFAULT '',
	created_at   INTEGER NOT NULL,
	use_count    INTEGER NOT NULL DEFAULT 0,
	last_used_at INTEGER
);
`},
	{Version: 2, SQL: `
CREATE TABLE catalogue_cache (
	name        TEXT    NOT NULL,
	version     TEXT    NOT NULL,
	manifest    BLOB    NOT NULL,
	bundle      BLOB    NOT NULL,
	verified    INTEGER NOT NULL,
	fetched_at  INTEGER NOT NULL,
	PRIMARY KEY (name, version)
);
`},
	// v3: secrets at rest (docs/plan/ROADMAP.md E1). The wrapped data key
	// lives here. Its presence also makes older Hubs refuse the database
	// (schema too new) instead of reading sealed values as if they were keys.
	{Version: 3, SQL: `
CREATE TABLE crypto_meta (
	id              INTEGER PRIMARY KEY CHECK (id = 1),
	wrapped_dek     TEXT    NOT NULL,
	kek_fingerprint TEXT    NOT NULL,
	created_at      INTEGER NOT NULL,
	rotated_at      INTEGER,
	sealed_at       INTEGER,  -- every plaintext secret has been sealed (strict from then on)
	scrubbed_at     INTEGER   -- plaintext remnants removed (WAL truncated, VACUUM done)
);
-- Actions taken by host-side commands, audited on the next Hub start.
CREATE TABLE cli_audit (
	id     INTEGER PRIMARY KEY AUTOINCREMENT,
	action TEXT    NOT NULL,
	route  TEXT    NOT NULL,
	at     INTEGER NOT NULL
);
`},
	// v4: users and roles (docs/plan/ROADMAP.md U1). Users are principals
	// (identity, role, source). The local credentials and MFA of the bootstrap
	// administrator stay in the admin table, which keeps their sealed values
	// bound to one row; admin exists if and only if user usr_admin does.
	// Sessions are recreated with a user, which logs everyone out once.
	{Version: 4, SQL: `
CREATE TABLE users (
	id            TEXT    PRIMARY KEY,
	username      TEXT    NOT NULL,
	role          TEXT    NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
	source        TEXT    NOT NULL CHECK (source IN ('local', 'oidc')),
	disabled      INTEGER NOT NULL DEFAULT 0,
	created_at    INTEGER NOT NULL,
	last_login_at INTEGER
);
CREATE UNIQUE INDEX users_username ON users (lower(username));
INSERT INTO users (id, username, role, source, created_at)
	SELECT 'usr_admin', 'admin', 'admin', 'local', created_at FROM admin WHERE id = 1;
DROP TABLE sessions;
CREATE TABLE sessions (
	token_hash   BLOB    PRIMARY KEY,
	user_id      TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	created_at   INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL,
	enrol_only   INTEGER NOT NULL DEFAULT 0
);
`},
	// v5: ingest durability and backpressure (F-603). Cumulative count of
	// events a sensor's SDK reported as lost (heartbeat dropped_events).
	{Version: 5, SQL: `
ALTER TABLE sensors ADD COLUMN dropped_events INTEGER NOT NULL DEFAULT 0;
`},
}

// SchemaVersion is the schema version this build migrates to.
func SchemaVersion() int { return len(migrations) }
