// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
)

// BootstrapUserID is the local administrator created by setup. Its
// credentials live in the admin table.
const BootstrapUserID = "usr_admin"

// Roles, lowest to highest privilege.
const (
	RoleViewer  = "viewer"
	RoleAnalyst = "analyst"
	RoleAdmin   = "admin"
)

// Sources of a user.
const (
	SourceLocal = "local"
	SourceOIDC  = "oidc"
)

// Errors for user changes.
var (
	ErrLastAdmin     = errors.New("the last enabled administrator cannot be demoted, disabled or deleted")
	ErrProtectedUser = errors.New("the bootstrap administrator cannot be changed through the API")
	ErrBadRole       = errors.New("role must be admin, analyst or viewer")
)

// ValidRole reports whether r is a known role.
func ValidRole(r string) bool { return r == RoleAdmin || r == RoleAnalyst || r == RoleViewer }

// User is a principal.
type User struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	Role        string     `json:"role"`
	Source      string     `json:"source"`
	Disabled    bool       `json:"disabled"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at"`
}

const userCols = `id, username, role, source, disabled, created_at, last_login_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var (
		u        User
		disabled int
		created  int64
		last     sql.NullInt64
	)
	if err := row.Scan(&u.ID, &u.Username, &u.Role, &u.Source, &disabled, &created, &last); err != nil {
		return nil, err
	}
	u.Disabled, u.CreatedAt, u.LastLoginAt = disabled != 0, fromMS(created), fromNullMS(last)
	return &u, nil
}

// UserByID returns a user or domain.ErrNotFound.
func (db *DB) UserByID(ctx context.Context, id string) (*User, error) {
	u, err := scanUser(db.sql.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	return u, err
}

// UserByUsername returns a user (case-insensitive) or domain.ErrNotFound.
func (db *DB) UserByUsername(ctx context.Context, name string) (*User, error) {
	u, err := scanUser(db.sql.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE lower(username) = lower(?)`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	return u, err
}

// ListUsers returns every user, bootstrap first.
func (db *DB) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY (id = ?) DESC, lower(username)`, BootstrapUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// CreateUser inserts a user. A taken username returns domain.ErrConflict.
func (db *DB) CreateUser(ctx context.Context, u User) error {
	if !ValidRole(u.Role) {
		return ErrBadRole
	}
	if strings.TrimSpace(u.Username) == "" {
		return errors.New("username is required")
	}
	if u.Source != SourceLocal && u.Source != SourceOIDC {
		return errors.New("unknown user source")
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO users (id, username, role, source, disabled, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.Role, u.Source, boolInt(u.Disabled), ms(db.now()))
	if isUniqueViolation(err) {
		return domain.ErrConflict
	}
	return err
}

// RecordLogin stamps the last login time.
func (db *DB) RecordLogin(ctx context.Context, id string) error {
	_, err := db.sql.ExecContext(ctx, `UPDATE users SET last_login_at = ? WHERE id = ?`, ms(db.now()), id)
	return err
}

// guardChange applies the rules shared by role change, disable and delete:
// the bootstrap administrator is untouchable, and at least one enabled
// administrator must remain. It runs inside tx.
func guardChange(ctx context.Context, tx *sql.Tx, id string, wouldRemoveAdmin func(u *User) bool) (*User, error) {
	u, err := scanUser(tx.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if u.ID == BootstrapUserID {
		return nil, ErrProtectedUser
	}
	if u.Role == RoleAdmin && !u.Disabled && wouldRemoveAdmin(u) {
		var others int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0 AND id != ?`, id).Scan(&others); err != nil {
			return nil, err
		}
		if others == 0 {
			return nil, ErrLastAdmin
		}
	}
	return u, nil
}

// SetUserRole changes a role. Sessions need no change: the role is read on
// every request.
func (db *DB) SetUserRole(ctx context.Context, id, role string) error {
	if !ValidRole(role) {
		return ErrBadRole
	}
	return db.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := guardChange(ctx, tx, id, func(*User) bool { return role != RoleAdmin }); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE users SET role = ? WHERE id = ?`, role, id)
		return err
	})
}

// SetUserDisabled disables or re-enables a user and ends a disabled user's sessions.
func (db *DB) SetUserDisabled(ctx context.Context, id string, disabled bool) error {
	return db.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := guardChange(ctx, tx, id, func(*User) bool { return disabled }); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET disabled = ? WHERE id = ?`, boolInt(disabled), id); err != nil {
			return err
		}
		if disabled {
			_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id)
			return err
		}
		return nil
	})
}

// DeleteUser removes a user; their sessions go with them (foreign key).
func (db *DB) DeleteUser(ctx context.Context, id string) error {
	return db.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := guardChange(ctx, tx, id, func(*User) bool { return true }); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
		return err
	})
}

// TestExec runs a statement for tests in other packages that need to set up
// a state the API deliberately cannot reach. It is not used by the Hub.
func (db *DB) TestExec(t interface {
	Helper()
	Fatal(args ...any)
}, query string, args ...any) {
	t.Helper()
	if _, err := db.sql.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}
