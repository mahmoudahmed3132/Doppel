// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
)

// v4 gives the existing administrator a user row and drops old sessions
// (they have no user), so everyone logs in again once.
func TestUsersMigrationBackfillsBootstrapAdmin(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ts.db")
	db, err := Open(ctx, path, Options{Migrations: migrations[:3]})
	if err != nil {
		t.Fatal(err)
	}
	db.sql.Exec(`INSERT INTO admin (id, password_hash, created_at, updated_at) VALUES (1, 'h', 1000, 1000)`)
	db.sql.Exec(`INSERT INTO sessions (token_hash, created_at, last_seen_at, enrol_only) VALUES (x'01', 1, 1, 0)`)
	db.Close()

	db, err = Open(ctx, path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	u, err := db.UserByID(ctx, BootstrapUserID)
	if err != nil || u.Username != "admin" || u.Role != RoleAdmin || u.Source != SourceLocal {
		t.Fatalf("bootstrap user: %+v %v", u, err)
	}
	if _, err := db.SessionByHash(ctx, []byte{1}); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("old session survived: %v", err)
	}
}

func TestUserRulesAndSessionCascade(t *testing.T) {
	ctx := context.Background()
	db, _ := openTest(t)
	if err := db.CreateAdmin(ctx, "h", nil); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateUser(ctx, User{ID: "u1", Username: "Alice", Role: RoleAnalyst, Source: SourceOIDC}); err != nil {
		t.Fatal(err)
	}
	// Usernames are unique case-insensitively.
	if err := db.CreateUser(ctx, User{ID: "u2", Username: "alice", Role: RoleViewer, Source: SourceOIDC}); !errors.Is(err, domain.ErrConflict) {
		t.Errorf("duplicate username: %v", err)
	}
	if err := db.CreateUser(ctx, User{ID: "u3", Username: "x", Role: "root", Source: SourceOIDC}); !errors.Is(err, ErrBadRole) {
		t.Errorf("bad role: %v", err)
	}
	if u, err := db.UserByUsername(ctx, "ALICE"); err != nil || u.ID != "u1" {
		t.Errorf("lookup: %v %v", u, err)
	}
	// A session belongs to a user and dies with them; a session for a
	// missing user cannot even be created (foreign key).
	if err := db.CreateSession(ctx, Session{TokenHash: []byte{9}, UserID: "ghost", CreatedAt: time.Now(), LastSeenAt: time.Now()}); err == nil {
		t.Error("session for an unknown user accepted")
	}
	db.CreateSession(ctx, Session{TokenHash: []byte{7}, UserID: "u1", CreatedAt: time.Now(), LastSeenAt: time.Now()})
	if err := db.DeleteUser(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SessionByHash(ctx, []byte{7}); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("session outlived its user: %v", err)
	}
	// Factory reset removes the bootstrap pair together (admin iff usr_admin).
	if err := db.FactoryReset(ctx, false); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UserByID(ctx, BootstrapUserID); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("bootstrap user survived factory reset: %v", err)
	}
	if ok, _ := db.AdminExists(ctx); ok {
		t.Error("admin survived factory reset")
	}
}
