// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package backup implements host-only online backup, offline restore, and
// integrity verification for the Doppel Hub SQLite database (B1 / WP-4C / F-003).
//
// Security properties:
//   - Online backup uses SQLite VACUUM INTO so it is safe while the Hub runs.
//   - The key-encryption key (KEK) is never included in the backup archive;
//     Backup refuses if the KEK file lies inside the output directory.
//   - Optional at-rest encryption uses age (filippo.io/age) with one or more
//     recipient public keys (--encrypt-to).
//   - Restore is offline-only, verifies checksums, SQLite integrity, schema
//     version (refusing newer schemas), and DEK unwrap under the supplied KEK
//     before touching the live database. The previous database is preserved as
//     <db>.pre-restore, all sessions are invalidated, and a system.restore_cli
//     audit record is queued for the next Hub start.
package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/seal"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

const (
	// FormatVersion is the current backup manifest format version.
	FormatVersion = 1
	// PlainDBFile is the filename of an unencrypted SQLite snapshot.
	PlainDBFile = "hub.db"
	// AgeDBFile is the filename of an age-encrypted SQLite snapshot.
	AgeDBFile = "hub.db.age"
	// ManifestFile is the filename of the backup manifest.
	ManifestFile = "manifest.json"
	// PreRestoreSuffix is appended to the live DB path to preserve the old DB on restore.
	PreRestoreSuffix = ".pre-restore"
	// LockSuffix is appended to the DB path for the running-Hub advisory lock.
	LockSuffix = ".lock"
	// RestoreAuditAction is the CLI audit action queued by Restore.
	RestoreAuditAction = "system.restore_cli"
	// RestoreAuditRoute is the CLI audit route queued by Restore.
	RestoreAuditRoute = "doppel-hub restore"
)

const (
	maxManifestBytes = 64 << 10
	sqliteHeader     = "SQLite format 3\x00"
)

// Errors returned by backup, verify, and restore operations.
var (
	ErrHubRunning       = errors.New("backup: database is in use by a running Hub (stop the Hub before restoring)")
	ErrKEKInBackupDir   = errors.New("backup: refusing to write backup into a directory that contains the KEK file; store the KEK separately")
	ErrOutputNotEmpty   = errors.New("backup: output directory already contains backup files; choose a fresh directory")
	ErrBadManifest      = errors.New("backup: invalid manifest")
	ErrChecksumMismatch = errors.New("backup: checksum mismatch (archive is corrupted or tampered)")
	ErrIdentityNeeded   = errors.New("backup: archive is age-encrypted; supply --identity <key-file> to decrypt")
	ErrCorruptDB        = errors.New("backup: SQLite integrity check failed")
	ErrKEKMismatch      = errors.New("backup: KEK fingerprint in manifest does not match database")
)

// Manifest describes a backup snapshot stored in a backup directory.
type Manifest struct {
	FormatVersion  int    `json:"format_version"`
	File           string `json:"file"`
	Encrypted      bool   `json:"encrypted"`
	Encryption     string `json:"encryption,omitempty"`
	SchemaVersion  int    `json:"schema_version"`
	DBSHA256       string `json:"db_sha256"`
	FileSHA256     string `json:"file_sha256,omitempty"`
	KEKFingerprint string `json:"kek_fingerprint,omitempty"`
	CreatedAt      string `json:"created_at"`
	HubVersion     string `json:"hub_version"`
}

// DBLock holds an exclusive advisory flock on <dbPath>.lock while the Hub is
// running (or while Restore is swapping files).
type DBLock struct {
	f *os.File
}

// AcquireDBLock acquires a non-blocking exclusive advisory lock for dbPath.
// Returns ErrHubRunning if another process already holds the lock.
func AcquireDBLock(dbPath string) (*DBLock, error) {
	if dbPath == "" || dbPath == ":memory:" {
		return &DBLock{}, nil
	}
	lockPath := dbPath + LockSuffix
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening lock file %s: %w", lockPath, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrHubRunning
		}
		return nil, fmt.Errorf("locking %s: %w", lockPath, err)
	}
	return &DBLock{f: f}, nil
}

// Close releases the advisory lock.
func (l *DBLock) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	err := l.f.Close()
	l.f = nil
	return err
}

// BackupOptions configures Backup.
type BackupOptions struct {
	DBPath     string
	OutDir     string
	KEKFile    string   // checked to ensure KEK is not inside OutDir
	EncryptTo  []string // optional age recipient public keys
	HubVersion string
	Now        func() time.Time
}

// Backup creates an online SQLite snapshot via VACUUM INTO and writes
// manifest.json into opts.OutDir. If opts.EncryptTo is non-empty, the snapshot
// is encrypted with age to hub.db.age and no plaintext snapshot is kept.
func Backup(ctx context.Context, opts BackupOptions) (*Manifest, error) {
	if opts.DBPath == "" {
		return nil, errors.New("backup: database path is required")
	}
	if opts.OutDir == "" {
		return nil, errors.New("backup: output directory (--out) is required")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	fi, err := os.Stat(opts.DBPath)
	if err != nil {
		return nil, fmt.Errorf("backup: database %s: %w", opts.DBPath, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("backup: database %s is not a regular file", opts.DBPath)
	}

	recipients, err := parseRecipients(opts.EncryptTo)
	if err != nil {
		return nil, err
	}

	if err := ensureKEKOutsideDir(opts.KEKFile, opts.OutDir); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(opts.OutDir, 0o700); err != nil {
		return nil, fmt.Errorf("backup: creating output directory: %w", err)
	}
	// Refuse to overwrite an existing backup in OutDir.
	for _, name := range []string{ManifestFile, PlainDBFile, AgeDBFile} {
		if _, err := os.Lstat(filepath.Join(opts.OutDir, name)); err == nil {
			return nil, ErrOutputNotEmpty
		}
	}

	srcDB, err := openRawSQLite(opts.DBPath, false, 10000)
	if err != nil {
		return nil, fmt.Errorf("backup: opening source database: %w", err)
	}
	defer srcDB.Close()

	encrypted := len(recipients) > 0
	snapName := PlainDBFile
	if encrypted {
		snapName = ".hub.db.tmp"
	}
	snapPath := filepath.Join(opts.OutDir, snapName)
	cleanupSnap := true
	defer func() {
		if cleanupSnap {
			_ = os.Remove(snapPath)
		}
	}()

	if _, err := srcDB.ExecContext(ctx, "VACUUM INTO ?", snapPath); err != nil {
		return nil, fmt.Errorf("backup: VACUUM INTO failed: %w", err)
	}
	if err := os.Chmod(snapPath, 0o600); err != nil {
		return nil, fmt.Errorf("backup: chmod snapshot: %w", err)
	}

	// Read metadata from the snapshot itself so manifest.json is guaranteed to
	// match the exact snapshotted bytes.
	meta, err := inspectSQLiteFile(ctx, snapPath)
	if err != nil {
		return nil, fmt.Errorf("backup: inspecting snapshot: %w", err)
	}
	dbHash, err := sha256File(snapPath)
	if err != nil {
		return nil, fmt.Errorf("backup: hashing snapshot: %w", err)
	}

	m := &Manifest{
		FormatVersion:  FormatVersion,
		File:           PlainDBFile,
		Encrypted:      encrypted,
		SchemaVersion:  meta.schemaVersion,
		DBSHA256:       dbHash,
		FileSHA256:     dbHash,
		KEKFingerprint: meta.kekFingerprint,
		CreatedAt:      opts.Now().UTC().Format(time.RFC3339),
		HubVersion:     opts.HubVersion,
	}

	if encrypted {
		m.File = AgeDBFile
		m.Encryption = "age"
		encPath := filepath.Join(opts.OutDir, AgeDBFile)
		if err := ageEncryptFile(snapPath, encPath, recipients); err != nil {
			_ = os.Remove(encPath)
			return nil, fmt.Errorf("backup: age encryption failed: %w", err)
		}
		fileHash, err := sha256File(encPath)
		if err != nil {
			_ = os.Remove(encPath)
			return nil, fmt.Errorf("backup: hashing encrypted archive: %w", err)
		}
		m.FileSHA256 = fileHash
		// Remove plaintext temporary snapshot now that hub.db.age is durable.
		if err := os.Remove(snapPath); err != nil {
			return nil, fmt.Errorf("backup: removing temporary plaintext snapshot: %w", err)
		}
		cleanupSnap = false
	} else {
		cleanupSnap = false
	}

	if err := writeManifestAtomic(filepath.Join(opts.OutDir, ManifestFile), m); err != nil {
		return nil, fmt.Errorf("backup: writing manifest: %w", err)
	}
	_ = syncDir(opts.OutDir)
	return m, nil
}

// VerifyOptions configures Verify.
type VerifyOptions struct {
	FromDir          string
	IdentityFile     string           // optional age identity file for encrypted backups
	Identities       []age.Identity   // optional pre-parsed age identities (tests)
	KEKProvider      seal.KeyProvider // optional; if set, verifies DEK unwrap
	MaxSchemaVersion int              // defaults to store.SchemaVersion()
	RequireDecrypt   bool             // fail if archive is encrypted and no identity was supplied
	RequireKEK       bool             // fail if DB is sealed and no KEKProvider was supplied
}

// VerifyResult reports what Verify checked.
type VerifyResult struct {
	Manifest     *Manifest
	FileVerified bool
	Decrypted    bool
	DBVerified   bool
	KEKVerified  bool
}

// Verify checks a backup directory's manifest, file checksum, optional age
// decryption, SQLite integrity, schema version, and optional KEK unwrap
// without modifying the backup or any live database.
func Verify(ctx context.Context, opts VerifyOptions) (*VerifyResult, error) {
	res, _, err := verifyAndStage(ctx, opts, "")
	return res, err
}

// RestoreOptions configures Restore.
type RestoreOptions struct {
	FromDir          string
	DBPath           string
	IdentityFile     string
	Identities       []age.Identity
	KEKProvider      seal.KeyProvider
	MaxSchemaVersion int
	Now              func() time.Time
}

// RestoreResult reports the outcome of Restore.
type RestoreResult struct {
	Manifest       *Manifest
	PreRestorePath string // non-empty if an existing DB was preserved
}

// Restore performs an offline restore from opts.FromDir to opts.DBPath.
//
// It verifies checksums, schema version (refusing newer schemas), SQLite
// integrity, and DEK unwrap under opts.KEKProvider BEFORE modifying opts.DBPath.
// The existing database (if any) is checkpointed and preserved at
// <DBPath>.pre-restore, all sessions in the restored DB are invalidated, and a
// system.restore_cli audit record is queued for the next Hub start.
func Restore(ctx context.Context, opts RestoreOptions) (*RestoreResult, error) {
	if opts.FromDir == "" {
		return nil, errors.New("restore: backup directory (--from) is required")
	}
	if opts.DBPath == "" {
		return nil, errors.New("restore: target database path is required")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	parentDir := filepath.Dir(opts.DBPath)
	if err := os.MkdirAll(parentDir, 0o700); err != nil {
		return nil, fmt.Errorf("restore: creating database directory: %w", err)
	}

	// Refuse to run while the Hub holds the advisory DB lock.
	lock, err := AcquireDBLock(opts.DBPath)
	if err != nil {
		return nil, err
	}
	defer lock.Close()

	stagingPath := opts.DBPath + ".restore-tmp"
	_ = os.Remove(stagingPath)
	_ = os.Remove(stagingPath + "-wal")
	_ = os.Remove(stagingPath + "-shm")
	cleanupStaging := true
	defer func() {
		if cleanupStaging {
			_ = os.Remove(stagingPath)
			_ = os.Remove(stagingPath + "-wal")
			_ = os.Remove(stagingPath + "-shm")
		}
	}()

	vRes, _, err := verifyAndStage(ctx, VerifyOptions{
		FromDir:          opts.FromDir,
		IdentityFile:     opts.IdentityFile,
		Identities:       opts.Identities,
		KEKProvider:      opts.KEKProvider,
		MaxSchemaVersion: opts.MaxSchemaVersion,
		RequireDecrypt:   true,
		RequireKEK:       true,
	}, stagingPath)
	if err != nil {
		return nil, err
	}

	// Prepare the staged database before swapping: invalidate all sessions and
	// queue the system.restore_cli audit record for the next Hub start.
	if err := prepareStagedDB(ctx, stagingPath, opts.Now()); err != nil {
		return nil, fmt.Errorf("restore: preparing restored database: %w", err)
	}

	// Preserve the previous database as <DBPath>.pre-restore (checkpointing WAL
	// first so .pre-restore is self-contained and no stale WAL remains).
	var preRestore string
	if _, err := os.Stat(opts.DBPath); err == nil {
		if err := checkpointOfflineDB(ctx, opts.DBPath); err != nil {
			return nil, fmt.Errorf("restore: existing database could not be checkpointed (is the Hub still running?): %w", err)
		}
		preRestore = opts.DBPath + PreRestoreSuffix
		_ = os.Remove(preRestore)
		if err := os.Rename(opts.DBPath, preRestore); err != nil {
			return nil, fmt.Errorf("restore: preserving previous database as %s: %w", preRestore, err)
		}
		_ = os.Chmod(preRestore, 0o600)
		// Remove stale WAL/SHM sidecars so SQLite never replays old frames onto
		// the restored database.
		_ = os.Remove(opts.DBPath + "-wal")
		_ = os.Remove(opts.DBPath + "-shm")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("restore: checking existing database: %w", err)
	}

	if err := os.Rename(stagingPath, opts.DBPath); err != nil {
		// Best-effort rollback if rename fails.
		if preRestore != "" {
			_ = os.Rename(preRestore, opts.DBPath)
		}
		return nil, fmt.Errorf("restore: swapping restored database into place: %w", err)
	}
	cleanupStaging = false
	_ = os.Chmod(opts.DBPath, 0o600)
	_ = syncDir(parentDir)

	return &RestoreResult{
		Manifest:       vRes.Manifest,
		PreRestorePath: preRestore,
	}, nil
}

// verifyAndStage runs all verification checks. If stagePath is non-empty, the
// verified plaintext SQLite database is written to stagePath (mode 0600).
func verifyAndStage(ctx context.Context, opts VerifyOptions, stagePath string) (*VerifyResult, string, error) {
	if opts.FromDir == "" {
		return nil, "", errors.New("backup: source directory (--from) is required")
	}
	maxSchema := opts.MaxSchemaVersion
	if maxSchema <= 0 {
		maxSchema = store.SchemaVersion()
	}

	m, err := readManifest(filepath.Join(opts.FromDir, ManifestFile))
	if err != nil {
		return nil, "", err
	}
	if m.SchemaVersion > maxSchema {
		return nil, "", fmt.Errorf("%w: backup is at schema v%d, this Hub supports up to v%d", store.ErrSchemaTooNew, m.SchemaVersion, maxSchema)
	}

	archivePath := filepath.Join(opts.FromDir, m.File)
	fi, err := os.Lstat(archivePath)
	if err != nil {
		return nil, "", fmt.Errorf("backup: archive file %s: %w", m.File, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, "", fmt.Errorf("%w: archive %s is not a regular file", ErrBadManifest, m.File)
	}

	actualFileHash, err := sha256File(archivePath)
	if err != nil {
		return nil, "", fmt.Errorf("backup: hashing %s: %w", m.File, err)
	}
	expectedFileHash := m.DBSHA256
	if m.Encrypted || m.FileSHA256 != "" {
		expectedFileHash = m.FileSHA256
	}
	if subtle.ConstantTimeCompare([]byte(actualFileHash), []byte(expectedFileHash)) != 1 {
		return nil, "", fmt.Errorf("%w: %s SHA-256 does not match manifest", ErrChecksumMismatch, m.File)
	}

	res := &VerifyResult{
		Manifest:     m,
		FileVerified: true,
	}

	var plainPath string
	var tempFile string
	defer func() {
		if tempFile != "" {
			_ = os.Remove(tempFile)
		}
	}()

	if m.Encrypted {
		ids, err := loadIdentities(opts.IdentityFile, opts.Identities)
		if err != nil {
			return nil, "", err
		}
		if len(ids) == 0 {
			if opts.RequireDecrypt {
				return nil, "", ErrIdentityNeeded
			}
			return res, "", nil
		}
		dst := stagePath
		if dst == "" {
			f, err := os.CreateTemp("", "doppel-verify-*.db")
			if err != nil {
				return nil, "", fmt.Errorf("backup: creating temp file: %w", err)
			}
			dst = f.Name()
			f.Close()
			tempFile = dst
		}
		if err := ageDecryptFile(archivePath, dst, ids); err != nil {
			return nil, "", fmt.Errorf("backup: age decryption failed: %w", err)
		}
		actualDBHash, err := sha256File(dst)
		if err != nil {
			return nil, "", fmt.Errorf("backup: hashing decrypted database: %w", err)
		}
		if subtle.ConstantTimeCompare([]byte(actualDBHash), []byte(m.DBSHA256)) != 1 {
			return nil, "", fmt.Errorf("%w: decrypted database SHA-256 does not match manifest", ErrChecksumMismatch)
		}
		res.Decrypted = true
		plainPath = dst
	} else {
		if stagePath != "" {
			if err := copyFileSecure(archivePath, stagePath); err != nil {
				return nil, "", fmt.Errorf("backup: staging database: %w", err)
			}
			plainPath = stagePath
		} else {
			plainPath = archivePath
		}
	}

	meta, err := inspectSQLiteFile(ctx, plainPath)
	if err != nil {
		return nil, "", err
	}
	if meta.schemaVersion > maxSchema {
		return nil, "", fmt.Errorf("%w: database header is at schema v%d, this Hub supports up to v%d", store.ErrSchemaTooNew, meta.schemaVersion, maxSchema)
	}
	if meta.schemaVersion != m.SchemaVersion {
		return nil, "", fmt.Errorf("%w: manifest claims schema v%d but database is v%d", ErrBadManifest, m.SchemaVersion, meta.schemaVersion)
	}
	if meta.kekFingerprint != m.KEKFingerprint {
		return nil, "", fmt.Errorf("%w: manifest has %q, database has %q", ErrKEKMismatch, m.KEKFingerprint, meta.kekFingerprint)
	}
	res.DBVerified = true

	if meta.wrappedDEK != "" {
		if opts.KEKProvider == nil {
			if opts.RequireKEK {
				return nil, "", store.ErrSealedNoKey
			}
		} else {
			kek, err := opts.KEKProvider.KEK(ctx)
			if err != nil {
				return nil, "", fmt.Errorf("backup: reading KEK: %w", err)
			}
			if _, err := seal.Unwrap(kek, meta.wrappedDEK); err != nil {
				return nil, "", err
			}
			if meta.kekFingerprint != "" && seal.Fingerprint(kek) != meta.kekFingerprint {
				return nil, "", fmt.Errorf("%w: supplied KEK fingerprint %s does not match backup %s", seal.ErrWrongKEK, seal.Fingerprint(kek), meta.kekFingerprint)
			}
			res.KEKVerified = true
		}
	}

	return res, plainPath, nil
}

type sqliteMeta struct {
	schemaVersion  int
	wrappedDEK     string
	kekFingerprint string
}

func inspectSQLiteFile(ctx context.Context, path string) (*sqliteMeta, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	hdr := make([]byte, len(sqliteHeader))
	_, err = io.ReadFull(f, hdr)
	f.Close()
	if err != nil || !bytes.Equal(hdr, []byte(sqliteHeader)) {
		return nil, fmt.Errorf("%w: file is not a valid SQLite 3 database", ErrCorruptDB)
	}

	sqldb, err := openRawSQLite(path, true, 5000)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptDB, err)
	}
	defer sqldb.Close()

	var integrity string
	if err := sqldb.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptDB, err)
	}
	if integrity != "ok" {
		return nil, fmt.Errorf("%w: PRAGMA integrity_check returned %q", ErrCorruptDB, integrity)
	}

	var version int
	if err := sqldb.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return nil, fmt.Errorf("%w: reading user_version: %v", ErrCorruptDB, err)
	}

	meta := &sqliteMeta{schemaVersion: version}
	var hasCrypto int
	if err := sqldb.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='crypto_meta'`).Scan(&hasCrypto); err != nil {
		return nil, err
	}
	if hasCrypto > 0 {
		err := sqldb.QueryRowContext(ctx, `SELECT wrapped_dek, kek_fingerprint FROM crypto_meta WHERE id = 1`).Scan(&meta.wrappedDEK, &meta.kekFingerprint)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("reading crypto_meta: %w", err)
		}
	}
	return meta, nil
}

func prepareStagedDB(ctx context.Context, stagingPath string, now time.Time) error {
	sqldb, err := openRawSQLite(stagingPath, false, 5000)
	if err != nil {
		return err
	}
	defer sqldb.Close()

	tx, err := sqldb.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var hasSessions int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='sessions'`).Scan(&hasSessions); err != nil {
		return err
	}
	if hasSessions > 0 {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions`); err != nil {
			return err
		}
	}

	var hasCLIAudit int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cli_audit'`).Scan(&hasCLIAudit); err != nil {
		return err
	}
	if hasCLIAudit > 0 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO cli_audit (action, route, at) VALUES (?, ?, ?)`,
			RestoreAuditAction, RestoreAuditRoute, now.UTC().UnixMilli()); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	_, _ = sqldb.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	if err := sqldb.Close(); err != nil {
		return err
	}
	_ = os.Remove(stagingPath + "-wal")
	_ = os.Remove(stagingPath + "-shm")
	if err := syncFile(stagingPath); err != nil {
		return err
	}
	return os.Chmod(stagingPath, 0o600)
}

func checkpointOfflineDB(ctx context.Context, dbPath string) error {
	sqldb, err := openRawSQLite(dbPath, false, 0)
	if err != nil {
		return err
	}
	defer sqldb.Close()
	if _, err := sqldb.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return err
	}
	return sqldb.Close()
}

func openRawSQLite(path string, readOnly bool, busyTimeoutMS int) (*sql.DB, error) {
	q := url.Values{}
	if readOnly {
		q.Set("mode", "ro")
		q.Set("immutable", "1")
	} else {
		q.Add("_pragma", "foreign_keys(1)")
		q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", busyTimeoutMS))
		q.Add("_pragma", "synchronous(FULL)")
		q.Add("_pragma", "secure_delete(1)")
	}
	dsn := "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + q.Encode()
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	sqldb.SetMaxOpenConns(1)
	if err := sqldb.Ping(); err != nil {
		sqldb.Close()
		return nil, err
	}
	return sqldb, nil
}

func readManifest(path string) (*Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadManifest, err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxManifestBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadManifest, err)
	}
	if len(b) > maxManifestBytes {
		return nil, fmt.Errorf("%w: manifest exceeds %d bytes", ErrBadManifest, maxManifestBytes)
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadManifest, err)
	}
	if m.FormatVersion != FormatVersion {
		return nil, fmt.Errorf("%w: unsupported format_version %d", ErrBadManifest, m.FormatVersion)
	}
	if m.File == "" || filepath.Base(m.File) != m.File || strings.ContainsAny(m.File, `/\`) || m.File == "." || m.File == ".." {
		return nil, fmt.Errorf("%w: invalid archive file name %q", ErrBadManifest, m.File)
	}
	if m.SchemaVersion < 1 {
		return nil, fmt.Errorf("%w: invalid schema_version %d", ErrBadManifest, m.SchemaVersion)
	}
	if !isSHA256Hex(m.DBSHA256) {
		return nil, fmt.Errorf("%w: invalid db_sha256", ErrBadManifest)
	}
	if m.Encrypted {
		if m.Encryption != "age" {
			return nil, fmt.Errorf("%w: unsupported encryption %q", ErrBadManifest, m.Encryption)
		}
		if !isSHA256Hex(m.FileSHA256) {
			return nil, fmt.Errorf("%w: missing or invalid file_sha256 for encrypted archive", ErrBadManifest)
		}
	} else if m.FileSHA256 != "" && !isSHA256Hex(m.FileSHA256) {
		return nil, fmt.Errorf("%w: invalid file_sha256", ErrBadManifest)
	}
	return &m, nil
}

func writeManifestAtomic(path string, m *Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func parseRecipients(raw []string) ([]age.Recipient, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var out []age.Recipient
	for _, r := range raw {
		r = strings.TrimSpace(r)
		if r == "" || strings.ContainsAny(r, "\r\n") {
			return nil, fmt.Errorf("backup: invalid age recipient %q", r)
		}
		parsed, err := age.ParseRecipients(strings.NewReader(r + "\n"))
		if err != nil || len(parsed) != 1 {
			return nil, fmt.Errorf("backup: invalid age recipient %q: %w", r, err)
		}
		out = append(out, parsed[0])
	}
	return out, nil
}

func loadIdentities(path string, extra []age.Identity) ([]age.Identity, error) {
	out := append([]age.Identity(nil), extra...)
	if path == "" {
		return out, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("backup: reading age identity file %s: %w", path, err)
	}
	defer f.Close()
	parsed, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("backup: parsing age identity file %s: %w", path, err)
	}
	return append(out, parsed...), nil
}

func ageEncryptFile(srcPath, dstPath string, recipients []age.Recipient) error {
	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	w, err := age.Encrypt(out, recipients...)
	if err != nil {
		out.Close()
		return err
	}
	if _, err := io.Copy(w, in); err != nil {
		_ = w.Close()
		out.Close()
		return err
	}
	if err := w.Close(); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func ageDecryptFile(srcPath, dstPath string, identities []age.Identity) error {
	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()

	r, err := age.Decrypt(in, identities...)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, r); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func copyFileSecure(srcPath, dstPath string) error {
	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func ensureKEKOutsideDir(kekFile, outDir string) error {
	if kekFile == "" {
		return nil
	}
	absKEK, err := filepath.Abs(kekFile)
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(absKEK); err == nil {
		absKEK = resolved
	}
	absOut, err := filepath.Abs(outDir)
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(absOut); err == nil {
		absOut = resolved
	}
	rel, err := filepath.Rel(absOut, absKEK)
	if err != nil {
		return nil
	}
	if rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..") {
		return ErrKEKInBackupDir
	}
	return nil
}

func syncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
