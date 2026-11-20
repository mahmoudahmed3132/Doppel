// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/seal"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
)

type testFixture struct {
	dir     string
	dbPath  string
	kekFile string
	kek     []byte
}

func newSealedTestDB(t *testing.T) *testFixture {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "hub.db")
	kekHex, err := seal.GenerateKEK()
	if err != nil {
		t.Fatalf("GenerateKEK: %v", err)
	}
	kekDir := t.TempDir() // separate dir from DB and backups
	kekFile := filepath.Join(kekDir, "hub.kek")
	if err := os.WriteFile(kekFile, []byte(kekHex+"\n"), 0o600); err != nil {
		t.Fatalf("write kek: %v", err)
	}
	kek, err := seal.ParseKEK([]byte(kekHex))
	if err != nil {
		t.Fatalf("ParseKEK: %v", err)
	}

	ctx := context.Background()
	db, err := store.Open(ctx, dbPath, store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()
	if err := db.EnableEncryption(ctx, seal.FileProvider{Path: kekFile}, nil); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	// Drain initial secrets.sealed CLI audit so restore test checks only restore's audit.
	if _, err := db.TakeCLIAudits(ctx); err != nil {
		t.Fatalf("TakeCLIAudits: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := db.CreateAdmin(ctx, "dummy-argon2-hash", map[string]string{
		"siem_token":  "dummy-siem-token-12345",
		"webhook_url": "https://example.invalid/webhook/test",
	}); err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}
	if err := db.CreateNode(ctx, &domain.Node{
		ID: "node-1", Alias: "decoy-host-1", KeyHash: []byte("hash-node-1"),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if err := db.CreateSensor(ctx, &domain.Sensor{
		ID: "sensor-1", NodeID: "node-1", CatalogueName: "tcp-tarpit", Version: "1.0.0",
		Status: domain.StatusOnline, Config: map[string]string{"TS_PORT": "2222"},
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("CreateSensor: %v", err)
	}
	if _, err := db.InsertEvent(ctx, &domain.Event{
		EventID: "evt-1", NodeID: "node-1", SensorID: "sensor-1",
		Trigger: "tcp_connection", Severity: domain.SeverityHigh,
		Source: "198.51.100.10:54321", SourceIP: "198.51.100.10", SourceKind: domain.SourceKindIP,
		OccurredAt: now, ReceivedAt: now,
		Details: json.RawMessage(`{"port":2222}`),
	}); err != nil {
		t.Fatalf("InsertEvent: %v", err)
	}
	if err := db.InsertHoneytoken(ctx, ported.Honeytoken{
		ID: "ht-1", Username: "svc_backup0001", Secret: "DummySecret12345!",
		PlantedNodeID: "node-1", PlantedSensorID: "sensor-1", Status: "active", CreatedAt: now,
	}); err != nil {
		t.Fatalf("InsertHoneytoken: %v", err)
	}
	if err := db.InsertBeacon(ctx, ported.Beacon{
		ID: "bc-1", Token: "tok1234567890", Type: "dns", Name: "corp-canary",
		Domain: "canary.example.invalid", CreatedAt: now,
	}); err != nil {
		t.Fatalf("InsertBeacon: %v", err)
	}
	if err := db.CreateSession(ctx, store.Session{
		TokenHash: []byte("sess-hash-1"), UserID: store.BootstrapUserID,
		CreatedAt: now, LastSeenAt: now,
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	return &testFixture{dir: dir, dbPath: dbPath, kekFile: kekFile, kek: kek}
}

func assertRestoredDataMatches(t *testing.T, dbPath, kekFile string) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, dbPath, store.Options{})
	if err != nil {
		t.Fatalf("store.Open restored: %v", err)
	}
	defer db.Close()
	if err := db.EnableEncryption(ctx, seal.FileProvider{Path: kekFile}, nil); err != nil {
		t.Fatalf("EnableEncryption restored: %v", err)
	}

	tok, ok, err := db.Setting(ctx, "siem_token")
	if err != nil || !ok || tok != "dummy-siem-token-12345" {
		t.Fatalf("siem_token = (%q, %v, %v), want dummy-siem-token-12345", tok, ok, err)
	}
	wh, ok, err := db.Setting(ctx, "webhook_url")
	if err != nil || !ok || wh != "https://example.invalid/webhook/test" {
		t.Fatalf("webhook_url = (%q, %v, %v)", wh, ok, err)
	}
	nodes, err := db.Nodes(ctx)
	if err != nil || len(nodes) != 1 || nodes[0].ID != "node-1" {
		t.Fatalf("nodes = (%+v, %v)", nodes, err)
	}
	sensors, err := db.Sensors(ctx, "node-1")
	if err != nil || len(sensors) != 1 || sensors[0].ID != "sensor-1" {
		t.Fatalf("sensors = (%+v, %v)", sensors, err)
	}
	evts, err := db.Events(ctx, store.EventFilter{Limit: 10})
	if err != nil || len(evts) != 1 || evts[0].EventID != "evt-1" {
		t.Fatalf("events = (%+v, %v)", evts, err)
	}
	hts, err := db.ListHoneytokens(ctx)
	if err != nil || len(hts) != 1 || hts[0].Secret != "DummySecret12345!" {
		t.Fatalf("honeytokens = (%+v, %v)", hts, err)
	}
	bcs, err := db.ListBeacons(ctx)
	if err != nil || len(bcs) != 1 || bcs[0].ID != "bc-1" {
		t.Fatalf("beacons = (%+v, %v)", bcs, err)
	}

	// All sessions must be invalidated on restore.
	if s, err := db.SessionByHash(ctx, []byte("sess-hash-1")); !errors.Is(err, domain.ErrNotFound) || s != nil {
		t.Fatalf("expected session sess-hash-1 to be invalidated, got (%+v, %v)", s, err)
	}

	// system.restore_cli audit record must be queued for next start.
	audits, err := db.TakeCLIAudits(ctx)
	if err != nil {
		t.Fatalf("TakeCLIAudits: %v", err)
	}
	found := false
	for _, a := range audits {
		if a.Action == RestoreAuditAction {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected %q in cli_audit queue, got %+v", RestoreAuditAction, audits)
	}
}

func TestBackupVerifyRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	fx := newSealedTestDB(t)
	backupDir := filepath.Join(t.TempDir(), "snap1")

	m, err := Backup(ctx, BackupOptions{
		DBPath:     fx.dbPath,
		OutDir:     backupDir,
		KEKFile:    fx.kekFile,
		HubVersion: "3.0.0-test",
	})
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if m.SchemaVersion != store.SchemaVersion() {
		t.Fatalf("schema_version = %d, want %d", m.SchemaVersion, store.SchemaVersion())
	}
	if m.KEKFingerprint != seal.Fingerprint(fx.kek) {
		t.Fatalf("kek_fingerprint = %q, want %q", m.KEKFingerprint, seal.Fingerprint(fx.kek))
	}
	if m.Encrypted || m.File != PlainDBFile {
		t.Fatalf("unexpected manifest encryption fields: %+v", m)
	}

	// Verify with KEK.
	vr, err := Verify(ctx, VerifyOptions{
		FromDir:     backupDir,
		KEKProvider: seal.FileProvider{Path: fx.kekFile},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !vr.FileVerified || !vr.DBVerified || !vr.KEKVerified {
		t.Fatalf("Verify flags = %+v, want all true", vr)
	}

	// Wipe original DB and restore from scratch.
	_ = os.Remove(fx.dbPath)
	_ = os.Remove(fx.dbPath + "-wal")
	_ = os.Remove(fx.dbPath + "-shm")

	rr, err := Restore(ctx, RestoreOptions{
		FromDir:     backupDir,
		DBPath:      fx.dbPath,
		KEKProvider: seal.FileProvider{Path: fx.kekFile},
	})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if rr.PreRestorePath != "" {
		t.Fatalf("expected empty PreRestorePath on wiped target, got %q", rr.PreRestorePath)
	}
	assertRestoredDataMatches(t, fx.dbPath, fx.kekFile)
}

func TestRestorePreservesPreRestoreCopy(t *testing.T) {
	ctx := context.Background()
	fx := newSealedTestDB(t)
	backupDir := filepath.Join(t.TempDir(), "snap")

	if _, err := Backup(ctx, BackupOptions{
		DBPath:     fx.dbPath,
		OutDir:     backupDir,
		KEKFile:    fx.kekFile,
		HubVersion: "3.0.0-test",
	}); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	// Mutate live DB after backup so we can confirm .pre-restore kept the pre-restore state.
	db, err := store.Open(ctx, fx.dbPath, store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := db.EnableEncryption(ctx, seal.FileProvider{Path: fx.kekFile}, nil); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	if err := db.CreateNode(ctx, &domain.Node{
		ID: "node-after-backup", Alias: "new-host", KeyHash: []byte("hash-new"),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	db.Close()

	rr, err := Restore(ctx, RestoreOptions{
		FromDir:     backupDir,
		DBPath:      fx.dbPath,
		KEKProvider: seal.FileProvider{Path: fx.kekFile},
	})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	wantPre := fx.dbPath + PreRestoreSuffix
	if rr.PreRestorePath != wantPre {
		t.Fatalf("PreRestorePath = %q, want %q", rr.PreRestorePath, wantPre)
	}
	if _, err := os.Stat(wantPre); err != nil {
		t.Fatalf("expected .pre-restore file at %s: %v", wantPre, err)
	}

	// Live DB has the restored state (1 node).
	assertRestoredDataMatches(t, fx.dbPath, fx.kekFile)

	// .pre-restore has the pre-restore state (2 nodes).
	oldDB, err := store.Open(ctx, wantPre, store.Options{})
	if err != nil {
		t.Fatalf("open .pre-restore: %v", err)
	}
	defer oldDB.Close()
	oldNodes, err := oldDB.Nodes(ctx)
	if err != nil || len(oldNodes) != 2 {
		t.Fatalf("expected 2 nodes in .pre-restore, got %d (%v)", len(oldNodes), err)
	}
}

func TestEncryptedBackupVerifyRestoreWithAge(t *testing.T) {
	ctx := context.Background()
	fx := newSealedTestDB(t)

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}
	wrongID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity wrong: %v", err)
	}
	idFile := filepath.Join(t.TempDir(), "backup.agekey")
	if err := os.WriteFile(idFile, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	wrongIDFile := filepath.Join(t.TempDir(), "wrong.agekey")
	if err := os.WriteFile(wrongIDFile, []byte(wrongID.String()+"\n"), 0o600); err != nil {
		t.Fatalf("write wrong identity: %v", err)
	}

	backupDir := filepath.Join(t.TempDir(), "enc-snap")
	m, err := Backup(ctx, BackupOptions{
		DBPath:     fx.dbPath,
		OutDir:     backupDir,
		KEKFile:    fx.kekFile,
		EncryptTo:  []string{id.Recipient().String()},
		HubVersion: "3.0.0-test",
	})
	if err != nil {
		t.Fatalf("Backup --encrypt-to: %v", err)
	}
	if !m.Encrypted || m.Encryption != "age" || m.File != AgeDBFile {
		t.Fatalf("unexpected encrypted manifest: %+v", m)
	}
	// Plaintext hub.db must NOT exist in backupDir.
	if _, err := os.Stat(filepath.Join(backupDir, PlainDBFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("plaintext hub.db must not exist in encrypted backup dir")
	}
	encBytes, err := os.ReadFile(filepath.Join(backupDir, AgeDBFile))
	if err != nil {
		t.Fatalf("read hub.db.age: %v", err)
	}
	if bytes.Contains(encBytes, []byte(sqliteHeader)) {
		t.Fatalf("encrypted archive contains plaintext SQLite header")
	}

	// Verify WITHOUT identity: checks ciphertext SHA-256 only.
	vrNoID, err := Verify(ctx, VerifyOptions{FromDir: backupDir})
	if err != nil {
		t.Fatalf("Verify without identity: %v", err)
	}
	if !vrNoID.FileVerified || vrNoID.Decrypted || vrNoID.DBVerified {
		t.Fatalf("unexpected Verify without identity: %+v", vrNoID)
	}

	// Verify WITH wrong identity must fail.
	if _, err := Verify(ctx, VerifyOptions{
		FromDir:      backupDir,
		IdentityFile: wrongIDFile,
		KEKProvider:  seal.FileProvider{Path: fx.kekFile},
	}); err == nil {
		t.Fatalf("expected Verify with wrong age identity to fail")
	}

	// Verify WITH right identity and KEK must verify everything.
	vrFull, err := Verify(ctx, VerifyOptions{
		FromDir:      backupDir,
		IdentityFile: idFile,
		KEKProvider:  seal.FileProvider{Path: fx.kekFile},
	})
	if err != nil {
		t.Fatalf("Verify with identity: %v", err)
	}
	if !vrFull.FileVerified || !vrFull.Decrypted || !vrFull.DBVerified || !vrFull.KEKVerified {
		t.Fatalf("unexpected Verify with identity: %+v", vrFull)
	}

	// Restore WITHOUT identity must fail with ErrIdentityNeeded.
	if _, err := Restore(ctx, RestoreOptions{
		FromDir:     backupDir,
		DBPath:      filepath.Join(t.TempDir(), "restored.db"),
		KEKProvider: seal.FileProvider{Path: fx.kekFile},
	}); !errors.Is(err, ErrIdentityNeeded) {
		t.Fatalf("Restore without identity = %v, want ErrIdentityNeeded", err)
	}

	// Restore WITH right identity succeeds and data matches.
	restoredPath := filepath.Join(t.TempDir(), "restored.db")
	if _, err := Restore(ctx, RestoreOptions{
		FromDir:      backupDir,
		DBPath:       restoredPath,
		IdentityFile: idFile,
		KEKProvider:  seal.FileProvider{Path: fx.kekFile},
	}); err != nil {
		t.Fatalf("Restore encrypted: %v", err)
	}
	assertRestoredDataMatches(t, restoredPath, fx.kekFile)
}

func TestWrongKEKAndMissingKEKRejected(t *testing.T) {
	ctx := context.Background()
	fx := newSealedTestDB(t)
	backupDir := filepath.Join(t.TempDir(), "snap")
	if _, err := Backup(ctx, BackupOptions{
		DBPath: fx.dbPath, OutDir: backupDir, KEKFile: fx.kekFile, HubVersion: "3.0.0-test",
	}); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	wrongKEKHex, _ := seal.GenerateKEK()
	wrongKEK, _ := seal.ParseKEK([]byte(wrongKEKHex))
	wrongProvider := seal.StaticProvider{Key: wrongKEK}

	if _, err := Verify(ctx, VerifyOptions{FromDir: backupDir, KEKProvider: wrongProvider}); !errors.Is(err, seal.ErrWrongKEK) {
		t.Fatalf("Verify with wrong KEK = %v, want ErrWrongKEK", err)
	}

	// Live DB must be untouched on wrong-KEK restore failure.
	origBytes, err := os.ReadFile(fx.dbPath)
	if err != nil {
		t.Fatalf("read orig db: %v", err)
	}
	if _, err := Restore(ctx, RestoreOptions{
		FromDir: backupDir, DBPath: fx.dbPath, KEKProvider: wrongProvider,
	}); !errors.Is(err, seal.ErrWrongKEK) {
		t.Fatalf("Restore with wrong KEK = %v, want ErrWrongKEK", err)
	}
	if _, err := Restore(ctx, RestoreOptions{
		FromDir: backupDir, DBPath: fx.dbPath, KEKProvider: nil,
	}); !errors.Is(err, store.ErrSealedNoKey) {
		t.Fatalf("Restore with missing KEK = %v, want ErrSealedNoKey", err)
	}
	afterBytes, err := os.ReadFile(fx.dbPath)
	if err != nil {
		t.Fatalf("read after db: %v", err)
	}
	if !bytes.Equal(origBytes, afterBytes) {
		t.Fatalf("live DB was modified after failed restore")
	}
}

func TestCorruptedArchiveAndPathTraversalRejected(t *testing.T) {
	ctx := context.Background()
	fx := newSealedTestDB(t)

	t.Run("bit-flipped hub.db", func(t *testing.T) {
		backupDir := filepath.Join(t.TempDir(), "snap")
		if _, err := Backup(ctx, BackupOptions{
			DBPath: fx.dbPath, OutDir: backupDir, KEKFile: fx.kekFile, HubVersion: "3.0.0-test",
		}); err != nil {
			t.Fatalf("Backup: %v", err)
		}
		p := filepath.Join(backupDir, PlainDBFile)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		b[len(b)/2] ^= 0xff
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(ctx, VerifyOptions{FromDir: backupDir}); !errors.Is(err, ErrChecksumMismatch) {
			t.Fatalf("Verify corrupted db = %v, want ErrChecksumMismatch", err)
		}
		if _, err := Restore(ctx, RestoreOptions{
			FromDir: backupDir, DBPath: filepath.Join(t.TempDir(), "out.db"),
			KEKProvider: seal.FileProvider{Path: fx.kekFile},
		}); !errors.Is(err, ErrChecksumMismatch) {
			t.Fatalf("Restore corrupted db = %v, want ErrChecksumMismatch", err)
		}
	})

	t.Run("path traversal in manifest", func(t *testing.T) {
		backupDir := filepath.Join(t.TempDir(), "snap")
		if _, err := Backup(ctx, BackupOptions{
			DBPath: fx.dbPath, OutDir: backupDir, KEKFile: fx.kekFile, HubVersion: "3.0.0-test",
		}); err != nil {
			t.Fatalf("Backup: %v", err)
		}
		mp := filepath.Join(backupDir, ManifestFile)
		m, err := readManifest(mp)
		if err != nil {
			t.Fatal(err)
		}
		m.File = "../escape.db"
		if err := writeManifestAtomic(mp, m); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(ctx, VerifyOptions{FromDir: backupDir}); !errors.Is(err, ErrBadManifest) {
			t.Fatalf("Verify path traversal = %v, want ErrBadManifest", err)
		}
	})

	t.Run("non-SQLite payload with matching SHA-256", func(t *testing.T) {
		backupDir := filepath.Join(t.TempDir(), "snap")
		if err := os.MkdirAll(backupDir, 0o700); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(backupDir, PlainDBFile)
		if err := os.WriteFile(p, []byte("not a sqlite database at all"), 0o600); err != nil {
			t.Fatal(err)
		}
		h, _ := sha256File(p)
		m := &Manifest{
			FormatVersion: FormatVersion,
			File:          PlainDBFile,
			SchemaVersion: store.SchemaVersion(),
			DBSHA256:      h,
			FileSHA256:    h,
			CreatedAt:     time.Now().UTC().Format(time.RFC3339),
			HubVersion:    "3.0.0-test",
		}
		if err := writeManifestAtomic(filepath.Join(backupDir, ManifestFile), m); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(ctx, VerifyOptions{FromDir: backupDir}); !errors.Is(err, ErrCorruptDB) {
			t.Fatalf("Verify non-SQLite = %v, want ErrCorruptDB", err)
		}
	})

	t.Run("newer schema version refused", func(t *testing.T) {
		backupDir := filepath.Join(t.TempDir(), "snap")
		if _, err := Backup(ctx, BackupOptions{
			DBPath: fx.dbPath, OutDir: backupDir, KEKFile: fx.kekFile, HubVersion: "3.0.0-test",
		}); err != nil {
			t.Fatalf("Backup: %v", err)
		}
		mp := filepath.Join(backupDir, ManifestFile)
		raw, _ := os.ReadFile(mp)
		var m Manifest
		_ = json.Unmarshal(raw, &m)
		m.SchemaVersion = store.SchemaVersion() + 1
		_ = writeManifestAtomic(mp, &m)

		if _, err := Verify(ctx, VerifyOptions{FromDir: backupDir}); !errors.Is(err, store.ErrSchemaTooNew) {
			t.Fatalf("Verify newer schema = %v, want ErrSchemaTooNew", err)
		}
		if _, err := Restore(ctx, RestoreOptions{
			FromDir: backupDir, DBPath: filepath.Join(t.TempDir(), "out.db"),
			KEKProvider: seal.FileProvider{Path: fx.kekFile},
		}); !errors.Is(err, store.ErrSchemaTooNew) {
			t.Fatalf("Restore newer schema = %v, want ErrSchemaTooNew", err)
		}
	})
}

func TestSafetyGuardsKEKDirAndRunningLock(t *testing.T) {
	ctx := context.Background()
	fx := newSealedTestDB(t)

	// Refuse if KEKFile is inside OutDir.
	if _, err := Backup(ctx, BackupOptions{
		DBPath:     fx.dbPath,
		OutDir:     filepath.Dir(fx.kekFile),
		KEKFile:    fx.kekFile,
		HubVersion: "3.0.0-test",
	}); !errors.Is(err, ErrKEKInBackupDir) {
		t.Fatalf("Backup into KEK dir = %v, want ErrKEKInBackupDir", err)
	}

	// Hold DB lock (simulating running Hub): online Backup MUST succeed, offline Restore MUST fail.
	lock, err := AcquireDBLock(fx.dbPath)
	if err != nil {
		t.Fatalf("AcquireDBLock: %v", err)
	}
	defer lock.Close()

	backupDir := filepath.Join(t.TempDir(), "online-snap")
	if _, err := Backup(ctx, BackupOptions{
		DBPath: fx.dbPath, OutDir: backupDir, KEKFile: fx.kekFile, HubVersion: "3.0.0-test",
	}); err != nil {
		t.Fatalf("online Backup while locked failed: %v", err)
	}

	// Second backup into same non-empty OutDir must be refused.
	if _, err := Backup(ctx, BackupOptions{
		DBPath: fx.dbPath, OutDir: backupDir, KEKFile: fx.kekFile, HubVersion: "3.0.0-test",
	}); !errors.Is(err, ErrOutputNotEmpty) {
		t.Fatalf("Backup into non-empty dir = %v, want ErrOutputNotEmpty", err)
	}

	// Restore while lock is held must fail with ErrHubRunning.
	if _, err := Restore(ctx, RestoreOptions{
		FromDir: backupDir, DBPath: fx.dbPath, KEKProvider: seal.FileProvider{Path: fx.kekFile},
	}); !errors.Is(err, ErrHubRunning) {
		t.Fatalf("Restore while locked = %v, want ErrHubRunning", err)
	}
}
