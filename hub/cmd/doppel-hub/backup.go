// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"strings"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/backup"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/config"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/seal"
)

const envBackupAgeIdentity = "TS_BACKUP_AGE_IDENTITY"

type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }
func (s *stringSliceFlag) Set(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return errors.New("value must not be empty")
	}
	*s = append(*s, v)
	return nil
}

const backupScheduleDoc = `# Doppel Hub scheduled backup examples (see docs/operations.md and deploy/backup/)
#
# Important:
# - Never store TS_KEK_FILE inside the backup directory; back up the KEK separately.
# - Use --encrypt-to <age-recipient> so off-site snapshots are encrypted at rest.
# - Verify backups regularly with: doppel-hub verify --from <dir> --identity <age-key>
#
# 1) systemd timer (deploy/backup/doppel-backup.service + deploy/backup/doppel-backup.timer):
#    ExecStart=/usr/local/bin/doppel-hub backup \
#      --out /var/backups/doppel/snap-%Y%m%dT%H%M%SZ \
#      --encrypt-to age1...
#    Schedule: OnCalendar=daily (RandomizedDelaySec=15m, Persistent=true)
#
# 2) Kubernetes CronJob (deploy/backup/cronjob.yaml):
#    schedule: "0 2 * * *"
#    command: ["doppel-hub", "backup", "--out", "/backups/$(POD_NAME)", "--encrypt-to", "$(AGE_RECIPIENT)"]
#    Mount the Hub data PVC and a separate backup PVC (never mount the KEK Secret into the backup destination).
`

func backupCmd(log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	var (
		outDir     string
		schedule   bool
		recipients stringSliceFlag
	)
	fs.StringVar(&outDir, "out", "", "destination directory for the backup snapshot")
	fs.Var(&recipients, "encrypt-to", "age recipient public key to encrypt the snapshot at rest (repeatable)")
	fs.BoolVar(&schedule, "schedule", false, "print systemd timer and Kubernetes CronJob scheduling examples")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: doppel-hub backup --out <dir> [--encrypt-to <age-recipient>] | --schedule")
	}
	if schedule {
		_, err := os.Stdout.WriteString(backupScheduleDoc)
		return err
	}
	if outDir == "" {
		return errors.New("usage: doppel-hub backup --out <dir> [--encrypt-to <age-recipient>] | --schedule")
	}

	cfg, err := config.Load(hubEnv(log))
	if err != nil {
		return err
	}
	m, err := backup.Backup(context.Background(), backup.BackupOptions{
		DBPath:     cfg.DBPath,
		OutDir:     outDir,
		KEKFile:    cfg.KEKFile,
		EncryptTo:  recipients,
		HubVersion: Version,
	})
	if err != nil {
		return err
	}
	log.Info("backup completed",
		"out", outDir,
		"file", m.File,
		"encrypted", m.Encrypted,
		"schema_version", m.SchemaVersion,
		"db_sha256", m.DBSHA256,
		"file_sha256", m.FileSHA256,
		"kek_fingerprint", m.KEKFingerprint,
	)
	return nil
}

func verifyCmd(log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	var (
		fromDir      string
		identityFile string
		kekFile      string
	)
	fs.StringVar(&fromDir, "from", "", "backup directory to verify")
	fs.StringVar(&identityFile, "identity", "", "age identity key file for decrypting hub.db.age")
	fs.StringVar(&kekFile, "kek-file", "", "KEK file to verify DEK unwrap (defaults to TS_KEK_FILE)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || fromDir == "" {
		return errors.New("usage: doppel-hub verify --from <dir> [--identity <age-key-file>] [--kek-file <path>]")
	}

	getenv := hubEnv(log)
	cfg, err := config.Load(getenv)
	if err != nil {
		return err
	}
	if identityFile == "" {
		identityFile = strings.TrimSpace(getenv(envBackupAgeIdentity))
	}
	if kekFile == "" {
		kekFile = cfg.KEKFile
	}
	var provider seal.KeyProvider
	if kekFile != "" {
		provider = seal.FileProvider{Path: kekFile}
	}

	res, err := backup.Verify(context.Background(), backup.VerifyOptions{
		FromDir:      fromDir,
		IdentityFile: identityFile,
		KEKProvider:  provider,
	})
	if err != nil {
		return err
	}
	log.Info("backup verified",
		"from", fromDir,
		"file", res.Manifest.File,
		"encrypted", res.Manifest.Encrypted,
		"decrypted", res.Decrypted,
		"db_verified", res.DBVerified,
		"kek_verified", res.KEKVerified,
		"schema_version", res.Manifest.SchemaVersion,
		"kek_fingerprint", res.Manifest.KEKFingerprint,
	)
	if res.Manifest.Encrypted && !res.Decrypted {
		log.Warn("archive is age-encrypted; ciphertext checksum verified, pass --identity <key-file> to also verify SQLite integrity and KEK unwrap")
	}
	return nil
}

func restoreCmd(log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	var (
		fromDir      string
		identityFile string
		kekFile      string
	)
	fs.StringVar(&fromDir, "from", "", "backup directory to restore from")
	fs.StringVar(&identityFile, "identity", "", "age identity key file for decrypting hub.db.age")
	fs.StringVar(&kekFile, "kek-file", "", "KEK file to verify DEK unwrap before swapping (defaults to TS_KEK_FILE)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || fromDir == "" {
		return errors.New("usage: doppel-hub restore --from <dir> [--identity <age-key-file>] [--kek-file <path>]")
	}

	getenv := hubEnv(log)
	cfg, err := config.Load(getenv)
	if err != nil {
		return err
	}
	if identityFile == "" {
		identityFile = strings.TrimSpace(getenv(envBackupAgeIdentity))
	}
	if kekFile == "" {
		kekFile = cfg.KEKFile
	}
	var provider seal.KeyProvider
	if kekFile != "" {
		provider = seal.FileProvider{Path: kekFile}
	}

	res, err := backup.Restore(context.Background(), backup.RestoreOptions{
		FromDir:      fromDir,
		DBPath:       cfg.DBPath,
		IdentityFile: identityFile,
		KEKProvider:  provider,
	})
	if err != nil {
		return err
	}
	log.Warn("database restored; all sessions invalidated; nodes linked after the backup are orphaned and must be re-linked; an audit record (system.restore_cli) will be emitted on next Hub start",
		"from", fromDir,
		"db", cfg.DBPath,
		"pre_restore", res.PreRestorePath,
		"schema_version", res.Manifest.SchemaVersion,
		"kek_fingerprint", res.Manifest.KEKFingerprint,
	)
	return nil
}
