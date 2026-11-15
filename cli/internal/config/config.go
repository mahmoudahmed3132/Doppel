// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package config holds the node agent's local state: the config file with
// the Hub endpoint, node id and node key (0600), and the working directory
// with the rendered compose file and its backup (0600).
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
)

// Default locations (§8). TS_CONFIG_FILE and TS_WORK_DIR override them,
// mainly for tests.
const (
	DefaultConfigFile = "/etc/doppel/config.json"
	DefaultWorkDir    = "/opt/doppel"
	// Legacy paths (before the Doppel rename). For one release a node
	// linked under them keeps using them (Q66); new links use the defaults.
	LegacyConfigFile = "/etc/truesignal/config.json"
	LegacyWorkDir    = "/opt/truesignal"
	ComposeFile      = "compose.json"
	BackupFile       = "compose.json.bak"
	LockFile         = ".apply.lock"
)

// Paths locates the agent's files.
type Paths struct {
	ConfigFile string
	WorkDir    string
}

// PathsFromEnv returns the default paths with environment overrides.
func PathsFromEnv(getenv func(string) string) Paths {
	return pathsFromEnv(getenv, exists)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func pathsFromEnv(getenv func(string) string, exists func(string) bool) Paths {
	p := Paths{ConfigFile: DefaultConfigFile, WorkDir: DefaultWorkDir}
	if !exists(DefaultConfigFile) && exists(LegacyConfigFile) {
		p = Paths{ConfigFile: LegacyConfigFile, WorkDir: LegacyWorkDir}
	}
	if v := getenv("TS_CONFIG_FILE"); v != "" {
		p.ConfigFile = v
	}
	if v := getenv("TS_WORK_DIR"); v != "" {
		p.WorkDir = v
	}
	return p
}

// Compose returns the path of the active compose file.
func (p Paths) Compose() string { return filepath.Join(p.WorkDir, ComposeFile) }

// Backup returns the path of the previous compose file.
func (p Paths) Backup() string { return filepath.Join(p.WorkDir, BackupFile) }

// Lock returns the path of the apply lock.
func (p Paths) Lock() string { return filepath.Join(p.WorkDir, LockFile) }

// Config is the persisted node identity. NodeKey is secret.
type Config struct {
	HubEndpoint string `json:"hub_endpoint"`
	NodeID      string `json:"node_id"`
	NodeKey     string `json:"node_key"`
}

var (
	keyRE  = regexp.MustCompile(`^tsk_[0-9a-f]{64}$`)
	nodeRE = regexp.MustCompile(`^node-[0-9a-f]{8}$`)
)

// ValidKey reports whether k has the node key format.
func ValidKey(k string) bool { return keyRE.MatchString(k) }

// ErrNotLinked means `doppel link` has not run yet.
var ErrNotLinked = errors.New("this node is not linked; run `doppel link <hub-url>` first")

// Load reads and validates the config file. It refuses a file readable by
// group or others, since it contains the node key.
func Load(p Paths) (*Config, error) {
	st, err := os.Stat(p.ConfigFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotLinked
	}
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is accessible by other users (mode %v); run: chmod 600 %s", p.ConfigFile, st.Mode().Perm(), p.ConfigFile)
	}
	b, err := os.ReadFile(p.ConfigFile)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s is corrupt: %w", p.ConfigFile, err)
	}
	if c.HubEndpoint == "" || !nodeRE.MatchString(c.NodeID) || !ValidKey(c.NodeKey) {
		return nil, fmt.Errorf("%s is incomplete; run `doppel link` again", p.ConfigFile)
	}
	return &c, nil
}

// Save writes the config file atomically with mode 0600 (directory 0700).
func Save(p Paths, c *Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return WriteSecret(p.ConfigFile, append(b, '\n'))
}

// WriteSecret writes data atomically (temp file + rename) with mode 0600,
// creating the parent directory with mode 0700.
func WriteSecret(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
