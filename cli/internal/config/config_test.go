// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package config

import "testing"

// New nodes use the Doppel paths; a node linked before the rename keeps its
// legacy paths for one release (Q66); explicit settings always win.
func TestPathsDefaultLegacyAndOverride(t *testing.T) {
	none := func(string) string { return "" }
	only := func(paths ...string) func(string) bool {
		return func(p string) bool {
			for _, x := range paths {
				if p == x {
					return true
				}
			}
			return false
		}
	}
	if p := pathsFromEnv(none, only()); p.ConfigFile != DefaultConfigFile || p.WorkDir != DefaultWorkDir {
		t.Fatalf("fresh node: %+v", p)
	}
	if p := pathsFromEnv(none, only(LegacyConfigFile)); p.ConfigFile != LegacyConfigFile || p.WorkDir != LegacyWorkDir {
		t.Fatalf("legacy node: %+v", p)
	}
	if p := pathsFromEnv(none, only(LegacyConfigFile, DefaultConfigFile)); p.ConfigFile != DefaultConfigFile {
		t.Fatalf("both present: %+v", p)
	}
	env := map[string]string{"TS_CONFIG_FILE": "/x/c.json", "TS_WORK_DIR": "/x/w"}
	if p := pathsFromEnv(func(k string) string { return env[k] }, only(LegacyConfigFile)); p.ConfigFile != "/x/c.json" || p.WorkDir != "/x/w" {
		t.Fatalf("override: %+v", p)
	}
}
