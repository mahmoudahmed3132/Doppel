// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package config

import (
	"strings"
	"testing"
)

func TestCompatGetenv(t *testing.T) {
	env := map[string]string{"TS_NODE_KEY": "legacy-key", "TS_WORK_DIR": "/old", "DOPPEL_WORK_DIR": "/new"}
	var out strings.Builder
	g := CompatGetenv(func(k string) string { return env[k] }, &out)
	if g("TS_WORK_DIR") != "/new" {
		t.Fatal("DOPPEL_WORK_DIR must win")
	}
	if out.Len() != 0 {
		t.Fatalf("unexpected warning %q", out.String())
	}
	if g("TS_NODE_KEY") != "legacy-key" || g("TS_NODE_KEY") != "legacy-key" {
		t.Fatal("legacy value must be honoured")
	}
	if n := strings.Count(out.String(), "TS_NODE_KEY is deprecated"); n != 1 {
		t.Fatalf("want one warning, got %d: %q", n, out.String())
	}
	if strings.Contains(out.String(), "legacy-key") {
		t.Fatal("warning must not contain the secret value")
	}
}
