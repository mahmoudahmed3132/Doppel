// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package envcompat

import "testing"

func TestDoppelWinsAndLegacyWarnsOnce(t *testing.T) {
	env := map[string]string{"TS_A": "old", "DOPPEL_A": "new", "TS_B": "legacy", "TS_C": "", "PLAIN": "x"}
	var warnings []string
	g := Wrap(func(k string) string { return env[k] }, func(m string) { warnings = append(warnings, m) })

	if g("TS_A") != "new" {
		t.Fatal("DOPPEL_A must win over TS_A")
	}
	if len(warnings) != 0 {
		t.Fatalf("no warning when DOPPEL_* is used: %v", warnings)
	}
	if g("TS_B") != "legacy" || g("TS_B") != "legacy" {
		t.Fatal("TS_B must still be honoured")
	}
	if len(warnings) != 1 {
		t.Fatalf("want exactly one warning for TS_B, got %v", warnings)
	}
	if g("TS_C") != "" || len(warnings) != 1 {
		t.Fatal("empty legacy value neither returns nor warns")
	}
	if g("PLAIN") != "x" {
		t.Fatal("non-TS_ names pass through")
	}
	for _, w := range warnings {
		if contains(w, "legacy") {
			t.Fatalf("warning leaks the value: %q", w)
		}
	}
}

func TestLookup(t *testing.T) {
	env := map[string]string{"TS_A": "o", "DOPPEL_A": "n", "TS_B": "l"}
	g := func(k string) string { return env[k] }
	if v, n := Lookup(g, "TS_A"); v != "n" || n != "DOPPEL_A" {
		t.Fatalf("got %q %q", v, n)
	}
	if v, n := Lookup(g, "TS_B"); v != "l" || n != "TS_B" {
		t.Fatalf("got %q %q", v, n)
	}
	if v, n := Lookup(g, "TS_Z"); v != "" || n != "" {
		t.Fatal("unset must report empty")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
