// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package envcompat implements the DOPPEL_* / TS_* environment-variable
// migration (F-004): every TS_<NAME> lookup first consults DOPPEL_<NAME>,
// which wins when set and non-empty; a value that is only available under the
// legacy TS_ name is still honoured and a deprecation warning naming the
// variable (never its value) is emitted once. The TS_ names stay supported for
// one major version.
package envcompat

import (
	"os"
	"strings"
	"sync"
)

const (
	legacyPrefix = "TS_"
	newPrefix    = "DOPPEL_"
)

// Wrap returns a getenv that prefers DOPPEL_<NAME> over TS_<NAME>. warn is
// called once per legacy variable that was actually used (nil to stay silent).
// Names that do not start with TS_ pass through unchanged.
func Wrap(getenv func(string) string, warn func(msg string)) func(string) string {
	var mu sync.Mutex
	warned := map[string]bool{}
	return func(key string) string {
		if !strings.HasPrefix(key, legacyPrefix) {
			return getenv(key)
		}
		nk := newPrefix + strings.TrimPrefix(key, legacyPrefix)
		if v := getenv(nk); v != "" {
			return v
		}
		v := getenv(key)
		if v != "" && warn != nil {
			mu.Lock()
			first := !warned[key]
			warned[key] = true
			mu.Unlock()
			if first {
				warn(key + " is deprecated; use " + nk + " (TS_* is accepted for one major version, DOPPEL_* wins when both are set)")
			}
		}
		return v
	}
}

// OS is Wrap over os.Getenv.
func OS(warn func(msg string)) func(string) string { return Wrap(os.Getenv, warn) }

// Lookup reports the value of key (a TS_ name) and which name supplied it
// ("" when unset), for diagnostics that must name the real variable.
func Lookup(getenv func(string) string, key string) (value, name string) {
	if strings.HasPrefix(key, legacyPrefix) {
		nk := newPrefix + strings.TrimPrefix(key, legacyPrefix)
		if v := getenv(nk); v != "" {
			return v, nk
		}
	}
	if v := getenv(key); v != "" {
		return v, key
	}
	return "", ""
}
