// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package config

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// CompatGetenv implements the DOPPEL_*/TS_* migration for the CLI (F-004; the
// CLI has no dependency on the SDK module, so this mirrors sdk/go/envcompat).
// DOPPEL_<NAME> wins over TS_<NAME>; a TS_ value that is actually used prints
// one deprecation warning to w (the variable name only, never the value).
func CompatGetenv(getenv func(string) string, w io.Writer) func(string) string {
	var mu sync.Mutex
	warned := map[string]bool{}
	return func(key string) string {
		if !strings.HasPrefix(key, "TS_") {
			return getenv(key)
		}
		nk := "DOPPEL_" + strings.TrimPrefix(key, "TS_")
		if v := getenv(nk); v != "" {
			return v
		}
		v := getenv(key)
		if v != "" && w != nil {
			mu.Lock()
			first := !warned[key]
			warned[key] = true
			mu.Unlock()
			if first {
				fmt.Fprintf(w, "warning: %s is deprecated; use %s (TS_* is accepted for one major version, DOPPEL_* wins)\n", key, nk)
			}
		}
		return v
	}
}

// OSGetenv is CompatGetenv over os.Getenv, warning on stderr.
func OSGetenv() func(string) string { return CompatGetenv(os.Getenv, os.Stderr) }
