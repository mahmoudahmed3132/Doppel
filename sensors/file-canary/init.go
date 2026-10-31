// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// LurePaths parses TS_LURES: comma-separated absolute, clean paths.
func LurePaths(raw string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return nil, fmt.Errorf("TS_LURES: %q must be an absolute clean path", p)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("TS_LURES is required")
	}
	return out, nil
}

// CreateLures creates every missing lure. Existing files are never
// overwritten (O_EXCL) and symbolic links are never followed (O_NOFOLLOW).
// It returns the paths it created.
func CreateLures(paths []string, ht Honeytoken, gen LureGenerator, log io.Writer) ([]string, error) {
	var created []string
	var errs []error
	for _, p := range paths {
		if st, err := os.Stat(filepath.Dir(p)); err != nil || !st.IsDir() {
			errs = append(errs, fmt.Errorf("%s: parent directory missing", p))
			continue
		}
		content, category, err := gen.Content(p, ht)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: generating content: %w", p, err))
			continue
		}
		fd, err := syscall.Open(p, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o644)
		if errors.Is(err, syscall.EEXIST) {
			fmt.Fprintf(log, "lure %s exists; left untouched\n", p)
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
			continue
		}
		f := os.NewFile(uintptr(fd), p)
		_, werr := f.Write(content)
		serr := f.Sync()
		cerr := f.Close()
		if err := errors.Join(werr, serr, cerr); err != nil {
			os.Remove(p)
			errs = append(errs, fmt.Errorf("%s: writing: %w", p, err))
			continue
		}
		fmt.Fprintf(log, "lure %s created (%s)\n", p, category)
		created = append(created, p)
	}
	return created, errors.Join(errs...)
}

// runInit is the init container: no network, no SDK, exit status only.
func runInit(getenv func(string) string, stderr io.Writer) int {
	paths, err := LurePaths(getenv("TS_LURES"))
	if err != nil {
		fmt.Fprintln(stderr, "file-canary init:", err)
		return 1
	}
	var ht Honeytoken
	if raw := getenv("TS_HONEYTOKEN"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &ht); err != nil {
			fmt.Fprintln(stderr, "file-canary init: TS_HONEYTOKEN is not valid JSON")
			return 1
		}
	}
	if ht.Username == "" || ht.Secret == "" {
		fmt.Fprintln(stderr, "file-canary init: TS_HONEYTOKEN is required (the Hub sets it)")
		return 1
	}
	if _, err := CreateLures(paths, ht, lures, stderr); err != nil {
		fmt.Fprintln(stderr, "file-canary init:", err)
		return 1
	}
	return 0
}
