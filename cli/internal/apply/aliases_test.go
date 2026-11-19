// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package apply

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Exercises the macOS alias handling on every platform with a fake alias
// (macOS: /var -> /private/var).
func TestHostPathSystemAliases(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	target := filepath.Join(root, "private", "var")
	alias := filepath.Join(root, "var")
	if err := os.MkdirAll(filepath.Join(target, "lures"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(root, "other")
	os.Symlink(filepath.Join(target, "lures"), other)
	aliases := map[string]string{alias: target}

	if err := checkHostPathWith(aliases, filepath.Join(alias, "lures")); err != nil {
		t.Fatalf("path under a system alias refused: %v", err)
	}
	if err := checkHostPathWith(aliases, filepath.Join(target, "lures")); err != nil {
		t.Fatalf("resolved form refused: %v", err)
	}
	if err := checkHostPathWith(aliases, other); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("non-alias symlink accepted: %v", err)
	}
	if err := checkHostPathWith(nil, filepath.Join(alias, "lures")); err == nil {
		t.Fatal("alias accepted without an alias table (Linux)")
	}

	// The /private form of a forbidden tree is still forbidden.
	if got := realiasPath(darwinAliases, "/private/etc/ssh", false); got != "/etc/ssh" || !forbiddenPath(got) {
		t.Fatalf("got %q", got)
	}
	if got := realiasPath(darwinAliases, "/var/folders/x", true); got != "/private/var/folders/x" {
		t.Fatalf("got %q", got)
	}
	if got := realiasPath(darwinAliases, "/variable", true); got != "/variable" {
		t.Fatalf("prefix matched a sibling: %q", got)
	}
}
