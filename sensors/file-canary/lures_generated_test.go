// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The real generator behind LureGenerator, through CreateLures: every lure
// type embeds the honeytoken, uses loopback hosts only, and never names the
// product.
func TestGeneratedLuresThroughCreateLures(t *testing.T) {
	dir := t.TempDir()
	names := []string{".env", "wp-config.php", ".pgpass", "dump.sql.bak", "corp-vpn.conf", "notes.txt"}
	var paths []string
	for _, n := range names {
		paths = append(paths, filepath.Join(dir, n))
	}
	var log bytes.Buffer
	created, err := CreateLures(paths, ht, generatedLures{}, &log)
	if err != nil || len(created) != len(names) {
		t.Fatalf("%v %v", created, err)
	}
	host := regexp.MustCompile(`(?i)\b(host|endpoint)\s*[=:,(]\s*'?([a-z0-9.:-]+)`)
	for _, p := range paths {
		b, _ := os.ReadFile(p)
		s := string(b)
		if !strings.Contains(s, ht.Username) || !strings.Contains(s, ht.Secret) {
			t.Errorf("%s: honeytoken missing:\n%s", filepath.Base(p), s)
		}
		low := strings.ToLower(s)
		if strings.Contains(low, "truesignal") || strings.Contains(low, "doppel") || strings.Contains(low, "honeytoken") {
			t.Errorf("%s names the product", filepath.Base(p))
		}
		for _, m := range host.FindAllStringSubmatch(s, -1) {
			if h := m[2]; !strings.HasPrefix(h, "127.0.0.1") && h != "localhost" {
				t.Errorf("%s: non-loopback host %q", filepath.Base(p), h)
			}
		}
	}
	env, _ := os.ReadFile(paths[0])
	if !regexp.MustCompile(`AWS_ACCESS_KEY_ID=AKIA[A-Z2-7]{16}\n`).Match(env) {
		t.Errorf("AWS key id shape: %s", env)
	}
	if _, _, err := (generatedLures{}).Content("/x/.env", Honeytoken{}); err == nil {
		t.Fatal("lure without a honeytoken generated")
	}
	if got := (generatedLures{}).Category("/srv/app/.env"); got != "config" {
		t.Fatalf("category %q", got)
	}
}
