// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package seal

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSealRoundTripAndBinding(t *testing.T) {
	dek, _ := NewDEK()
	s, _ := New(dek)
	a, err := s.Seal("settings/siem_token", "hunter2-token")
	if err != nil || !IsSealed(a) || strings.Contains(a, "hunter2") {
		t.Fatalf("seal: %q %v", a, err)
	}
	if b, _ := s.Seal("settings/siem_token", "hunter2-token"); a == b {
		t.Error("two seals of one value are identical (nonce reuse)")
	}
	if got, err := s.Open("settings/siem_token", a); err != nil || got != "hunter2-token" {
		t.Fatalf("open: %q %v", got, err)
	}
	// Bound to its place.
	if _, err := s.Open("settings/webhook_url", a); !errors.Is(err, ErrOpen) {
		t.Errorf("moved ciphertext opened: %v", err)
	}
	// Tampered.
	if _, err := s.Open("settings/siem_token", a[:len(a)-2]+"AA"); !errors.Is(err, ErrOpen) {
		t.Errorf("tampered value opened: %v", err)
	}
	// Other key.
	other, _ := NewDEK()
	o, _ := New(other)
	if _, err := o.Open("settings/siem_token", a); !errors.Is(err, ErrOpen) {
		t.Errorf("wrong key opened: %v", err)
	}
	// Empty stays empty both ways.
	if v, _ := s.Seal("x", ""); v != "" {
		t.Error("empty sealed")
	}
	if v, err := s.Open("x", ""); v != "" || err != nil {
		t.Error("empty opened")
	}
}

func TestStrictRefusesPlaintext(t *testing.T) {
	dek, _ := NewDEK()
	s, _ := New(dek)
	if v, err := s.Open("a", "plain"); v != "plain" || err != nil {
		t.Fatalf("lenient: %q %v", v, err)
	}
	s.SetStrict(true)
	if _, err := s.Open("a", "plain"); !errors.Is(err, ErrNotSealed) {
		t.Errorf("strict accepted plaintext: %v", err)
	}
}

func TestWrapUnwrap(t *testing.T) {
	kek, _ := ParseKEK(bytes.Repeat([]byte{7}, 32))
	dek, _ := NewDEK()
	w, err := Wrap(kek, dek)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unwrap(kek, w)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap: %v", err)
	}
	if _, err := Unwrap(bytes.Repeat([]byte{8}, 32), w); !errors.Is(err, ErrWrongKEK) {
		t.Errorf("wrong kek: %v", err)
	}
	if Fingerprint(kek) == Fingerprint(bytes.Repeat([]byte{8}, 32)) || len(Fingerprint(kek)) != 16 {
		t.Error("fingerprint")
	}
	// A wrapped DEK is not a valid sealed value for a settings AAD.
	s, _ := New(dek)
	if _, err := s.Open("settings/x", w); err == nil {
		t.Error("wrapped dek opened as a value")
	}
}

func TestKEKFiles(t *testing.T) {
	dir := t.TempDir()
	hexKey, _ := GenerateKEK()
	for name, content := range map[string][]byte{"hex": []byte(hexKey + "\n"), "raw": bytes.Repeat([]byte{1}, 32)} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, content, 0o600)
		if k, err := (FileProvider{Path: p}).KEK(context.Background()); err != nil || len(k) != 32 {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, content := range map[string]string{"short": "abcd", "nothex": strings.Repeat("zz", 32), "long": strings.Repeat("a", 65)} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(content), 0o600)
		if _, err := (FileProvider{Path: p}).KEK(context.Background()); !errors.Is(err, ErrBadKEK) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	if _, err := (FileProvider{Path: filepath.Join(dir, "missing")}).KEK(context.Background()); err == nil {
		t.Error("missing file accepted")
	}
}
