// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package totp

import (
	"strings"
	"testing"
)

func TestRecoveryCodesFormatUniqueAndSingleUse(t *testing.T) {
	codes, hashes, err := Module{}.GenerateRecoveryCodes(10)
	if err != nil || len(codes) != 10 || len(hashes) != 10 {
		t.Fatal(len(codes), len(hashes), err)
	}
	seen := map[string]bool{}
	for i, c := range codes {
		if len(c) != 11 || c[5] != '-' || seen[c] {
			t.Fatalf("code %q", c)
		}
		seen[c] = true
		if strings.Contains(hashes[i], c) || len(hashes[i]) != 64 {
			t.Fatalf("hash %q", hashes[i])
		}
	}
	// Typed in upper case, with spaces instead of the dash: still accepted.
	typed := strings.ToUpper(strings.Replace(codes[3], "-", " ", 1))
	rest, ok := Module{}.ConsumeRecoveryCode(hashes, typed)
	if !ok || len(rest) != 9 {
		t.Fatal("valid code refused", ok, len(rest))
	}
	if _, ok := (Module{}).ConsumeRecoveryCode(rest, codes[3]); ok {
		t.Fatal("recovery code accepted twice")
	}
	if len(hashes) != 10 {
		t.Fatal("input slice modified")
	}
	for _, bad := range []string{"", "short", "aaaaa-aaaaa", codes[3] + "x"} {
		if _, ok := (Module{}).ConsumeRecoveryCode(hashes, bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, _, err := (Module{}).GenerateRecoveryCodes(0); err == nil {
		t.Fatal("zero codes accepted")
	}
}

func TestGenerateSecretValidatesLabel(t *testing.T) {
	if _, _, err := (Module{}).GenerateSecret("admin", "Bad:Issuer"); err == nil {
		t.Fatal("issuer with ':' accepted")
	}
	s, uri, err := Module{}.GenerateSecret("admin", "Doppel")
	if err != nil || len(s) != 32 || !strings.HasPrefix(uri, "otpauth://totp/Doppel:admin?") {
		t.Fatal(s, uri, err)
	}
}
