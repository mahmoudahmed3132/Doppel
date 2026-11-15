// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package totp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

// Recovery codes: 10 characters of base32 (50 bits), shown as "xxxxx-xxxxx".
// Only their hashes are kept. These are the recovery-code hunks of the
// imported MFA commit, as pure functions: storage, replay of the remaining
// list and auditing stay with the Hub's auth service.

func normalizeCode(code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	return strings.NewReplacer(" ", "", "-", "").Replace(code)
}

func hashRecovery(code string) string {
	sum := sha256.Sum256([]byte("truesignal-recovery:" + normalizeCode(code)))
	return hex.EncodeToString(sum[:])
}

// newRecoveryCodes returns n fresh codes (shown once) and their hashes.
func newRecoveryCodes(n int) (codes, hashes []string, err error) {
	codes = make([]string, n)
	hashes = make([]string, n)
	for i := range codes {
		raw := make([]byte, 7)
		if _, err := rand.Read(raw); err != nil {
			return nil, nil, err
		}
		c := strings.ToLower(b32.EncodeToString(raw))[:10] // 50 bits
		codes[i] = c[:5] + "-" + c[5:]
		hashes[i] = hashRecovery(c)
	}
	return codes, hashes, nil
}

// consumeRecovery removes code's hash from hashes. Every entry is compared,
// in constant time, so timing does not reveal the position of a match.
func consumeRecovery(hashes []string, code string) ([]string, bool) {
	code = normalizeCode(code)
	if len(code) != 10 {
		return hashes, false
	}
	want := hashRecovery(code)
	idx := -1
	for i, h := range hashes {
		if subtle.ConstantTimeCompare([]byte(h), []byte(want)) == 1 && idx < 0 {
			idx = i
		}
	}
	if idx < 0 {
		return hashes, false
	}
	return append(append([]string{}, hashes[:idx]...), hashes[idx+1:]...), true
}
