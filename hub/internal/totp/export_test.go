// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package totp

import (
	"strings"
	"time"
)

// CodeAt computes the code for secret at t (tests only).
func CodeAt(secret string, t time.Time) string {
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return ""
	}
	return hotp(key, uint64(t.Unix()/totpPeriod))
}
