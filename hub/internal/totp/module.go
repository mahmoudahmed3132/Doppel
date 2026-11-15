// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package totp

import (
	"errors"
	"strings"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
)

// Module adapts this package to ported.TOTP.
type Module struct{}

var _ ported.TOTP = Module{}

// GenerateSecret returns a 160-bit base32 secret and its otpauth:// URI.
func (Module) GenerateSecret(accountName, issuer string) (string, string, error) {
	if issuer == "" || accountName == "" || strings.ContainsAny(issuer, ":") {
		return "", "", errors.New("totp: issuer and account required; issuer must not contain ':'")
	}
	s, err := newTOTPSecret()
	if err != nil {
		return "", "", err
	}
	return s, totpURI(s, issuer, accountName), nil
}

// Verify accepts code for secret at now, one step of skew either side, only
// for a step later than lastStep, and returns the matched step.
func (Module) Verify(secret, code string, lastStep int64, now time.Time) (int64, bool) {
	return verifyTOTP(secret, strings.TrimSpace(code), now, lastStep)
}

// GenerateRecoveryCodes returns n codes and their hashes.
func (Module) GenerateRecoveryCodes(n int) ([]string, []string, error) {
	if n <= 0 || n > 100 {
		return nil, nil, errors.New("totp: recovery code count out of range")
	}
	return newRecoveryCodes(n)
}

// ConsumeRecoveryCode returns the remaining hashes when code matches one.
func (Module) ConsumeRecoveryCode(hashed []string, code string) ([]string, bool) {
	return consumeRecovery(hashed, code)
}
