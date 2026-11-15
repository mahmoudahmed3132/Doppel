// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package secrets_test

import (
	"slices"
	"testing"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/secrets"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/siem"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/webhook"
)

// The store seals settings by literal key; every secret setting declared by
// its owning package must be on that list, or it would be stored in plaintext.
func TestEverySecretSettingIsSealed(t *testing.T) {
	declared := append([]string{siem.SettingToken, webhook.SettingURL}, secrets.SecretSettings...)
	for _, k := range declared {
		if !slices.Contains(store.SecretSettingKeys, k) {
			t.Errorf("secret setting %q is not in store.SecretSettingKeys", k)
		}
	}
	for _, k := range store.SecretSettingKeys {
		if !slices.Contains(declared, k) {
			t.Errorf("store seals %q but no package declares it secret", k)
		}
	}
}
