// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

// Package secrets holds the Hub master keys (capture-hash and beacon). They
// are generated on first use, stored in settings, and never leave the Hub:
// sensors only ever receive keys derived from them.
package secrets

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/ids"
)

// Settings keys. The settings API must never return these values.
const (
	SettingCaptureMasterKey = "capture_master_key"
	SettingBeaconMasterKey  = "beacon_master_key"
)

// SecretSettings lists settings that are secret (reported only as "is set").
var SecretSettings = []string{SettingCaptureMasterKey, SettingBeaconMasterKey}

// Store is the persistence needed.
type Store interface {
	PutSettingIfAbsent(ctx context.Context, key, value string) (string, error)
}

// Keys implements compose.MasterKeys.
type Keys struct{ Store Store }

func (k *Keys) load(ctx context.Context, name string) ([]byte, error) {
	v, err := k.Store.PutSettingIfAbsent(ctx, name, ids.Hex(32))
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(v)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("setting %s is corrupt", name)
	}
	return b, nil
}

// CaptureMasterKey returns the capture master key, creating it once.
func (k *Keys) CaptureMasterKey(ctx context.Context) ([]byte, error) {
	return k.load(ctx, SettingCaptureMasterKey)
}

// BeaconMasterKey returns the beacon master key, creating it once.
func (k *Keys) BeaconMasterKey(ctx context.Context) ([]byte, error) {
	return k.load(ctx, SettingBeaconMasterKey)
}
