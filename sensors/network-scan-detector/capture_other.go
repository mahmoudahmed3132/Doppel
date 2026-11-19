// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

//go:build !linux

package main

import (
	"context"
	"errors"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

// run needs AF_PACKET, which only Linux has. On macOS run the sensor image
// in Docker (Linux VM) instead; the binary still builds so the workspace
// compiles and the fire drill / test mode work everywhere.
func run(ctx context.Context, s *sensor.Sensor) error {
	if _, err := LoadSettings(s); err != nil {
		return err
	}
	return errors.New("network-scan-detector requires Linux (AF_PACKET capture); run its container image under Docker")
}
