// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

//go:build !linux && !darwin && !freebsd && !netbsd

package main

import (
	"os"
	"time"
)

// accessTime is unavailable here: only tampering is detected.
func accessTime(os.FileInfo) (time.Time, bool) { return time.Time{}, false }
