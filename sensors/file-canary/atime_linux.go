// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

//go:build linux

package main

import (
	"os"
	"syscall"
	"time"
)

func accessTime(fi os.FileInfo) (time.Time, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(st.Atim.Sec), int64(st.Atim.Nsec)), true
}
