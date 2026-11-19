// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

//go:build darwin || freebsd || netbsd

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
	return time.Unix(int64(st.Atimespec.Sec), int64(st.Atimespec.Nsec)), true
}
