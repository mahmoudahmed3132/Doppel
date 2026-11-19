// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

//go:build !linux

package main

import "context"

// Run watches until ctx ends. Without inotify, lures are stat-polled
// (poll.go); access detection is atime-based and best-effort.
func (w *Watcher) Run(ctx context.Context) error {
	if w.Log != nil {
		w.Log("inotify unavailable on this platform; polling lures (access detection is atime-based, best-effort)")
	}
	return w.runPoll(ctx)
}
