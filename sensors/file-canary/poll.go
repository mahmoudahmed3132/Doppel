// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"context"
	"os"
	"sort"
	"time"
)

// Portable stat-polling backend. Linux uses inotify (watch_linux.go); other
// platforms (macOS, BSD) have no kernel open/read notification available to
// an unprivileged process, so lures are polled:
//   - tampering (modify, chmod, rename/replace, delete) is detected reliably
//     from size, mtime, mode and file identity;
//   - access is detected from atime, which is best-effort: on volumes mounted
//     noatime it never moves, and under relatime-style semantics (APFS and
//     Linux defaults) only the first read after a change advances it.

// lureState is one polled snapshot of a lure.
type lureState struct {
	exists bool
	info   os.FileInfo
	atime  time.Time
}

func statLure(path string) lureState {
	fi, err := os.Lstat(path)
	if err != nil {
		return lureState{}
	}
	at, _ := accessTime(fi)
	return lureState{exists: true, info: fi, atime: at}
}

// diff returns the action between two snapshots of the same path, whether it
// is tampering, and whether anything happened at all.
func diff(prev, cur lureState) (string, bool, bool) {
	switch {
	case !prev.exists && !cur.exists:
		return "", false, false
	case prev.exists && !cur.exists:
		return "delete", true, true
	case !prev.exists && cur.exists:
		return "modify", true, true // recreated
	case !os.SameFile(prev.info, cur.info):
		return "rename", true, true // replaced by another inode
	case prev.info.Size() != cur.info.Size() || !prev.info.ModTime().Equal(cur.info.ModTime()):
		return "modify", true, true
	case prev.info.Mode() != cur.info.Mode():
		return "attrib", true, true
	case cur.atime.After(prev.atime):
		return "read", false, true
	}
	return "", false, false
}

// runPoll polls every lure each PollPeriod until ctx ends.
func (w *Watcher) runPoll(ctx context.Context) error {
	w.init()
	paths := make([]string, 0, len(w.Lures))
	for p := range w.Lures {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	snap := make(map[string]lureState, len(paths))
	for _, p := range paths {
		snap[p] = statLure(p)
	}
	t := time.NewTicker(w.PollPeriod)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		for _, p := range paths {
			cur := statLure(p)
			if action, tamper, ok := diff(snap[p], cur); ok {
				w.report(p, action, tamper)
			}
			snap[p] = cur
		}
	}
}
