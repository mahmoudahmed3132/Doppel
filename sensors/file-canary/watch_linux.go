// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"path/filepath"
	"syscall"
	"time"
)

const watchMask = syscall.IN_OPEN | syscall.IN_ACCESS | syscall.IN_MODIFY | syscall.IN_CLOSE_WRITE |
	syscall.IN_ATTRIB | syscall.IN_DELETE | syscall.IN_MOVED_FROM | syscall.IN_MOVED_TO |
	syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF

func (w *Watcher) watched(dir string) bool {
	for _, d := range w.wds {
		if d == dir {
			return true
		}
	}
	return false
}

func (w *Watcher) addWatches() {
	for _, d := range w.dirs() {
		if w.watched(d) {
			continue
		}
		wd, err := syscall.InotifyAddWatch(w.fd, d, watchMask)
		if err != nil {
			w.Log("cannot watch lure directory; will retry", "dir", d, "error", err.Error())
			continue
		}
		w.wds[int32(wd)] = d
	}
}

// Run watches until ctx ends (inotify).
func (w *Watcher) Run(ctx context.Context) error {
	w.init()
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	w.fd, w.wds = fd, map[int32]string{}
	w.addWatches()
	if len(w.wds) == 0 {
		return errors.New("no lure directory could be watched")
	}
	buf := make([]byte, 64<<10)
	lastRewatch := time.Now()
	for ctx.Err() == nil {
		n, err := syscall.Read(fd, buf)
		if err != nil && !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EINTR) {
			return err
		}
		if n > 0 {
			w.handle(buf[:n])
			continue
		}
		if time.Since(lastRewatch) >= w.RewatchPeriod {
			w.addWatches()
			lastRewatch = time.Now()
		}
		select {
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil
}

func (w *Watcher) handle(b []byte) {
	for len(b) >= syscall.SizeofInotifyEvent {
		wd := int32(binary.LittleEndian.Uint32(b[0:4]))
		mask := binary.LittleEndian.Uint32(b[4:8])
		nameLen := int(binary.LittleEndian.Uint32(b[12:16]))
		if syscall.SizeofInotifyEvent+nameLen > len(b) {
			return
		}
		name := string(b[16 : 16+nameLen])
		for len(name) > 0 && name[len(name)-1] == 0 {
			name = name[:len(name)-1]
		}
		b = b[syscall.SizeofInotifyEvent+nameLen:]

		dir := w.wds[wd]
		if mask&syscall.IN_IGNORED != 0 || mask&(syscall.IN_DELETE_SELF|syscall.IN_MOVE_SELF) != 0 {
			delete(w.wds, wd) // re-added by the periodic rewatch
			continue
		}
		if dir == "" || name == "" {
			continue // event on the directory itself
		}
		path := filepath.Join(dir, name)
		if !w.Lures[path] {
			continue
		}
		w.event(path, mask)
	}
}

// actionOf maps an inotify mask to the reported action and whether it is
// tampering.
func actionOf(mask uint32) (string, bool, bool) {
	switch {
	case mask&syscall.IN_DELETE != 0:
		return "delete", true, true
	case mask&(syscall.IN_MOVED_FROM|syscall.IN_MOVED_TO) != 0:
		return "rename", true, true
	case mask&(syscall.IN_MODIFY|syscall.IN_CLOSE_WRITE) != 0:
		return "modify", true, true
	case mask&syscall.IN_ATTRIB != 0:
		return "attrib", true, true
	case mask&syscall.IN_OPEN != 0:
		return "open", false, true
	case mask&syscall.IN_ACCESS != 0:
		return "read", false, true
	}
	return "", false, false
}

// event reports an inotify mask for path.
func (w *Watcher) event(path string, mask uint32) {
	if action, tamper, ok := actionOf(mask); ok {
		w.report(path, action, tamper)
	}
}
