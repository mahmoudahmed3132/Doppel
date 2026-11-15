// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

// Triggers.
const (
	TriggerAccessed = "decoy_file_accessed"
	TriggerTampered = "decoy_file_tampered"
)

const watchMask = syscall.IN_OPEN | syscall.IN_ACCESS | syscall.IN_MODIFY | syscall.IN_CLOSE_WRITE |
	syscall.IN_ATTRIB | syscall.IN_DELETE | syscall.IN_MOVED_FROM | syscall.IN_MOVED_TO |
	syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF

// Watcher reports access to and tampering with lure files. It watches
// the parent directories, so a lure that is deleted and recreated stays
// covered, and re-adds a directory watch that disappears.
type Watcher struct {
	Lures         map[string]bool // absolute lure paths
	AccessAlerts  bool
	AccessCool    time.Duration
	TamperCool    time.Duration
	R             sensor.Reporter
	Gen           LureGenerator
	Log           func(msg string, args ...any)
	RewatchPeriod time.Duration

	access *sensor.SourceLimiter
	tamper *sensor.SourceLimiter
	fd     int
	wds    map[int32]string // watch descriptor -> directory
}

// dirs returns the distinct parent directories of the lures.
func (w *Watcher) dirs() []string {
	set := map[string]bool{}
	for p := range w.Lures {
		set[filepath.Dir(p)] = true
	}
	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

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

// Run watches until ctx ends.
func (w *Watcher) Run(ctx context.Context) error {
	if w.RewatchPeriod == 0 {
		w.RewatchPeriod = 5 * time.Second
	}
	w.access = sensor.NewSourceLimiter(w.AccessCool, 0)
	w.tamper = sensor.NewSourceLimiter(w.TamperCool, 0)
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

func (w *Watcher) event(path string, mask uint32) {
	action, tamper, ok := actionOf(mask)
	if !ok {
		return
	}
	trig, sev, lim, key := TriggerAccessed, sensor.SeverityHigh, w.access, path
	if tamper {
		trig, sev, lim, key = TriggerTampered, sensor.SeverityCritical, w.tamper, path+"|"+action
	} else if !w.AccessAlerts {
		return
	}
	allowed, suppressed := lim.Allow(key)
	if !allowed {
		return
	}
	// The sensor cannot see the actor; the SOC correlates with EDR.
	w.R.ReportSeverity(sev, trig, "local", path, sensor.Fields{
		sensor.F("path", path), sensor.F("action", action), sensor.F("category", w.Gen.Category(path)),
		sensor.F("suppressed_since_last", suppressed),
	})
}
