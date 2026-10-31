// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"container/list"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/sdk/go/sensor"
)

// Trigger is the event of this sensor.
const Trigger = "network_scan_detected"

const (
	maxPortsPerSource = 1024
	maxPortsReported  = 64
)

// Detector tracks distinct destination ports per source in a sliding
// window and reports once per source per window.
type Detector struct {
	Threshold  int
	Window     time.Duration
	Ignored    map[int]bool
	MaxSources int
	R          sensor.Reporter
	Now        func() time.Time

	mu    sync.Mutex
	order *list.List // front = most recently seen
	srcs  map[string]*list.Element
}

type sourceState struct {
	src       string
	ports     map[int]time.Time
	types     map[string]int
	tools     map[string]int
	lastAlert time.Time
}

// NewDetector returns a detector with LRU-bounded state.
func NewDetector(threshold int, window time.Duration, ignored map[int]bool, maxSources int, r sensor.Reporter) *Detector {
	if maxSources <= 0 {
		maxSources = 4096
	}
	return &Detector{Threshold: threshold, Window: window, Ignored: ignored, MaxSources: maxSources, R: r,
		Now: time.Now, order: list.New(), srcs: map[string]*list.Element{}}
}

// Observe processes one inbound probe.
func (d *Detector) Observe(p Probe) {
	if !IsScanProbe(p) || d.Ignored[p.DstPort] {
		return
	}
	now := d.Now()
	d.mu.Lock()
	el, ok := d.srcs[p.Src]
	if !ok {
		if d.order.Len() >= d.MaxSources {
			old := d.order.Back()
			d.order.Remove(old)
			delete(d.srcs, old.Value.(*sourceState).src)
		}
		el = d.order.PushFront(&sourceState{src: p.Src, ports: map[int]time.Time{}, types: map[string]int{}, tools: map[string]int{}})
		d.srcs[p.Src] = el
	} else {
		d.order.MoveToFront(el)
	}
	st := el.Value.(*sourceState)
	for port, at := range st.ports {
		if now.Sub(at) > d.Window {
			delete(st.ports, port)
		}
	}
	if _, seen := st.ports[p.DstPort]; seen || len(st.ports) < maxPortsPerSource {
		st.ports[p.DstPort] = now
	}
	st.types[ScanType(p)]++
	if g := ToolGuess(p); g != "" {
		st.tools[g]++
	}
	fire := len(st.ports) >= d.Threshold && (st.lastAlert.IsZero() || now.Sub(st.lastAlert) >= d.Window)
	var details sensor.Fields
	if fire {
		st.lastAlert = now
		details = d.details(st, p.Proto)
		st.types, st.tools = map[string]int{}, map[string]int{}
	}
	d.mu.Unlock()
	if fire {
		d.R.ReportSeverity(sensor.SeverityHigh, Trigger, p.Src, "host ("+strconv.Itoa(len(st.ports))+" ports)", details)
	}
}

func top(m map[string]int) string {
	best, n := "", 0
	for k, v := range m {
		if v > n || (v == n && k < best) {
			best, n = k, v
		}
	}
	return best
}

func (d *Detector) details(st *sourceState, proto string) sensor.Fields {
	ports := make([]int, 0, len(st.ports))
	for p := range st.ports {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	count := len(ports)
	if len(ports) > maxPortsReported {
		ports = ports[:maxPortsReported]
	}
	tool := ""
	// Only claim a tool when it explains most probes.
	total := 0
	for _, v := range st.types {
		total += v
	}
	if t := top(st.tools); t != "" && st.tools[t]*2 > total {
		tool = t
	}
	return sensor.Fields{
		sensor.F("scan_type", top(st.types)), sensor.F("tool_guess", tool), sensor.F("ports_hit", ports),
		sensor.F("count", count), sensor.F("window_sec", int(d.Window/time.Second)), sensor.F("protocol", proto),
	}
}

// Sources returns the number of tracked sources.
func (d *Detector) Sources() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.order.Len()
}
