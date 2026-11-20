// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package sensor

import "sync"

// ring is a bounded FIFO that discards its oldest element when full.
type ring struct {
	mu      sync.Mutex
	buf     []wireEvent
	head    int // index of oldest element
	n       int
	bytes   int // sum of wireSize over the queued elements
	dropped uint64
	notify  chan struct{} // 1-buffered; signalled on push
}

func newRing(capacity int) *ring {
	if capacity < 1 {
		capacity = 1
	}
	return &ring{buf: make([]wireEvent, capacity), notify: make(chan struct{}, 1)}
}

func (r *ring) push(e wireEvent) {
	r.mu.Lock()
	if r.n == len(r.buf) {
		r.bytes -= r.buf[r.head].wireSize()
		r.buf[r.head] = wireEvent{}
		r.head = (r.head + 1) % len(r.buf)
		r.n--
		r.dropped++
	}
	r.buf[(r.head+r.n)%len(r.buf)] = e
	r.n++
	r.bytes += e.wireSize()
	r.mu.Unlock()
	select {
	case r.notify <- struct{}{}:
	default:
	}
}

// pop removes and returns the oldest elements: at most max of them, and no
// more than budget bytes of wireSize in total. It always takes at least one
// element from a non-empty ring, so an event that alone exceeds budget is
// still sent (it cannot exceed the Hub's limit; see wireSize).
func (r *ring) pop(max, budget int) []wireEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]wireEvent, 0, min(max, r.n))
	used := 0
	for r.n > 0 && len(out) < max {
		e := r.buf[r.head]
		sz := e.wireSize()
		if len(out) > 0 && used+sz > budget {
			break
		}
		out = append(out, e)
		used += sz
		r.buf[r.head] = wireEvent{}
		r.head = (r.head + 1) % len(r.buf)
		r.n--
	}
	r.bytes -= used
	return out
}

// full reports whether the queue already holds a complete batch: max
// elements, or at least budget bytes, so waiting cannot make the next pop
// larger.
func (r *ring) full(max, budget int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n >= max || r.bytes >= budget
}

func (r *ring) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

// addDropped records events lost outside the queue (undeliverable batches).
func (r *ring) addDropped(n uint64) {
	r.mu.Lock()
	r.dropped += n
	r.mu.Unlock()
}

// takeDropped returns and resets the drop counter.
func (r *ring) takeDropped() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := r.dropped
	r.dropped = 0
	return d
}
