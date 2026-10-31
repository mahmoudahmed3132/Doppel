// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package sensor

import "sync"

// ring is a bounded FIFO that discards its oldest element when full.
type ring struct {
	mu      sync.Mutex
	buf     []wireEvent
	head    int // index of oldest element
	n       int
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
		r.head = (r.head + 1) % len(r.buf)
		r.n--
		r.dropped++
	}
	r.buf[(r.head+r.n)%len(r.buf)] = e
	r.n++
	r.mu.Unlock()
	select {
	case r.notify <- struct{}{}:
	default:
	}
}

// pop removes and returns up to max of the oldest elements.
func (r *ring) pop(max int) []wireEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	if max > r.n {
		max = r.n
	}
	out := make([]wireEvent, max)
	for i := range out {
		out[i] = r.buf[r.head]
		r.buf[r.head] = wireEvent{}
		r.head = (r.head + 1) % len(r.buf)
	}
	r.n -= max
	return out
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
