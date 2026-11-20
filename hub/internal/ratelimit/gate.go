// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package ratelimit

import (
	"context"
	"sync/atomic"
	"time"
)

// Gate bounds how many requests run a section at once (admission control).
// A caller that cannot get a slot within the gate's wait is refused, so
// overload turns into fast refusals the client retries later instead of
// unbounded queues of in-flight requests and their bodies.
type Gate struct {
	slots    chan struct{}
	wait     time.Duration
	refused  atomic.Uint64
	inFlight atomic.Int64
}

// NewGate returns a gate of n concurrent slots (n < 1 means 1). A caller
// waits at most wait for a slot.
func NewGate(n int, wait time.Duration) *Gate {
	if n < 1 {
		n = 1
	}
	return &Gate{slots: make(chan struct{}, n), wait: max(wait, 0)}
}

// Enter takes a slot. It returns a release function and true, or nil and
// false when no slot freed up within the gate's wait or ctx ended first.
func (g *Gate) Enter(ctx context.Context) (func(), bool) {
	select {
	case g.slots <- struct{}{}:
		return g.release(), true
	default:
	}
	if g.wait > 0 {
		t := time.NewTimer(g.wait)
		defer t.Stop()
		select {
		case g.slots <- struct{}{}:
			return g.release(), true
		case <-t.C:
		case <-ctx.Done():
		}
	}
	g.refused.Add(1)
	return nil, false
}

func (g *Gate) release() func() {
	g.inFlight.Add(1)
	var done atomic.Bool
	return func() {
		if done.CompareAndSwap(false, true) {
			g.inFlight.Add(-1)
			<-g.slots
		}
	}
}

// Refused is the number of callers refused since the gate was created.
func (g *Gate) Refused() uint64 { return g.refused.Load() }

// InFlight is the number of slots currently held.
func (g *Gate) InFlight() int64 { return g.inFlight.Load() }
