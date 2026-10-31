// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package ratelimit provides keyed token buckets.
package ratelimit

import (
	"math"
	"sync"
	"time"
)

// Keyed holds one token bucket per key. Idle buckets are evicted lazily so
// memory stays proportional to active keys.
type Keyed struct {
	rate  float64 // tokens per second
	burst float64
	now   func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
	lastGC  time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewKeyed returns a limiter of rate tokens/s with the given burst.
func NewKeyed(rate float64, burst int) *Keyed {
	return &Keyed{rate: rate, burst: float64(burst), now: time.Now, buckets: map[string]*bucket{}}
}

// Allow takes one token for key. When none is available it returns false
// and how long until one is.
func (k *Keyed) Allow(key string) (bool, time.Duration) {
	now := k.now()
	k.mu.Lock()
	defer k.mu.Unlock()
	k.gc(now)
	b, ok := k.buckets[key]
	if !ok {
		b = &bucket{tokens: k.burst, last: now}
		k.buckets[key] = b
	}
	b.tokens = math.Min(k.burst, b.tokens+now.Sub(b.last).Seconds()*k.rate)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / k.rate * float64(time.Second))
	return false, wait
}

// gc drops buckets that have been idle long enough to be full again.
func (k *Keyed) gc(now time.Time) {
	if now.Sub(k.lastGC) < time.Minute {
		return
	}
	k.lastGC = now
	full := time.Duration(k.burst / k.rate * float64(time.Second))
	for key, b := range k.buckets {
		if now.Sub(b.last) > full {
			delete(k.buckets, key)
		}
	}
}
