// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

package sensor

import (
	"container/list"
	"sync"
	"time"
)

// SourceLimiter enforces a per-source cooldown between emitted events while
// counting suppressed ones. Memory is bounded: when MaxSources is reached the
// least recently seen source is evicted (its suppressed count is lost, which
// errs toward emitting, never toward silence).
type SourceLimiter struct {
	cooldown time.Duration
	max      int
	now      func() time.Time

	mu    sync.Mutex
	order *list.List // front = most recently seen
	byKey map[string]*list.Element
}

type limiterEntry struct {
	key        string
	lastEmit   time.Time
	suppressed int
}

// NewSourceLimiter returns a limiter allowing one event per source per
// cooldown, tracking at most maxSources sources (default 4096 if ≤ 0).
func NewSourceLimiter(cooldown time.Duration, maxSources int) *SourceLimiter {
	if maxSources <= 0 {
		maxSources = 4096
	}
	return &SourceLimiter{
		cooldown: cooldown,
		max:      maxSources,
		now:      time.Now,
		order:    list.New(),
		byKey:    make(map[string]*list.Element),
	}
}

// Allow reports whether an event for source may be emitted now. When it
// may, suppressed is the number of events suppressed for that source since
// the last emitted one (to be reported as "suppressed_since_last").
func (l *SourceLimiter) Allow(source string) (ok bool, suppressed int) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if el, found := l.byKey[source]; found {
		e := el.Value.(*limiterEntry)
		l.order.MoveToFront(el)
		if now.Sub(e.lastEmit) < l.cooldown {
			e.suppressed++
			return false, 0
		}
		suppressed, e.suppressed, e.lastEmit = e.suppressed, 0, now
		return true, suppressed
	}
	if l.order.Len() >= l.max {
		oldest := l.order.Back()
		l.order.Remove(oldest)
		delete(l.byKey, oldest.Value.(*limiterEntry).key)
	}
	l.byKey[source] = l.order.PushFront(&limiterEntry{key: source, lastEmit: now})
	return true, 0
}

// Len returns the number of tracked sources.
func (l *SourceLimiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.order.Len()
}
