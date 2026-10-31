// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

package auth

import (
	"sync"
	"time"
)

// Lockout counts authentication failures per client IP and account-wide.
// A counter that reaches its threshold within Window locks for Duration.
// State is in memory: a restart clears it, which an attacker cannot cause.
type Lockout struct {
	PerIP    int
	Account  int
	Window   time.Duration
	Duration time.Duration
	MaxIPs   int
	now      func() time.Time

	mu      sync.Mutex
	ips     map[string]*counter
	account counter
}

type counter struct {
	failures    int
	first       time.Time
	lockedUntil time.Time
}

// NewLockout returns the §6.3 policy: 5 per IP, 10 account-wide, 15 min.
func NewLockout(now func() time.Time) *Lockout {
	return &Lockout{PerIP: 5, Account: 10, Window: 15 * time.Minute, Duration: 15 * time.Minute, MaxIPs: 10000,
		now: now, ips: map[string]*counter{}}
}

// Check reports whether ip (or the account) is locked, and for how long.
func (l *Lockout) Check(ip string) (bool, time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	var until time.Time
	if c := l.ips[ip]; c != nil && now.Before(c.lockedUntil) {
		until = c.lockedUntil
	}
	if now.Before(l.account.lockedUntil) && l.account.lockedUntil.After(until) {
		until = l.account.lockedUntil
	}
	if until.IsZero() {
		return false, 0
	}
	return true, until.Sub(now)
}

// Fail records one failure from ip.
func (l *Lockout) Fail(ip string) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	c := l.ips[ip]
	if c == nil {
		if len(l.ips) >= l.MaxIPs {
			l.gc(now)
		}
		c = &counter{}
		l.ips[ip] = c
	}
	l.bump(c, l.PerIP, now)
	l.bump(&l.account, l.Account, now)
}

func (l *Lockout) bump(c *counter, threshold int, now time.Time) {
	if c.failures == 0 || now.Sub(c.first) > l.Window {
		c.failures, c.first = 0, now
	}
	c.failures++
	if c.failures >= threshold {
		c.lockedUntil = now.Add(l.Duration)
		c.failures = 0
	}
}

// Success clears the counter of ip. The account-wide counter only decays:
// a successful login must not reset a distributed guessing campaign.
func (l *Lockout) Success(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if c := l.ips[ip]; c != nil && !l.now().Before(c.lockedUntil) {
		delete(l.ips, ip)
	}
}

// gc removes idle entries; if the table is still full the oldest counters
// are dropped (errs toward forgetting failures of a large botnet, while the
// account-wide counter still applies).
func (l *Lockout) gc(now time.Time) {
	for ip, c := range l.ips {
		if now.Sub(c.first) > l.Window && !now.Before(c.lockedUntil) {
			delete(l.ips, ip)
		}
	}
	for ip := range l.ips {
		if len(l.ips) < l.MaxIPs {
			break
		}
		delete(l.ips, ip)
	}
}
