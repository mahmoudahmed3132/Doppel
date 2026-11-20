// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package ratelimit

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestGateBoundsConcurrency(t *testing.T) {
	g := NewGate(2, 0)
	r1, ok1 := g.Enter(context.Background())
	r2, ok2 := g.Enter(context.Background())
	if !ok1 || !ok2 || g.InFlight() != 2 {
		t.Fatalf("first two must enter: %v %v in-flight %d", ok1, ok2, g.InFlight())
	}
	if _, ok := g.Enter(context.Background()); ok {
		t.Fatal("third caller entered a full gate")
	}
	if g.Refused() != 1 {
		t.Fatalf("refused = %d", g.Refused())
	}
	r1()
	r1() // idempotent: must not free a second slot
	if g.InFlight() != 1 {
		t.Fatalf("in-flight after release = %d", g.InFlight())
	}
	r3, ok := g.Enter(context.Background())
	if !ok {
		t.Fatal("slot not reusable after release")
	}
	if _, ok := g.Enter(context.Background()); ok {
		t.Fatal("double release freed an extra slot")
	}
	r2()
	r3()
}

func TestGateWaitsForSlot(t *testing.T) {
	g := NewGate(1, time.Second)
	rel, _ := g.Enter(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); rel() }()
	r, ok := g.Enter(context.Background())
	if !ok {
		t.Fatal("waiter refused although a slot freed within the wait")
	}
	r()

	short := NewGate(1, 10*time.Millisecond)
	hold, _ := short.Enter(context.Background())
	defer hold()
	start := time.Now()
	if _, ok := short.Enter(context.Background()); ok {
		t.Fatal("entered a held gate")
	}
	if time.Since(start) < 10*time.Millisecond {
		t.Fatal("refused before the wait elapsed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := NewGate(1, time.Hour).enterFull(ctx); ok {
		t.Fatal("cancelled caller entered")
	}
}

// enterFull fills the gate, then tries once more with ctx.
func (g *Gate) enterFull(ctx context.Context) (func(), bool) {
	g.Enter(context.Background())
	return g.Enter(ctx)
}

func TestGateConcurrentNeverExceeds(t *testing.T) {
	const n = 4
	g := NewGate(n, 5*time.Millisecond)
	var (
		mu       sync.Mutex
		cur, top int
		wg       sync.WaitGroup
	)
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, ok := g.Enter(context.Background())
			if !ok {
				return
			}
			mu.Lock()
			cur++
			top = max(top, cur)
			mu.Unlock()
			time.Sleep(time.Millisecond)
			mu.Lock()
			cur--
			mu.Unlock()
			rel()
		}()
	}
	wg.Wait()
	if top > n || top == 0 {
		t.Fatalf("peak concurrency %d, limit %d", top, n)
	}
	if g.InFlight() != 0 {
		t.Fatalf("slots leaked: %d", g.InFlight())
	}
}
