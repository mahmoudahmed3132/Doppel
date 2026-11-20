// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package sensor

import (
	"context"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"
)

// queuedBytes sums the variable-size fields held by the ring.
func (r *ring) queuedBytes() (n, bytes int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := 0; i < r.n; i++ {
		e := r.buf[(r.head+i)%len(r.buf)]
		bytes += len(e.Details) + len(e.Source) + len(e.Target)
	}
	return r.n, bytes
}

func TestEventSizeBounded(t *testing.T) {
	s := &Sensor{cfg: &Config{SensorID: "ts-sensor-demo", DefaultSeverity: SeverityMedium},
		log: quietLogger(), ids: newUUIDGen(nil), now: time.Now}
	huge := strings.Repeat("A", 1<<20)
	ev := s.build(SeverityHigh, "x", strings.Repeat("é", 400), huge, Map{"blob": huge})
	if string(ev.Details) != `{"details_dropped":true}` {
		t.Fatalf("oversized details kept: %d bytes", len(ev.Details))
	}
	if len(ev.Source) > MaxFieldBytes || len(ev.Target) > MaxFieldBytes || !utf8.ValidString(ev.Source) {
		t.Fatalf("fields not clamped: source %d target %d", len(ev.Source), len(ev.Target))
	}
	if len(ev.Target) != MaxFieldBytes || len(ev.Source) != MaxFieldBytes {
		t.Fatalf("fields over-truncated: source %d target %d", len(ev.Source), len(ev.Target))
	}
	// At the limit the details are kept as sent.
	edge := Map{"b": strings.Repeat("B", MaxDetailsBytes-len(`{"b":""}`))}
	if ev := s.build(SeverityHigh, "x", "s", "t", edge); len(ev.Details) != MaxDetailsBytes {
		t.Fatalf("details at the limit altered: %d bytes", len(ev.Details))
	}
}

// TestBoundedMemoryUnderSustainedOverload: while the Hub answers every batch
// with 429 overloaded, the SDK keeps at most QueueSize events of bounded size
// (plus one in-flight batch), drops the oldest, and reports the drops in its
// heartbeats (F-603).
func TestBoundedMemoryUnderSustainedOverload(t *testing.T) {
	h := newMockHub(t)
	for i := 0; i < 100000; i++ {
		h.eventStatus = append(h.eventStatus, 429)
	}
	const queue, reported = 50, 300
	sigs := make(chan os.Signal, 1)
	peak := make(chan [2]int, 1)
	spec := Spec{Drill: drill, Run: func(ctx context.Context, s *Sensor) error {
		blob := strings.Repeat("A", 1<<20)
		pk := [2]int{}
		for i := 0; i < reported; i++ {
			s.Report("tcp_connection", strings.Repeat("1", 4096), "port 22", Map{"blob": blob, "i": i})
			n, b := s.q.queuedBytes()
			pk[0], pk[1] = max(pk[0], n), max(pk[1], b)
		}
		peak <- pk
		<-ctx.Done()
		return nil
	}}
	opts := fastOpts(h.env(nil), sigs)
	opts.QueueSize = queue
	done := make(chan int, 1)
	go func() { done <- Run(context.Background(), spec, opts) }()

	pk := <-peak
	perEvent := MaxDetailsBytes + 2*MaxFieldBytes
	if pk[0] > queue || pk[1] > queue*perEvent {
		t.Fatalf("queue grew to %d events / %d bytes; bound %d events / %d bytes", pk[0], pk[1], queue, queue*perEvent)
	}
	// Everything beyond the queue and one in-flight batch was dropped and
	// must be reported through heartbeats.
	waitFor(t, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		var sum uint64
		for _, hb := range h.heartbeats {
			sum += hb.DroppedEvents
		}
		return sum >= reported-2*queue
	})
	sigs <- syscall.SIGINT
	<-done
	if n := len(h.events()); n != 0 {
		t.Fatalf("hub refused everything but %d events were recorded", n)
	}
}
