// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package sensor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// hubBodyLimit mirrors maxIngestBody in hub/internal/httpapi/ingest.go.
const hubBodyLimit = 256 << 10

// deliverAll runs a sensor that reports evs once, waits until the mock Hub
// holds want events, stops it, and returns the summed heartbeat drop count.
func deliverAll(t *testing.T, h *mockHub, want int, report func(s *Sensor)) uint64 {
	t.Helper()
	sigs := make(chan os.Signal, 1)
	spec := Spec{Drill: drill, Run: func(ctx context.Context, s *Sensor) error {
		report(s)
		<-ctx.Done()
		return nil
	}}
	done := make(chan int, 1)
	go func() { done <- Run(context.Background(), spec, fastOpts(h.env(nil), sigs)) }()
	waitFor(t, func() bool { return len(h.events()) >= want })
	// Let at least one heartbeat after the last delivery report any drops.
	time.Sleep(120 * time.Millisecond)
	sigs <- syscall.SIGINT
	if code := <-done; code != 0 {
		t.Fatalf("exit code %d", code)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	var dropped uint64
	for _, hb := range h.heartbeats {
		dropped += hb.DroppedEvents
	}
	return dropped
}

func assertAllDelivered(t *testing.T, h *mockHub, n int) {
	t.Helper()
	seen := map[int]bool{}
	for _, e := range h.events() {
		var d struct {
			I int `json:"i"`
		}
		if err := json.Unmarshal(e.Details, &d); err != nil {
			t.Fatalf("details: %v", err)
		}
		seen[d.I] = true
	}
	if len(seen) != n {
		t.Fatalf("delivered %d distinct events, want %d", len(seen), n)
	}
}

// TestLargeEventsSplitAcrossBatches: 100 events with ~60 KiB of details each
// fit the 100-event batch size but not the Hub's 256 KiB body limit. Before
// the batch byte budget the whole batch was refused with 413 and all 100
// events dropped; now every batch stays under the limit and nothing is lost.
func TestLargeEventsSplitAcrossBatches(t *testing.T) {
	h := newMockHub(t)
	h.maxBody = hubBodyLimit
	const n = 100
	blob := strings.Repeat("A", 60<<10)
	dropped := deliverAll(t, h, n, func(s *Sensor) {
		for i := 0; i < n; i++ {
			s.Report("file_read", "10.0.0.5", "/srv/share/payroll.xlsx", Fields{F("i", i), F("blob", blob)})
		}
	})
	if h.tooLarge != 0 {
		t.Fatalf("%d batches refused with 413", h.tooLarge)
	}
	if dropped != 0 {
		t.Fatalf("dropped_events=%d, want 0", dropped)
	}
	assertAllDelivered(t, h, n)
	if len(h.batches) < n/4 {
		t.Fatalf("only %d batches for %d large events", len(h.batches), n)
	}
}

// TestEscapingCannotOverflowBatch: source and target are attacker-influenced.
// Characters json.Marshal escapes to six bytes (<, >, &, control bytes) must
// not let a batch that looks small by len() exceed the Hub limit.
func TestEscapingCannotOverflowBatch(t *testing.T) {
	h := newMockHub(t)
	h.maxBody = hubBodyLimit
	const n = 100
	nasty := strings.Repeat("<\x01&", MaxFieldBytes/3+1)
	dropped := deliverAll(t, h, n, func(s *Sensor) {
		for i := 0; i < n; i++ {
			s.Report("http_request", nasty, nasty, Map{"i": i, "ua": strings.Repeat(">", 1024)})
		}
	})
	if h.tooLarge != 0 || dropped != 0 {
		t.Fatalf("413s=%d dropped=%d, want 0/0", h.tooLarge, dropped)
	}
	assertAllDelivered(t, h, n)
}

// TestTooLargeBatchIsSplit: a proxy in front of the Hub with a lower body
// limit answers 413; the SDK halves the batch instead of dropping it.
func TestTooLargeBatchIsSplit(t *testing.T) {
	h := newMockHub(t)
	h.maxBody = 100 << 10
	const n = 40
	blob := strings.Repeat("B", 30<<10)
	dropped := deliverAll(t, h, n, func(s *Sensor) {
		for i := 0; i < n; i++ {
			s.Report("file_read", "10.0.0.5", "/srv/share/x", Map{"i": i, "blob": blob})
		}
	})
	if h.tooLarge == 0 {
		t.Fatal("expected the lower limit to refuse some batches")
	}
	if dropped != 0 {
		t.Fatalf("dropped_events=%d, want 0", dropped)
	}
	assertAllDelivered(t, h, n)
}

// TestWireSizeIsUpperBound checks wireSize against the client's actual
// encoding for worst-case escaping in every variable-size field.
func TestWireSizeIsUpperBound(t *testing.T) {
	s := &Sensor{cfg: &Config{SensorID: "ts-sensor-demo", DefaultSeverity: SeverityMedium},
		log: quietLogger(), ids: newUUIDGen(nil), now: time.Now}
	cases := []string{"", "plain", strings.Repeat("<", 400), strings.Repeat("\x00", 300),
		strings.Repeat(" ", 100), strings.Repeat("\xff", 300), strings.Repeat(`"\`, 200)}
	for _, src := range cases {
		for _, det := range []Details{nil, Map{"v": src}, Fields{F("k"+src, src)},
			Map{"v": strings.Repeat("<", MaxDetailsBytes/6-10)}} {
			ev := s.build(SeverityCritical, "trigger_"+src[:min(len(src), 32)], src, src, det)
			b, err := json.Marshal(eventBatch{Events: []wireEvent{ev, ev}})
			if err != nil {
				t.Fatal(err)
			}
			got := len(b) - len(`{"events":[]}`)
			if bound := 2 * ev.wireSize(); got > bound {
				t.Fatalf("source %q: encoded %d > bound %d", src[:min(len(src), 16)], got, bound)
			}
		}
	}
}

func TestRingByteBudget(t *testing.T) {
	r := newRing(10)
	big := wireEvent{Details: json.RawMessage(`"` + strings.Repeat("x", 100<<10) + `"`)}
	for i := 0; i < 5; i++ {
		e := big
		e.Trigger = fmt.Sprint(i)
		r.push(e)
	}
	if !r.full(100, maxBatchBytes) {
		t.Fatal("500 KiB queued should count as a full batch")
	}
	for _, want := range []int{2, 2, 1} {
		if got := r.pop(100, maxBatchBytes); len(got) != want {
			t.Fatalf("pop took %d, want %d", len(got), want)
		}
	}
	// A single event above the budget is still taken on its own.
	huge := wireEvent{Details: json.RawMessage(strings.Repeat("y", maxBatchBytes+1))}
	r.push(huge)
	r.push(big)
	if got := r.pop(100, maxBatchBytes); len(got) != 1 {
		t.Fatalf("oversized head: took %d, want 1", len(got))
	}
	r.pop(100, maxBatchBytes)
	if r.bytes != 0 || r.full(1, maxBatchBytes) {
		t.Fatalf("byte accounting off: %d", r.bytes)
	}
	// Overflow eviction keeps the byte count consistent.
	r2 := newRing(2)
	for i := 0; i < 5; i++ {
		r2.push(big)
	}
	if r2.bytes != 2*big.wireSize() {
		t.Fatalf("bytes after eviction %d, want %d", r2.bytes, 2*big.wireSize())
	}
}
