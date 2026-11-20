// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package sensor

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"
)

func runDrillService(t *testing.T, h *mockHub) []wireEvent {
	t.Helper()
	sigs := make(chan os.Signal, 2)
	done := make(chan int, 1)
	go func() {
		done <- Run(context.Background(), Spec{Drill: drill, Run: func(ctx context.Context, s *Sensor) error {
			s.Report("tcp_connection", DrillSource, "port 22", nil) // a real event whose source reads like a drill
			<-ctx.Done()
			return nil
		}}, Options{Getenv: h.env(nil), Signals: sigs, Logger: quietLogger(), BatchDelay: 10 * time.Millisecond, HeartbeatInterval: time.Hour})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for len(h.events()) < 1 {
		if time.Now().After(deadline) {
			t.Fatal("event not delivered")
		}
		time.Sleep(5 * time.Millisecond)
	}
	sigs <- syscall.SIGUSR1
	sigs <- syscall.SIGTERM
	if code := <-done; code != 0 {
		t.Fatalf("exit %d", code)
	}
	return h.events()
}

// TestDrillFlagCapableHub: with capability event.drill the SDK sends
// "drill": true on drill-path events (SIGUSR1 and test mode) and an explicit
// "drill": false on every other event (F-001).
func TestDrillFlagCapableHub(t *testing.T) {
	h := newMockHub(t)
	h.caps = []string{"event.drill"}
	if code := Run(context.Background(), Spec{Drill: drill}, Options{Getenv: h.env(map[string]string{EnvTestMode: "true"}), Logger: quietLogger()}); code != 0 {
		t.Fatalf("test mode exit %d", code)
	}
	ev := h.events()
	if len(ev) != 1 || ev[0].Drill == nil || !*ev[0].Drill || ev[0].Source != DrillSource {
		t.Fatalf("test mode drill %+v", ev)
	}

	h = newMockHub(t)
	h.caps = []string{"event.drill"}
	ev = runDrillService(t, h)
	if len(ev) != 2 {
		t.Fatalf("events %+v", ev)
	}
	if ev[0].Trigger != "tcp_connection" || ev[0].Drill == nil || *ev[0].Drill {
		t.Fatalf("real event must carry drill=false: %+v", ev[0])
	}
	if ev[1].Trigger != drill.Trigger || ev[1].Drill == nil || !*ev[1].Drill || ev[1].Source != DrillSource {
		t.Fatalf("SIGUSR1 drill %+v", ev[1])
	}
	if h.versionCalls != 1 {
		t.Fatalf("capability probed %d times, want 1 (cached)", h.versionCalls)
	}
}

// TestDrillFlagOldHub: a Hub without the capability never sees the field
// (it would refuse the event); drills keep the "Fire drill" source.
func TestDrillFlagOldHub(t *testing.T) {
	h := newMockHub(t)
	if code := Run(context.Background(), Spec{Drill: drill}, Options{Getenv: h.env(map[string]string{EnvTestMode: "true"}), Logger: quietLogger()}); code != 0 {
		t.Fatalf("test mode exit %d", code)
	}
	if h.drillKeySeen || len(h.events()) != 1 {
		t.Fatal("test mode: drill field sent to a Hub without capability event.drill")
	}
	h = newMockHub(t)
	ev := runDrillService(t, h)
	if h.drillKeySeen {
		t.Fatal("drill field sent to a Hub without capability event.drill")
	}
	if len(ev) != 2 || ev[1].Source != DrillSource {
		t.Fatalf("events %+v", ev)
	}
}
