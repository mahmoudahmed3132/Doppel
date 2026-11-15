// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

type fakeReporter struct {
	mu     sync.Mutex
	events []sensor.Fields
	cfg    map[string]string
}

func (f *fakeReporter) ReportSeverity(_ sensor.Severity, trig, _, _ string, d sensor.Details) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if trig == trigger {
		f.events = append(f.events, d.(sensor.Fields))
	}
}

func (f *fakeReporter) Setting(n string) (string, bool) { v, ok := f.cfg[n]; return v, ok }

func (f *fakeReporter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.events)
}

func TestServeReportsOncePerCooldown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &fakeReporter{}
	done := make(chan error, 1)
	go func() { done <- serve(ctx, ln, r, sensor.NewSourceLimiter(time.Hour, 0)) }()

	for i := 0; i < 5; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	deadline := time.Now().Add(2 * time.Second)
	for r.count() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if n := r.count(); n != 1 {
		t.Fatalf("expected 1 event within cooldown, got %d", n)
	}
	cancel()
	ln.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLoadSettings(t *testing.T) {
	if _, err := loadSettings(&fakeReporter{cfg: map[string]string{envPort: "70000"}}); err == nil {
		t.Fatal("invalid port accepted")
	}
	s, err := loadSettings(&fakeReporter{cfg: map[string]string{envPort: "2222", envCooldown: "5"}})
	if err != nil || s.port != 2222 || s.cooldown != 5*time.Second {
		t.Fatalf("%+v %v", s, err)
	}
}
