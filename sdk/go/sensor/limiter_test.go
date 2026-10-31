// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package sensor

import (
	"strconv"
	"testing"
	"time"
)

func TestSourceLimiter(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewSourceLimiter(time.Minute, 2)
	l.now = func() time.Time { return now }

	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("first event suppressed")
	}
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("a"); ok {
			t.Fatal("event inside cooldown allowed")
		}
	}
	now = now.Add(time.Minute)
	ok, sup := l.Allow("a")
	if !ok || sup != 3 {
		t.Fatalf("ok=%v suppressed=%d", ok, sup)
	}
	if ok, sup := l.Allow("b"); !ok || sup != 0 {
		t.Fatal("new source suppressed")
	}
	for i := 0; i < 100; i++ {
		l.Allow(strconv.Itoa(i))
	}
	if l.Len() != 2 {
		t.Fatalf("limiter not bounded: %d", l.Len())
	}
}

func TestPrintableAndClean(t *testing.T) {
	if got := Printable([]byte("GET /\r\n\x00\xff\\x"), 100); got != `GET /\r\n\x00\xff\\x` {
		t.Fatalf("%q", got)
	}
	if got := Printable([]byte("abcdef"), 3); got != "abc" {
		t.Fatalf("%q", got)
	}
	if got := Clean("a\nb\xffc"+string(make([]byte, 10)), 6); got != "a b�" {
		t.Fatalf("%q", got)
	}
}
