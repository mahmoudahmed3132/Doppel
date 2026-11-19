// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Adapted from TrueSignal's decoy helper tests (PROVENANCE.md).

package decoy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseServices(t *testing.T) {
	got, err := ParseServices(" mysql:3306, POSTGRES:5432 ", "mysql", "postgres")
	if err != nil || len(got) != 2 || got[1] != (Service{"postgres", 5432}) {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{"", "ssh:22", "mysql", "mysql:0", "mysql:70000", "mysql:3306,postgres:3306"} {
		if _, err := ParseServices(bad, "mysql", "postgres"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCaptureModes(t *testing.T) {
	key := strings.Repeat("ab", 32)
	h, err := NewCaptureWith("", key)
	if err != nil {
		t.Fatal(err)
	}
	d := h.Password("correct pwd")
	mac := hmac.New(sha256.New, bytes.Repeat([]byte{0xab}, 32))
	mac.Write([]byte("correct pwd"))
	if d[0].Key != "password_hmac" || d[0].Value != hex.EncodeToString(mac.Sum(nil)) || d[1].Value != 11 {
		t.Fatalf("hash = %v", d)
	}
	if p, _ := NewCaptureWith("plain", ""); p.Password("x")[0].Key != "password" || p.Password("x")[0].Value != "x" {
		t.Fatal("plain")
	}
	if n, _ := NewCaptureWith("none", ""); n.Password("x")[0].Key != "password_submitted" {
		t.Fatal("none")
	}
	for _, bad := range [][2]string{{"hash", ""}, {"hash", "zz"}, {"", "abcd"}, {"sha1", key}} {
		if _, err := NewCaptureWith(bad[0], bad[1]); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestDeriveKey(t *testing.T) {
	k1 := bytes.Repeat([]byte{0x11}, 32)
	k2 := bytes.Repeat([]byte{0x22}, 32)
	k1Copy := append([]byte(nil), k1...)

	got1 := DeriveKey(k1, "doppel:ssh-host-key:v1:ts-sensor-a")
	got1Again := DeriveKey(k1, "doppel:ssh-host-key:v1:ts-sensor-a")
	gotDiffPurpose := DeriveKey(k1, "doppel:snmp-engine-id:v1:ts-sensor-a")
	gotDiffKey := DeriveKey(k2, "doppel:ssh-host-key:v1:ts-sensor-a")

	if len(got1) != sha256.Size {
		t.Fatalf("len(DeriveKey) = %d, want %d", len(got1), sha256.Size)
	}
	if !bytes.Equal(got1, got1Again) {
		t.Fatal("DeriveKey is not deterministic")
	}
	if bytes.Equal(got1, gotDiffPurpose) {
		t.Fatal("DeriveKey did not separate different purposes")
	}
	if bytes.Equal(got1, gotDiffKey) {
		t.Fatal("DeriveKey did not separate different capture keys")
	}
	if !bytes.Equal(k1, k1Copy) {
		t.Fatal("DeriveKey mutated input key")
	}

	mac := hmac.New(sha256.New, k1)
	mac.Write([]byte("doppel:ssh-host-key:v1:ts-sensor-a"))
	if !bytes.Equal(got1, mac.Sum(nil)) {
		t.Fatal("DeriveKey output does not match HMAC-SHA256")
	}
}

func TestSanitize(t *testing.T) {
	if got := Sanitize("ab\xffcd", 0); got != "ab?cd" {
		t.Fatalf("got %q", got)
	}
	if got := Sanitize("héllo", 2); got != "h" {
		t.Fatalf("truncation split a rune: %q", got)
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(2, time.Minute)
	t0 := time.Unix(0, 0)
	l.now = func() time.Time { return t0 }
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("first")
	}
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("second")
	}
	for i := 0; i < 5; i++ {
		if ok, _ := l.Allow("a"); ok {
			t.Fatal("over limit allowed")
		}
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("other source limited")
	}
	l.now = func() time.Time { return t0.Add(61 * time.Second) }
	if ok, sup := l.Allow("a"); !ok || sup != 5 {
		t.Fatalf("new window: ok=%v suppressed=%d, want 5", ok, sup)
	}
}

func TestLimiterStateIsBounded(t *testing.T) {
	l := NewLimiter(1, time.Minute)
	l.maxTracked = 100
	t0 := time.Unix(0, 0)
	l.now = func() time.Time { return t0 }
	allowed := 0
	for i := 0; i < 5000; i++ { // distinct spoofed sources within one window
		if ok, _ := l.Allow(strconv.Itoa(i)); ok {
			allowed++
		}
	}
	if len(l.seen) > l.maxTracked+1 {
		t.Fatalf("tracked %d sources, cap %d", len(l.seen), l.maxTracked)
	}
	// 100 tracked sources plus one event from the shared overflow bucket.
	if allowed != l.maxTracked+1 {
		t.Fatalf("allowed %d events, want %d", allowed, l.maxTracked+1)
	}
	// Once the window passes, expired entries are swept and new sources tracked.
	l.now = func() time.Time { return t0.Add(2 * time.Minute) }
	if ok, _ := l.Allow("fresh"); !ok || l.seen["fresh"] == nil {
		t.Fatal("new source not tracked after sweep")
	}
	if len(l.seen) > 2 {
		t.Fatalf("sweep left %d entries", len(l.seen))
	}
}

func TestLimiterSweepKeepsSuppressedCountsOneWindow(t *testing.T) {
	l := NewLimiter(1, time.Minute)
	l.maxTracked = 2
	t0 := time.Unix(0, 0)
	at := func(d time.Duration) { l.now = func() time.Time { return t0.Add(d) } }
	at(0)
	l.Allow("sprayer")
	for i := 0; i < 4; i++ {
		l.Allow("sprayer") // 4 suppressed
	}
	l.Allow("quiet") // table full: sprayer, quiet

	// One window later a new source forces a sweep: "quiet" (nothing
	// suppressed) is dropped, "sprayer" is kept for its count.
	at(61 * time.Second)
	l.Allow("new")
	if l.seen["quiet"] != nil || l.seen["sprayer"] == nil {
		t.Fatalf("after first sweep: %v", l.seen)
	}
	if ok, sup := l.Allow("sprayer"); !ok || sup != 4 {
		t.Fatalf("returning sprayer: ok=%v suppressed=%d, want 4", ok, sup)
	}

	// An expired entry with suppressed attempts that never returns is
	// dropped after the extra window.
	at(62 * time.Second)
	for i := 0; i < 3; i++ {
		l.Allow("new") // suppressed on "new"
	}
	at(62*time.Second + 2*time.Minute + time.Second)
	l.Allow("another")
	l.Allow("yet-another")
	if l.seen["new"] != nil {
		t.Fatal("stale suppressed entry kept past the extra window")
	}
}

func TestServePacket(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no udp:", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan []byte, 4)
	done := make(chan struct{})
	go func() { ServePacket(ctx, pc, 8, func(_ net.Addr, p []byte) { got <- p }); close(done) }()
	c, _ := net.Dial("udp", pc.LocalAddr().String())
	c.Write([]byte("abc"))
	c.Write([]byte("0123456789")) // longer than maxSize: truncated, still delivered
	for _, want := range []string{"abc", "01234567"} {
		select {
		case p := <-got:
			if string(p) != want {
				t.Errorf("got %q want %q", p, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("no datagram")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ServePacket did not stop")
	}
}
