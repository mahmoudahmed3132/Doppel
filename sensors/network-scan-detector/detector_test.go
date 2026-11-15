// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

type rec struct {
	ev  []map[string]any
	src []string
	cfg map[string]string
}

func (r *rec) ReportSeverity(_ sensor.Severity, _, src, _ string, d sensor.Details) {
	m := map[string]any{}
	for _, f := range d.(sensor.Fields) {
		m[f.Key] = f.Value
	}
	r.ev, r.src = append(r.ev, m), append(r.src, src)
}
func (r *rec) Setting(k string) (string, bool) { v, ok := r.cfg[k]; return v, ok }

// frame builds an Ethernet/IPv4/TCP frame.
func frame(src [4]byte, dport uint16, flags byte, window uint16, opts []byte, ipid uint16) []byte {
	tcpLen := 20 + len(opts)
	b := make([]byte, 14+20+tcpLen)
	binary.BigEndian.PutUint16(b[12:], 0x0800)
	ip := b[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[4:], ipid)
	ip[8], ip[9] = 64, 6
	copy(ip[12:16], src[:])
	copy(ip[16:20], []byte{10, 0, 0, 1})
	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:], 40000)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	tcp[12] = byte(tcpLen/4) << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], window)
	copy(tcp[20:], opts)
	return b
}

var (
	mssOnly = []byte{2, 4, 0x05, 0xb4}
	linux   = []byte{2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7}
)

func TestParseFrame(t *testing.T) {
	p, ok := ParseFrame(frame([4]byte{198, 51, 100, 7}, 443, flagSYN, 1024, mssOnly, 1), true)
	if !ok || p.Src != "198.51.100.7" || p.DstPort != 443 || p.Proto != "tcp" || p.Options != "M" || p.Window != 1024 {
		t.Fatalf("%+v", p)
	}
	if ScanType(p) != "syn" || ToolGuess(p) != "nmap" {
		t.Fatalf("%s %s", ScanType(p), ToolGuess(p))
	}
	p, _ = ParseFrame(frame([4]byte{1, 2, 3, 4}, 22, flagSYN, 64240, linux, 1), true)
	if p.Options != "MSTNW" || ScanType(p) != "connect" || ToolGuess(p) != "" {
		t.Fatalf("%+v %s", p, ScanType(p))
	}
	for flags, want := range map[byte]string{0: "null", flagFIN: "fin", flagFIN | flagPSH | flagURG: "xmas"} {
		p, _ := ParseFrame(frame([4]byte{1, 2, 3, 4}, 22, flags, 1024, nil, 1), true)
		if ScanType(p) != want {
			t.Errorf("flags %x: %s", flags, ScanType(p))
		}
	}
	z, _ := ParseFrame(frame([4]byte{1, 2, 3, 4}, 22, flagSYN, 65535, nil, 54321), true)
	if ToolGuess(z) != "zmap" {
		t.Fatal("zmap fingerprint")
	}
	for _, bad := range [][]byte{nil, make([]byte, 10), frame([4]byte{}, 1, 0, 0, nil, 0)[:30]} {
		if _, ok := ParseFrame(bad, true); ok {
			t.Errorf("parsed garbage %x", bad)
		}
	}
	ack, _ := ParseFrame(frame([4]byte{1, 2, 3, 4}, 22, flagACK|flagPSH, 500, nil, 1), true)
	rst, _ := ParseFrame(frame([4]byte{1, 2, 3, 4}, 22, flagRST, 0, nil, 1), true)
	if IsScanProbe(ack) || IsScanProbe(rst) {
		t.Fatal("established/RST traffic counted as a probe")
	}
}

func TestDetectorThresholdWindowAndOncePerWindow(t *testing.T) {
	r := &rec{}
	now := time.Unix(1000, 0)
	d := NewDetector(10, time.Minute, map[int]bool{80: true}, 0, r)
	d.Now = func() time.Time { return now }
	src := [4]byte{203, 0, 113, 5}
	probe := func(port int) {
		p, _ := ParseFrame(frame(src, uint16(port), flagSYN, 1024, mssOnly, 7), true)
		d.Observe(p)
	}
	for port := 1; port <= 9; port++ {
		probe(port)
	}
	probe(80) // ignored
	if len(r.ev) != 0 {
		t.Fatal("fired below threshold")
	}
	probe(10)
	for port := 11; port <= 30; port++ {
		probe(port)
	}
	if len(r.ev) != 1 {
		t.Fatalf("%d events, want exactly 1 per window", len(r.ev))
	}
	e := r.ev[0]
	if e["scan_type"] != "syn" || e["tool_guess"] != "nmap" || e["count"] != 10 || e["window_sec"] != 60 || r.src[0] != "203.0.113.5" {
		t.Fatalf("%v", e)
	}
	if fmt.Sprint(e["ports_hit"]) != "[1 2 3 4 5 6 7 8 9 10]" {
		t.Fatalf("ports %v", e["ports_hit"])
	}
	// A slow scan spread beyond the window never reaches the threshold.
	r2 := &rec{}
	d2 := NewDetector(10, time.Minute, nil, 0, r2)
	t2 := time.Unix(0, 0)
	d2.Now = func() time.Time { return t2 }
	for port := 1; port <= 30; port++ {
		p, _ := ParseFrame(frame(src, uint16(port), flagSYN, 1024, mssOnly, 7), true)
		d2.Observe(p)
		t2 = t2.Add(10 * time.Second)
	}
	if len(r2.ev) != 0 {
		t.Fatal("slow scan beyond the window fired")
	}
	// After the window, a new scan alerts again.
	now = now.Add(2 * time.Minute)
	for port := 100; port < 110; port++ {
		probe(port)
	}
	if len(r.ev) != 2 {
		t.Fatalf("no second alert after the window: %d", len(r.ev))
	}
}

func TestDetectorBoundedMemory(t *testing.T) {
	d := NewDetector(1000, time.Minute, nil, 32, &rec{})
	for i := 0; i < 1000; i++ {
		p, _ := ParseFrame(frame([4]byte{10, byte(i >> 8), byte(i), 1}, 22, flagSYN, 1024, nil, 1), true)
		d.Observe(p)
	}
	if d.Sources() != 32 {
		t.Fatalf("tracked %d sources", d.Sources())
	}
	src := [4]byte{10, 9, 9, 9}
	for port := 1; port <= 5000; port++ {
		p, _ := ParseFrame(frame(src, uint16(port), flagSYN, 1024, nil, 1), true)
		d.Observe(p)
	}
	d.mu.Lock()
	n := len(d.srcs["10.9.9.9"].Value.(*sourceState).ports)
	d.mu.Unlock()
	if n > maxPortsPerSource {
		t.Fatalf("%d ports tracked for one source", n)
	}
}

func TestTestModeAgainstMockHub(t *testing.T) {
	var got []map[string]any
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b struct{ Events []map[string]any }
		json.NewDecoder(r.Body).Decode(&b)
		got = append(got, b.Events...)
		io.WriteString(w, `{"ok":true,"accepted":1,"duplicates":0,"rejected":[]}`)
	}))
	defer hub.Close()
	env := map[string]string{"TS_HUB_ENDPOINT": hub.URL, "TS_TEST_MODE": "true"}
	if code := sensor.Run(context.Background(), spec, sensor.Options{Getenv: func(k string) string { return env[k] },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}); code != 0 || len(got) != 1 || got[0]["severity"] != "high" {
		t.Fatalf("%d %v", code, got)
	}
}
