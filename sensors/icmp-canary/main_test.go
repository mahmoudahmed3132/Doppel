// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/sdk/go/sensor"
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

func echo(typ byte, id, seq uint16, size int) []byte {
	b := make([]byte, size)
	b[0] = typ
	b[4], b[5], b[6], b[7] = byte(id>>8), byte(id), byte(seq>>8), byte(seq)
	return b
}

func TestEchoRequestAndCooldown(t *testing.T) {
	r := &rec{}
	cfg, _ := LoadSettings(r)
	c := NewCanary(cfg, r)
	now := time.Unix(0, 0)
	c.lim = sensor.NewSourceLimiter(time.Minute, 0)
	_ = now
	src := &net.IPAddr{IP: net.ParseIP("198.51.100.9")}
	c.Handle(echo(8, 0x1234, 7, 64), src, false)
	c.Handle(echo(8, 0x1234, 8, 64), src, false) // suppressed
	c.Handle(echo(0, 1, 1, 64), src, false)      // echo reply: ignored
	c.Handle(echo(3, 0, 0, 64), src, false)      // unreachable: ignored
	c.Handle([]byte{8}, src, false)              // truncated
	if len(r.ev) != 1 {
		t.Fatalf("%d events", len(r.ev))
	}
	e := r.ev[0]
	if e["icmp_type"] != 8 || e["icmp_id"] != 0x1234 || e["icmp_seq"] != 7 || e["packet_size"] != 64 || r.src[0] != "198.51.100.9" {
		t.Fatalf("%v %v", e, r.src)
	}
	c.Handle(echo(128, 5, 1, 56), &net.IPAddr{IP: net.ParseIP("2001:db8::1")}, true)
	if len(r.ev) != 2 || r.ev[1]["ip_version"] != 6 || r.src[1] != "2001:db8::1" {
		t.Fatalf("%v", r.ev)
	}
}

func TestSuppressedCounterReported(t *testing.T) {
	r := &rec{}
	cfg, _ := LoadSettings(&rec{cfg: map[string]string{"TS_COOLDOWN_SEC": "0"}})
	c := NewCanary(cfg, r)
	src := &net.IPAddr{IP: net.ParseIP("203.0.113.1")}
	c.cfg.Cooldown = time.Hour
	c.lim = sensor.NewSourceLimiter(50*time.Millisecond, 0)
	c.Handle(echo(8, 1, 1, 64), src, false)
	for i := 0; i < 5; i++ {
		c.Handle(echo(8, 1, 1, 64), src, false)
	}
	time.Sleep(60 * time.Millisecond)
	c.Handle(echo(8, 1, 1, 64), src, false)
	if len(r.ev) != 2 || r.ev[1]["suppressed_since_last"] != 5 {
		t.Fatalf("%v", r.ev)
	}
}

func TestSettings(t *testing.T) {
	s, err := LoadSettings(&rec{cfg: map[string]string{"TS_ICMP_TYPES": "8, 13", "TS_IPV6": "false"}})
	if err != nil || !s.TypesV4[13] || s.TypesV4[17] || s.IPv6 {
		t.Fatalf("%+v %v", s, err)
	}
	if _, err := LoadSettings(&rec{cfg: map[string]string{"TS_ICMP_TYPES": "300"}}); err == nil {
		t.Fatal("bad type accepted")
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
	code := sensor.Run(context.Background(), spec, sensor.Options{Getenv: func(k string) string { return env[k] },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if code != 0 || len(got) != 1 || got[0]["trigger"] != Trigger || got[0]["severity"] != "low" {
		t.Fatalf("%d %v", code, got)
	}
}
