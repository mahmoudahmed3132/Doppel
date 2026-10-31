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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/sdk/go/sensor"
)

type event struct {
	sev     sensor.Severity
	trigger string
	source  string
	details map[string]any
}

type rec struct {
	mu  sync.Mutex
	ev  []event
	cfg map[string]string
}

func (r *rec) ReportSeverity(sev sensor.Severity, trig, src, _ string, d sensor.Details) {
	m := map[string]any{}
	for _, f := range d.(sensor.Fields) {
		m[f.Key] = f.Value
	}
	r.mu.Lock()
	r.ev = append(r.ev, event{sev, trig, src, m})
	r.mu.Unlock()
}
func (r *rec) Setting(k string) (string, bool) { v, ok := r.cfg[k]; return v, ok }
func (r *rec) events(trig string) []event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []event
	for _, e := range r.ev {
		if e.trigger == trig {
			out = append(out, e)
		}
	}
	return out
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func start(t *testing.T, cfg *Settings, setup ...func(port int)) (*Tarpit, *rec, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range setup {
		f(ln.Addr().(*net.TCPAddr).Port)
	}
	r := &rec{}
	tp := NewTarpit(cfg, r)
	tp.ReadDelay, tp.EchoDelay = time.Millisecond, time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { tp.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); ln.Close(); <-done })
	return tp, r, ln.Addr().String()
}

func cfg(mode string) *Settings {
	return &Settings{Mode: mode, MaxDuration: 5 * time.Second, Banners: map[int][]byte{}, MaxConns: 8, MaxPerSrc: 2, Cooldown: time.Hour}
}

func TestHoldCapturesPayload(t *testing.T) {
	_, r, addr := start(t, cfg("hold"))
	c, _ := net.Dial("tcp", addr)
	c.Write([]byte("USER root\r\n\x00\xffPASS " + strings.Repeat("A", 3000)))
	time.Sleep(50 * time.Millisecond)
	c.Close()
	waitFor(t, func() bool { return len(r.events(TriggerPayload)) == 1 })
	conn := r.events(TriggerConnection)
	if len(conn) != 1 || conn[0].details["action_taken"] != "hold" || conn[0].details["phase"] != "connect" {
		t.Fatalf("%+v", conn)
	}
	p := r.events(TriggerPayload)[0]
	payload := p.details["payload"].(string)
	if !strings.HasPrefix(payload, `USER root\r\n\x00\xffPASS `) || p.details["bytes_received"].(int) < 3000 || p.details["phase"] != "close" {
		t.Fatalf("%+v", p.details)
	}
	if strings.ContainsAny(payload, "\r\n\x00") || len(payload) > 4*maxCapture {
		t.Fatal("payload not escaped/bounded")
	}
}

func TestEchoAndBannerAndClose(t *testing.T) {
	c1 := cfg("echo")
	_, _, addr := start(t, c1)
	c, _ := net.Dial("tcp", addr)
	c.Write([]byte("ping"))
	buf := make([]byte, 4)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo: %q %v", buf, err)
	}
	c.Close()

	c2 := cfg("close")
	_, r, addr := start(t, c2, func(port int) { c2.Banners[port] = []byte("SSH-2.0-OpenSSH_9.6\r\n") })
	conn, _ := net.Dial("tcp", addr)
	b, _ := io.ReadAll(conn)
	if string(b) != "SSH-2.0-OpenSSH_9.6\r\n" {
		t.Fatalf("banner %q", b)
	}
	waitFor(t, func() bool { return len(r.events(TriggerConnection)) == 1 })
	if len(r.events(TriggerPayload)) != 0 {
		t.Fatal("payload event without data")
	}
}

func TestLimitsAndCooldown(t *testing.T) {
	_, r, addr := start(t, cfg("hold"))
	var conns []net.Conn
	for i := 0; i < 5; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	time.Sleep(100 * time.Millisecond)
	// Per-source cap 2: the rest are closed by the tarpit.
	open := 0
	for _, c := range conns {
		c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, err := c.Read(make([]byte, 1))
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			open++
		}
		c.Close()
	}
	if open != 2 {
		t.Fatalf("%d connections held, want 2", open)
	}
	if n := len(r.events(TriggerConnection)); n != 1 {
		t.Fatalf("cooldown not applied: %d events", n)
	}
}

func TestBanners(t *testing.T) {
	b, err := ParseBanners(`22=SSH-2.0-OpenSSH_8.9\r\n|21=220 FTP ready\r\n`)
	if err != nil || string(b[22]) != "SSH-2.0-OpenSSH_8.9\r\n" || string(b[21]) != "220 FTP ready\r\n" {
		t.Fatalf("%v %v", b, err)
	}
	for _, bad := range []string{"x=1", "22=a\x01b", `22=\q`, "22=" + strings.Repeat("a", 600)} {
		if _, err := ParseBanners(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestSettings(t *testing.T) {
	if _, err := LoadSettings(&rec{cfg: map[string]string{}}); err == nil {
		t.Fatal("missing TS_PORTS accepted")
	}
	s, err := LoadSettings(&rec{cfg: map[string]string{"TS_PORTS": "22, 2222,22", "TS_MODE": "echo"}})
	if err != nil || len(s.Ports) != 2 || s.Mode != "echo" || s.MaxPerSrc != 16 || s.MaxConns != 512 {
		t.Fatalf("%+v %v", s, err)
	}
	if _, err := LoadSettings(&rec{cfg: map[string]string{"TS_PORTS": "22", "TS_MODE": "proxy"}}); err == nil {
		t.Fatal("unknown mode accepted")
	}
}

// §14.12: test mode sends the synthetic event and exits 0 against a mock Hub.
func TestTestModeAgainstMockHub(t *testing.T) {
	var mu sync.Mutex
	var got []map[string]any
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b struct{ Events []map[string]any }
		json.NewDecoder(r.Body).Decode(&b)
		mu.Lock()
		got = append(got, b.Events...)
		mu.Unlock()
		io.WriteString(w, `{"ok":true,"accepted":1,"duplicates":0,"rejected":[]}`)
	}))
	defer hub.Close()
	env := map[string]string{"TS_HUB_ENDPOINT": hub.URL, "TS_TEST_MODE": "true", "TS_SENSOR_ID": "ts-sensor-tcp-tarpit"}
	code := sensor.Run(context.Background(), spec, sensor.Options{Getenv: func(k string) string { return env[k] },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if code != 0 || len(got) != 1 || got[0]["trigger"] != TriggerConnection || got[0]["source"] != "Fire drill" {
		t.Fatalf("exit %d events %v", code, got)
	}
}
