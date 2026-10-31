// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/sdk/go/sensor"
)

// Tarpit serves connections on one or more listeners.
type Tarpit struct {
	cfg  *Settings
	r    sensor.Reporter
	conn *sensor.SourceLimiter // tcp_connection per source+port
	pay  *sensor.SourceLimiter // tcp_session_payload per source
	sem  chan struct{}

	// ReadDelay paces reads in hold mode; EchoDelay paces echoed chunks.
	ReadDelay time.Duration
	EchoDelay time.Duration
	Now       func() time.Time

	mu    sync.Mutex
	perIP map[string]int
}

// NewTarpit returns a tarpit for cfg reporting to r.
func NewTarpit(cfg *Settings, r sensor.Reporter) *Tarpit {
	return &Tarpit{
		cfg: cfg, r: r,
		conn: sensor.NewSourceLimiter(cfg.Cooldown, 0), pay: sensor.NewSourceLimiter(cfg.Cooldown, 0),
		sem: make(chan struct{}, cfg.MaxConns), ReadDelay: time.Second, EchoDelay: 500 * time.Millisecond,
		Now: time.Now, perIP: map[string]int{},
	}
}

func (t *Tarpit) acquire(ip string) bool {
	select {
	case t.sem <- struct{}{}:
	default:
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.perIP[ip] >= t.cfg.MaxPerSrc {
		<-t.sem
		return false
	}
	t.perIP[ip]++
	return true
}

func (t *Tarpit) release(ip string) {
	t.mu.Lock()
	if t.perIP[ip]--; t.perIP[ip] <= 0 {
		delete(t.perIP, ip)
	}
	t.mu.Unlock()
	<-t.sem
}

// Serve accepts connections on ln until it is closed.
func (t *Tarpit) Serve(ctx context.Context, ln net.Listener) {
	port := ln.Addr().(*net.TCPAddr).Port
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond) // e.g. EMFILE
			continue
		}
		ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		if !t.acquire(ip) {
			c.Close() // over capacity: refuse without reporting (bounded)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer t.release(ip)
			t.handle(ctx, c, ip, port)
		}()
	}
}

func target(port int) string { return "TCP port " + strconv.Itoa(port) }

func (t *Tarpit) handle(ctx context.Context, c net.Conn, ip string, port int) {
	defer c.Close()
	start := t.Now()
	src := c.RemoteAddr().String()
	if ok, sup := t.conn.Allow(ip + "|" + strconv.Itoa(port)); ok {
		t.r.ReportSeverity(sensor.SeverityMedium, TriggerConnection, src, target(port), sensor.Fields{
			sensor.F("dst_port", port), sensor.F("phase", "connect"), sensor.F("action_taken", t.cfg.Mode),
			sensor.F("suppressed_since_last", sup),
		})
	}
	_ = c.SetDeadline(start.Add(t.cfg.MaxDuration))
	stop := context.AfterFunc(ctx, func() { c.SetDeadline(time.Now()) })
	defer stop()

	if b := t.cfg.Banners[port]; len(b) > 0 {
		if _, err := c.Write(b); err != nil {
			return
		}
	}
	var (
		captured []byte
		total    int
	)
	if t.cfg.Mode != "close" {
		buf := make([]byte, readChunk)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				total += n
				if room := maxCapture - len(captured); room > 0 {
					captured = append(captured, buf[:min(n, room)]...)
				}
				if t.cfg.Mode == "echo" {
					// Echo back slowly, in small chunks (bounded by what was read).
					for off := 0; off < n; off += 16 {
						if _, err := c.Write(buf[off:min(n, off+16)]); err != nil {
							break
						}
						if !t.pause(ctx, t.EchoDelay) {
							break
						}
					}
				}
			}
			if err != nil {
				break
			}
			if t.cfg.Mode == "hold" && !t.pause(ctx, t.ReadDelay) {
				break
			}
		}
	}
	if total == 0 {
		return
	}
	if ok, sup := t.pay.Allow(ip); ok {
		t.r.ReportSeverity(sensor.SeverityHigh, TriggerPayload, src, target(port), sensor.Fields{
			sensor.F("dst_port", port), sensor.F("bytes_received", total),
			sensor.F("duration_sec", int(t.Now().Sub(start)/time.Second)),
			sensor.F("payload", sensor.Printable(captured, maxCapture)), sensor.F("phase", "close"),
			sensor.F("suppressed_since_last", sup),
		})
	}
}

func (t *Tarpit) pause(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
