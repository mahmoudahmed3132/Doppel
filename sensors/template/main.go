// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

// Command template is the reference TrueSignal sensor. It listens on one TCP
// port, reports every connection as "template_connection" (one event per
// source per cooldown, with a suppressed counter), and closes the
// connection. Copy this directory to start a new sensor.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/sdk/go/sensor"
)

const (
	trigger = "template_connection"

	envPort     = "TS_TEMPLATE_PORT"
	envCooldown = "TS_TEMPLATE_COOLDOWN_SEC"

	defaultPort     = 9099
	defaultCooldown = 60
	maxConcurrent   = 64
)

func main() {
	sensor.Main(sensor.Spec{
		Drill: sensor.Drill{
			Trigger: trigger,
			Target:  "Template (fire drill)",
			Details: sensor.Fields{sensor.F("dst_port", 0), sensor.F("phase", "connect")},
		},
		Run: run,
	})
}

type settings struct {
	port     int
	cooldown time.Duration
}

func loadSettings(r sensor.Reporter) (settings, error) {
	s := settings{port: defaultPort, cooldown: defaultCooldown * time.Second}
	if v, ok := r.Setting(envPort); ok {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 || p > 65535 {
			return s, fmt.Errorf("%s: invalid port %q", envPort, v)
		}
		s.port = p
	}
	if v, ok := r.Setting(envCooldown); ok {
		c, err := strconv.Atoi(v)
		if err != nil || c < 0 || c > 86400 {
			return s, fmt.Errorf("%s: invalid value %q", envCooldown, v)
		}
		s.cooldown = time.Duration(c) * time.Second
	}
	return s, nil
}

func run(ctx context.Context, s *sensor.Sensor) error {
	cfg, err := loadSettings(s)
	if err != nil {
		return err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", net.JoinHostPort("", strconv.Itoa(cfg.port)))
	if err != nil {
		return err
	}
	s.Logger().Info("listening", "port", cfg.port)
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	return serve(ctx, ln, s, sensor.NewSourceLimiter(cfg.cooldown, 0))
}

func serve(ctx context.Context, ln net.Listener, r sensor.Reporter, lim *sensor.SourceLimiter) error {
	sem := make(chan struct{}, maxConcurrent)
	port := ln.Addr().(*net.TCPAddr).Port
	target := fmt.Sprintf("Template (port %d)", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			time.Sleep(50 * time.Millisecond) // transient accept error (e.g. EMFILE)
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			conn.Close() // over capacity: refuse without reporting
			continue
		}
		go func() {
			defer func() { <-sem }()
			defer conn.Close()
			src, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			ok, suppressed := lim.Allow(src)
			if !ok {
				return
			}
			r.ReportSeverity(sensor.SeverityMedium, trigger, conn.RemoteAddr().String(), target, sensor.Fields{
				sensor.F("dst_port", port),
				sensor.F("phase", "connect"),
				sensor.F("action_taken", "closed"),
				sensor.F("suppressed_since_last", suppressed),
			})
		}()
	}
}
