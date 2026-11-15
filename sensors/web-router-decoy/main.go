// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Command web-router-decoy serves a fake device login portal (§11.5) and
// reports page views, path probes and login attempts. Logins always fail.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

// ContainerPort is the fixed listening port inside the container.
const ContainerPort = 8080

// skins is the page renderer; replaced by the PORTED module on import.
var skins Skins = builtinSkins{}

var spec = sensor.Spec{
	Drill: sensor.Drill{
		Trigger: TriggerLogin, Target: "Web login (fire drill)", Severity: sensor.SeverityCritical,
		Details: sensor.Fields{sensor.F("username", "fire-drill"), sensor.F("auth", "form"), sensor.F("skin", "drill"),
			sensor.F("path", "/login"), sensor.F("method", "POST"), sensor.F("user_agent", ""), sensor.F("dst_port", 0)},
	},
	Run: run,
}

func main() { sensor.Main(spec) }

func seconds(r sensor.Reporter, k string, def int) (time.Duration, error) {
	v, ok := r.Setting(k)
	if !ok {
		return time.Duration(def) * time.Second, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 86400 {
		return 0, errors.New(k + " must be 0..86400")
	}
	return time.Duration(n) * time.Second, nil
}

// NewFromSettings builds the decoy and its port from TS_ configuration.
func NewFromSettings(r sensor.Reporter) (*Decoy, int, error) {
	port := 8080
	if v, ok := r.Setting("TS_PORT"); ok {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 65535 {
			return nil, 0, errors.New("TS_PORT must be 1..65535")
		}
		port = n
	}
	name, _ := r.Setting("TS_SKIN")
	skin, ok := skins.Skin(name)
	if !ok {
		return nil, 0, fmt.Errorf("TS_SKIN: unknown skin %q", sensor.Clean(name, 40))
	}
	capture := "hash"
	if v, ok := r.Setting("TS_PASSWORD_CAPTURE"); ok {
		capture = v
	}
	var key []byte
	switch capture {
	case "hash":
		raw, _ := r.Setting("TS_CAPTURE_KEY")
		k, err := hex.DecodeString(raw)
		if err != nil || len(k) < 16 {
			return nil, 0, errors.New("TS_CAPTURE_KEY (set by the Hub) is required for password capture \"hash\"")
		}
		key = k
	case "plain", "none":
	default:
		return nil, 0, errors.New("TS_PASSWORD_CAPTURE must be hash, plain or none")
	}
	view, err := seconds(r, "TS_PAGEVIEW_WINDOW_SEC", 300)
	if err != nil {
		return nil, 0, err
	}
	probe, err := seconds(r, "TS_PROBE_COOLDOWN_SEC", 10)
	if err != nil {
		return nil, 0, err
	}
	login, err := seconds(r, "TS_LOGIN_COOLDOWN_SEC", 0)
	if err != nil {
		return nil, 0, err
	}
	return NewDecoy(skin, capture, key, port, view, probe, login, r), port, nil
}

func run(ctx context.Context, s *sensor.Sensor) error {
	d, port, err := NewFromSettings(s)
	if err != nil {
		return err
	}
	sensor.LogPrivileges(s.Logger())
	srv := &http.Server{
		Handler:           d,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	// The container always listens on ContainerPort; the Hub publishes the
	// host port TS_PORT to it (bridge network), so the decoy needs no
	// privilege to appear on port 80.
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", net.JoinHostPort("", strconv.Itoa(ContainerPort)))
	if err != nil {
		return fmt.Errorf("listening on %d: %w", ContainerPort, err)
	}
	s.Logger().Info("web decoy listening", "port", port, "skin", d.Skin.Name(), "password_capture", d.Capture)
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	srv.Shutdown(sctx)
	return nil
}
