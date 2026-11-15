// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Command tcp-tarpit listens on configured TCP ports, reports connections
// and payloads, and holds, echoes or closes them (§11.1). It never forwards
// traffic and never interprets received bytes.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

// Triggers.
const (
	TriggerConnection = "tcp_connection"
	TriggerPayload    = "tcp_session_payload"
)

var spec = sensor.Spec{
	Drill: sensor.Drill{
		Trigger: TriggerConnection,
		Target:  "TCP tarpit (fire drill)",
		Details: sensor.Fields{sensor.F("dst_port", 0), sensor.F("phase", "connect"), sensor.F("action_taken", "drill")},
	},
	Run: run,
}

func main() { sensor.Main(spec) }

// Settings is the parsed sensor configuration.
type Settings struct {
	Ports       []int
	Mode        string // hold | echo | close
	MaxDuration time.Duration
	Banners     map[int][]byte
	MaxConns    int
	MaxPerSrc   int
	Cooldown    time.Duration
}

const (
	maxBanner   = 512
	maxCapture  = 2048
	readChunk   = 64
	defaultHold = 600
)

func intSetting(r sensor.Reporter, key string, def, min, max int) (int, error) {
	v, ok := r.Setting(key)
	if !ok {
		return def, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < min || n > max {
		return 0, fmt.Errorf("%s must be an integer in %d..%d", key, min, max)
	}
	return n, nil
}

// LoadSettings reads the TS_ configuration.
func LoadSettings(r sensor.Reporter) (*Settings, error) {
	s := &Settings{Mode: "hold", Banners: map[int][]byte{}}
	raw, ok := r.Setting("TS_PORTS")
	if !ok {
		return nil, errors.New("TS_PORTS is required")
	}
	seen := map[int]bool{}
	for _, p := range strings.Split(raw, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("TS_PORTS: invalid port %q", p)
		}
		if !seen[n] {
			seen[n] = true
			s.Ports = append(s.Ports, n)
		}
	}
	if len(s.Ports) == 0 || len(s.Ports) > 64 {
		return nil, errors.New("TS_PORTS must list 1..64 ports")
	}
	if m, ok := r.Setting("TS_MODE"); ok {
		switch m {
		case "hold", "echo", "close":
			s.Mode = m
		default:
			return nil, errors.New("TS_MODE must be hold, echo or close")
		}
	}
	var err error
	var secs int
	if secs, err = intSetting(r, "TS_MAX_DURATION_SEC", defaultHold, 1, 86400); err != nil {
		return nil, err
	}
	s.MaxDuration = time.Duration(secs) * time.Second
	if s.MaxConns, err = intSetting(r, "TS_MAX_CONNS", 512, 1, 65536); err != nil {
		return nil, err
	}
	if s.MaxPerSrc, err = intSetting(r, "TS_MAX_PER_SOURCE", 16, 1, 4096); err != nil {
		return nil, err
	}
	if secs, err = intSetting(r, "TS_EVENT_COOLDOWN_SEC", 10, 0, 86400); err != nil {
		return nil, err
	}
	s.Cooldown = time.Duration(secs) * time.Second
	if b, ok := r.Setting("TS_BANNERS"); ok {
		if s.Banners, err = ParseBanners(b); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// ParseBanners parses "port=banner|port=banner". Banners may use the
// escapes \r \n \t and \\; any other control byte is refused; at most 512
// bytes after decoding.
func ParseBanners(raw string) (map[int][]byte, error) {
	out := map[int][]byte{}
	for _, entry := range strings.Split(raw, "|") {
		if strings.TrimSpace(entry) == "" {
			continue
		}
		k, v, ok := strings.Cut(entry, "=")
		port, err := strconv.Atoi(strings.TrimSpace(k))
		if !ok || err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("TS_BANNERS: entry %q must be port=banner", sensor.Clean(entry, 40))
		}
		var b []byte
		for i := 0; i < len(v); i++ {
			c := v[i]
			if c == '\\' && i+1 < len(v) {
				i++
				switch v[i] {
				case 'r':
					b = append(b, '\r')
				case 'n':
					b = append(b, '\n')
				case 't':
					b = append(b, '\t')
				case '\\':
					b = append(b, '\\')
				default:
					return nil, fmt.Errorf("TS_BANNERS: unknown escape \\%c", v[i])
				}
				continue
			}
			if c < 0x20 || c == 0x7f {
				return nil, errors.New("TS_BANNERS: control characters must be escaped")
			}
			b = append(b, c)
		}
		if len(b) > maxBanner {
			return nil, fmt.Errorf("TS_BANNERS: banner for port %d exceeds %d bytes", port, maxBanner)
		}
		out[port] = b
	}
	return out, nil
}

func run(ctx context.Context, s *sensor.Sensor) error {
	cfg, err := LoadSettings(s)
	if err != nil {
		return err
	}
	sensor.LogPrivileges(s.Logger())
	t := NewTarpit(cfg, s)
	var lc net.ListenConfig
	var lns []net.Listener
	for _, p := range cfg.Ports {
		ln, err := lc.Listen(ctx, "tcp", net.JoinHostPort("", strconv.Itoa(p)))
		if err != nil {
			for _, l := range lns {
				l.Close()
			}
			return fmt.Errorf("listening on %d: %w (ports < 1024 need NET_BIND_SERVICE)", p, err)
		}
		lns = append(lns, ln)
	}
	s.Logger().Info("tarpit listening", "ports", cfg.Ports, "mode", cfg.Mode)
	var wg sync.WaitGroup
	for _, ln := range lns {
		wg.Add(1)
		go func(ln net.Listener) {
			defer wg.Done()
			t.Serve(ctx, ln)
		}(ln)
	}
	<-ctx.Done()
	for _, ln := range lns {
		ln.Close()
	}
	wg.Wait()
	return nil
}
