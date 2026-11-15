// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Command network-scan-detector passively captures inbound frames (§11.3)
// and reports sources that touch many distinct ports within a window. It
// needs NET_RAW (uid 0) and host networking; it never sends packets.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

var spec = sensor.Spec{
	Drill: sensor.Drill{
		Trigger: Trigger, Target: "host (fire drill)", Severity: sensor.SeverityHigh,
		Details: sensor.Fields{sensor.F("scan_type", "syn"), sensor.F("tool_guess", ""), sensor.F("ports_hit", []int{}),
			sensor.F("count", 0), sensor.F("window_sec", 60)},
	},
	Run: run,
}

func main() { sensor.Main(spec) }

// Settings is the parsed configuration.
type Settings struct {
	Threshold      int
	Window         time.Duration
	Ignored        map[int]bool
	IgnoreLoopback bool
	MaxSources     int
}

func atoi(r sensor.Reporter, k string, def, min, max int) (int, error) {
	v, ok := r.Setting(k)
	if !ok {
		return def, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < min || n > max {
		return 0, fmt.Errorf("%s must be %d..%d", k, min, max)
	}
	return n, nil
}

// LoadSettings reads TS_ configuration.
func LoadSettings(r sensor.Reporter) (*Settings, error) {
	s := &Settings{Ignored: map[int]bool{}, IgnoreLoopback: true}
	var err error
	if s.Threshold, err = atoi(r, "TS_THRESHOLD", 10, 2, 1024); err != nil {
		return nil, err
	}
	w, err := atoi(r, "TS_WINDOW_SEC", 60, 1, 3600)
	if err != nil {
		return nil, err
	}
	s.Window = time.Duration(w) * time.Second
	if s.MaxSources, err = atoi(r, "TS_MAX_SOURCES", 4096, 16, 1<<20); err != nil {
		return nil, err
	}
	if v, ok := r.Setting("TS_IGNORED_PORTS"); ok {
		for _, it := range strings.Split(v, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(it))
			if err != nil || n < 1 || n > 65535 {
				return nil, fmt.Errorf("TS_IGNORED_PORTS: invalid port %q", sensor.Clean(it, 10))
			}
			s.Ignored[n] = true
		}
	}
	if v, ok := r.Setting("TS_IGNORE_LOOPBACK"); ok {
		s.IgnoreLoopback = v != "false"
	}
	return s, nil
}

// Linux AF_PACKET constants.
const (
	ethPAll     = 0x0003
	packetHost  = 0
	arphrdEther = 1
	arphrdLoop  = 772
	arphrdNone  = 65534
	arphrdRawIP = 519
)

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func run(ctx context.Context, s *sensor.Sensor) error {
	cfg, err := LoadSettings(s)
	if err != nil {
		return err
	}
	sensor.LogPrivileges(s.Logger())
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return fmt.Errorf("opening packet socket: %w (needs NET_RAW as uid 0)", err)
	}
	defer syscall.Close(fd)
	// A receive timeout lets the loop observe cancellation.
	tv := syscall.Timeval{Sec: 1}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	loIndex := -1
	if cfg.IgnoreLoopback {
		if lo, err := net.InterfaceByName("lo"); err == nil {
			loIndex = lo.Index
		}
	}
	det := NewDetector(cfg.Threshold, cfg.Window, cfg.Ignored, cfg.MaxSources, s)
	s.Logger().Info("scan detector capturing inbound frames", "threshold", cfg.Threshold, "window_sec", int(cfg.Window/time.Second))
	buf := make([]byte, 256) // headers only
	for ctx.Err() == nil {
		n, from, err := syscall.Recvfrom(fd, buf, syscall.MSG_TRUNC)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
				continue
			}
			return fmt.Errorf("capture: %w", err)
		}
		ll, ok := from.(*syscall.SockaddrLinklayer)
		if !ok || ll.Pkttype != packetHost || ll.Ifindex == loIndex {
			continue // outgoing, broadcast/multicast/other-host, or loopback
		}
		if n > len(buf) {
			n = len(buf)
		}
		var p Probe
		switch ll.Hatype {
		case arphrdEther, arphrdLoop:
			p, ok = ParseFrame(buf[:n], true)
		case arphrdNone, arphrdRawIP:
			p, ok = ParseFrame(buf[:n], false)
		default:
			ok = false
		}
		if ok {
			det.Observe(p)
		}
	}
	return nil
}
