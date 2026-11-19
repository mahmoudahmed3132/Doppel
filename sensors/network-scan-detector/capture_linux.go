// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

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
