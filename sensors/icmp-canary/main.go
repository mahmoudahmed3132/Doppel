// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Command icmp-canary reports ICMP requests reaching the host (§11.2): a raw
// ICMP socket (NET_RAW, host network) receives a copy of every ICMP packet;
// the kernel still answers pings itself. Nothing is ever sent.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/sdk/go/sensor"
)

// Trigger is the only event of this sensor.
const Trigger = "icmp_scan_received"

var spec = sensor.Spec{
	Drill: sensor.Drill{
		Trigger: Trigger, Target: "ICMP (fire drill)", Severity: sensor.SeverityLow,
		Details: sensor.Fields{sensor.F("icmp_type", 8), sensor.F("icmp_id", 0), sensor.F("icmp_seq", 0), sensor.F("packet_size", 0)},
	},
	Run: run,
}

func main() { sensor.Main(spec) }

// Request types reported by default: echo, timestamp, information and
// address-mask requests (IPv4); echo request and node information query
// (IPv6). Replies and errors are answers to the host's own traffic.
var (
	defaultV4 = []int{8, 13, 15, 17}
	defaultV6 = []int{128, 139}
)

// Settings is the parsed configuration.
type Settings struct {
	Cooldown time.Duration
	TypesV4  map[int]bool
	TypesV6  map[int]bool
	IPv6     bool
}

func set(types []int) map[int]bool {
	m := map[int]bool{}
	for _, t := range types {
		m[t] = true
	}
	return m
}

// LoadSettings reads TS_ configuration.
func LoadSettings(r sensor.Reporter) (*Settings, error) {
	s := &Settings{Cooldown: 60 * time.Second, TypesV4: set(defaultV4), TypesV6: set(defaultV6), IPv6: true}
	if v, ok := r.Setting("TS_COOLDOWN_SEC"); ok {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 86400 {
			return nil, errors.New("TS_COOLDOWN_SEC must be 0..86400")
		}
		s.Cooldown = time.Duration(n) * time.Second
	}
	if v, ok := r.Setting("TS_ICMP_TYPES"); ok {
		var types []int
		for _, it := range strings.Split(v, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(it))
			if err != nil || n < 0 || n > 255 {
				return nil, fmt.Errorf("TS_ICMP_TYPES: invalid type %q", sensor.Clean(it, 10))
			}
			types = append(types, n)
		}
		s.TypesV4 = set(types)
	}
	if v, ok := r.Setting("TS_IPV6"); ok {
		s.IPv6 = v == "true"
	}
	return s, nil
}

// Packet is a parsed ICMP message.
type Packet struct {
	Type, Code int
	ID, Seq    int
	Size       int
}

// Parse decodes an ICMP message (without IP header). Echo-style messages
// carry identifier and sequence; for others they are reported as 0.
func Parse(b []byte, v6 bool) (Packet, bool) {
	if len(b) < 4 {
		return Packet{}, false
	}
	p := Packet{Type: int(b[0]), Code: int(b[1]), Size: len(b)}
	echo := (!v6 && (p.Type == 8 || p.Type == 0 || p.Type == 13 || p.Type == 15 || p.Type == 17)) ||
		(v6 && (p.Type == 128 || p.Type == 129))
	if echo && len(b) >= 8 {
		p.ID = int(b[4])<<8 | int(b[5])
		p.Seq = int(b[6])<<8 | int(b[7])
	}
	return p, true
}

// Canary turns packets into events.
type Canary struct {
	cfg *Settings
	r   sensor.Reporter
	lim *sensor.SourceLimiter
}

// NewCanary returns a canary.
func NewCanary(cfg *Settings, r sensor.Reporter) *Canary {
	return &Canary{cfg: cfg, r: r, lim: sensor.NewSourceLimiter(cfg.Cooldown, 0)}
}

// Handle processes one received message from src.
func (c *Canary) Handle(b []byte, src net.Addr, v6 bool) {
	p, ok := Parse(b, v6)
	if !ok {
		return
	}
	if (v6 && !c.cfg.TypesV6[p.Type]) || (!v6 && !c.cfg.TypesV4[p.Type]) {
		return
	}
	ip := src.String()
	if a, ok := src.(*net.IPAddr); ok {
		ip = a.IP.String()
	}
	allowed, suppressed := c.lim.Allow(ip)
	if !allowed {
		return
	}
	proto := "ICMP"
	if v6 {
		proto = "ICMPv6"
	}
	c.r.ReportSeverity(sensor.SeverityLow, Trigger, ip, proto+" (host)", sensor.Fields{
		sensor.F("icmp_type", p.Type), sensor.F("icmp_code", p.Code), sensor.F("icmp_id", p.ID), sensor.F("icmp_seq", p.Seq),
		sensor.F("packet_size", p.Size), sensor.F("ip_version", map[bool]int{false: 4, true: 6}[v6]),
		sensor.F("suppressed_since_last", suppressed),
	})
}

// Serve reads from pc until ctx ends.
func (c *Canary) Serve(ctx context.Context, pc net.PacketConn, v6 bool) {
	stop := context.AfterFunc(ctx, func() { pc.Close() })
	defer stop()
	buf := make([]byte, 65536)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		c.Handle(buf[:n], src, v6)
	}
}

func run(ctx context.Context, s *sensor.Sensor) error {
	cfg, err := LoadSettings(s)
	if err != nil {
		return err
	}
	sensor.LogPrivileges(s.Logger())
	c := NewCanary(cfg, s)
	v4, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("opening raw ICMP socket: %w (needs NET_RAW as uid 0)", err)
	}
	done := make(chan struct{}, 2)
	go func() { c.Serve(ctx, v4, false); done <- struct{}{} }()
	waits := 1
	if cfg.IPv6 {
		if v6, err := net.ListenPacket("ip6:ipv6-icmp", "::"); err != nil {
			s.Logger().Warn("IPv6 ICMP unavailable; IPv4 only", "error", err.Error())
		} else {
			waits++
			go func() { c.Serve(ctx, v6, true); done <- struct{}{} }()
		}
	}
	s.Logger().Info("ICMP canary listening", "ipv6", waits == 2)
	for i := 0; i < waits; i++ {
		<-done
	}
	return nil
}
