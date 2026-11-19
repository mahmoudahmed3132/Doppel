// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Command token-receiver is the callback end of the Hub's beacons: DNS names,
// web bugs and kubeconfig files an operator plants where only an intruder
// would use them. When one is resolved or fetched, the lookup or request
// lands here and becomes a beacon_triggered event.
//
// It is the one component meant to face the internet (beacons fire from
// wherever the artefact is opened), so it runs on its own node in a DMZ and
// only talks outbound to the Hub. It serves an authoritative-only DNS zone and
// a fixed-response HTTP endpoint; it never resolves, forwards or proxies.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/decoy"
	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

func main() {
	sensor.Main(sensor.Spec{
		Drill: sensor.Drill{
			Trigger: Trigger,
			Target:  "DNS (beacon zone, fire drill)",
			Details: sensor.Fields{sensor.F("token", "firedrill"), sensor.F("channel", "dns")},
		},
		Run: run,
	})
}

type config struct {
	zone     zone
	key      string
	proxies  []*net.IPNet
	cooldown time.Duration
	dnsPort  int
	httpPort int // 0: HTTP off
}

func setting(r sensor.Reporter, k, def string) string {
	if v, ok := r.Setting(k); ok {
		return v
	}
	return def
}

func portSetting(r sensor.Reporter, k string, def int, allowZero bool) (int, error) {
	v := setting(r, k, strconv.Itoa(def))
	p, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || p < 0 || p > 65535 || (p == 0 && !allowZero) {
		return 0, fmt.Errorf("%s: invalid port %q", k, v)
	}
	return p, nil
}

func loadConfig(r sensor.Reporter) (config, error) {
	var c config
	var err error
	if c.zone, err = loadZone(setting(r, "TS_BEACON_DOMAIN", ""), setting(r, "TS_BEACON_NS", ""), setting(r, "TS_ANSWER_IPV4", "")); err != nil {
		return c, err
	}
	if c.key = setting(r, "TS_BEACON_KEY", ""); c.key == "" {
		return c, errors.New("TS_BEACON_KEY is empty; the Hub sets it: deploy this sensor through the Hub")
	}
	if c.proxies, err = parseCIDRs(setting(r, "TS_TRUSTED_PROXIES", "")); err != nil {
		return c, err
	}
	sec, err := strconv.Atoi(setting(r, "TS_ALERT_COOLDOWN_SEC", "60"))
	if err != nil || sec < 0 || sec > 86400 {
		return c, errors.New("TS_ALERT_COOLDOWN_SEC: want 0..86400")
	}
	c.cooldown = time.Duration(sec) * time.Second
	if c.dnsPort, err = portSetting(r, "TS_DNS_PORT", 53, false); err != nil {
		return c, err
	}
	if c.httpPort, err = portSetting(r, "TS_HTTP_PORT", 80, true); err != nil {
		return c, err
	}
	if c.httpPort == c.dnsPort {
		return c, errors.New("TS_HTTP_PORT and TS_DNS_PORT must differ")
	}
	return c, nil
}

func run(ctx context.Context, s *sensor.Sensor) error {
	c, err := loadConfig(s)
	if err != nil {
		return err
	}
	r := &receiver{ts: s, zone: c.zone, verify: verifier{key: []byte(c.key)}, proxies: c.proxies, cooldown: c.cooldown,
		replies: decoy.NewLimiter(50, time.Second), seen: map[string]*cooldownState{}, now: time.Now}
	sat := newSaturation(s, c.zone.domain)
	log := s.Logger()

	var lc net.ListenConfig
	bind := net.JoinHostPort("", strconv.Itoa(c.dnsPort))
	pc, err := lc.ListenPacket(ctx, "udp", bind)
	if err != nil {
		return fmt.Errorf("bind dns udp/%d: %w", c.dnsPort, err)
	}
	ln, err := lc.Listen(ctx, "tcp", bind)
	if err != nil {
		pc.Close()
		return fmt.Errorf("bind dns tcp/%d: %w", c.dnsPort, err)
	}
	go r.serveDNSUDP(ctx, pc)
	go decoy.Accept(ctx, newLimitListener(ln, "dns", maxDNSTCPConns, perSourceDNS, nil, sat.refused), r.serveDNSTCP)
	log.Info("serving beacon zone", "zone", c.zone.domain, "port", c.dnsPort, "ns", strings.Join(c.zone.ns, ","))

	if c.httpPort != 0 {
		hl, err := lc.Listen(ctx, "tcp", net.JoinHostPort("", strconv.Itoa(c.httpPort)))
		if err != nil {
			return fmt.Errorf("bind http/%d: %w", c.httpPort, err)
		}
		srv := r.httpServer()
		go srv.Serve(newLimitListener(hl, "http", maxHTTPConns, perSourceHTTP, r.trustedProxy, sat.refused))
		go func() {
			<-ctx.Done()
			srv.Close()
		}()
		log.Info("serving HTTP beacons", "port", c.httpPort)
	}
	if c.zone.ipv4 == nil {
		log.Warn("TS_ANSWER_IPV4 is not set: A queries get NODATA, so web bugs cannot reach this receiver")
	}
	<-ctx.Done()
	return nil
}
