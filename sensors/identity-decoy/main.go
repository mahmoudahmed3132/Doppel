// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Command identity-decoy emulates Active Directory LDAP, LDAPS and RDP
// (NLA/CredSSP) services to capture credential guessing, directory enumeration
// and NTLM authentication attempts. Every login fails with a wire-accurate
// server error.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/decoy"
	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

// Triggers.
const (
	TriggerLDAPLogin       = "ldap_login"
	TriggerLDAPQuery       = "ldap_query"
	TriggerLDAPConnection  = "ldap_connection"
	TriggerLDAPSLogin      = "ldaps_login"
	TriggerLDAPSQuery      = "ldaps_query"
	TriggerLDAPSConnection = "ldaps_connection"
	TriggerRDPLogin        = "rdp_login"
	TriggerRDPConnection   = "rdp_connection"
)

const (
	defaultDomainDNS     = "corp.local"
	defaultDomainNetBIOS = "CORP"
	defaultHostname      = "DC01"
	defaultOSBuild       = "10.0.20348"
	defaultMaxConns      = 512
	defaultMaxPerSource  = 16
	defaultCooldownSec   = 10
	defaultIdleTimeout   = 30 * time.Second
	defaultTotalTimeout  = 2 * time.Minute
	loginLimiterBurst    = 6
)

var spec = sensor.Spec{
	Drill: sensor.Drill{
		Trigger:  TriggerLDAPLogin,
		Target:   "LDAP port 389 (fire drill)",
		Severity: sensor.SeverityHigh,
		Details: sensor.Fields{
			sensor.F("protocol", "ldap"),
			sensor.F("dst_port", 389),
			sensor.F("auth", "simple"),
			sensor.F("username", "drill"),
			sensor.F("bind_dn", "CN=drill,CN=Users,DC=corp,DC=local"),
		},
	},
	Run: run,
}

func main() { sensor.Main(spec) }

// Settings is the parsed sensor configuration.
type Settings struct {
	EnableLDAP  bool
	LDAPPort    int
	EnableLDAPS bool
	LDAPSPort   int
	EnableRDP   bool
	RDPPort     int

	Persona Persona

	MaxConns  int
	MaxPerSrc int
	Cooldown  time.Duration
}

func boolSetting(r sensor.Reporter, key string, def bool) (bool, error) {
	v, ok := r.Setting(key)
	if !ok {
		return def, nil
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1":
		return true, nil
	case "false", "0":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be true or false", key)
	}
}

func intSetting(r sensor.Reporter, key string, def, minVal, maxVal int) (int, error) {
	v, ok := r.Setting(key)
	if !ok {
		return def, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < minVal || n > maxVal {
		return 0, fmt.Errorf("%s must be an integer in %d..%d", key, minVal, maxVal)
	}
	return n, nil
}

func stringSetting(r sensor.Reporter, key, def string, maxLen int) (string, error) {
	v, ok := r.Setting(key)
	if !ok {
		return def, nil
	}
	if len(v) > maxLen {
		return "", fmt.Errorf("%s exceeds %d bytes", key, maxLen)
	}
	for i := 0; i < len(v); i++ {
		if v[i] == '\r' || v[i] == '\n' || v[i] == 0 {
			return "", fmt.Errorf("%s must not contain CR, LF or NUL", key)
		}
	}
	return v, nil
}

func parseOSBuild(raw string) (OSVersion, error) {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 3 {
		return OSVersion{}, errors.New("TS_OS_BUILD must be major.minor.build")
	}
	maj, err := strconv.Atoi(parts[0])
	if err != nil || maj < 0 || maj > 255 {
		return OSVersion{}, errors.New("TS_OS_BUILD major must be 0..255")
	}
	minV, err := strconv.Atoi(parts[1])
	if err != nil || minV < 0 || minV > 255 {
		return OSVersion{}, errors.New("TS_OS_BUILD minor must be 0..255")
	}
	bld, err := strconv.Atoi(parts[2])
	if err != nil || bld < 0 || bld > 65535 {
		return OSVersion{}, errors.New("TS_OS_BUILD build must be 0..65535")
	}
	return OSVersion{Major: uint8(maj), Minor: uint8(minV), Build: uint16(bld)}, nil
}

// LoadSettings reads and validates the TS_ configuration.
func LoadSettings(r sensor.Reporter) (*Settings, error) {
	s := &Settings{}
	var err error

	if s.EnableLDAP, err = boolSetting(r, "TS_ENABLE_LDAP", true); err != nil {
		return nil, err
	}
	if s.LDAPPort, err = intSetting(r, "TS_LDAP_PORT", 389, 1, 65535); err != nil {
		return nil, err
	}
	if s.EnableLDAPS, err = boolSetting(r, "TS_ENABLE_LDAPS", true); err != nil {
		return nil, err
	}
	if s.LDAPSPort, err = intSetting(r, "TS_LDAPS_PORT", 636, 1, 65535); err != nil {
		return nil, err
	}
	if s.EnableRDP, err = boolSetting(r, "TS_ENABLE_RDP", true); err != nil {
		return nil, err
	}
	if s.RDPPort, err = intSetting(r, "TS_RDP_PORT", 3389, 1, 65535); err != nil {
		return nil, err
	}

	if s.Persona.DomainDNS, err = stringSetting(r, "TS_DOMAIN_DNS", defaultDomainDNS, 128); err != nil {
		return nil, err
	}
	if strings.TrimSpace(s.Persona.DomainDNS) == "" {
		return nil, errors.New("TS_DOMAIN_DNS must not be empty")
	}
	if s.Persona.DomainNetBIOS, err = stringSetting(r, "TS_DOMAIN_NETBIOS", defaultDomainNetBIOS, 15); err != nil {
		return nil, err
	}
	if strings.TrimSpace(s.Persona.DomainNetBIOS) == "" {
		return nil, errors.New("TS_DOMAIN_NETBIOS must not be empty")
	}
	if s.Persona.Hostname, err = stringSetting(r, "TS_HOSTNAME", defaultHostname, 63); err != nil {
		return nil, err
	}
	if strings.TrimSpace(s.Persona.Hostname) == "" {
		return nil, errors.New("TS_HOSTNAME must not be empty")
	}
	osRaw, err := stringSetting(r, "TS_OS_BUILD", defaultOSBuild, 32)
	if err != nil {
		return nil, err
	}
	if s.Persona.OS, err = parseOSBuild(osRaw); err != nil {
		return nil, err
	}

	if s.MaxConns, err = intSetting(r, "TS_MAX_CONNS", defaultMaxConns, 1, 65536); err != nil {
		return nil, err
	}
	if s.MaxPerSrc, err = intSetting(r, "TS_MAX_PER_SOURCE", defaultMaxPerSource, 1, 4096); err != nil {
		return nil, err
	}
	cooldownSec, err := intSetting(r, "TS_EVENT_COOLDOWN_SEC", defaultCooldownSec, 0, 86400)
	if err != nil {
		return nil, err
	}
	s.Cooldown = time.Duration(cooldownSec) * time.Second

	if !s.EnableLDAP && !s.EnableLDAPS && !s.EnableRDP {
		return nil, errors.New("at least one protocol (TS_ENABLE_LDAP, TS_ENABLE_LDAPS, TS_ENABLE_RDP) must be enabled")
	}

	ports := map[int]string{}
	checkPort := func(enabled bool, proto string, port int) error {
		if !enabled {
			return nil
		}
		if prev, dup := ports[port]; dup {
			return fmt.Errorf("port %d configured for both %s and %s", port, prev, proto)
		}
		ports[port] = proto
		return nil
	}
	if err := checkPort(s.EnableLDAP, "ldap", s.LDAPPort); err != nil {
		return nil, err
	}
	if err := checkPort(s.EnableLDAPS, "ldaps", s.LDAPSPort); err != nil {
		return nil, err
	}
	if err := checkPort(s.EnableRDP, "rdp", s.RDPPort); err != nil {
		return nil, err
	}
	return s, nil
}

// Decoy serves the enabled LDAP, LDAPS and RDP listeners.
type Decoy struct {
	cfg          *Settings
	r            sensor.Reporter
	capture      decoy.Capture
	tlsCfg       *tls.Config
	connLimiter  *decoy.Limiter
	loginLimiter *decoy.Limiter

	sem   chan struct{}
	mu    sync.Mutex
	perIP map[string]int

	idleTimeout  time.Duration
	totalTimeout time.Duration
	authDelay    func(minD, maxD time.Duration) time.Duration
	now          func() time.Time
}

// NewDecoy constructs a Decoy from cfg, generating a fresh ephemeral in-memory
// self-signed ECDSA P-256 TLS certificate for the persona host.
func NewDecoy(cfg *Settings, r sensor.Reporter) (*Decoy, error) {
	capPolicy, err := decoy.NewCapture(r)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := generateEphemeralTLSConfig(cfg.Persona.Hostname, cfg.Persona.DomainDNS, time.Now())
	if err != nil {
		return nil, err
	}
	d := &Decoy{
		cfg:          cfg,
		r:            r,
		capture:      capPolicy,
		tlsCfg:       tlsCfg,
		sem:          make(chan struct{}, cfg.MaxConns),
		perIP:        map[string]int{},
		idleTimeout:  defaultIdleTimeout,
		totalTimeout: defaultTotalTimeout,
		authDelay:    randomDelay,
		now:          time.Now,
	}
	if cfg.Cooldown > 0 {
		d.connLimiter = decoy.NewLimiter(1, cfg.Cooldown)
		d.loginLimiter = decoy.NewLimiter(loginLimiterBurst, cfg.Cooldown)
	}
	return d, nil
}

func randomDelay(minD, maxD time.Duration) time.Duration {
	if maxD <= minD {
		return minD
	}
	return minD + rand.N(maxD-minD+1)
}

func (d *Decoy) acquire(ip string) bool {
	select {
	case d.sem <- struct{}{}:
	default:
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.perIP[ip] >= d.cfg.MaxPerSrc {
		<-d.sem
		return false
	}
	d.perIP[ip]++
	return true
}

func (d *Decoy) release(ip string) {
	d.mu.Lock()
	if d.perIP[ip]--; d.perIP[ip] <= 0 {
		delete(d.perIP, ip)
	}
	d.mu.Unlock()
	<-d.sem
}

func (d *Decoy) allowLogin(ip, proto string) (bool, int) {
	if d.loginLimiter == nil {
		return true, 0
	}
	return d.loginLimiter.Allow(ip + "|" + proto)
}

func (d *Decoy) allowConn(ip, proto string) (bool, int) {
	if d.connLimiter == nil {
		return true, 0
	}
	return d.connLimiter.Allow(ip + "|" + proto)
}

func (d *Decoy) pause(ctx context.Context, minD, maxD time.Duration) bool {
	delay := d.authDelay(minD, maxD)
	if delay <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (d *Decoy) serve(ctx context.Context, ln net.Listener, port int, handle func(context.Context, net.Conn, int)) {
	decoy.Accept(ctx, ln, func(c net.Conn) {
		ip := decoy.RemoteIP(c.RemoteAddr())
		if !d.acquire(ip) {
			c.Close()
			return
		}
		defer d.release(ip)
		handle(ctx, c, port)
	})
}

// ServeLDAP serves plaintext LDAP connections on ln until ctx is cancelled.
func (d *Decoy) ServeLDAP(ctx context.Context, ln net.Listener) {
	d.serve(ctx, ln, listenerPort(ln, d.cfg.LDAPPort), func(ctx context.Context, c net.Conn, port int) {
		d.handleLDAP(ctx, c, port, false)
	})
}

// ServeLDAPS serves TLS-wrapped LDAPS connections on ln until ctx is cancelled.
func (d *Decoy) ServeLDAPS(ctx context.Context, ln net.Listener) {
	d.serve(ctx, ln, listenerPort(ln, d.cfg.LDAPSPort), func(ctx context.Context, c net.Conn, port int) {
		d.handleLDAP(ctx, c, port, true)
	})
}

// ServeRDP serves RDP (X.224 + TLS + CredSSP/NTLM) connections on ln until ctx is cancelled.
func (d *Decoy) ServeRDP(ctx context.Context, ln net.Listener) {
	d.serve(ctx, ln, listenerPort(ln, d.cfg.RDPPort), d.handleRDP)
}

func listenerPort(ln net.Listener, fallback int) int {
	if addr, ok := ln.Addr().(*net.TCPAddr); ok && addr.Port > 0 {
		return addr.Port
	}
	return fallback
}

// boundedConn enforces both an overall connection deadline and a per-read/write
// idle timeout.
type boundedConn struct {
	net.Conn
	idle  time.Duration
	limit time.Time
}

func newBoundedConn(c net.Conn, idle, total time.Duration) *boundedConn {
	limit := time.Now().Add(total)
	_ = c.SetDeadline(limit)
	return &boundedConn{Conn: c, idle: idle, limit: limit}
}

func (b *boundedConn) Read(p []byte) (int, error) {
	dl := time.Now().Add(b.idle)
	if dl.After(b.limit) {
		dl = b.limit
	}
	_ = b.Conn.SetReadDeadline(dl)
	return b.Conn.Read(p)
}

func (b *boundedConn) Write(p []byte) (int, error) {
	dl := time.Now().Add(b.idle)
	if dl.After(b.limit) {
		dl = b.limit
	}
	_ = b.Conn.SetWriteDeadline(dl)
	return b.Conn.Write(p)
}

func run(ctx context.Context, s *sensor.Sensor) error {
	cfg, err := LoadSettings(s)
	if err != nil {
		return err
	}
	d, err := NewDecoy(cfg, s)
	if err != nil {
		return err
	}
	sensor.LogPrivileges(s.Logger())

	type binding struct {
		name  string
		port  int
		ln    net.Listener
		serve func(context.Context, net.Listener)
	}
	var lc net.ListenConfig
	var bindings []binding
	closeAll := func() {
		for _, b := range bindings {
			_ = b.ln.Close()
		}
	}

	listen := func(name string, port int, fn func(context.Context, net.Listener)) error {
		ln, err := lc.Listen(ctx, "tcp", net.JoinHostPort("", strconv.Itoa(port)))
		if err != nil {
			return fmt.Errorf("listen %s on :%d: %w", name, port, err)
		}
		bindings = append(bindings, binding{name: name, port: port, ln: ln, serve: fn})
		return nil
	}

	if cfg.EnableLDAP {
		if err := listen("ldap", cfg.LDAPPort, d.ServeLDAP); err != nil {
			closeAll()
			return err
		}
	}
	if cfg.EnableLDAPS {
		if err := listen("ldaps", cfg.LDAPSPort, d.ServeLDAPS); err != nil {
			closeAll()
			return err
		}
	}
	if cfg.EnableRDP {
		if err := listen("rdp", cfg.RDPPort, d.ServeRDP); err != nil {
			closeAll()
			return err
		}
	}

	var names []string
	for _, b := range bindings {
		names = append(names, fmt.Sprintf("%s:%d", b.name, b.port))
	}
	s.Logger().Info("identity-decoy listening", "services", names, "persona", cfg.Persona.FQDN())

	var wg sync.WaitGroup
	for _, b := range bindings {
		wg.Add(1)
		go func(b binding) {
			defer wg.Done()
			b.serve(ctx, b.ln)
		}(b)
	}
	<-ctx.Done()
	wg.Wait()
	return nil
}
