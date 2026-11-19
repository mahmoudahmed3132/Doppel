// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Command remote-access-decoy emulates SSH 2.0, Telnet and FTP login services,
// capturing authentication attempts and connection probes. Every login fails.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/decoy"
	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

// Triggers.
const (
	TriggerSSHLogin         = "ssh_login"
	TriggerSSHConnection    = "ssh_connection"
	TriggerTelnetLogin      = "telnet_login"
	TriggerTelnetConnection = "telnet_connection"
	TriggerFTPLogin         = "ftp_login"
	TriggerFTPConnection    = "ftp_connection"
)

const (
	defaultSSHBanner       = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
	defaultTelnetBanner    = "Ubuntu 24.04.1 LTS"
	defaultFTPBanner       = "(vsFTPd 3.0.5)"
	defaultSSHMaxAuthTries = 6
	defaultMaxConns        = 512
	defaultMaxPerSource    = 16
	defaultCooldownSec     = 10
	defaultIdleTimeout     = 30 * time.Second
	defaultTotalTimeout    = 2 * time.Minute
	loginLimiterBurst      = 6
)

var spec = sensor.Spec{
	Drill: sensor.Drill{
		Trigger:  TriggerSSHLogin,
		Target:   "SSH port 22 (fire drill)",
		Severity: sensor.SeverityHigh,
		Details: sensor.Fields{
			sensor.F("protocol", "ssh"),
			sensor.F("dst_port", 22),
			sensor.F("username", "drill"),
			sensor.F("method", "password"),
		},
	},
	Run: run,
}

func main() { sensor.Main(spec) }

// Settings is the parsed sensor configuration.
type Settings struct {
	EnableSSH       bool
	SSHPort         int
	SSHBanner       string
	SSHMaxAuthTries int

	EnableTelnet bool
	TelnetPort   int
	TelnetBanner string

	EnableFTP bool
	FTPPort   int
	FTPBanner string

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

// LoadSettings reads and validates the TS_ configuration.
func LoadSettings(r sensor.Reporter) (*Settings, error) {
	s := &Settings{}
	var err error

	if s.EnableSSH, err = boolSetting(r, "TS_ENABLE_SSH", true); err != nil {
		return nil, err
	}
	if s.SSHPort, err = intSetting(r, "TS_SSH_PORT", 22, 1, 65535); err != nil {
		return nil, err
	}
	if s.SSHBanner, err = stringSetting(r, "TS_SSH_BANNER", defaultSSHBanner, 253); err != nil {
		return nil, err
	}
	if err := validateSSHBanner(s.SSHBanner); err != nil {
		return nil, err
	}
	if s.SSHMaxAuthTries, err = intSetting(r, "TS_SSH_MAX_AUTH_TRIES", defaultSSHMaxAuthTries, 1, 20); err != nil {
		return nil, err
	}

	if s.EnableTelnet, err = boolSetting(r, "TS_ENABLE_TELNET", false); err != nil {
		return nil, err
	}
	if s.TelnetPort, err = intSetting(r, "TS_TELNET_PORT", 23, 1, 65535); err != nil {
		return nil, err
	}
	if s.TelnetBanner, err = stringSetting(r, "TS_TELNET_BANNER", defaultTelnetBanner, 512); err != nil {
		return nil, err
	}

	if s.EnableFTP, err = boolSetting(r, "TS_ENABLE_FTP", false); err != nil {
		return nil, err
	}
	if s.FTPPort, err = intSetting(r, "TS_FTP_PORT", 21, 1, 65535); err != nil {
		return nil, err
	}
	if s.FTPBanner, err = stringSetting(r, "TS_FTP_BANNER", defaultFTPBanner, 512); err != nil {
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

	if !s.EnableSSH && !s.EnableTelnet && !s.EnableFTP {
		return nil, errors.New("at least one protocol (TS_ENABLE_SSH, TS_ENABLE_TELNET, TS_ENABLE_FTP) must be enabled")
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
	if err := checkPort(s.EnableSSH, "ssh", s.SSHPort); err != nil {
		return nil, err
	}
	if err := checkPort(s.EnableTelnet, "telnet", s.TelnetPort); err != nil {
		return nil, err
	}
	if err := checkPort(s.EnableFTP, "ftp", s.FTPPort); err != nil {
		return nil, err
	}
	return s, nil
}

func validateSSHBanner(banner string) error {
	if !strings.HasPrefix(banner, "SSH-2.0-") || len(banner) <= len("SSH-2.0-") {
		return errors.New("TS_SSH_BANNER must start with SSH-2.0- followed by a software version")
	}
	for i := 0; i < len(banner); i++ {
		if banner[i] < 0x20 || banner[i] > 0x7e {
			return errors.New("TS_SSH_BANNER must contain printable ASCII only")
		}
	}
	return nil
}

// Decoy serves the enabled SSH, Telnet and FTP listeners.
type Decoy struct {
	cfg          *Settings
	r            sensor.Reporter
	capture      decoy.Capture
	hostKey      ssh.Signer
	connLimiter  *decoy.Limiter
	loginLimiter *decoy.Limiter

	sem   chan struct{}
	mu    sync.Mutex
	perIP map[string]int

	idleTimeout  time.Duration
	totalTimeout time.Duration
	authDelay    func(minD, maxD time.Duration) time.Duration
}

// NewDecoy constructs a Decoy from cfg, reporting to r. sensorID is mixed
// into the deterministic SSH Ed25519 host key derivation.
func NewDecoy(cfg *Settings, r sensor.Reporter, sensorID string) (*Decoy, error) {
	capPolicy, err := decoy.NewCapture(r)
	if err != nil {
		return nil, err
	}
	var captureKey []byte
	if raw, ok := r.Setting(decoy.CaptureKeyKey); ok {
		if decoded, decErr := hex.DecodeString(strings.TrimSpace(raw)); decErr == nil && len(decoded) >= 16 {
			captureKey = decoded
		}
	}
	hostKey, err := deriveSSHHostKey(captureKey, sensorID)
	if err != nil {
		return nil, fmt.Errorf("ssh host key: %w", err)
	}
	d := &Decoy{
		cfg:          cfg,
		r:            r,
		capture:      capPolicy,
		hostKey:      hostKey,
		sem:          make(chan struct{}, cfg.MaxConns),
		perIP:        map[string]int{},
		idleTimeout:  defaultIdleTimeout,
		totalTimeout: defaultTotalTimeout,
		authDelay:    randomDelay,
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

// ServeSSH serves SSH connections on ln until ctx is cancelled.
func (d *Decoy) ServeSSH(ctx context.Context, ln net.Listener) {
	d.serve(ctx, ln, listenerPort(ln, d.cfg.SSHPort), d.handleSSH)
}

// ServeTelnet serves Telnet connections on ln until ctx is cancelled.
func (d *Decoy) ServeTelnet(ctx context.Context, ln net.Listener) {
	d.serve(ctx, ln, listenerPort(ln, d.cfg.TelnetPort), d.handleTelnet)
}

// ServeFTP serves FTP connections on ln until ctx is cancelled.
func (d *Decoy) ServeFTP(ctx context.Context, ln net.Listener) {
	d.serve(ctx, ln, listenerPort(ln, d.cfg.FTPPort), d.handleFTP)
}

func listenerPort(ln net.Listener, fallback int) int {
	if addr, ok := ln.Addr().(*net.TCPAddr); ok && addr.Port > 0 {
		return addr.Port
	}
	return fallback
}

// boundedConn enforces both an overall connection deadline and a per-read
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
	d, err := NewDecoy(cfg, s, s.Config().SensorID)
	if err != nil {
		return err
	}
	sensor.LogPrivileges(s.Logger())

	type bound struct {
		proto  string
		port   int
		ln     net.Listener
		runner func(context.Context, net.Listener)
	}
	var lc net.ListenConfig
	var listeners []bound
	listen := func(enabled bool, proto string, port int, runner func(context.Context, net.Listener)) error {
		if !enabled {
			return nil
		}
		ln, err := lc.Listen(ctx, "tcp", net.JoinHostPort("", strconv.Itoa(port)))
		if err != nil {
			for _, b := range listeners {
				b.ln.Close()
			}
			return fmt.Errorf("listening on %s port %d: %w (ports < 1024 need NET_BIND_SERVICE)", proto, port, err)
		}
		listeners = append(listeners, bound{proto: proto, port: port, ln: ln, runner: runner})
		return nil
	}
	if err := listen(cfg.EnableSSH, "ssh", cfg.SSHPort, d.ServeSSH); err != nil {
		return err
	}
	if err := listen(cfg.EnableTelnet, "telnet", cfg.TelnetPort, d.ServeTelnet); err != nil {
		return err
	}
	if err := listen(cfg.EnableFTP, "ftp", cfg.FTPPort, d.ServeFTP); err != nil {
		return err
	}

	var active []string
	for _, b := range listeners {
		active = append(active, fmt.Sprintf("%s:%d", b.proto, b.port))
	}
	s.Logger().Info("remote-access-decoy listening", "services", active)

	var wg sync.WaitGroup
	for _, b := range listeners {
		wg.Add(1)
		go func(b bound) {
			defer wg.Done()
			b.runner(ctx, b.ln)
		}(b)
	}
	<-ctx.Done()
	wg.Wait()
	return nil
}
