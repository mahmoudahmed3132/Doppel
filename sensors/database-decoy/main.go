// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Command database-decoy emulates MySQL/MariaDB, PostgreSQL and Microsoft SQL
// Server (MS-TDS 7.x) login services to capture authentication attempts and
// connection probes. Every login fails with a wire-accurate server error.
package main

import (
	"context"
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
	TriggerMySQLLogin         = "mysql_login"
	TriggerMySQLConnection    = "mysql_connection"
	TriggerPostgresLogin      = "postgres_login"
	TriggerPostgresConnection = "postgres_connection"
	TriggerMSSQLLogin         = "mssql_login"
	TriggerMSSQLConnection    = "mssql_connection"
)

const (
	defaultMySQLVersion    = "8.0.39-0ubuntu0.24.04.1"
	defaultMSSQLServerName = "SQL-PROD-01"
	defaultMSSQLVersion    = "16.0.1000"
	defaultMaxConns        = 512
	defaultMaxPerSource    = 16
	defaultCooldownSec     = 10
	defaultIdleTimeout     = 30 * time.Second
	defaultTotalTimeout    = 2 * time.Minute
	loginLimiterBurst      = 6
)

var spec = sensor.Spec{
	Drill: sensor.Drill{
		Trigger:  TriggerMySQLLogin,
		Target:   "MySQL port 3306 (fire drill)",
		Severity: sensor.SeverityHigh,
		Details: sensor.Fields{
			sensor.F("protocol", "mysql"),
			sensor.F("dst_port", 3306),
			sensor.F("username", "drill"),
			sensor.F("password_supplied", true),
		},
	},
	Run: run,
}

func main() { sensor.Main(spec) }

// MSSQLVersion holds the parsed major.minor.build advertised in TDS PRELOGIN.
type MSSQLVersion struct {
	Major uint8
	Minor uint8
	Build uint16
}

// Settings is the parsed sensor configuration.
type Settings struct {
	EnableMySQL  bool
	MySQLPort    int
	MySQLVersion string

	EnablePostgres bool
	PostgresPort   int

	EnableMSSQL     bool
	MSSQLPort       int
	MSSQLServerName string
	MSSQLVer        MSSQLVersion

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

func parseMSSQLVersion(raw string) (MSSQLVersion, error) {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 3 {
		return MSSQLVersion{}, fmt.Errorf("TS_MSSQL_VERSION must be major.minor.build")
	}
	maj, err := strconv.Atoi(parts[0])
	if err != nil || maj < 0 || maj > 255 {
		return MSSQLVersion{}, fmt.Errorf("TS_MSSQL_VERSION major must be 0..255")
	}
	minV, err := strconv.Atoi(parts[1])
	if err != nil || minV < 0 || minV > 255 {
		return MSSQLVersion{}, fmt.Errorf("TS_MSSQL_VERSION minor must be 0..255")
	}
	bld, err := strconv.Atoi(parts[2])
	if err != nil || bld < 0 || bld > 65535 {
		return MSSQLVersion{}, fmt.Errorf("TS_MSSQL_VERSION build must be 0..65535")
	}
	return MSSQLVersion{Major: uint8(maj), Minor: uint8(minV), Build: uint16(bld)}, nil
}

// LoadSettings reads and validates the TS_ configuration.
func LoadSettings(r sensor.Reporter) (*Settings, error) {
	s := &Settings{}
	var err error

	if s.EnableMySQL, err = boolSetting(r, "TS_ENABLE_MYSQL", true); err != nil {
		return nil, err
	}
	if s.MySQLPort, err = intSetting(r, "TS_MYSQL_PORT", 3306, 1024, 65535); err != nil {
		return nil, err
	}
	if s.MySQLVersion, err = stringSetting(r, "TS_MYSQL_VERSION", defaultMySQLVersion, 128); err != nil {
		return nil, err
	}
	if strings.TrimSpace(s.MySQLVersion) == "" {
		return nil, errors.New("TS_MYSQL_VERSION must not be empty")
	}

	if s.EnablePostgres, err = boolSetting(r, "TS_ENABLE_POSTGRES", true); err != nil {
		return nil, err
	}
	if s.PostgresPort, err = intSetting(r, "TS_POSTGRES_PORT", 5432, 1024, 65535); err != nil {
		return nil, err
	}

	if s.EnableMSSQL, err = boolSetting(r, "TS_ENABLE_MSSQL", true); err != nil {
		return nil, err
	}
	if s.MSSQLPort, err = intSetting(r, "TS_MSSQL_PORT", 1433, 1024, 65535); err != nil {
		return nil, err
	}
	if s.MSSQLServerName, err = stringSetting(r, "TS_MSSQL_SERVER_NAME", defaultMSSQLServerName, 128); err != nil {
		return nil, err
	}
	if strings.TrimSpace(s.MSSQLServerName) == "" {
		return nil, errors.New("TS_MSSQL_SERVER_NAME must not be empty")
	}
	verRaw, err := stringSetting(r, "TS_MSSQL_VERSION", defaultMSSQLVersion, 32)
	if err != nil {
		return nil, err
	}
	if s.MSSQLVer, err = parseMSSQLVersion(verRaw); err != nil {
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

	if !s.EnableMySQL && !s.EnablePostgres && !s.EnableMSSQL {
		return nil, errors.New("at least one protocol (TS_ENABLE_MYSQL, TS_ENABLE_POSTGRES, TS_ENABLE_MSSQL) must be enabled")
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
	if err := checkPort(s.EnableMySQL, "mysql", s.MySQLPort); err != nil {
		return nil, err
	}
	if err := checkPort(s.EnablePostgres, "postgres", s.PostgresPort); err != nil {
		return nil, err
	}
	if err := checkPort(s.EnableMSSQL, "mssql", s.MSSQLPort); err != nil {
		return nil, err
	}
	return s, nil
}

// Decoy serves the enabled MySQL, PostgreSQL and MS SQL Server listeners.
type Decoy struct {
	cfg          *Settings
	r            sensor.Reporter
	capture      decoy.Capture
	connLimiter  *decoy.Limiter
	loginLimiter *decoy.Limiter

	sem   chan struct{}
	mu    sync.Mutex
	perIP map[string]int

	idleTimeout  time.Duration
	totalTimeout time.Duration
	authDelay    func(minD, maxD time.Duration) time.Duration
}

// NewDecoy constructs a Decoy from cfg, reporting to r.
func NewDecoy(cfg *Settings, r sensor.Reporter) (*Decoy, error) {
	capPolicy, err := decoy.NewCapture(r)
	if err != nil {
		return nil, err
	}
	d := &Decoy{
		cfg:          cfg,
		r:            r,
		capture:      capPolicy,
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

// ServeMySQL serves MySQL/MariaDB connections on ln until ctx is cancelled.
func (d *Decoy) ServeMySQL(ctx context.Context, ln net.Listener) {
	d.serve(ctx, ln, listenerPort(ln, d.cfg.MySQLPort), d.handleMySQL)
}

// ServePostgres serves PostgreSQL connections on ln until ctx is cancelled.
func (d *Decoy) ServePostgres(ctx context.Context, ln net.Listener) {
	d.serve(ctx, ln, listenerPort(ln, d.cfg.PostgresPort), d.handlePostgres)
}

// ServeMSSQL serves MS SQL Server (MS-TDS) connections on ln until ctx is cancelled.
func (d *Decoy) ServeMSSQL(ctx context.Context, ln net.Listener) {
	d.serve(ctx, ln, listenerPort(ln, d.cfg.MSSQLPort), d.handleMSSQL)
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
			return fmt.Errorf("listening on %s port %d: %w", proto, port, err)
		}
		listeners = append(listeners, bound{proto: proto, port: port, ln: ln, runner: runner})
		return nil
	}
	if err := listen(cfg.EnableMySQL, "mysql", cfg.MySQLPort, d.ServeMySQL); err != nil {
		return err
	}
	if err := listen(cfg.EnablePostgres, "postgres", cfg.PostgresPort, d.ServePostgres); err != nil {
		return err
	}
	if err := listen(cfg.EnableMSSQL, "mssql", cfg.MSSQLPort, d.ServeMSSQL); err != nil {
		return err
	}

	var active []string
	for _, b := range listeners {
		active = append(active, fmt.Sprintf("%s:%d", b.proto, b.port))
	}
	s.Logger().Info("database-decoy listening", "services", active)

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
