// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Command network-service-decoy emulates SNMP (v1/v2c/v3) and log-only DNS
// (UDP and TCP) with strict anti-amplification guards to detect MIB
// enumeration, community-string guessing, SNMP writes and DNS reconnaissance
// or zone transfers.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/decoy"
	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

// Triggers.
const (
	TriggerSNMPQuery = "snmp_query"
	TriggerDNSQuery  = "dns_query"
)

const (
	defaultSNMPPort        = 161
	defaultDNSPort         = 53
	defaultSysDescr        = "Linux sw-core-01 6.1.0-26-amd64 #1 SMP Debian 6.1.112 x86_64"
	defaultSysObjectID     = "1.3.6.1.4.1.8072.3.2.10"
	defaultSysContact      = "noc@corp.local"
	defaultSysName         = "sw-core-01.corp.local"
	defaultSysLocation     = "DC1-Rack-A04"
	defaultReplyRatePerSec = 10
	defaultMaxConns        = 256
	defaultMaxPerSource    = 8
	defaultCooldownSec     = 10
	defaultIdleTimeout     = 30 * time.Second
	defaultTotalTimeout    = 2 * time.Minute
	eventLimiterBurst      = 6

	// Realistic uptime offset (14 days in hundredths of a second) so sysUpTime
	// does not betray a freshly started container.
	snmpUptimeBaseTicks = 14 * 24 * 3600 * 100
)

var spec = sensor.Spec{
	Drill: sensor.Drill{
		Trigger:  TriggerSNMPQuery,
		Target:   "SNMP port 161 (fire drill)",
		Severity: sensor.SeverityMedium,
		Details: sensor.Fields{
			sensor.F("protocol", "snmp"),
			sensor.F("dst_port", 161),
			sensor.F("version", "2c"),
			sensor.F("pdu_type", "GetRequest"),
			sensor.F("username", "drill"),
		},
	},
	Run: run,
}

func main() { sensor.Main(spec) }

// SNMPPersona holds the read-only system-group values and engine identity.
type SNMPPersona struct {
	SysDescr    string
	SysObjectID []uint32
	SysContact  string
	SysName     string
	SysLocation string
	EngineID    []byte
}

// Settings is the parsed sensor configuration.
type Settings struct {
	EnableSNMP    bool
	SNMPPort      int
	SNMPCommunity string
	SNMPPersona   SNMPPersona

	EnableDNS    bool
	EnableDNSTCP bool
	DNSPort      int

	ReplyRatePerSec int
	MaxConns        int
	MaxPerSrc       int
	Cooldown        time.Duration
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

	if s.EnableSNMP, err = boolSetting(r, "TS_ENABLE_SNMP", true); err != nil {
		return nil, err
	}
	if s.SNMPPort, err = intSetting(r, "TS_SNMP_PORT", defaultSNMPPort, 1, 65535); err != nil {
		return nil, err
	}
	if s.SNMPCommunity, err = stringSetting(r, "TS_SNMP_COMMUNITY", "", 128); err != nil {
		return nil, err
	}
	if s.SNMPPersona.SysDescr, err = stringSetting(r, "TS_SNMP_SYS_DESCR", defaultSysDescr, 255); err != nil {
		return nil, err
	}
	sysOIDStr, err := stringSetting(r, "TS_SNMP_SYS_OBJECT_ID", defaultSysObjectID, 128)
	if err != nil {
		return nil, err
	}
	if s.SNMPPersona.SysObjectID, err = parseOIDString(sysOIDStr); err != nil {
		return nil, fmt.Errorf("TS_SNMP_SYS_OBJECT_ID: %w", err)
	}
	if s.SNMPPersona.SysContact, err = stringSetting(r, "TS_SNMP_SYS_CONTACT", defaultSysContact, 128); err != nil {
		return nil, err
	}
	if s.SNMPPersona.SysName, err = stringSetting(r, "TS_SNMP_SYS_NAME", defaultSysName, 128); err != nil {
		return nil, err
	}
	if s.SNMPPersona.SysLocation, err = stringSetting(r, "TS_SNMP_SYS_LOCATION", defaultSysLocation, 128); err != nil {
		return nil, err
	}

	if s.EnableDNS, err = boolSetting(r, "TS_ENABLE_DNS", true); err != nil {
		return nil, err
	}
	if s.EnableDNSTCP, err = boolSetting(r, "TS_ENABLE_DNS_TCP", true); err != nil {
		return nil, err
	}
	if s.DNSPort, err = intSetting(r, "TS_DNS_PORT", defaultDNSPort, 1, 65535); err != nil {
		return nil, err
	}

	if s.ReplyRatePerSec, err = intSetting(r, "TS_REPLY_RATE_PER_SEC", defaultReplyRatePerSec, 1, 1000); err != nil {
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

	if !s.EnableSNMP && !s.EnableDNS && !s.EnableDNSTCP {
		return nil, errors.New("at least one listener (TS_ENABLE_SNMP, TS_ENABLE_DNS, TS_ENABLE_DNS_TCP) must be enabled")
	}
	if s.EnableSNMP && s.EnableDNS && s.SNMPPort == s.DNSPort {
		return nil, fmt.Errorf("UDP port %d configured for both snmp and dns", s.SNMPPort)
	}

	s.SNMPPersona.EngineID = deriveSNMPEngineID(r, s.SNMPPersona.SysName)
	return s, nil
}

// deriveSNMPEngineID produces a deterministic 11-byte RFC 3411 engine ID
// (enterprise 8072 / Net-SNMP, format 0x05 octets, plus 6 derived bytes) via
// decoy.DeriveKey so two Doppel nodes do not share an identical SNMPv3
// fingerprint.
func deriveSNMPEngineID(r sensor.Reporter, sysName string) []byte {
	sensorID, _ := r.Setting("TS_SENSOR_ID")
	rawKey, _ := r.Setting(decoy.CaptureKeyKey)
	var digest [32]byte
	if key, err := hex.DecodeString(strings.TrimSpace(rawKey)); err == nil && len(key) >= 16 {
		copy(digest[:], decoy.DeriveKey(key, "doppel:snmp-engine-id:v1:"+sensorID))
	} else {
		digest = sha256.Sum256([]byte("doppel:snmp-engine-id:v1:" + sensorID + ":" + sysName))
	}
	// RFC 3411 §5: 0x80001f88 (enterprise 8072 with bit 31 set) + format 0x05 + 6 bytes = 11 bytes.
	out := make([]byte, 11)
	out[0], out[1], out[2], out[3], out[4] = 0x80, 0x00, 0x1f, 0x88, 0x05
	copy(out[5:], digest[:6])
	return out
}

// Decoy serves the enabled SNMP and DNS listeners.
type Decoy struct {
	cfg          *Settings
	r            sensor.Reporter
	capture      decoy.Capture
	eventLimiter *decoy.Limiter
	replyLimiter *decoy.Limiter

	sem   chan struct{}
	mu    sync.Mutex
	perIP map[string]int

	idleTimeout  time.Duration
	totalTimeout time.Duration
	startedAt    time.Time
	now          func() time.Time

	unknownEngineCount atomic.Uint32
}

// NewDecoy constructs a Decoy from cfg.
func NewDecoy(cfg *Settings, r sensor.Reporter) (*Decoy, error) {
	capPolicy, err := decoy.NewCapture(r)
	if err != nil {
		return nil, err
	}
	d := &Decoy{
		cfg:          cfg,
		r:            r,
		capture:      capPolicy,
		replyLimiter: decoy.NewLimiter(cfg.ReplyRatePerSec, time.Second),
		sem:          make(chan struct{}, cfg.MaxConns),
		perIP:        map[string]int{},
		idleTimeout:  defaultIdleTimeout,
		totalTimeout: defaultTotalTimeout,
		startedAt:    time.Now(),
		now:          time.Now,
	}
	if cfg.Cooldown > 0 {
		d.eventLimiter = decoy.NewLimiter(eventLimiterBurst, cfg.Cooldown)
	}
	return d, nil
}

func (d *Decoy) allowReply(ip string) bool {
	if d.replyLimiter == nil {
		return true
	}
	ok, _ := d.replyLimiter.Allow(ip)
	return ok
}

func (d *Decoy) emit(sev sensor.Severity, trigger, ip, target string, fields sensor.Fields) {
	if d.eventLimiter != nil {
		ok, suppressed := d.eventLimiter.Allow(ip)
		if !ok {
			return
		}
		if suppressed > 0 {
			fields = append(fields, sensor.F("suppressed_since_last", suppressed))
		}
	}
	d.r.ReportSeverity(sev, trigger, ip, target, fields)
}

func (d *Decoy) acquireTCP(ip string) bool {
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

func (d *Decoy) releaseTCP(ip string) {
	d.mu.Lock()
	if d.perIP[ip] <= 1 {
		delete(d.perIP, ip)
	} else {
		d.perIP[ip]--
	}
	d.mu.Unlock()
	<-d.sem
}

func (d *Decoy) uptimeTicks() uint32 {
	elapsed := d.now().Sub(d.startedAt)
	if elapsed < 0 {
		elapsed = 0
	}
	return uint32(snmpUptimeBaseTicks + uint64(elapsed/(10*time.Millisecond)))
}

func (d *Decoy) uptimeSeconds() int64 {
	elapsed := d.now().Sub(d.startedAt)
	if elapsed < 0 {
		elapsed = 0
	}
	return 14*24*3600 + int64(elapsed/time.Second)
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

	var (
		snmpPC net.PacketConn
		dnsPC  net.PacketConn
		dnsLN  net.Listener
	)
	closeAll := func() {
		if snmpPC != nil {
			_ = snmpPC.Close()
		}
		if dnsPC != nil {
			_ = dnsPC.Close()
		}
		if dnsLN != nil {
			_ = dnsLN.Close()
		}
	}

	if cfg.EnableSNMP {
		snmpPC, err = net.ListenPacket("udp", fmt.Sprintf(":%d", cfg.SNMPPort))
		if err != nil {
			closeAll()
			return fmt.Errorf("listen snmp udp:%d: %w", cfg.SNMPPort, err)
		}
	}
	if cfg.EnableDNS {
		dnsPC, err = net.ListenPacket("udp", fmt.Sprintf(":%d", cfg.DNSPort))
		if err != nil {
			closeAll()
			return fmt.Errorf("listen dns udp:%d: %w", cfg.DNSPort, err)
		}
	}
	if cfg.EnableDNSTCP {
		dnsLN, err = net.Listen("tcp", fmt.Sprintf(":%d", cfg.DNSPort))
		if err != nil {
			closeAll()
			return fmt.Errorf("listen dns tcp:%d: %w", cfg.DNSPort, err)
		}
	}

	var wg sync.WaitGroup
	if snmpPC != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			decoy.ServePacket(ctx, snmpPC, snmpMaxPacketSize, func(from net.Addr, payload []byte) {
				d.HandleSNMPPacket(snmpPC, from, payload, cfg.SNMPPort)
			})
		}()
	}
	if dnsPC != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			decoy.ServePacket(ctx, dnsPC, dnsMaxUDPPacketSize, func(from net.Addr, payload []byte) {
				d.HandleDNSPacket(dnsPC, from, payload, cfg.DNSPort)
			})
		}()
	}
	if dnsLN != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			decoy.Accept(ctx, dnsLN, func(c net.Conn) {
				d.HandleDNSTCPConn(c, cfg.DNSPort)
			})
		}()
	}

	wg.Wait()
	return nil
}
