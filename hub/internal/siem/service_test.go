// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package siem

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported/stub"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// collector is a TCP (or TLS) line collector that can be restarted on the
// same port.
type collector struct {
	t     *testing.T
	addr  string
	tls   *tls.Config
	mu    sync.Mutex
	lines []string
	ln    net.Listener
	conns []net.Conn
}

func newCollector(t *testing.T, tlsCfg *tls.Config) *collector {
	c := &collector{t: t, tls: tlsCfg}
	c.start("127.0.0.1:0")
	t.Cleanup(c.stop)
	return c
}

func (c *collector) start(addr string) {
	var (
		ln  net.Listener
		err error
	)
	for i := 0; i < 50; i++ { // the port may linger briefly after stop
		ln, err = net.Listen("tcp", addr)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		c.t.Fatal(err)
	}
	if c.tls != nil {
		ln = tls.NewListener(ln, c.tls)
	}
	c.mu.Lock()
	c.ln, c.addr = ln, ln.Addr().String()
	c.mu.Unlock()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.mu.Lock()
			c.conns = append(c.conns, conn)
			c.mu.Unlock()
			go func() {
				sc := bufio.NewScanner(conn)
				sc.Buffer(make([]byte, 1<<20), 1<<20)
				for sc.Scan() {
					c.mu.Lock()
					c.lines = append(c.lines, sc.Text())
					c.mu.Unlock()
				}
			}()
		}
	}()
}

// stop closes the listener and every connection (collector shutdown: FIN).
func (c *collector) stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ln != nil {
		c.ln.Close()
	}
	for _, conn := range c.conns {
		conn.Close()
	}
	c.conns = nil
}

func (c *collector) got() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.lines...)
}

func (c *collector) waitFor(n int) []string {
	c.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if l := c.got(); len(l) >= n {
			return l
		}
		time.Sleep(10 * time.Millisecond)
	}
	c.t.Fatalf("collector got %d lines, want %d", len(c.got()), n)
	return nil
}

func event(id string) domain.Record {
	return domain.Record{Kind: domain.RecordEvent, Event: &domain.EnrichedEvent{Event: domain.Event{
		EventID: id, NodeID: "node-00000001", SensorID: "ts-sensor-a", Trigger: "tcp_connection", Severity: "high",
		ReceivedAt: time.Now(), OccurredAt: time.Now(), Source: "198.51.100.7", Target: "SSH", Details: []byte(`{}`)}}}
}

func newService(t *testing.T, cfg Config) *Service {
	t.Helper()
	s := &Service{PEN: 32473, Log: quiet(), BackoffBase: 5 * time.Millisecond, BackoffCap: 20 * time.Millisecond, ReconnectGap: 10 * time.Millisecond}
	if err := s.Start(cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		s.Shutdown(ctx)
	})
	return s
}

func TestTCPCollectorRestartLosesNothing(t *testing.T) {
	col := newCollector(t, nil)
	s := newService(t, Config{Protocol: ProtoTCP, Address: col.addr, Format: FormatRFC5424})
	for i := 0; i < 5; i++ {
		s.Enqueue(event(fmt.Sprintf("before-%d", i)))
	}
	col.waitFor(5)

	addr := col.addr
	col.stop()
	time.Sleep(50 * time.Millisecond) // FIN reaches the Hub side
	col.start(addr)

	for i := 0; i < 5; i++ {
		s.Enqueue(event(fmt.Sprintf("after-%d", i)))
	}
	lines := col.waitFor(10)
	joined := strings.Join(lines, "\n")
	for i := 0; i < 5; i++ {
		for _, p := range []string{"before", "after"} {
			if !strings.Contains(joined, fmt.Sprintf(`event_id="%s-%d"`, p, i)) {
				t.Errorf("lost %s-%d", p, i)
			}
		}
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "<131>1 ") { // local0 (16*8) + high (3)
			t.Fatalf("not RFC 5424: %q", l)
		}
	}
}

// fakeHTTP is a stand-in for the PORTED HTTP transport.
type fakeHTTP struct {
	mu       sync.Mutex
	outcomes []ported.SendOutcome
	calls    int
	docs     [][]byte
}

func (f *fakeHTTP) Send(_ context.Context, proto, addr, token string, doc []byte) (ported.SendOutcome, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	o := ported.SendSuccess
	if len(f.outcomes) > 0 {
		o, f.outcomes = f.outcomes[0], f.outcomes[1:]
	}
	if o == ported.SendSuccess {
		f.docs = append(f.docs, doc)
	}
	return o, nil
}

func (f *fakeHTTP) state() (int, int) { f.mu.Lock(); defer f.mu.Unlock(); return f.calls, len(f.docs) }

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func httpService(t *testing.T, h *fakeHTTP) *Service {
	t.Helper()
	s := &Service{Renderer: stub.ECS{}, HTTP: h, Log: quiet(), BackoffBase: time.Millisecond, BackoffCap: 2 * time.Millisecond}
	cfg, err := Config{Protocol: ProtoElastic, Address: "https://es.example:9200/logs-truesignal-default", Token: "k"}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	return s
}

func TestHTTPTransientRetriedTerminalDropped(t *testing.T) {
	h := &fakeHTTP{outcomes: []ported.SendOutcome{ported.SendTransient, ported.SendTransient}}
	s := httpService(t, h)
	s.Enqueue(event("e1"))
	waitUntil(t, func() bool { _, n := h.state(); return n == 1 })
	if calls, _ := h.state(); calls != 3 {
		t.Fatalf("transient not retried: %d calls", calls)
	}

	h.mu.Lock()
	h.outcomes, h.calls = []ported.SendOutcome{ported.SendTerminal}, 0
	h.mu.Unlock()
	s.Enqueue(event("e2"))
	s.Enqueue(event("e3"))
	waitUntil(t, func() bool { _, n := h.state(); return n == 2 })
	if calls, _ := h.state(); calls != 2 {
		t.Fatalf("terminal failure retried: %d calls", calls)
	}

	// Gives up after MaxAttempts.
	h.mu.Lock()
	h.outcomes, h.calls = make([]ported.SendOutcome, 20), 0
	for i := range h.outcomes {
		h.outcomes[i] = ported.SendTransient
	}
	h.mu.Unlock()
	s.Enqueue(event("e4"))
	waitUntil(t, func() bool { c, _ := h.state(); return c >= DefaultMaxAttempts })
	time.Sleep(50 * time.Millisecond)
	if c, _ := h.state(); c != DefaultMaxAttempts {
		t.Fatalf("attempts %d, want %d", c, DefaultMaxAttempts)
	}
}

func TestQueueOverflowCounted(t *testing.T) {
	// Nothing listens on this port: deliveries keep failing.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	s := &Service{QueueSize: 3, Log: quiet(), BackoffBase: time.Hour, BackoffCap: time.Hour, ReconnectGap: time.Millisecond}
	s.Start(Config{Protocol: ProtoTCP, Address: addr, Format: FormatRFC5424})
	defer func() {
		ctx, c := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer c()
		s.Shutdown(ctx)
	}()
	for i := 0; i < 20; i++ {
		s.Enqueue(event(fmt.Sprint(i)))
	}
	depth, dropped := s.Stats()
	if depth != 3 || dropped < 16 {
		t.Fatalf("depth %d dropped %d", depth, dropped)
	}
}

func TestSwitchAuditReachesPreviousDestination(t *testing.T) {
	a := newCollector(t, nil)
	b := newCollector(t, nil)
	s := newService(t, Config{Protocol: ProtoTCP, Address: a.addr, Format: FormatRFC5424})
	s.Enqueue(event("on-a"))
	a.waitFor(1)

	audit := domain.AuditRecord{Time: time.Now(), Action: "siem.update", Method: "PUT", Route: "/api/v3/settings/siem",
		Path: "/api/v3/settings/siem", Status: 200, Outcome: "success", ActorIP: "10.0.0.1"}
	if err := s.Switch(context.Background(), Config{Protocol: ProtoTCP, Address: b.addr, Format: FormatRFC5424}, &audit); err != nil {
		t.Fatal(err)
	}
	la := a.waitFor(2)
	if !strings.Contains(la[1], " AUDIT ") || !strings.Contains(la[1], `action="siem.update"`) {
		t.Fatalf("previous destination did not get the audit: %q", la[1])
	}
	// The post-request audit (from the middleware) and later records go to B.
	s.Enqueue(domain.Record{Kind: domain.RecordAudit, Audit: &audit})
	s.Enqueue(event("on-b"))
	lb := b.waitFor(2)
	if !strings.Contains(lb[0], `action="siem.update"`) || !strings.Contains(lb[1], `event_id="on-b"`) {
		t.Fatalf("new destination: %q", lb)
	}
	if len(a.got()) != 2 {
		t.Fatal("records still sent to the previous destination")
	}
}

func TestSwitchInterruptsRetriesAgainstDeadDestination(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	good := newCollector(t, nil)
	s := &Service{Log: quiet(), BackoffBase: time.Hour, BackoffCap: time.Hour, ReconnectGap: time.Millisecond, SwitchAuditTimeout: 200 * time.Millisecond}
	s.Start(Config{Protocol: ProtoTCP, Address: dead, Format: FormatRFC5424})
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	s.Enqueue(event("stuck"))
	time.Sleep(50 * time.Millisecond) // worker is in a 1 h backoff

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s.Switch(ctx, Config{Protocol: ProtoTCP, Address: good.addr, Format: FormatRFC5424}, &domain.AuditRecord{Action: "siem.update", Time: time.Now()})
	if time.Since(start) > 2*time.Second {
		t.Fatal("switch blocked behind a dead destination")
	}
	if l := good.waitFor(1); !strings.Contains(l[0], `event_id="stuck"`) {
		t.Fatalf("interrupted record not moved to the new destination: %q", l)
	}
}

func TestUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	s := newService(t, Config{Protocol: ProtoUDP, Address: pc.LocalAddr().String(), Format: FormatRFC5424})
	s.Enqueue(event("udp-1"))
	buf := make([]byte, 70000)
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil || !strings.Contains(string(buf[:n]), `event_id="udp-1"`) || strings.HasSuffix(string(buf[:n]), "\n") {
		t.Fatalf("%v %q", err, buf[:n])
	}
}

func selfSigned(t *testing.T) (*tls.Config, string) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb, _ := x509.MarshalECPrivateKey(key)
	pair, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(path, certPEM, 0o600)
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, path
}

func TestTLSVerifiesCollector(t *testing.T) {
	srvCfg, ca := selfSigned(t)
	col := newCollector(t, srvCfg)

	// Untrusted certificate: never delivered.
	s := &Service{Log: quiet(), BackoffBase: time.Millisecond, BackoffCap: time.Millisecond, MaxAttempts: 3, ReconnectGap: time.Millisecond}
	s.Start(Config{Protocol: ProtoTLS, Address: col.addr, Format: FormatRFC5424})
	s.Enqueue(event("untrusted"))
	time.Sleep(200 * time.Millisecond)
	s.Shutdown(context.Background())
	if len(col.got()) != 0 {
		t.Fatal("delivered to a collector with an untrusted certificate")
	}

	s2 := &Service{CABundle: ca, Log: quiet(), ReconnectGap: time.Millisecond}
	if err := s2.Start(Config{Protocol: ProtoTLS, Address: col.addr, Format: FormatRFC5424}); err != nil {
		t.Fatal(err)
	}
	defer s2.Shutdown(context.Background())
	s2.Enqueue(event("trusted"))
	if l := col.waitFor(1); !strings.Contains(l[0], `event_id="trusted"`) {
		t.Fatalf("%q", l)
	}
}

func TestShutdownFlushes(t *testing.T) {
	col := newCollector(t, nil)
	s := &Service{Log: quiet(), ReconnectGap: time.Millisecond}
	s.Start(Config{Protocol: ProtoTCP, Address: col.addr, Format: FormatRFC5424})
	for i := 0; i < 200; i++ {
		s.Enqueue(event(fmt.Sprint(i)))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.Shutdown(ctx)
	col.waitFor(200)
}

func TestConfigValidation(t *testing.T) {
	bad := []Config{
		{Protocol: "smtp"},
		{Protocol: ProtoTCP, Address: "nohost"},
		{Protocol: ProtoTCP, Address: "h:99999"},
		{Protocol: ProtoTCP, Address: "h:514", Format: "cef"},
		{Protocol: ProtoElastic, Address: "http://es:9200/logs", Token: "k"},
		{Protocol: ProtoElastic, Address: "https://es:9200/", Token: "k"},
		{Protocol: ProtoLogScale, Address: "https://u:p@ls/api/v1/ingest/hec"},
		{Protocol: ProtoLogScale, Address: "https://ls/api/v1/ingest/hec"},
	}
	for i, c := range bad {
		if _, err := c.Normalize(); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d accepted: %+v", i, c)
		}
	}
	c, err := Config{Protocol: "TCP", Address: " siem.local:6514 "}.Normalize()
	if err != nil || c.Format != FormatRFC5424 || c.Address != "siem.local:6514" {
		t.Fatalf("%+v %v", c, err)
	}
	if c.Public().TokenSet {
		t.Fatal("stream output reports a token")
	}
}

type fleet struct {
	nodes   []domain.Node
	sensors []domain.Sensor
}

func (f fleet) Nodes(context.Context) ([]domain.Node, error)             { return f.nodes, nil }
func (f fleet) Sensors(context.Context, string) ([]domain.Sensor, error) { return f.sensors, nil }

func TestHubHeartbeat(t *testing.T) {
	col := newCollector(t, nil)
	s := newService(t, Config{Protocol: ProtoTCP, Address: col.addr, Format: FormatRFC5424})
	now := time.Now()
	old := now.Add(-time.Hour)
	h := &Heartbeat{Sink: s, Version: "3.0.0", StartedAt: now.Add(-90 * time.Second), Log: quiet(), Now: func() time.Time { return now },
		Fleet: fleet{
			nodes:   []domain.Node{{ID: "node-00000001", LastSeenAt: &now}, {ID: "node-00000002", LastSeenAt: &old}},
			sensors: []domain.Sensor{{Status: domain.StatusOnline}, {Status: domain.StatusOffline}, {Status: domain.StatusOnline}},
		}}
	hb, _ := h.Build(context.Background())
	if hb.NodesTotal != 2 || hb.NodesOnline != 1 || hb.SensorsTotal != 3 || hb.SensorsOnline != 2 || hb.UptimeSeconds != 90 {
		t.Fatalf("%+v", hb)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go h.Run(ctx, 20*time.Millisecond)
	lines := col.waitFor(2)
	cancel()
	if !strings.Contains(lines[0], " HEARTBEAT [truesignal-hub@32473 version=\"3.0.0\"") {
		t.Fatalf("%q", lines[0])
	}
	if HeartbeatInterval != 5*time.Minute {
		t.Fatal("heartbeat interval must be 5 minutes")
	}
}

func TestHoneytokenInventory(t *testing.T) {
	col := newCollector(t, nil)
	s := newService(t, Config{Protocol: ProtoTCP, Address: col.addr, Format: FormatRFC5424})
	ht := &stub.Honeytokens{}
	ht.Add(ported.Honeytoken{ID: "ht_existing", Username: "svc_old", Secret: "OLD-SECRET"})
	inv := &InventoryHoneytokens{HoneytokenService: ht, Sink: s, Log: quiet(), Now: time.Now}
	inv.EmitInventory(context.Background())
	inv.Ensure(context.Background(), "node-00000001", "ts-sensor-files") // new token
	inv.Ensure(context.Background(), "node-00000001", "ts-sensor-files") // same token: no repeat
	inv.Ensure(context.Background(), "node-00000002", "ts-sensor-x")     // existing seeded? no: new
	lines := col.waitFor(3)
	time.Sleep(50 * time.Millisecond)
	if n := len(col.got()); n != 3 {
		t.Fatalf("%d inventory records: %v", n, lines)
	}
	joined := strings.Join(col.got(), "\n")
	if strings.Contains(joined, "OLD-SECRET") || strings.Contains(joined, "stub-secret") {
		t.Fatal("honeytoken secret sent to the SIEM")
	}
	if !strings.Contains(joined, " HONEYTOKEN ") || !strings.Contains(joined, `honeytoken_id="ht_existing"`) {
		t.Fatalf("%s", joined)
	}
}
