// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

const testCaptureKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type recordedEvent struct {
	Severity sensor.Severity
	Trigger  string
	Source   string
	Target   string
	Details  map[string]any
}

type fakeReporter struct {
	mu       sync.Mutex
	settings map[string]string
	events   []recordedEvent
}

func newFakeReporter(settings map[string]string) *fakeReporter {
	s := map[string]string{
		"TS_CAPTURE_KEY":        testCaptureKeyHex,
		"TS_EVENT_COOLDOWN_SEC": "0",
	}
	for k, v := range settings {
		s[k] = v
	}
	return &fakeReporter{settings: s}
}

func (f *fakeReporter) Setting(name string) (string, bool) {
	v, ok := f.settings[name]
	return v, ok && v != ""
}

func (f *fakeReporter) ReportSeverity(sev sensor.Severity, trigger, source, target string, details sensor.Details) {
	m := map[string]any{}
	if fields, ok := details.(sensor.Fields); ok {
		for _, kv := range fields {
			m[kv.Key] = kv.Value
		}
	} else if mp, ok := details.(sensor.Map); ok {
		for k, v := range mp {
			m[k] = v
		}
	}
	// Round-trip through JSON to match wire representation.
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)

	f.mu.Lock()
	f.events = append(f.events, recordedEvent{
		Severity: sev,
		Trigger:  trigger,
		Source:   source,
		Target:   target,
		Details:  out,
	})
	f.mu.Unlock()
}

func (f *fakeReporter) snapshot() []recordedEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]recordedEvent, len(f.events))
	copy(out, f.events)
	return out
}

func expectedHMAC(t *testing.T, secret string) string {
	t.Helper()
	key, err := hex.DecodeString(testCaptureKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(secret))
	return hex.EncodeToString(mac.Sum(nil))
}

func newTestDecoy(t *testing.T, settings map[string]string) (*Decoy, *fakeReporter) {
	t.Helper()
	rep := newFakeReporter(settings)
	cfg, err := LoadSettings(rep)
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	d, err := NewDecoy(cfg, rep, "ts-sensor-remote-access-decoy")
	if err != nil {
		t.Fatalf("NewDecoy: %v", err)
	}
	d.authDelay = func(_, _ time.Duration) time.Duration { return 0 }
	d.idleTimeout = 2 * time.Second
	d.totalTimeout = 5 * time.Second
	return d, rep
}

func TestLoadSettings(t *testing.T) {
	rep := newFakeReporter(nil)
	cfg, err := LoadSettings(rep)
	if err != nil {
		t.Fatalf("default settings failed: %v", err)
	}
	if !cfg.EnableSSH || cfg.SSHPort != 22 || cfg.EnableTelnet || cfg.EnableFTP {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}

	// All protocols disabled must fail.
	if _, err := LoadSettings(newFakeReporter(map[string]string{
		"TS_ENABLE_SSH": "false",
	})); err == nil {
		t.Fatal("expected error when all protocols disabled")
	}

	// Duplicate ports on enabled protocols must fail.
	if _, err := LoadSettings(newFakeReporter(map[string]string{
		"TS_ENABLE_SSH":    "true",
		"TS_SSH_PORT":      "2222",
		"TS_ENABLE_TELNET": "true",
		"TS_TELNET_PORT":   "2222",
	})); err == nil {
		t.Fatal("expected error on duplicate enabled ports")
	}

	// Duplicate port with disabled protocol is allowed.
	if _, err := LoadSettings(newFakeReporter(map[string]string{
		"TS_ENABLE_SSH":    "true",
		"TS_SSH_PORT":      "23",
		"TS_ENABLE_TELNET": "false",
		"TS_TELNET_PORT":   "23",
	})); err != nil {
		t.Fatalf("unexpected error when duplicate port is disabled: %v", err)
	}

	// Bad SSH banners.
	for _, bad := range []string{"OpenSSH_9.6", "SSH-1.99-foo", "SSH-2.0-", "SSH-2.0-foo\r\nbar", "SSH-2.0-\x01"} {
		if _, err := LoadSettings(newFakeReporter(map[string]string{"TS_SSH_BANNER": bad})); err == nil {
			t.Errorf("accepted invalid SSH banner %q", bad)
		}
	}

	// Bad FTP banner with CRLF.
	if _, err := LoadSettings(newFakeReporter(map[string]string{"TS_FTP_BANNER": "ok\r\n220 injected"})); err == nil {
		t.Fatal("accepted FTP banner with CRLF")
	}
}

func TestDeriveSSHHostKey(t *testing.T) {
	keyA, _ := hex.DecodeString(testCaptureKeyHex)
	keyB, _ := hex.DecodeString(strings.Repeat("fe", 32))

	s1, err := deriveSSHHostKey(keyA, "ts-sensor-a")
	if err != nil {
		t.Fatal(err)
	}
	s2, err := deriveSSHHostKey(keyA, "ts-sensor-a")
	if err != nil {
		t.Fatal(err)
	}
	s3, err := deriveSSHHostKey(keyA, "ts-sensor-b")
	if err != nil {
		t.Fatal(err)
	}
	s4, err := deriveSSHHostKey(keyB, "ts-sensor-a")
	if err != nil {
		t.Fatal(err)
	}

	if s1.PublicKey().Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("key type = %q, want %q", s1.PublicKey().Type(), ssh.KeyAlgoED25519)
	}
	fp1 := ssh.FingerprintSHA256(s1.PublicKey())
	fp2 := ssh.FingerprintSHA256(s2.PublicKey())
	fp3 := ssh.FingerprintSHA256(s3.PublicKey())
	fp4 := ssh.FingerprintSHA256(s4.PublicKey())
	if fp1 != fp2 {
		t.Fatalf("host key not deterministic: %s != %s", fp1, fp2)
	}
	if fp1 == fp3 {
		t.Fatalf("different sensor IDs produced same host key: %s", fp1)
	}
	if fp1 == fp4 {
		t.Fatalf("different capture keys produced same host key: %s", fp1)
	}

	// Empty capture key generates ephemeral key without error.
	eph, err := deriveSSHHostKey(nil, "ts-sensor-a")
	if err != nil || eph.PublicKey().Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("ephemeral key failed: %v", err)
	}
}

func TestSSHEndToEnd(t *testing.T) {
	d, rep := newTestDecoy(t, map[string]string{
		"TS_ENABLE_SSH": "true",
		"TS_SSH_BANNER": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.ServeSSH(ctx, ln)
	}()
	defer func() {
		cancel()
		<-done
	}()

	addr := ln.Addr().String()
	wantHostFP := ssh.FingerprintSHA256(d.hostKey.PublicKey())
	verifyHostKey := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if got := ssh.FingerprintSHA256(key); got != wantHostFP {
			t.Errorf("server host key mismatch: got %s want %s", got, wantHostFP)
		}
		return nil
	}

	// 1. Password authentication.
	t.Run("password", func(t *testing.T) {
		raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		_, _, _, err = ssh.NewClientConn(raw, addr, &ssh.ClientConfig{
			User:            "root",
			ClientVersion:   "SSH-2.0-TestClient_1.0",
			Auth:            []ssh.AuthMethod{ssh.Password("hunter2")},
			HostKeyCallback: verifyHostKey,
			Timeout:         2 * time.Second,
		})
		if err == nil {
			t.Fatal("SSH password auth unexpectedly succeeded")
		}
	})

	// 2. Keyboard-interactive authentication.
	t.Run("keyboard-interactive", func(t *testing.T) {
		raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		var gotQuestion string
		var gotEcho bool
		_, _, _, err = ssh.NewClientConn(raw, addr, &ssh.ClientConfig{
			User:          "ubuntu",
			ClientVersion: "SSH-2.0-KbdClient_2.0",
			Auth: []ssh.AuthMethod{ssh.KeyboardInteractive(func(_, _ string, questions []string, echos []bool) ([]string, error) {
				if len(questions) > 0 {
					gotQuestion = questions[0]
					gotEcho = echos[0]
				}
				return []string{"s3cr3t!"}, nil
			})},
			HostKeyCallback: verifyHostKey,
			Timeout:         2 * time.Second,
		})
		if err == nil {
			t.Fatal("SSH keyboard-interactive auth unexpectedly succeeded")
		}
		if gotQuestion != "Password: " || gotEcho {
			t.Fatalf("unexpected challenge: question=%q echo=%v", gotQuestion, gotEcho)
		}
	})

	// 3. Public key authentication.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	clientPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	wantClientFP := ssh.FingerprintSHA256(clientPub)

	t.Run("publickey", func(t *testing.T) {
		raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		_, _, _, err = ssh.NewClientConn(raw, addr, &ssh.ClientConfig{
			User:            "deploy",
			ClientVersion:   "SSH-2.0-KeyClient_3.0",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientSigner)},
			HostKeyCallback: verifyHostKey,
			Timeout:         2 * time.Second,
		})
		if err == nil {
			t.Fatal("SSH publickey auth unexpectedly succeeded")
		}
	})

	// 4. Banner-only probe (no auth).
	t.Run("connection-no-auth", func(t *testing.T) {
		raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		br := bufio.NewReader(raw)
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read banner: %v", err)
		}
		if strings.TrimSpace(line) != "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5" {
			t.Fatalf("unexpected banner: %q", line)
		}
		_, _ = raw.Write([]byte("SSH-2.0-Scanner_0.1\r\n"))
		raw.Close()
	})

	// Wait briefly for server goroutines to finish reporting.
	deadline := time.Now().Add(2 * time.Second)
	for len(rep.snapshot()) < 4 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	events := rep.snapshot()
	if len(events) < 4 {
		t.Fatalf("got %d events, want at least 4: %+v", len(events), events)
	}

	var sawPass, sawKbd, sawPubKey, sawConn bool
	for _, ev := range events {
		switch ev.Trigger {
		case TriggerSSHLogin:
			if ev.Severity != sensor.SeverityHigh {
				t.Errorf("ssh_login severity = %q, want high", ev.Severity)
			}
			switch ev.Details["method"] {
			case "password":
				sawPass = true
				if ev.Details["username"] != "root" || ev.Details["password_hmac"] != expectedHMAC(t, "hunter2") || ev.Details["password_length"] != float64(7) {
					t.Errorf("unexpected password details: %+v", ev.Details)
				}
				if ev.Details["client_version"] != "SSH-2.0-TestClient_1.0" {
					t.Errorf("unexpected client_version: %+v", ev.Details)
				}
			case "keyboard-interactive":
				sawKbd = true
				if ev.Details["username"] != "ubuntu" || ev.Details["password_hmac"] != expectedHMAC(t, "s3cr3t!") || ev.Details["password_length"] != float64(7) {
					t.Errorf("unexpected kbd details: %+v", ev.Details)
				}
			case "publickey":
				sawPubKey = true
				if ev.Details["username"] != "deploy" || ev.Details["key_type"] != "ssh-ed25519" || ev.Details["key_fingerprint"] != wantClientFP {
					t.Errorf("unexpected publickey details: %+v", ev.Details)
				}
			}
		case TriggerSSHConnection:
			sawConn = true
			if ev.Severity != sensor.SeverityMedium {
				t.Errorf("ssh_connection severity = %q, want medium", ev.Severity)
			}
			if ev.Details["client_version"] != "SSH-2.0-Scanner_0.1" {
				t.Errorf("unexpected connection client_version: %+v", ev.Details)
			}
		}
	}
	if !sawPass || !sawKbd || !sawPubKey || !sawConn {
		t.Fatalf("missing expected events: pass=%v kbd=%v pubkey=%v conn=%v; events=%+v", sawPass, sawKbd, sawPubKey, sawConn, events)
	}
}

func TestTelnetParser(t *testing.T) {
	var replies bytes.Buffer
	p := newTelnetParser(func(b []byte) { replies.Write(b) })

	// Stream with IAC DO/WILL, NEW-ENVIRON USER, control bytes, and username.
	var input bytes.Buffer
	input.Write([]byte{telnetIAC, telnetDO, 24})                                     // unknown DO -> WONT 24
	input.Write([]byte{telnetIAC, telnetWILL, optNewEnviron})                        // WILL NEW-ENVIRON -> DO + SB SEND
	input.Write([]byte{telnetIAC, telnetSB, optNewEnviron, envIS, envVAR})           // SB NEW-ENVIRON IS VAR
	input.WriteString("USER")                                                        //
	input.WriteByte(envVALUE)                                                        // VALUE
	input.WriteString("envadmin")                                                    //
	input.Write([]byte{telnetIAC, telnetSE})                                         // IAC SE
	input.Write([]byte{telnetIAC, telnetWILL, 31})                                   // unknown WILL -> DONT 31
	input.Write([]byte{0x07, 'a', 'd', 'm', 'i', 'n', 0x00, '\r', '\n'})             // BEL + "admin" + NUL + CRLF
	input.Write([]byte{'p', 'a', 's', 's', telnetIAC, telnetIAC, '1', '2', '\r', 0}) // CR-NUL line ending with escaped IAC

	br := bufio.NewReader(&input)
	line1, err := p.readLine(br)
	if err != nil {
		t.Fatalf("readLine 1: %v", err)
	}
	if line1 != "admin" {
		t.Fatalf("line1 = %q, want %q", line1, "admin")
	}
	if p.envUser != "envadmin" {
		t.Fatalf("envUser = %q, want %q", p.envUser, "envadmin")
	}
	if !bytes.Contains(replies.Bytes(), []byte{telnetIAC, telnetWONT, 24}) {
		t.Errorf("missing WONT 24 in replies: %x", replies.Bytes())
	}
	if !bytes.Contains(replies.Bytes(), []byte{telnetIAC, telnetDONT, 31}) {
		t.Errorf("missing DONT 31 in replies: %x", replies.Bytes())
	}

	line2, err := p.readLine(br)
	if err != nil {
		t.Fatalf("readLine 2: %v", err)
	}
	if line2 != "pass12" {
		t.Fatalf("line2 = %q, want %q", line2, "pass12")
	}

	// Oversized line must fail.
	over := bufio.NewReader(strings.NewReader(strings.Repeat("a", maxTelnetLine+10) + "\r\n"))
	if _, err := newTelnetParser(nil).readLine(over); err != errTelnetLineTooLong {
		t.Fatalf("oversized line err = %v, want %v", err, errTelnetLineTooLong)
	}
}

func TestTelnetEndToEnd(t *testing.T) {
	d, rep := newTestDecoy(t, map[string]string{
		"TS_ENABLE_TELNET": "true",
		"TS_TELNET_BANNER": "Debian GNU/Linux 12",
	})

	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		d.handleTelnet(ctx, serverConn, 23)
	}()

	// Read banner + login prompt.
	buf := make([]byte, 512)
	readUntil := func(substr string) string {
		var acc strings.Builder
		for !strings.Contains(acc.String(), substr) {
			_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := clientConn.Read(buf)
			if n > 0 {
				acc.Write(buf[:n])
			}
			if err != nil {
				t.Fatalf("waiting for %q: got %q, err=%v", substr, acc.String(), err)
			}
		}
		return acc.String()
	}

	greeting := readUntil("login: ")
	if !strings.Contains(greeting, "Debian GNU/Linux 12") {
		t.Fatalf("banner missing from greeting: %q", greeting)
	}

	_, _ = clientConn.Write([]byte("root\r\n"))
	readUntil("Password: ")
	_, _ = clientConn.Write([]byte("toor123\r\n"))
	readUntil("Login incorrect\r\n")
	clientConn.Close()
	<-done

	events := rep.snapshot()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1: %+v", len(events), events)
	}
	ev := events[0]
	if ev.Trigger != TriggerTelnetLogin || ev.Severity != sensor.SeverityHigh {
		t.Fatalf("unexpected event: %+v", ev)
	}
	if ev.Details["username"] != "root" || ev.Details["password_hmac"] != expectedHMAC(t, "toor123") || ev.Details["password_length"] != float64(7) {
		t.Fatalf("unexpected details: %+v", ev.Details)
	}
}

func TestFTPLineBounds(t *testing.T) {
	exact := strings.Repeat("A", maxFTPLine-2) + "\r\n"
	got, err := readFTPLine(bufio.NewReader(strings.NewReader(exact)))
	if err != nil || len(got) != maxFTPLine-2 {
		t.Fatalf("exact 512-byte line failed: len=%d err=%v", len(got), err)
	}
	tooLong := strings.Repeat("A", maxFTPLine-1) + "\r\n"
	if _, err := readFTPLine(bufio.NewReader(strings.NewReader(tooLong))); err != errFTPLineTooLong {
		t.Fatalf("oversized line err = %v, want %v", err, errFTPLineTooLong)
	}
}

func TestFTPEndToEnd(t *testing.T) {
	d, rep := newTestDecoy(t, map[string]string{
		"TS_ENABLE_FTP": "true",
		"TS_FTP_BANNER": "(vsFTPd 3.0.5)",
	})

	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		d.handleFTP(ctx, serverConn, 21)
	}()

	br := bufio.NewReader(clientConn)
	expectLine := func(prefix string) {
		t.Helper()
		_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading line (want prefix %q): %v", prefix, err)
		}
		if !strings.HasPrefix(line, prefix) {
			t.Fatalf("got %q, want prefix %q", line, prefix)
		}
	}
	send := func(cmd string) {
		t.Helper()
		_ = clientConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.WriteString(clientConn, cmd+"\r\n"); err != nil {
			t.Fatalf("write %q: %v", cmd, err)
		}
	}

	expectLine("220 (vsFTPd 3.0.5)")

	send("SYST")
	expectLine("215 UNIX Type: L8")

	send("FEAT")
	expectLine("211-Features:")
	expectLine("211 End")

	send("AUTH TLS")
	expectLine("534 ")

	send("LIST")
	expectLine("530 Please login with USER and PASS.")

	send("PASS orphan")
	expectLine("503 ")

	send("USER alice")
	expectLine("331 ")
	send("PASS supersecret")
	expectLine("530 Login incorrect.")

	send("USER anonymous")
	expectLine("331 ")
	send("PASS guest@example.com")
	expectLine("530 Login incorrect.")

	send("QUIT")
	expectLine("221 Goodbye.")
	clientConn.Close()
	<-done

	events := rep.snapshot()
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(events), events)
	}
	if events[0].Trigger != TriggerFTPLogin || events[0].Details["username"] != "alice" || events[0].Details["anonymous"] != false || events[0].Details["password_hmac"] != expectedHMAC(t, "supersecret") {
		t.Fatalf("unexpected event 0: %+v", events[0])
	}
	if events[1].Trigger != TriggerFTPLogin || events[1].Details["username"] != "anonymous" || events[1].Details["anonymous"] != true || events[1].Details["password_hmac"] != expectedHMAC(t, "guest@example.com") {
		t.Fatalf("unexpected event 1: %+v", events[1])
	}
}

func TestFTPOversizedLineClosesConnection(t *testing.T) {
	d, rep := newTestDecoy(t, map[string]string{"TS_ENABLE_FTP": "true"})
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		d.handleFTP(ctx, serverConn, 21)
	}()

	br := bufio.NewReader(clientConn)
	_, _ = br.ReadString('\n') // 220 banner
	_, _ = io.WriteString(clientConn, "USER "+strings.Repeat("x", 600)+"\r\n")
	// Server must close immediately.
	_, err := br.ReadByte()
	if err == nil {
		t.Fatal("expected server to close connection on oversized FTP line")
	}
	clientConn.Close()
	<-done

	events := rep.snapshot()
	if len(events) != 1 || events[0].Trigger != TriggerFTPConnection {
		t.Fatalf("expected 1 ftp_connection event, got: %+v", events)
	}
}

func TestConnectionCapsAndCooldown(t *testing.T) {
	d, _ := newTestDecoy(t, map[string]string{
		"TS_MAX_CONNS":          "3",
		"TS_MAX_PER_SOURCE":     "2",
		"TS_EVENT_COOLDOWN_SEC": "60",
	})

	if !d.acquire("10.0.0.1") || !d.acquire("10.0.0.1") {
		t.Fatal("first two connections from 10.0.0.1 should succeed")
	}
	if d.acquire("10.0.0.1") {
		t.Fatal("third connection from 10.0.0.1 should exceed MaxPerSrc")
	}
	if !d.acquire("10.0.0.2") {
		t.Fatal("first connection from 10.0.0.2 should succeed")
	}
	if d.acquire("10.0.0.3") {
		t.Fatal("fourth total connection should exceed MaxConns")
	}
	d.release("10.0.0.1")
	d.release("10.0.0.1")
	d.release("10.0.0.2")

	// Login limiter allows burst of 6 then suppresses.
	for i := 0; i < loginLimiterBurst; i++ {
		if ok, _ := d.allowLogin("10.0.0.1", "ssh"); !ok {
			t.Fatalf("attempt %d unexpectedly limited", i)
		}
	}
	if ok, _ := d.allowLogin("10.0.0.1", "ssh"); ok {
		t.Fatal("attempt past burst should be suppressed")
	}
}
