// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/decoy"
	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

const sshHostKeyLabelPrefix = "doppel:ssh-host-key:v1:"

// deriveSSHHostKey derives an Ed25519 SSH host key deterministically from the
// node capture key and sensor ID so the fingerprint is stable across restarts
// on one node and distinct across nodes, without writing key material to disk.
// When captureKey is empty (possible only when TS_PASSWORD_CAPTURE is plain or
// none), an ephemeral Ed25519 key is generated in memory.
func deriveSSHHostKey(captureKey []byte, sensorID string) (ssh.Signer, error) {
	var priv ed25519.PrivateKey
	if len(captureKey) > 0 {
		mac := hmac.New(sha256.New, captureKey)
		mac.Write([]byte(sshHostKeyLabelPrefix + sensorID))
		seed := mac.Sum(nil)
		priv = ed25519.NewKeyFromSeed(seed)
	} else {
		var err error
		_, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
	}
	return ssh.NewSignerFromKey(priv)
}

// bannerCaptureConn captures the peer's initial SSH identification string
// (up to 255 bytes) while transparently passing all bytes through to ssh.
type bannerCaptureConn struct {
	net.Conn
	mu   sync.Mutex
	buf  []byte
	done bool
}

func (b *bannerCaptureConn) Read(p []byte) (int, error) {
	n, err := b.Conn.Read(p)
	if n > 0 {
		b.mu.Lock()
		if !b.done {
			for i := 0; i < n && len(b.buf) < 255; i++ {
				ch := p[i]
				if ch == '\n' {
					b.done = true
					break
				}
				if ch != '\r' {
					b.buf = append(b.buf, ch)
				}
			}
			if len(b.buf) >= 255 {
				b.done = true
			}
		}
		b.mu.Unlock()
	}
	return n, err
}

func (b *bannerCaptureConn) clientVersion() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := string(b.buf)
	if !strings.HasPrefix(s, "SSH-") {
		return ""
	}
	return sensor.Clean(s, 128)
}

func sshTarget(port int) string { return "SSH port " + strconv.Itoa(port) }

func (d *Decoy) handleSSH(ctx context.Context, raw net.Conn, port int) {
	defer raw.Close()

	stop := context.AfterFunc(ctx, func() { _ = raw.SetDeadline(time.Now()) })
	defer stop()

	bc := &bannerCaptureConn{Conn: newBoundedConn(raw, d.idleTimeout, d.totalTimeout)}
	src := raw.RemoteAddr().String()
	ip := decoy.RemoteIP(raw.RemoteAddr())
	target := sshTarget(port)

	var authAttempted atomic.Bool
	rejectErr := errors.New("permission denied")

	reportLogin := func(conn ssh.ConnMetadata, method string, extra sensor.Fields) {
		authAttempted.Store(true)
		if ok, sup := d.allowLogin(ip, "ssh"); ok {
			fields := sensor.Fields{
				sensor.F("protocol", "ssh"),
				sensor.F("dst_port", port),
				sensor.F("username", sensor.Clean(conn.User(), 128)),
				sensor.F("method", method),
				sensor.F("client_version", sensor.Clean(string(conn.ClientVersion()), 128)),
			}
			fields = append(fields, extra...)
			fields = append(fields, sensor.F("suppressed_since_last", sup))
			d.r.ReportSeverity(sensor.SeverityHigh, TriggerSSHLogin, src, target, fields)
		}
	}

	sshCfg := &ssh.ServerConfig{
		ServerVersion: d.cfg.SSHBanner,
		MaxAuthTries:  d.cfg.SSHMaxAuthTries,
		PasswordCallback: func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			reportLogin(conn, "password", d.capture.Password(string(pass)))
			return nil, rejectErr
		},
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			answers, err := client(conn.User(), "", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			pw := ""
			if len(answers) > 0 {
				pw = answers[0]
			}
			reportLogin(conn, "keyboard-interactive", d.capture.Password(pw))
			return nil, rejectErr
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			extra := sensor.Fields{
				sensor.F("key_type", sensor.Clean(key.Type(), 64)),
				sensor.F("key_fingerprint", ssh.FingerprintSHA256(key)),
			}
			reportLogin(conn, "publickey", extra)
			return nil, rejectErr
		},
	}
	sshCfg.AddHostKey(d.hostKey)

	sc, chans, reqs, err := ssh.NewServerConn(bc, sshCfg)
	if err == nil && sc != nil {
		// Defense in depth: every auth callback rejects, so a session should
		// never be established. Close immediately if it ever were.
		go ssh.DiscardRequests(reqs)
		go func() {
			for ch := range chans {
				_ = ch.Reject(ssh.Prohibited, "access denied")
			}
		}()
		_ = sc.Close()
	}

	if !authAttempted.Load() {
		if ok, sup := d.allowConn(ip, "ssh"); ok {
			fields := sensor.Fields{
				sensor.F("protocol", "ssh"),
				sensor.F("dst_port", port),
			}
			if cv := bc.clientVersion(); cv != "" {
				fields = append(fields, sensor.F("client_version", cv))
			}
			fields = append(fields, sensor.F("suppressed_since_last", sup))
			d.r.ReportSeverity(sensor.SeverityMedium, TriggerSSHConnection, src, target, fields)
		}
	}
}
