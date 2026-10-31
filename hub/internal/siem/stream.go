// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package siem

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// Transport delivers one rendered record.
type Transport interface {
	Send(ctx context.Context, record []byte) error
	Close() error
}

// deliveryError classifies a failure; terminal failures are not retried.
type deliveryError struct {
	terminal bool
	err      error
}

func (e *deliveryError) Error() string { return e.err.Error() }
func (e *deliveryError) Unwrap() error { return e.err }

func terminal(err error) error  { return &deliveryError{terminal: true, err: err} }
func transient(err error) error { return &deliveryError{err: err} }

// IsTerminal reports whether err must not be retried.
func IsTerminal(err error) bool {
	var de *deliveryError
	return errors.As(err, &de) && de.terminal
}

const (
	maxUDPRecord   = 65000
	writeTimeout   = 10 * time.Second
	dialTimeout    = 10 * time.Second
	reconnectGap   = 2 * time.Second
	peerCheckDelay = time.Millisecond
)

// streamTransport writes newline-framed records over tcp or tls, or one
// datagram per record over udp.
type streamTransport struct {
	proto string
	addr  string
	tls   *tls.Config
	now   func() time.Time
	gap   time.Duration

	mu       sync.Mutex
	conn     net.Conn
	lastDial time.Time
}

func newStream(c Config, caBundle string) (*streamTransport, error) {
	t := &streamTransport{proto: c.Protocol, addr: c.Address, now: time.Now, gap: reconnectGap}
	if c.Protocol == ProtoTLS {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if caBundle != "" {
			pem, err := os.ReadFile(caBundle)
			if err != nil {
				return nil, fmt.Errorf("SIEM CA bundle: %w", err)
			}
			if !pool.AppendCertsFromPEM(pem) {
				return nil, errors.New("SIEM CA bundle contains no certificates")
			}
		}
		host, _, _ := net.SplitHostPort(c.Address)
		t.tls = &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS12}
	}
	return t, nil
}

// peerClosed detects a collector that closed the connection: a read with a
// 1 ms deadline returning EOF or a reset means closed; a timeout means open.
func peerClosed(c net.Conn) bool {
	if err := c.SetReadDeadline(time.Now().Add(peerCheckDelay)); err != nil {
		return true
	}
	var b [1]byte
	_, err := c.Read(b[:])
	_ = c.SetReadDeadline(time.Time{})
	if err == nil {
		return false // collector sent data; ignore it, connection is alive
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	// EOF (collector closed), reset, or any other read error: reconnect.
	return true
}

func (t *streamTransport) connect(ctx context.Context) (net.Conn, error) {
	if t.conn != nil {
		if t.proto == ProtoUDP || !peerClosed(t.conn) {
			return t.conn, nil
		}
		t.conn.Close()
		t.conn = nil
	}
	if wait := t.gap - t.now().Sub(t.lastDial); !t.lastDial.IsZero() && wait > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	t.lastDial = t.now()
	d := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	var (
		c   net.Conn
		err error
	)
	switch t.proto {
	case ProtoTLS:
		c, err = (&tls.Dialer{NetDialer: d, Config: t.tls}).DialContext(ctx, "tcp", t.addr)
	case ProtoUDP:
		c, err = d.DialContext(ctx, "udp", t.addr)
	default:
		c, err = d.DialContext(ctx, "tcp", t.addr)
	}
	if err != nil {
		return nil, err
	}
	t.conn = c
	return c, nil
}

// Send writes one record. Any failure closes the connection so the next
// attempt reconnects (throttled to one dial per reconnect gap).
func (t *streamTransport) Send(ctx context.Context, record []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.proto == ProtoUDP && len(record) > maxUDPRecord {
		return terminal(fmt.Errorf("record of %d bytes exceeds the UDP limit", len(record)))
	}
	c, err := t.connect(ctx)
	if err != nil {
		return transient(err)
	}
	line := record
	if t.proto != ProtoUDP {
		line = append(record[:len(record):len(record)], '\n') // full slice expression: always copies, never touches the caller's buffer
	}
	_ = c.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := c.Write(line); err != nil {
		c.Close()
		t.conn = nil
		return transient(err)
	}
	return nil
}

func (t *streamTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn != nil {
		err := t.conn.Close()
		t.conn = nil
		return err
	}
	return nil
}
