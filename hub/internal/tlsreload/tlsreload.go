// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package tlsreload loads and hot-reloads a PEM TLS certificate/key pair for
// the Hub's native HTTPS listener (H1 / WP-4A). TLS 1.2+ with modern AEAD
// cipher suites is enforced; a failed reload keeps the previous valid
// certificate so a mistyped rotation never drops traffic.
package tlsreload

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"sync/atomic"
)

// ModernCipherSuites lists the AEAD cipher suites permitted for TLS 1.2.
// TLS 1.3 cipher suites are always modern and managed by crypto/tls.
var ModernCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

// Reloader holds a live TLS certificate that can be reloaded atomically (e.g.
// on SIGHUP).
type Reloader struct {
	certFile string
	keyFile  string
	log      *slog.Logger
	cert     atomic.Pointer[tls.Certificate]
}

// New loads certFile and keyFile eagerly. Startup fails closed if either file
// is unreadable, invalid, or mismatched.
func New(certFile, keyFile string, log *slog.Logger) (*Reloader, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	r := &Reloader{certFile: certFile, keyFile: keyFile, log: log}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Reload reads certFile and keyFile from disk and atomically replaces the
// active certificate. On error the previously loaded certificate (if any)
// remains active.
func (r *Reloader) Reload() error {
	c, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("loading TLS key pair (%s, %s): %w", r.certFile, r.keyFile, err)
	}
	if len(c.Certificate) > 0 {
		if leaf, err := x509.ParseCertificate(c.Certificate[0]); err == nil {
			c.Leaf = leaf
		}
	}
	prev := r.cert.Swap(&c)
	if prev != nil {
		attrs := []any{"cert_file", r.certFile}
		if c.Leaf != nil {
			attrs = append(attrs, "subject", c.Leaf.Subject.String(), "not_after", c.Leaf.NotAfter.UTC().Format("2006-01-02T15:04:05Z"))
		}
		r.log.Info("TLS certificate reloaded", attrs...)
	}
	return nil
}

// GetCertificate satisfies tls.Config.GetCertificate.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.cert.Load(), nil
}

// TLSConfig returns a hardened server tls.Config backed by this Reloader.
func (r *Reloader) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		CipherSuites:   append([]uint16(nil), ModernCipherSuites...),
		GetCertificate: r.GetCertificate,
	}
}
