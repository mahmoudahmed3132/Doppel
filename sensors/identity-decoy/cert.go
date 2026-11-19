// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// generateEphemeralTLSConfig creates a fresh in-memory self-signed ECDSA P-256
// certificate for the persona FQDN. The key and certificate are never written
// to disk.
func generateEphemeralTLSConfig(hostname, domainDNS string, now time.Time) (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ECDSA P-256 key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}

	fqdn := strings.ToLower(strings.TrimSpace(hostname))
	if d := strings.ToLower(strings.TrimSpace(domainDNS)); d != "" {
		fqdn = fqdn + "." + d
	}
	if fqdn == "" {
		fqdn = "dc01.corp.local"
	}

	dnsNames := []string{fqdn}
	short := strings.ToLower(strings.TrimSpace(hostname))
	if short != "" && short != fqdn {
		dnsNames = append(dnsNames, short)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: fqdn,
		},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("create self-signed certificate: %w", err)
	}

	parsed, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("parse self-signed certificate: %w", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
		Leaf:        parsed,
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}
