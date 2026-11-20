// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package tlsreload

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeSelfSigned(t *testing.T, certPath, keyPath, cn string, serial int64) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReloadAndTLSMinVersion(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	// Missing files must fail closed.
	if _, err := New(certPath, keyPath, nil); err == nil {
		t.Fatal("expected error for missing cert/key")
	}

	writeSelfSigned(t, certPath, keyPath, "hub-v1.example.test", 1)
	rel, err := New(certPath, keyPath, nil)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", rel.TLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	dialCN := func() string {
		conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatalf("tls dial: %v", err)
		}
		defer conn.Close()
		if conn.ConnectionState().Version < tls.VersionTLS12 {
			t.Fatalf("negotiated TLS version %x < TLS 1.2", conn.ConnectionState().Version)
		}
		return conn.ConnectionState().PeerCertificates[0].Subject.CommonName
	}

	if got := dialCN(); got != "hub-v1.example.test" {
		t.Fatalf("initial CN = %q, want hub-v1.example.test", got)
	}

	// TLS 1.1 client must be rejected.
	if conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS11,
	}); err == nil {
		conn.Close()
		t.Fatal("TLS 1.1 client was accepted")
	}

	// Hot reload to v2 certificate.
	writeSelfSigned(t, certPath, keyPath, "hub-v2.example.test", 2)
	if err := rel.Reload(); err != nil {
		t.Fatal(err)
	}
	if got := dialCN(); got != "hub-v2.example.test" {
		t.Fatalf("reloaded CN = %q, want hub-v2.example.test", got)
	}

	// Broken reload must fail and keep v2 active.
	if err := os.WriteFile(certPath, []byte("not-a-cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rel.Reload(); err == nil {
		t.Fatal("expected error on corrupt cert reload")
	}
	if got := dialCN(); got != "hub-v2.example.test" {
		t.Fatalf("after failed reload CN = %q, want hub-v2.example.test", got)
	}
}
