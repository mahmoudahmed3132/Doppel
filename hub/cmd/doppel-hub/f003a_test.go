// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/auth"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/config"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/seal"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}

func writeTestCert(t *testing.T, certPath, keyPath, cn string, serial int64) {
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
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestProductionRefusesWithoutHTTPS(t *testing.T) {
	if testing.Short() {
		t.Skip("starts the real Hub")
	}
	dir := t.TempDir()
	kekPath := filepath.Join(dir, "kek")
	k, err := seal.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kekPath, []byte(k+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(),
		childEnv+"=1",
		config.EnvEnvironment+"=production",
		config.EnvKEKFile+"="+kekPath,
		config.EnvDBPath+"="+filepath.Join(dir, "hub.db"),
		config.EnvListenPort+"="+strconv.Itoa(freePort(t)),
		config.EnvMetricsAddr+"=off",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("production Hub started without TLS or TS_TRUSTED_PROXIES:\n%s", out)
	}
	if !strings.Contains(string(out), "production requires HTTPS") {
		t.Fatalf("unexpected error output:\n%s", out)
	}

	// Also refuse production start when stored public_endpoint is http://.
	dbPath := filepath.Join(dir, "http-ep.db")
	db, err := store.Open(context.Background(), dbPath, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ep := "http://hub.example.com"
	if err := db.PutSettings(context.Background(), map[string]*string{auth.SettingEndpoint: &ep}); err != nil {
		t.Fatal(err)
	}
	db.Close()

	cmd = exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(),
		childEnv+"=1",
		config.EnvEnvironment+"=production",
		config.EnvKEKFile+"="+kekPath,
		config.EnvTrustedProxies+"=127.0.0.1/32",
		config.EnvDBPath+"="+dbPath,
		config.EnvListenPort+"="+strconv.Itoa(freePort(t)),
		config.EnvMetricsAddr+"=off",
	)
	out, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("production Hub started with http:// public_endpoint:\n%s", out)
	}
	if !strings.Contains(string(out), "public_endpoint to use https://") {
		t.Fatalf("unexpected error output:\n%s", out)
	}
}

func TestNativeTLSSIGHUPHealthAndMetrics(t *testing.T) {
	if testing.Short() {
		t.Skip("starts the real Hub")
	}
	dir := t.TempDir()
	kekPath := filepath.Join(dir, "kek")
	k, err := seal.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kekPath, []byte(k+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writeTestCert(t, certPath, keyPath, "hub-initial.test", 1)

	mainPort := freePort(t)
	metricsPort := freePort(t)
	logf, err := os.OpenFile(filepath.Join(dir, "hub.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(),
		childEnv+"=1",
		config.EnvEnvironment+"=production",
		config.EnvKEKFile+"="+kekPath,
		config.EnvDBPath+"="+filepath.Join(dir, "hub.db"),
		config.EnvListenPort+"="+strconv.Itoa(mainPort),
		config.EnvTLSCertFile+"="+certPath,
		config.EnvTLSKeyFile+"="+keyPath,
		config.EnvMetricsAddr+"=127.0.0.1:"+strconv.Itoa(metricsPort),
		config.EnvUpdateCheckURL+"=https://127.0.0.1:1/none",
		config.EnvRegistryURL+"=https://127.0.0.1:1/",
	)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Signal(syscall.SIGTERM)
		cmd.Wait()
		logf.Close()
		if t.Failed() {
			b, _ := os.ReadFile(logf.Name())
			t.Logf("hub log:\n%s", tail(b, 4000))
		}
	})

	httpsClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   5 * time.Second,
	}
	mainBase := "https://127.0.0.1:" + strconv.Itoa(mainPort)
	metricsBase := "http://127.0.0.1:" + strconv.Itoa(metricsPort)

	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := httpsClient.Get(mainBase + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("TLS hub did not start: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Verify /readyz returns 200 {"status":"ok"} and HSTS header is present.
	resp, err := httpsClient.Get(mainBase + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != `{"status":"ok"}` {
		t.Fatalf("/readyz = %d %q", resp.StatusCode, string(body))
	}
	if resp.Header.Get("Strict-Transport-Security") == "" {
		t.Fatal("missing Strict-Transport-Security on native TLS response")
	}

	// Verify /metrics is NOT exposed on the public port.
	resp, err = httpsClient.Get(mainBase + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	pubMetrics, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(pubMetrics), "doppel_build_info") {
		t.Fatalf("/metrics was exposed on the public port!")
	}

	// Verify /metrics IS served on the dedicated loopback metrics port.
	resp, err = http.Get(metricsBase + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	mbody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics port /metrics status = %d", resp.StatusCode)
	}
	for _, want := range []string{
		"doppel_build_info{",
		"doppel_http_requests_total{",
		"doppel_http_request_seconds_count",
		"doppel_db_query_seconds_count",
		"doppel_nodes{state=\"online\"}",
		"doppel_sensors{state=\"online\"}",
		"doppel_siem_queue_depth{",
		"doppel_legacy_drills_total",
	} {
		if !strings.Contains(string(mbody), want) {
			t.Errorf("metrics output missing %q", want)
		}
	}

	// Verify initial TLS certificate CN and hot reload on SIGHUP.
	dialCN := func() string {
		conn, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(mainPort), &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatalf("tls dial: %v", err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].Subject.CommonName
	}
	if got := dialCN(); got != "hub-initial.test" {
		t.Fatalf("initial CN = %q want hub-initial.test", got)
	}
	writeTestCert(t, certPath, keyPath, "hub-reloaded.test", 2)
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	reloadDeadline := time.Now().Add(5 * time.Second)
	for {
		if dialCN() == "hub-reloaded.test" {
			break
		}
		if time.Now().After(reloadDeadline) {
			t.Fatalf("certificate did not reload after SIGHUP; CN=%q", dialCN())
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Verify default listen address is 127.0.0.1 in startup log.
	logBytes, _ := os.ReadFile(logf.Name())
	if !strings.Contains(string(logBytes), `"addr":"127.0.0.1:`+strconv.Itoa(mainPort)+`"`) {
		t.Fatalf("hub did not bind default 127.0.0.1:\n%s", tail(logBytes, 2000))
	}
}
