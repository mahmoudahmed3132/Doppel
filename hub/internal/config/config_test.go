// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestDefaults(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != "127.0.0.1" || c.ListenPort != 8080 || c.MetricsAddr != "127.0.0.1:9090" ||
		c.DBPath != "/data/truesignal.db" || c.SessionTTL != 12*time.Hour ||
		c.SessionIdle != 15*time.Minute || c.SyslogPEN != 32473 || c.Development || len(c.TrustedProxies) != 0 {
		t.Fatalf("%+v", c)
	}
	if !c.ListenIsLoopback() {
		t.Fatal("default ListenAddr must be loopback")
	}
	if len(c.DevWarnings()) != 0 {
		t.Fatal("unexpected dev warnings")
	}
}

// The source repository is private, so public artefacts come from the public
// releases repository; an anonymous Hub could not read the source repository.
func TestDefaultsUsePublicReleasesRepo(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.RegistryURL != "https://raw.githubusercontent.com/mahmoudahmed3132/truesignal-releases/registry/" {
		t.Fatalf("registry URL %q", c.RegistryURL)
	}
	if c.UpdateCheckURL != "https://api.github.com/repos/mahmoudahmed3132/truesignal-releases/releases?per_page=100" {
		t.Fatalf("update check URL %q", c.UpdateCheckURL)
	}
	if strings.Contains(c.RegistryURL+c.UpdateCheckURL, "TrueSignal-Rewrite") {
		t.Fatal("a default points at the private source repository")
	}
}

func TestTrustedProxies(t *testing.T) {
	c, err := Load(env(map[string]string{EnvTrustedProxies: "10.0.0.1, 172.16.0.0/12,::1"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.TrustedProxies) != 3 || c.TrustedProxies[0].String() != "10.0.0.1/32" {
		t.Fatalf("%v", c.TrustedProxies)
	}
	if _, err := Load(env(map[string]string{EnvTrustedProxies: "10.0.0.1,proxy.local"})); err == nil {
		t.Fatal("invalid trusted proxy accepted")
	}
}

func TestInvalidValuesRefuse(t *testing.T) {
	bad := map[string]string{
		EnvListenPort:        "0",
		EnvEnvironment:       "staging",
		EnvRequireMFA:        "maybe",
		EnvDashboardPassword: "short",
		EnvSessionTTL:        "5s",
		EnvSyslogPEN:         "-1",
	}
	_, err := Load(env(bad))
	if err == nil {
		t.Fatal("accepted")
	}
	for k := range bad {
		if !strings.Contains(err.Error(), k) {
			t.Errorf("error does not mention %s", k)
		}
	}
	if strings.Contains(err.Error(), "short") {
		t.Fatal("secret echoed in error")
	}
}

func TestSecretsPolicy(t *testing.T) {
	for name, tc := range map[string]struct {
		env map[string]string
		ok  bool
	}{
		"production, no kek":     {map[string]string{}, false},
		"production, plaintext":  {map[string]string{"TS_DEV_ALLOW_PLAINTEXT_SECRETS": "true"}, false},
		"production, kek":        {map[string]string{"TS_KEK_FILE": "/run/secrets/k"}, true},
		"development, no flag":   {map[string]string{"TS_ENV": "development"}, false},
		"development, plaintext": {map[string]string{"TS_ENV": "development", "TS_DEV_ALLOW_PLAINTEXT_SECRETS": "true"}, true},
		"development, kek":       {map[string]string{"TS_ENV": "development", "TS_KEK_FILE": "/k"}, true},
	} {
		c, err := Load(env(tc.env))
		if err != nil {
			t.Fatal(name, err)
		}
		if got := c.SecretsPolicy() == nil; got != tc.ok {
			t.Errorf("%s: ok=%v want %v", name, got, tc.ok)
		}
	}
	c, _ := Load(env(map[string]string{"TS_ENV": "development", "TS_DEV_ALLOW_PLAINTEXT_SECRETS": "true"}))
	found := false
	for _, w := range c.DevWarnings() {
		found = found || strings.Contains(w, "plaintext")
	}
	if !found {
		t.Error("no warning for plaintext secrets")
	}
}

func TestListenTLSAndMetrics(t *testing.T) {
	c, err := Load(env(map[string]string{
		EnvListenAddr:  "0.0.0.0",
		EnvListenPort:  "8443",
		EnvTLSCertFile: "/etc/hub/cert.pem",
		EnvTLSKeyFile:  "/etc/hub/key.pem",
		EnvMetricsAddr: "127.0.0.1:9191",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenEndpoint() != "0.0.0.0:8443" || c.ListenIsLoopback() || !c.TLSEnabled() || c.MetricsAddr != "127.0.0.1:9191" {
		t.Fatalf("unexpected config: %+v", c)
	}

	// Metrics disabled via "off"
	c, err = Load(env(map[string]string{EnvMetricsAddr: "off"}))
	if err != nil || c.MetricsAddr != "" {
		t.Fatalf("metrics off: cfg=%+v err=%v", c, err)
	}

	// IPv6 loopback and localhost
	c, err = Load(env(map[string]string{EnvListenAddr: "::1"}))
	if err != nil || !c.ListenIsLoopback() || c.ListenEndpoint() != "[::1]:8080" {
		t.Fatalf("ipv6 loopback: cfg=%+v err=%v", c, err)
	}
	c, err = Load(env(map[string]string{EnvListenAddr: "localhost"}))
	if err != nil || c.ListenAddr != "127.0.0.1" {
		t.Fatalf("localhost: cfg=%+v err=%v", c, err)
	}

	// Invalid cases must fail closed
	for name, m := range map[string]map[string]string{
		"bad listen addr":       {EnvListenAddr: "not-an-ip"},
		"cert without key":      {EnvTLSCertFile: "/etc/cert.pem"},
		"key without cert":      {EnvTLSKeyFile: "/etc/key.pem"},
		"bad metrics addr":      {EnvMetricsAddr: "9090"},
		"bad metrics host":      {EnvMetricsAddr: "example.com:9090"},
		"bad metrics port":      {EnvMetricsAddr: "127.0.0.1:70000"},
		"metrics shares public": {EnvListenAddr: "127.0.0.1", EnvListenPort: "8080", EnvMetricsAddr: "127.0.0.1:8080"},
	} {
		if _, err := Load(env(m)); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestTransportPolicy(t *testing.T) {
	for name, tc := range map[string]struct {
		env      map[string]string
		endpoint string
		ok       bool
	}{
		"prod, no tls, no proxy":               {map[string]string{}, "", false},
		"prod, non-loopback, no tls, no proxy": {map[string]string{EnvListenAddr: "0.0.0.0"}, "", false},
		"prod, native tls, no endpoint":        {map[string]string{EnvTLSCertFile: "/c", EnvTLSKeyFile: "/k"}, "", true},
		"prod, native tls, https endpoint":     {map[string]string{EnvTLSCertFile: "/c", EnvTLSKeyFile: "/k"}, "https://hub.example.com", true},
		"prod, native tls, http endpoint":      {map[string]string{EnvTLSCertFile: "/c", EnvTLSKeyFile: "/k"}, "http://hub.example.com", false},
		"prod, trusted proxy, https endpoint":  {map[string]string{EnvTrustedProxies: "10.0.0.1"}, "https://hub.example.com", true},
		"prod, trusted proxy, http endpoint":   {map[string]string{EnvTrustedProxies: "10.0.0.1"}, "http://hub.example.com", false},
		"prod, non-loopback + trusted proxy":   {map[string]string{EnvListenAddr: "0.0.0.0", EnvTrustedProxies: "10.0.0.1"}, "https://hub.example.com", true},
		"dev, no tls, no proxy, http endpoint": {map[string]string{EnvEnvironment: "development"}, "http://127.0.0.1:8080", true},
	} {
		c, err := Load(env(tc.env))
		if err != nil {
			t.Fatalf("%s: load: %v", name, err)
		}
		if got := c.TransportPolicy(tc.endpoint) == nil; got != tc.ok {
			t.Errorf("%s: ok=%v want %v (err=%v)", name, got, tc.ok, c.TransportPolicy(tc.endpoint))
		}
	}
}
