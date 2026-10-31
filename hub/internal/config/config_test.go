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
	if c.ListenPort != 8080 || c.DBPath != "/data/truesignal.db" || c.SessionTTL != 12*time.Hour ||
		c.SessionIdle != 15*time.Minute || c.SyslogPEN != 32473 || c.Development || len(c.TrustedProxies) != 0 {
		t.Fatalf("%+v", c)
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
