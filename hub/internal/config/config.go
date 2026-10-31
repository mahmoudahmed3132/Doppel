// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package config loads the Hub configuration from TS_ environment variables.
// Invalid values refuse startup (fail closed).
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Environment variable names.
const (
	EnvListenPort          = "TS_LISTEN_PORT"
	EnvDBPath              = "TS_DB_PATH"
	EnvEnvironment         = "TS_ENV"
	EnvTrustedProxies      = "TS_TRUSTED_PROXIES"
	EnvRequireMFA          = "TS_REQUIRE_MFA"
	EnvDashboardPassword   = "TS_DASHBOARD_PASSWORD"
	EnvSetupToken          = "TS_SETUP_TOKEN"
	EnvSessionTTL          = "TS_SESSION_TTL"
	EnvSessionIdle         = "TS_SESSION_IDLE_TIMEOUT"
	EnvSIEMCABundle        = "TS_SIEM_CA_BUNDLE"
	EnvSyslogPEN           = "TS_SYSLOG_PEN"
	EnvGeoIPDB             = "TS_GEOIP_DB"
	EnvGeoIPAutoUpdate     = "TS_GEOIP_AUTO_UPDATE"
	EnvSignerRepo          = "TS_MANIFEST_SIGNER_REPO"
	EnvSigstoreTrustedRoot = "TS_SIGSTORE_TRUSTED_ROOT"
	EnvDevAllowUnsigned    = "TS_DEV_ALLOW_UNSIGNED_MANIFESTS"
	EnvDevAllowUnpinned    = "TS_DEV_ALLOW_UNPINNED_IMAGES"
	EnvRegistryURL         = "TS_REGISTRY_URL"
	EnvUpdateCheckURL      = "TS_UPDATE_CHECK_URL"
)

// Config is the Hub process configuration.
type Config struct {
	ListenPort        int
	DBPath            string
	Development       bool
	TrustedProxies    []netip.Prefix
	RequireMFA        bool
	DashboardPassword string // secret; when set, UI password change is disabled
	SetupToken        string // secret; one-time setup token override
	SessionTTL        time.Duration
	SessionIdle       time.Duration
	SIEMCABundle      string
	SyslogPEN         int
	GeoIPDB           string
	GeoIPAutoUpdate   bool
	SignerRepo        string
	SigstoreRoot      string
	DevAllowUnsigned  bool
	DevAllowUnpinned  bool
	RegistryURL       string // default registry; the registry_url setting overrides it
	UpdateCheckURL    string // releases API queried by the update check (§6.11)
}

// ReleasesRepo is the public repository that serves the product's public
// artefacts: the registry branch, CLI and Hub releases, install.sh. The
// source repository is private; signatures still name it (signing.DefaultSignerRepo).
const ReleasesRepo = "mahmoudahmed3132/truesignal-releases"

// DefaultRegistryURL is the product's registry branch (§10).
const DefaultRegistryURL = "https://raw.githubusercontent.com/" + ReleasesRepo + "/registry/"

// DefaultUpdateCheckURL lists the product's releases (§6.11).
const DefaultUpdateCheckURL = "https://api.github.com/repos/" + ReleasesRepo + "/releases?per_page=100"

// Load reads the configuration through getenv.
func Load(getenv func(string) string) (*Config, error) {
	get := func(k string) string { return strings.TrimSpace(getenv(k)) }
	c := &Config{
		ListenPort:  8080,
		DBPath:      "/data/truesignal.db",
		SessionTTL:  12 * time.Hour,
		SessionIdle: 15 * time.Minute,
		SyslogPEN:   32473,
	}
	var errs []error
	fail := func(k string, format string, a ...any) {
		errs = append(errs, fmt.Errorf("%s: "+format, append([]any{k}, a...)...))
	}

	if v := get(EnvListenPort); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 || p > 65535 {
			fail(EnvListenPort, "invalid port %q", v)
		}
		c.ListenPort = p
	}
	if v := get(EnvDBPath); v != "" {
		c.DBPath = v
	}
	switch v := strings.ToLower(get(EnvEnvironment)); v {
	case "", "production":
	case "development":
		c.Development = true
	default:
		fail(EnvEnvironment, "must be production or development, got %q", v)
	}
	if v := get(EnvTrustedProxies); v != "" {
		for _, item := range strings.Split(v, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			p, err := parsePrefix(item)
			if err != nil {
				fail(EnvTrustedProxies, "invalid entry %q", item)
				continue
			}
			c.TrustedProxies = append(c.TrustedProxies, p)
		}
	}
	boolVar := func(k string, dst *bool) {
		switch v := strings.ToLower(get(k)); v {
		case "":
		case "true", "1", "yes":
			*dst = true
		case "false", "0", "no":
			*dst = false
		default:
			fail(k, "must be true or false, got %q", v)
		}
	}
	boolVar(EnvRequireMFA, &c.RequireMFA)
	boolVar(EnvGeoIPAutoUpdate, &c.GeoIPAutoUpdate)
	boolVar(EnvDevAllowUnsigned, &c.DevAllowUnsigned)
	boolVar(EnvDevAllowUnpinned, &c.DevAllowUnpinned)

	// Secrets are not trimmed beyond surrounding whitespace and never echoed.
	c.DashboardPassword = getenv(EnvDashboardPassword)
	if c.DashboardPassword != "" && len(c.DashboardPassword) < 12 {
		fail(EnvDashboardPassword, "must be at least 12 characters")
	}
	c.SetupToken = get(EnvSetupToken)
	if c.SetupToken != "" && len(c.SetupToken) < 32 {
		fail(EnvSetupToken, "must be at least 32 characters")
	}

	durVar := func(k string, dst *time.Duration, min time.Duration) {
		if v := get(k); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil || d < min {
				fail(k, "invalid duration %q (minimum %s)", v, min)
				return
			}
			*dst = d
		}
	}
	durVar(EnvSessionTTL, &c.SessionTTL, time.Minute)
	durVar(EnvSessionIdle, &c.SessionIdle, time.Minute)

	if v := get(EnvSyslogPEN); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			fail(EnvSyslogPEN, "invalid enterprise number %q", v)
		}
		c.SyslogPEN = n
	}
	c.SIEMCABundle = get(EnvSIEMCABundle)
	c.GeoIPDB = get(EnvGeoIPDB)
	c.SignerRepo = get(EnvSignerRepo)
	c.SigstoreRoot = get(EnvSigstoreTrustedRoot)
	c.UpdateCheckURL = DefaultUpdateCheckURL
	if v := get(EnvUpdateCheckURL); v != "" {
		if !strings.HasPrefix(v, "https://") {
			fail(EnvUpdateCheckURL, "must be an https:// URL")
		}
		c.UpdateCheckURL = v
	}
	c.RegistryURL = DefaultRegistryURL
	if v := get(EnvRegistryURL); v != "" {
		c.RegistryURL = v
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return c, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
}

// DevWarnings lists active development-only relaxations, for a loud startup log.
func (c *Config) DevWarnings() []string {
	var w []string
	if c.DevAllowUnsigned {
		w = append(w, EnvDevAllowUnsigned+" is set: unsigned sensor manifests are accepted")
	}
	if c.DevAllowUnpinned {
		w = append(w, EnvDevAllowUnpinned+" is set: images without @sha256 digests are accepted")
	}
	if c.Development {
		w = append(w, EnvEnvironment+"=development: cookie Secure flag and WebSocket origin check are relaxed")
	}
	return w
}
