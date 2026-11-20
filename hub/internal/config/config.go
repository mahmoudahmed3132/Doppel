// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package config loads the Hub configuration from TS_ environment variables.
// Invalid values refuse startup (fail closed).
package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Environment variable names.
const (
	EnvListenAddr          = "TS_LISTEN_ADDR"
	EnvListenPort          = "TS_LISTEN_PORT"
	EnvTLSCertFile         = "TS_TLS_CERT_FILE"
	EnvTLSKeyFile          = "TS_TLS_KEY_FILE"
	EnvMetricsAddr         = "TS_METRICS_ADDR"
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
	EnvGeoIPASNDB          = "TS_GEOIP_ASN_DB"
	EnvGeoIPAutoUpdate     = "TS_GEOIP_AUTO_UPDATE"
	EnvSignerRepo          = "TS_MANIFEST_SIGNER_REPO"
	EnvSigstoreTrustedRoot = "TS_SIGSTORE_TRUSTED_ROOT"
	EnvDevAllowUnsigned    = "TS_DEV_ALLOW_UNSIGNED_MANIFESTS"
	EnvDevAllowUnpinned    = "TS_DEV_ALLOW_UNPINNED_IMAGES"
	EnvRegistryURL         = "TS_REGISTRY_URL"
	EnvUpdateCheckURL      = "TS_UPDATE_CHECK_URL"
	EnvKEKFile             = "TS_KEK_FILE"
	EnvDevAllowPlaintext   = "TS_DEV_ALLOW_PLAINTEXT_SECRETS"
)

// DefaultListenAddr and DefaultMetricsAddr bind loopback only (F-003).
const (
	DefaultListenAddr  = "127.0.0.1"
	DefaultMetricsAddr = "127.0.0.1:9090"
)

// Config is the Hub process configuration.
type Config struct {
	ListenAddr        string
	ListenPort        int
	TLSCertFile       string
	TLSKeyFile        string
	MetricsAddr       string // "" disables the dedicated /metrics listener
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
	GeoIPASNDB        string
	GeoIPAutoUpdate   bool
	SignerRepo        string
	SigstoreRoot      string
	DevAllowUnsigned  bool
	DevAllowUnpinned  bool
	KEKFile           string // key-encryption key file (secrets at rest); required in production
	DevAllowPlaintext bool   // development only: run without a KEK, secrets in plaintext
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
		ListenAddr:  DefaultListenAddr,
		ListenPort:  8080,
		MetricsAddr: DefaultMetricsAddr,
		DBPath:      "/data/truesignal.db",
		SessionTTL:  12 * time.Hour,
		SessionIdle: 15 * time.Minute,
		SyslogPEN:   32473,
	}
	var errs []error
	fail := func(k string, format string, a ...any) {
		errs = append(errs, fmt.Errorf("%s: "+format, append([]any{k}, a...)...))
	}

	if v := get(EnvListenAddr); v != "" {
		if strings.EqualFold(v, "localhost") {
			c.ListenAddr = "127.0.0.1"
		} else if a, err := netip.ParseAddr(v); err != nil {
			fail(EnvListenAddr, "invalid IP address %q", v)
		} else {
			c.ListenAddr = a.Unmap().String()
		}
	}
	if v := get(EnvListenPort); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 || p > 65535 {
			fail(EnvListenPort, "invalid port %q", v)
		}
		c.ListenPort = p
	}
	c.TLSCertFile = get(EnvTLSCertFile)
	c.TLSKeyFile = get(EnvTLSKeyFile)
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		fail(EnvTLSCertFile, "must be set together with %s", EnvTLSKeyFile)
	}
	if v := get(EnvMetricsAddr); v != "" {
		switch strings.ToLower(v) {
		case "off", "none", "disabled":
			c.MetricsAddr = ""
		default:
			host, portStr, err := net.SplitHostPort(v)
			if err != nil {
				fail(EnvMetricsAddr, "must be host:port or off, got %q", v)
			} else {
				p, perr := strconv.Atoi(portStr)
				if perr != nil || p < 0 || p > 65535 {
					fail(EnvMetricsAddr, "invalid port %q", portStr)
				}
				if strings.EqualFold(host, "localhost") {
					host = "127.0.0.1"
				} else if a, aerr := netip.ParseAddr(host); aerr != nil {
					fail(EnvMetricsAddr, "invalid host %q (must be an IP address)", host)
				} else {
					host = a.Unmap().String()
				}
				c.MetricsAddr = net.JoinHostPort(host, strconv.Itoa(p))
			}
		}
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
	boolVar(EnvDevAllowPlaintext, &c.DevAllowPlaintext)
	c.KEKFile = get(EnvKEKFile)

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
	c.GeoIPASNDB = get(EnvGeoIPASNDB)
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

	if c.MetricsAddr != "" && c.MetricsAddr == c.ListenEndpoint() {
		fail(EnvMetricsAddr, "must not share the Hub listen address %s", c.ListenEndpoint())
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return c, nil
}

// TLSEnabled reports whether native TLS is configured via cert and key files.
func (c *Config) TLSEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}

// ListenEndpoint returns host:port for the main Hub HTTP(S) listener.
func (c *Config) ListenEndpoint() string {
	return net.JoinHostPort(c.ListenAddr, strconv.Itoa(c.ListenPort))
}

// ListenIsLoopback reports whether ListenAddr is a loopback IP address.
func (c *Config) ListenIsLoopback() bool {
	a, err := netip.ParseAddr(c.ListenAddr)
	return err == nil && a.IsLoopback()
}

// TransportPolicy enforces HTTPS in production (H1 / WP-4A / F-003):
// production refuses to start unless native TLS is configured or
// TS_TRUSTED_PROXIES is set (TLS terminated by a trusted reverse proxy), and
// any configured public_endpoint uses https://.
func (c *Config) TransportPolicy(publicEndpoint string) error {
	if c.Development {
		return nil
	}
	if !c.TLSEnabled() && len(c.TrustedProxies) == 0 {
		return fmt.Errorf("production requires HTTPS: configure native TLS (%s and %s) or a TLS-terminating reverse proxy (%s); for local lab use set %s=development",
			EnvTLSCertFile, EnvTLSKeyFile, EnvTrustedProxies, EnvEnvironment)
	}
	if ep := strings.TrimSpace(publicEndpoint); ep != "" && !strings.HasPrefix(strings.ToLower(ep), "https://") {
		return fmt.Errorf("production requires public_endpoint to use https:// (got %q); update public_endpoint or set %s=development for local lab use",
			ep, EnvEnvironment)
	}
	return nil
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

// SecretsPolicy says how the Hub must treat secrets at rest: a KEK file is
// always used when given; without one, only a development Hub that opted in
// with TS_DEV_ALLOW_PLAINTEXT_SECRETS may start.
func (c *Config) SecretsPolicy() error {
	if c.KEKFile != "" || (c.Development && c.DevAllowPlaintext) {
		return nil
	}
	return fmt.Errorf("%s is required: the Hub encrypts its secrets at rest under a key-encryption key (create one with `truesignal-hub kek-generate`; development may set %s=true instead)", EnvKEKFile, EnvDevAllowPlaintext)
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
	if c.DevAllowPlaintext && c.KEKFile == "" {
		w = append(w, EnvDevAllowPlaintext+" is set: secrets are stored in plaintext")
	}
	if c.Development {
		w = append(w, EnvEnvironment+"=development: HTTPS enforcement, cookie Secure flag and WebSocket origin check are relaxed")
	}
	return w
}
