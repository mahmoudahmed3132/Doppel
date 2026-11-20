// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package sensor

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Environment variables read by the SDK. All are set by the Hub's compose
// compiler and are reserved: user configuration cannot override them.
const (
	EnvHubEndpoint     = "TS_HUB_ENDPOINT"
	EnvNodeKey         = "TS_NODE_KEY"
	EnvSensorID        = "TS_SENSOR_ID"
	EnvDefaultSeverity = "TS_DEFAULT_SEVERITY"
	EnvConfigRevision  = "TS_CONFIG_REVISION"
	EnvTestMode        = "TS_TEST_MODE"
	EnvCABundle        = "TS_CA_BUNDLE"
	EnvDevAllowHTTP    = "TS_DEV_ALLOW_HTTP"
)

// testModeSensorID is used in test mode when TS_SENSOR_ID is unset.
const testModeSensorID = "ts-sensor-test"

// Config is the SDK runtime configuration.
type Config struct {
	HubEndpoint     *url.URL
	NodeKey         string
	SensorID        string
	DefaultSeverity Severity
	ConfigRevision  string
	TestMode        bool
	DevAllowHTTP    bool
	CABundlePath    string

	getenv func(string) string
}

// LoadConfig reads the configuration from getenv (normally os.Getenv).
func LoadConfig(getenv func(string) string) (*Config, error) {
	get := func(k string) string { return strings.TrimSpace(getenv(k)) }
	c := &Config{
		NodeKey:        get(EnvNodeKey),
		SensorID:       get(EnvSensorID),
		ConfigRevision: get(EnvConfigRevision),
		CABundlePath:   get(EnvCABundle),
		getenv:         getenv,
	}

	switch tm := strings.ToLower(get(EnvTestMode)); tm {
	case "", "false", "0":
	case "true":
		c.TestMode = true
	default:
		return nil, fmt.Errorf("%s must be true or false, got %q", EnvTestMode, tm)
	}
	switch ah := strings.ToLower(get(EnvDevAllowHTTP)); ah {
	case "", "false", "0", "no":
	case "true", "1", "yes":
		c.DevAllowHTTP = true
	default:
		return nil, fmt.Errorf("%s must be true or false, got %q", EnvDevAllowHTTP, ah)
	}

	var errs []error
	raw := get(EnvHubEndpoint)
	if raw == "" {
		errs = append(errs, fmt.Errorf("%s is required", EnvHubEndpoint))
	} else {
		u, err := url.Parse(raw)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: %v", EnvHubEndpoint, err))
		case u.Scheme != "https" && u.Scheme != "http":
			errs = append(errs, fmt.Errorf("%s must use https://", EnvHubEndpoint))
		case u.Scheme == "http" && !c.DevAllowHTTP:
			errs = append(errs, fmt.Errorf("%s must use https:// (set %s=true for local development)", EnvHubEndpoint, EnvDevAllowHTTP))
		case u.Host == "":
			errs = append(errs, fmt.Errorf("%s has no host", EnvHubEndpoint))
		case u.User != nil:
			errs = append(errs, fmt.Errorf("%s must not contain credentials", EnvHubEndpoint))
		default:
			u.Path = strings.TrimRight(u.Path, "/")
			u.RawQuery, u.Fragment = "", ""
			c.HubEndpoint = u
		}
	}
	if !c.TestMode {
		if c.NodeKey == "" {
			errs = append(errs, fmt.Errorf("%s is required", EnvNodeKey))
		}
		if c.SensorID == "" {
			errs = append(errs, fmt.Errorf("%s is required", EnvSensorID))
		}
	}
	if c.SensorID == "" {
		c.SensorID = testModeSensorID
	}

	c.DefaultSeverity = SeverityMedium
	if v := get(EnvDefaultSeverity); v != "" {
		s, err := ParseSeverity(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", EnvDefaultSeverity, err))
		} else {
			c.DefaultSeverity = s
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return c, nil
}

// Setting returns a sensor configuration value declared in the manifest
// (a TS_ environment variable). Reserved SDK keys are not exposed.
func (c *Config) Setting(name string) (string, bool) {
	if !strings.HasPrefix(name, "TS_") || isReservedKey(name) || c.getenv == nil {
		return "", false
	}
	v := c.getenv(name)
	return v, v != ""
}

func isReservedKey(name string) bool {
	switch name {
	case EnvHubEndpoint, EnvNodeKey, EnvSensorID, EnvConfigRevision, EnvTestMode, EnvCABundle, EnvDevAllowHTTP:
		return true
	}
	return false
}
