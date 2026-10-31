// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package siem delivers events, audit records, honeytoken inventory and Hub
// heartbeats to one SIEM destination (§6.9): a bounded queue, per-record
// retries with backoff, stream transports (tcp, udp, tls) with RFC 5424 or
// ECS lines, and the PORTED HTTP transports (elastic, logscale).
package siem

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Protocols.
const (
	ProtoNone     = "none"
	ProtoTCP      = "tcp"
	ProtoUDP      = "udp"
	ProtoTLS      = "tls"
	ProtoElastic  = "elastic"
	ProtoLogScale = "logscale"
)

// Formats for stream transports.
const (
	FormatRFC5424 = "rfc5424"
	FormatECS     = "ecs"
)

// Settings keys. SettingToken is secret.
const (
	SettingOutput = "siem_output"
	SettingToken  = "siem_token"
)

// Config is one SIEM destination. Token is secret and never returned.
type Config struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Format   string `json:"format"`
	Token    string `json:"-"`
}

// Public is the config as shown to the admin.
type Public struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Format   string `json:"format"`
	TokenSet bool   `json:"token_set"`
}

// Public strips the secret.
func (c Config) Public() Public {
	return Public{Protocol: c.Protocol, Address: c.Address, Format: c.Format, TokenSet: c.Token != ""}
}

// Capabilities states which PORTED modules are installed.
type Capabilities struct {
	ECS  bool // ECS renderer
	HTTP bool // elastic / logscale transports
}

// ErrInvalid wraps configuration errors suitable for the API.
var ErrInvalid = errors.New("invalid SIEM configuration")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Normalize validates c and fills defaults.
func (c Config) Normalize(caps Capabilities) (Config, error) {
	c.Protocol = strings.ToLower(strings.TrimSpace(c.Protocol))
	c.Address = strings.TrimSpace(c.Address)
	c.Format = strings.ToLower(strings.TrimSpace(c.Format))
	switch c.Protocol {
	case ProtoNone, "":
		return Config{Protocol: ProtoNone}, nil
	case ProtoTCP, ProtoUDP, ProtoTLS:
		if c.Format == "" {
			c.Format = FormatRFC5424
		}
		if c.Format != FormatRFC5424 && c.Format != FormatECS {
			return c, invalid("format must be rfc5424 or ecs")
		}
		if c.Format == FormatECS && !caps.ECS {
			return c, invalid("the ECS renderer module is not installed; use rfc5424")
		}
		host, port, err := net.SplitHostPort(c.Address)
		if err != nil || host == "" || strings.ContainsAny(host, " /\\@") {
			return c, invalid("address must be host:port")
		}
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return c, invalid("port must be 1..65535")
		}
		c.Token = "" // stream outputs take no token
	case ProtoElastic, ProtoLogScale:
		if !caps.HTTP || !caps.ECS {
			return c, invalid("the %s transport module is not installed", c.Protocol)
		}
		u, err := url.Parse(c.Address)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			return c, invalid("address must be an https:// URL without credentials")
		}
		if c.Protocol == ProtoElastic && strings.Trim(u.Path, "/") == "" {
			return c, invalid("elastic address must include the data stream, e.g. https://es:9200/logs-truesignal-default")
		}
		if c.Token == "" {
			return c, invalid("a token is required")
		}
		c.Format = FormatECS
	default:
		return c, invalid("protocol must be none, tcp, udp, tls, elastic or logscale")
	}
	if len(c.Address) > 512 || len(c.Token) > 4096 {
		return c, invalid("address or token too long")
	}
	return c, nil
}

// SettingsStore persists the configuration.
type SettingsStore interface {
	Setting(ctx context.Context, key string) (string, bool, error)
	PutSettings(ctx context.Context, kv map[string]*string) error
}

// LoadConfig reads the stored configuration (protocol none when unset).
func LoadConfig(ctx context.Context, s SettingsStore) (Config, error) {
	raw, ok, err := s.Setting(ctx, SettingOutput)
	if err != nil || !ok {
		return Config{Protocol: ProtoNone}, err
	}
	var c Config
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return Config{Protocol: ProtoNone}, fmt.Errorf("stored SIEM configuration is corrupt: %w", err)
	}
	if tok, ok, err := s.Setting(ctx, SettingToken); err != nil {
		return c, err
	} else if ok {
		c.Token = tok
	}
	return c, nil
}

// SaveConfig stores the configuration.
func SaveConfig(ctx context.Context, s SettingsStore, c Config) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	out := string(b)
	kv := map[string]*string{SettingOutput: &out, SettingToken: nil}
	if c.Token != "" {
		tok := c.Token
		kv[SettingToken] = &tok
	}
	return s.PutSettings(ctx, kv)
}
