// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package webhook sends chat notifications for events (§6.8): ntfy, gotify,
// Discord or Slack. Delivery is asynchronous through a bounded queue with
// three retries, a 10 s timeout and no redirects. The URL is a secret: it is
// never logged and never returned by the API.
//
// Event fields are attacker-controlled. They never go into HTTP headers,
// Discord mentions are disabled and Markdown is escaped, and Slack control
// sequences (<!channel>, links) are neutralised.
package webhook

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
)

// Types.
const (
	TypeNone    = "none"
	TypeNtfy    = "ntfy"
	TypeGotify  = "gotify"
	TypeDiscord = "discord"
	TypeSlack   = "slack"
)

// Settings keys. SettingURL is secret.
const (
	SettingConfig = "webhook"
	SettingURL    = "webhook_url"
	SettingArmed  = "armed"
)

const (
	queueSize      = 1000
	maxRetries     = 3
	requestTimeout = 10 * time.Second
	maxField       = 256
)

// DefaultSeverities notify on everything except info.
var DefaultSeverities = []domain.Severity{domain.SeverityLow, domain.SeverityMedium, domain.SeverityHigh, domain.SeverityCritical}

// Config is the webhook configuration. URL is secret.
type Config struct {
	Type       string            `json:"type"`
	Severities []domain.Severity `json:"severities"`
	URL        string            `json:"-"`
}

// Public is the configuration without the secret.
type Public struct {
	Type       string            `json:"type"`
	Severities []domain.Severity `json:"severities"`
	URLSet     bool              `json:"url_set"`
}

// Public strips the URL.
func (c Config) Public() Public {
	return Public{Type: c.Type, Severities: c.Severities, URLSet: c.URL != ""}
}

// ErrInvalid wraps configuration errors.
var ErrInvalid = errors.New("invalid webhook configuration")

// Normalize validates c. Plain http is allowed only when allowHTTP.
func (c Config) Normalize(allowHTTP bool) (Config, error) {
	c.Type = strings.ToLower(strings.TrimSpace(c.Type))
	switch c.Type {
	case "", TypeNone:
		return Config{Type: TypeNone, Severities: DefaultSeverities}, nil
	case TypeNtfy, TypeGotify, TypeDiscord, TypeSlack:
	default:
		return c, fmt.Errorf("%w: type must be none, ntfy, gotify, discord or slack", ErrInvalid)
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || u.Host == "" || len(c.URL) > 2048 || u.Fragment != "" {
		return c, fmt.Errorf("%w: url must be an absolute URL", ErrInvalid)
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return c, fmt.Errorf("%w: url must use https", ErrInvalid)
	}
	c.URL = u.String()
	if c.Severities == nil {
		c.Severities = DefaultSeverities
	}
	seen := map[domain.Severity]bool{}
	var sev []domain.Severity
	for _, s := range c.Severities {
		if !s.Valid() {
			return c, fmt.Errorf("%w: unknown severity %q", ErrInvalid, s)
		}
		if !seen[s] {
			seen[s] = true
			sev = append(sev, s)
		}
	}
	c.Severities = sev
	return c, nil
}

// SettingsStore persists configuration and the armed state.
type SettingsStore interface {
	Setting(ctx context.Context, key string) (string, bool, error)
	PutSettings(ctx context.Context, kv map[string]*string) error
}

// Notifier implements ingest.Notifier.
type Notifier struct {
	Store     SettingsStore
	AllowHTTP bool
	Log       *slog.Logger
	Now       func() time.Time
	Client    *http.Client  // default: no redirects, 10 s timeout
	Backoff   time.Duration // base retry delay (default 1 s)

	mu      sync.RWMutex
	cfg     Config
	armed   atomic.Bool
	queue   chan domain.EnrichedEvent
	dropped atomic.Uint64
	wg      sync.WaitGroup
}

// Load reads the stored configuration and armed state (armed by default).
func (n *Notifier) Load(ctx context.Context) error {
	if n.Client == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		n.Client = &http.Client{Transport: tr, Timeout: requestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if n.Backoff <= 0 {
		n.Backoff = time.Second
	}
	cfg := Config{Type: TypeNone, Severities: DefaultSeverities}
	if raw, ok, err := n.Store.Setting(ctx, SettingConfig); err != nil {
		return err
	} else if ok {
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			return fmt.Errorf("stored webhook configuration is corrupt: %w", err)
		}
	}
	if u, ok, err := n.Store.Setting(ctx, SettingURL); err != nil {
		return err
	} else if ok {
		cfg.URL = u
	}
	armed := true
	if v, ok, err := n.Store.Setting(ctx, SettingArmed); err != nil {
		return err
	} else if ok {
		armed = v == "true"
	}
	n.mu.Lock()
	n.cfg = cfg
	n.mu.Unlock()
	n.armed.Store(armed)
	return nil
}

// Config returns the active configuration.
func (n *Notifier) Config() Config {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.cfg
}

// Update validates, stores and activates a configuration.
func (n *Notifier) Update(ctx context.Context, c Config) (Config, error) {
	c, err := c.Normalize(n.AllowHTTP)
	if err != nil {
		return c, err
	}
	b, _ := json.Marshal(c)
	raw := string(b)
	kv := map[string]*string{SettingConfig: &raw, SettingURL: nil}
	if c.URL != "" {
		u := c.URL
		kv[SettingURL] = &u
	}
	if err := n.Store.PutSettings(ctx, kv); err != nil {
		return c, err
	}
	n.mu.Lock()
	n.cfg = c
	n.mu.Unlock()
	return c, nil
}

// Armed reports the system armed state.
func (n *Notifier) Armed() bool { return n.armed.Load() }

// SetArmed stores and applies the armed state.
func (n *Notifier) SetArmed(ctx context.Context, v bool) error {
	s := "false"
	if v {
		s = "true"
	}
	if err := n.Store.PutSettings(ctx, map[string]*string{SettingArmed: &s}); err != nil {
		return err
	}
	n.armed.Store(v)
	return nil
}

// Dropped returns notifications dropped because the queue was full.
func (n *Notifier) Dropped() uint64 { return n.dropped.Load() }

// Start runs the delivery worker until ctx ends.
func (n *Notifier) Start(ctx context.Context) {
	n.queue = make(chan domain.EnrichedEvent, queueSize)
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-n.queue:
				if err := n.deliver(ctx, n.Config(), ev); err != nil {
					n.Log.Warn("webhook notification failed", "type", n.Config().Type, "event_id", ev.EventID, "error", err.Error())
				}
			}
		}
	}()
}

// Wait blocks until the worker has stopped.
func (n *Notifier) Wait() { n.wg.Wait() }

func (n *Notifier) selected(c Config, s domain.Severity) bool {
	for _, x := range c.Severities {
		if x == s {
			return true
		}
	}
	return false
}

// Notify implements ingest.Notifier (the pipeline already skips silenced
// sensors). It never blocks.
func (n *Notifier) Notify(ev domain.EnrichedEvent) {
	c := n.Config()
	if !n.Armed() || c.Type == TypeNone || c.URL == "" || !n.selected(c, ev.Severity) || n.queue == nil {
		return
	}
	select {
	case n.queue <- ev:
	default:
		n.dropped.Add(1)
		n.Log.Warn("webhook queue full; notification dropped", "event_id", ev.EventID)
	}
}

// Test sends a synthetic notification synchronously (ignores armed state
// and severity selection).
func (n *Notifier) Test(ctx context.Context) error {
	c := n.Config()
	if c.Type == TypeNone || c.URL == "" {
		return errors.New("no webhook configured")
	}
	now := n.Now().UTC()
	ev := domain.EnrichedEvent{NodeAlias: "TrueSignal Hub", Event: domain.Event{EventID: "test", NodeID: "-", SensorID: "-",
		Trigger: "webhook_test", Severity: domain.SeverityInfo, OccurredAt: now, ReceivedAt: now, Source: domain.HubSource, Target: "Webhook test"}}
	return n.deliver(ctx, c, ev)
}

// statusError is a non-2xx response.
type statusError struct{ code int }

func (e statusError) Error() string { return fmt.Sprintf("webhook answered %d", e.code) }

func retryable(err error) bool {
	var se statusError
	if errors.As(err, &se) {
		return se.code >= 500 || se.code == http.StatusTooManyRequests || se.code == http.StatusRequestTimeout
	}
	return true
}

// deliver sends one notification with up to three retries.
func (n *Notifier) deliver(ctx context.Context, c Config, ev domain.EnrichedEvent) error {
	var err error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			d := n.Backoff << (attempt - 1)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(d/2 + rand.N(d/2+1)):
			}
		}
		if err = n.send(ctx, c, ev); err == nil || !retryable(err) {
			return err
		}
	}
	return err
}

func (n *Notifier) send(ctx context.Context, c Config, ev domain.EnrichedEvent) error {
	req, err := build(ctx, c, ev)
	if err != nil {
		return err
	}
	resp, err := n.Client.Do(req)
	if err != nil {
		// *url.Error embeds the URL, which contains secrets: unwrap it.
		var ue *url.Error
		if errors.As(err, &ue) {
			return fmt.Errorf("webhook request failed: %v", ue.Err)
		}
		return errors.New("webhook request failed")
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return statusError{resp.StatusCode}
	}
	return nil
}

// --- formatting -----------------------------------------------------------

// clean removes control characters and bounds length.
func clean(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(s, "�"))
	if len(s) > max {
		cut := max
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "…"
	}
	return s
}

type field struct{ name, value string }

func fields(ev domain.EnrichedEvent) []field {
	node := ev.NodeID
	if ev.NodeAlias != "" {
		node = ev.NodeAlias + " (" + ev.NodeID + ")"
	}
	return []field{
		{"Severity", strings.ToUpper(string(ev.Severity))},
		{"Trigger", ev.Trigger},
		{"Node", node},
		{"Sensor", ev.SensorID},
		{"Source", ev.Source},
		{"Target", ev.Target},
		{"Time", ev.ReceivedAt.UTC().Format(time.RFC3339)},
	}
}

// title uses only Hub-controlled or validated values (severity enum and a
// snake_case trigger), so it is safe in an HTTP header.
func title(ev domain.EnrichedEvent) string {
	t := "TrueSignal [" + strings.ToUpper(string(ev.Severity)) + "] " + ev.Trigger
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return '_'
		}
		return r
	}, t)
}

func plainBody(ev domain.EnrichedEvent) string {
	var b strings.Builder
	for _, f := range fields(ev) {
		fmt.Fprintf(&b, "%s: %s\n", f.name, clean(f.value, maxField))
	}
	return strings.TrimRight(b.String(), "\n")
}

var discordColor = map[domain.Severity]int{
	domain.SeverityCritical: 0x8B0000, domain.SeverityHigh: 0xE53935, domain.SeverityMedium: 0xFB8C00,
	domain.SeverityLow: 0xFDD835, domain.SeverityInfo: 0x1E88E5,
}

var slackColor = map[domain.Severity]string{
	domain.SeverityCritical: "#8B0000", domain.SeverityHigh: "#E53935", domain.SeverityMedium: "#FB8C00",
	domain.SeverityLow: "#FDD835", domain.SeverityInfo: "#1E88E5",
}

var ntfyPriority = map[domain.Severity]string{
	domain.SeverityCritical: "5", domain.SeverityHigh: "4", domain.SeverityMedium: "3", domain.SeverityLow: "2", domain.SeverityInfo: "1",
}

var gotifyPriority = map[domain.Severity]int{
	domain.SeverityCritical: 10, domain.SeverityHigh: 8, domain.SeverityMedium: 5, domain.SeverityLow: 3, domain.SeverityInfo: 1,
}

// discordEscape neutralises Markdown so attacker text cannot format, link
// or hide content. Mentions are disabled separately via allowed_mentions.
func discordEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune("\\*_~`|>[]()#-<@:!", r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// slackEscape applies Slack's required escaping of &, < and >, which also
// disables <!channel>, <@user> and <url|text> sequences.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func build(ctx context.Context, c Config, ev domain.EnrichedEvent) (*http.Request, error) {
	var (
		body        []byte
		contentType = "application/json"
		err         error
	)
	switch c.Type {
	case TypeNtfy:
		body, contentType = []byte(plainBody(ev)), "text/plain; charset=utf-8"
	case TypeGotify:
		body, err = json.Marshal(map[string]any{
			"title": title(ev), "message": plainBody(ev), "priority": gotifyPriority[ev.Severity],
			"extras": map[string]any{"client::display": map[string]string{"contentType": "text/plain"}},
		})
	case TypeDiscord:
		var fs []map[string]any
		for _, f := range fields(ev) {
			fs = append(fs, map[string]any{"name": f.name, "value": discordEscape(clean(f.value, maxField)), "inline": f.name != "Source" && f.name != "Target"})
		}
		body, err = json.Marshal(map[string]any{
			"username":         "TrueSignal",
			"allowed_mentions": map[string]any{"parse": []string{}},
			"embeds": []map[string]any{{
				"title": discordEscape(title(ev)), "color": discordColor[ev.Severity], "fields": fs,
				"timestamp": ev.ReceivedAt.UTC().Format(time.RFC3339),
			}},
		})
	case TypeSlack:
		var fs []map[string]any
		for _, f := range fields(ev) {
			fs = append(fs, map[string]any{"title": f.name, "value": slackEscape(clean(f.value, maxField)), "short": f.name != "Source" && f.name != "Target"})
		}
		body, err = json.Marshal(map[string]any{
			"text":        slackEscape(title(ev)),
			"attachments": []map[string]any{{"color": slackColor[ev.Severity], "fields": fs, "mrkdwn_in": []string{}}},
		})
	default:
		return nil, fmt.Errorf("unknown webhook type %q", c.Type)
	}
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("invalid webhook URL")
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "truesignal-hub")
	if c.Type == TypeNtfy {
		req.Header.Set("Title", title(ev))
		req.Header.Set("Priority", ntfyPriority[ev.Severity])
		req.Header.Set("Tags", "rotating_light")
	}
	return req, nil
}
