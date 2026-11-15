// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

// Triggers.
const (
	TriggerPageView = "web_page_view"
	TriggerProbe    = "web_path_probe"
	TriggerLogin    = "web_login_attempt"
)

// Limits.
const (
	maxBody       = 16 << 10
	maxFormFields = 20
	maxField      = 256
	maxPath       = 512
)

// Decoy is the HTTP handler.
type Decoy struct {
	Skin       Skin
	Capture    string // hash | plain | none
	CaptureKey []byte
	Port       int
	R          sensor.Reporter
	// FailDelay returns the delay before answering a login (plausible,
	// slows brute force). Default 300-900 ms.
	FailDelay func() time.Duration

	views  *sensor.SourceLimiter
	probes *sensor.SourceLimiter
	logins *sensor.SourceLimiter
	login  map[string]bool
}

// NewDecoy builds the handler.
func NewDecoy(skin Skin, capture string, key []byte, port int, viewWindow, probeCool, loginCool time.Duration, r sensor.Reporter) *Decoy {
	d := &Decoy{Skin: skin, Capture: capture, CaptureKey: key, Port: port, R: r,
		views: sensor.NewSourceLimiter(viewWindow, 0), probes: sensor.NewSourceLimiter(probeCool, 0),
		logins: sensor.NewSourceLimiter(loginCool, 0), login: map[string]bool{}}
	d.FailDelay = func() time.Duration { return 300*time.Millisecond + rand.N(600*time.Millisecond) }
	for _, p := range skin.LoginPaths() {
		d.login[p] = true
	}
	return d
}

func (d *Decoy) render(w http.ResponseWriter, kind string, rc RequestContext) {
	status, h, body := d.Skin.Render(kind, rc)
	for k, vs := range h {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	w.Write(body)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (d *Decoy) base(r *http.Request, path string) sensor.Fields {
	return sensor.Fields{
		sensor.F("path", path), sensor.F("method", sensor.Clean(r.Method, 16)),
		sensor.F("user_agent", sensor.Clean(r.UserAgent(), maxField)), sensor.F("dst_port", d.Port),
	}
}

func (d *Decoy) target() string { return "Web login (port " + strconv.Itoa(d.Port) + ")" }

// ServeHTTP implements http.Handler.
func (d *Decoy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	path := sensor.Clean(r.URL.EscapedPath(), maxPath)
	rc := RequestContext{Path: path, Method: r.Method, Host: sensor.Clean(r.Host, maxField), UserAgent: sensor.Clean(r.UserAgent(), maxField)}

	if user, pass, ok := r.BasicAuth(); ok {
		d.reportLogin(r, ip, path, "basic", user, pass, nil)
		d.pause(r)
		d.render(w, PageBasicAuth, rc)
		return
	}
	if !d.login[r.URL.Path] {
		if ok, sup := d.probes.Allow(ip); ok {
			f := append(d.base(r, path), sensor.F("suppressed_since_last", sup))
			d.R.ReportSeverity(sensor.SeverityMedium, TriggerProbe, r.RemoteAddr, d.target(), f)
		}
		d.render(w, PageNotFound, rc)
		return
	}
	if r.Method == http.MethodPost {
		form, err := readForm(w, r)
		if err != nil {
			d.render(w, PageLoginFailed, rc)
			return
		}
		user := form.Get("username")
		extra := url.Values{}
		for k, vs := range form {
			if k != "username" && k != "password" {
				extra[k] = vs
			}
		}
		d.reportLogin(r, ip, path, "form", user, form.Get("password"), extra)
		rc.Username = sensor.Clean(user, maxField)
		d.pause(r)
		d.render(w, PageLoginFailed, rc) // always a plausible failure
		return
	}
	if ok, sup := d.views.Allow(ip); ok {
		f := append(d.base(r, path), sensor.F("skin", d.Skin.Name()), sensor.F("suppressed_since_last", sup))
		d.R.ReportSeverity(sensor.SeverityLow, TriggerPageView, r.RemoteAddr, d.target(), f)
	}
	d.render(w, PageLogin, rc)
}

func (d *Decoy) pause(r *http.Request) {
	select {
	case <-r.Context().Done():
	case <-time.After(d.FailDelay()):
	}
}

var errForm = errors.New("bad form")

// readForm parses an urlencoded body of at most maxBody bytes.
func readForm(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	ct := r.Header.Get("Content-Type")
	if ct != "" && !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		return nil, errForm
	}
	if err := r.ParseForm(); err != nil {
		return nil, errForm
	}
	return r.PostForm, nil
}

// PasswordHMAC is hex HMAC-SHA256(capture key, password) — the value the
// Hub's honeytoken matcher compares against.
func PasswordHMAC(key []byte, password string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(password))
	return hex.EncodeToString(m.Sum(nil))
}

func (d *Decoy) reportLogin(r *http.Request, ip, path, auth, user, pass string, extra url.Values) {
	ok, sup := d.logins.Allow(ip)
	if !ok {
		return
	}
	f := sensor.Fields{sensor.F("username", sensor.Clean(user, maxField))}
	switch d.Capture {
	case "plain":
		f = append(f, sensor.F("password", sensor.Clean(pass, maxField)))
	case "hash":
		f = append(f, sensor.F("password_hmac", PasswordHMAC(d.CaptureKey, pass)))
	}
	f = append(f, sensor.F("auth", auth), sensor.F("skin", d.Skin.Name()))
	keys := make([]string, 0, len(extra))
	for k := range extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	n := 0
	for _, k := range keys {
		if n >= maxFormFields {
			break
		}
		name := sanitizeFieldName(k)
		if name == "" {
			continue
		}
		f = append(f, sensor.F("form_"+name, sensor.Clean(extra.Get(k), maxField)))
		n++
	}
	f = append(f, d.base(r, path)...)
	f = append(f, sensor.F("suppressed_since_last", sup))
	d.R.ReportSeverity(sensor.SeverityCritical, TriggerLogin, r.RemoteAddr, d.target(), f)
}

// sanitizeFieldName keeps [a-z0-9_] (lower-cased), at most 48 bytes, so
// attacker field names cannot create odd detail keys.
func sanitizeFieldName(k string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(k) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
			b.WriteRune(c)
		} else if c == '-' || c == '.' {
			b.WriteByte('_')
		}
		if b.Len() >= 48 {
			break
		}
	}
	return b.String()
}
