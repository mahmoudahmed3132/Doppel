// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
)

// ContentSecurityPolicy is applied to every response (§7, §13).
const ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

// SecurityHeaders sets the §13 headers on every response; HSTS only when
// the client connection is HTTPS.
func SecurityHeaders(n Network, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", ContentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if n.IsHTTPS(r) {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// AuditSink receives audit records. It must not block.
type AuditSink interface {
	Record(ctx context.Context, rec domain.AuditRecord)
}

// statusWriter captures the response status for auditing.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// sameOrigin implements the CSRF check: the Origin header (or, failing
// that, the Referer's origin) must equal the expected origin. Requests with
// neither are refused.
func sameOrigin(r *http.Request, expected string) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || origin == "null" {
		ref := r.Header.Get("Referer")
		if ref == "" {
			return false
		}
		u, err := url.Parse(ref)
		if err != nil || u.Host == "" {
			return false
		}
		origin = u.Scheme + "://" + u.Host
	}
	return strings.EqualFold(strings.TrimRight(origin, "/"), expected)
}

// endpointOrigin returns scheme://host of a public endpoint URL.
func endpointOrigin(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

func retryAfterSeconds(d time.Duration) string {
	s := int(d / time.Second)
	if d%time.Second != 0 {
		s++
	}
	if s < 1 {
		s = 1
	}
	return strconv.Itoa(s)
}
