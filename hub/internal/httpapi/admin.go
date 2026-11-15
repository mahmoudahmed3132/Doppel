// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/auth"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
)

// SessionCookie is the name of the admin session cookie.
const SessionCookie = "ts_session"

const maxAdminBody = 1 << 20

// SettingsReader reads Hub settings.
type SettingsReader interface {
	Setting(ctx context.Context, key string) (string, bool, error)
}

// Admin serves the cookie-authenticated admin API under /api/v3.
type Admin struct {
	Auth        *auth.Service
	Settings    SettingsReader
	Audit       AuditSink
	Network     Network
	Development bool
	Log         *slog.Logger
	Now         func() time.Time

	mux  *http.ServeMux
	once sync.Once
}

// access describes who may call a route.
type access int

const (
	public    access = iota // no session (setup, login)
	enrolment               // any session, including enrolment-only
	full                    // fully authenticated session
)

type ctxKey int

const sessionKey ctxKey = 1

func sessionFrom(r *http.Request) *auth.Session {
	s, _ := r.Context().Value(sessionKey).(*auth.Session)
	return s
}

// Handler returns the admin API handler. Other packages register further
// routes through Route before the server starts.
func (a *Admin) Handler() http.Handler {
	a.once.Do(a.routes)
	return a.mux
}

// Route registers a handler. pattern is a net/http pattern
// ("METHOD /api/v3/..."), which is also the audited route template;
// action is the semantic audit action ("" = not audited: read-only).
func (a *Admin) Route(pattern, action string, acc access, h http.HandlerFunc) {
	if a.mux == nil {
		a.mux = http.NewServeMux()
	}
	method, route := splitPattern(pattern)
	a.mux.Handle(pattern, a.wrap(method, route, action, acc, h))
}

// RouteFull registers a fully authenticated route (for other packages).
func (a *Admin) RouteFull(pattern, action string, h http.HandlerFunc) {
	a.Route(pattern, action, full, h)
}

func splitPattern(p string) (string, string) {
	for i := 0; i < len(p); i++ {
		if p[i] == ' ' {
			return p[:i], p[i+1:]
		}
	}
	return "", p
}

func (a *Admin) routes() {
	a.Route("GET /api/v3/setup", "", public, a.setupStatus)
	a.Route("POST /api/v3/setup", "setup.complete", public, a.setup)
	a.Route("POST /api/v3/session/login", "session.login", public, a.login)
	a.Route("POST /api/v3/session/logout", "session.logout", enrolment, a.logout)
	a.Route("GET /api/v3/session", "", full, a.sessionInfo)
	a.Route("GET /api/v3/mfa", "", enrolment, a.mfaStatus)
	a.Route("POST /api/v3/mfa/enrolment", "mfa.enrol_begin", enrolment, a.mfaBegin)
	a.Route("POST /api/v3/mfa/enrolment/confirm", "mfa.enrol_confirm", enrolment, a.mfaConfirm)
	a.Route("POST /api/v3/mfa/disable", "mfa.disable", full, a.mfaDisable)
	a.Route("POST /api/v3/mfa/recovery-codes", "mfa.recovery_codes_regenerate", full, a.mfaRegenerate)
	a.Route("POST /api/v3/system/password", "system.password_change", full, a.changePassword)
}

// wrap applies, in order: body limit, CSRF origin check for state-changing
// requests, session authentication and access level, then auditing of
// state-changing requests after completion.
func (a *Admin) wrap(method, route, action string, acc access, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
		if action != "" {
			defer func() {
				status := sw.status
				if status == 0 {
					status = http.StatusOK
				}
				outcome := "success"
				if status >= 400 {
					outcome = "failure"
				}
				a.Audit.Record(r.Context(), domain.AuditRecord{
					Time: a.Now().UTC(), Action: action, Method: method, Route: route, Path: r.URL.Path,
					Status: status, Outcome: outcome, ActorIP: a.Network.ClientIP(r),
				})
			}()
		}
		r.Body = http.MaxBytesReader(sw, r.Body, maxAdminBody)

		if !isSafeMethod(r.Method) && !sameOrigin(r, a.expectedOrigin(r)) {
			Fail(sw, http.StatusForbidden, "origin_mismatch", "cross-origin request refused")
			return
		}
		if acc != public {
			sess, err := a.authenticate(r)
			if err != nil {
				if !errors.Is(err, auth.ErrSessionInvalid) {
					a.Log.Error("session lookup failed", "error", err.Error())
					Fail(sw, http.StatusInternalServerError, CodeInternal, "session store unavailable")
					return
				}
				a.clearCookie(sw)
				Fail(sw, http.StatusUnauthorized, "unauthenticated", "login required")
				return
			}
			if acc == full && sess.EnrolOnly {
				Fail(sw, http.StatusForbidden, "mfa_enrolment_required", "MFA enrolment is required before using the Hub")
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), sessionKey, sess))
		}
		h(sw, r)
	})
}

// ExpectedOrigin returns the Hub origin a browser request must come from.
func (a *Admin) ExpectedOrigin(r *http.Request) string { return a.expectedOrigin(r) }

func (a *Admin) expectedOrigin(r *http.Request) string {
	if ep, ok, err := a.Settings.Setting(r.Context(), auth.SettingEndpoint); err == nil && ok {
		if o := endpointOrigin(ep); o != "" {
			return o
		}
	}
	return a.Network.Origin(r)
}

func (a *Admin) authenticate(r *http.Request) (*auth.Session, error) {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return nil, auth.ErrSessionInvalid
	}
	return a.Auth.Authenticate(r.Context(), c.Value)
}

func (a *Admin) setCookie(w http.ResponseWriter, s *auth.Session) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: s.Token, Path: "/", Expires: s.ExpiresAt,
		HttpOnly: true, Secure: !a.Development, SameSite: http.SameSiteStrictMode,
	})
}

func (a *Admin) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: !a.Development, SameSite: http.SameSiteStrictMode,
	})
}

// failAuth maps auth service errors to the envelope.
func (a *Admin) failAuth(w http.ResponseWriter, err error) {
	var le *auth.LockedError
	switch {
	case errors.As(err, &le):
		w.Header().Set("Retry-After", retryAfterSeconds(le.RetryAfter))
		Fail(w, http.StatusTooManyRequests, "locked", "too many failed attempts; try again later")
	case errors.Is(err, auth.ErrInvalidCredentials):
		Fail(w, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")
	case errors.Is(err, auth.ErrMFARequired):
		Fail(w, http.StatusUnauthorized, "mfa_required", "an MFA code is required")
	case errors.Is(err, auth.ErrInvalidCode):
		Fail(w, http.StatusUnauthorized, "invalid_code", "invalid or already used code")
	case errors.Is(err, auth.ErrSetupRequired):
		Fail(w, http.StatusConflict, "setup_required", "complete setup first")
	case errors.Is(err, auth.ErrSetupCompleted):
		Fail(w, http.StatusConflict, "setup_completed", "setup has already been completed")
	case errors.Is(err, auth.ErrInvalidSetupToken):
		Fail(w, http.StatusForbidden, "invalid_setup_token", "invalid setup token")
	case errors.Is(err, auth.ErrWeakPassword):
		Fail(w, http.StatusBadRequest, "weak_password", err.Error())
	case errors.Is(err, auth.ErrInvalidEndpoint):
		Fail(w, http.StatusBadRequest, "invalid_endpoint", err.Error())
	case errors.Is(err, auth.ErrMFAUnavailable):
		Fail(w, http.StatusServiceUnavailable, "mfa_unavailable", "the MFA module is not installed")
	case errors.Is(err, auth.ErrMFAEnabled):
		Fail(w, http.StatusConflict, "mfa_enabled", err.Error())
	case errors.Is(err, auth.ErrMFANotEnabled):
		Fail(w, http.StatusConflict, "mfa_not_enabled", err.Error())
	case errors.Is(err, auth.ErrMFAMandatory):
		Fail(w, http.StatusForbidden, "mfa_mandatory", err.Error())
	case errors.Is(err, auth.ErrNoPendingEnrolment):
		Fail(w, http.StatusConflict, "no_pending_enrolment", err.Error())
	case errors.Is(err, auth.ErrPasswordManaged):
		Fail(w, http.StatusForbidden, "password_managed", err.Error())
	default:
		a.Log.Error("auth operation failed", "error", err.Error())
		Fail(w, http.StatusInternalServerError, CodeInternal, "internal error")
	}
}

func (a *Admin) decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := DecodeStrict(w, r, maxAdminBody, dst); err != nil {
		FailDecode(w, err)
		return false
	}
	return true
}

func sessionJSON(s *auth.Session) map[string]any {
	return map[string]any{"enrol_only": s.EnrolOnly, "created_at": s.CreatedAt, "expires_at": s.ExpiresAt, "idle_expires_at": s.IdleExpiry}
}

func (a *Admin) setupStatus(w http.ResponseWriter, r *http.Request) {
	done, err := a.Auth.SetupCompleted(r.Context())
	if err != nil {
		a.failAuth(w, err)
		return
	}
	mfa, _ := a.Auth.MFAStatus(r.Context()) // zero value before setup
	OK(w, map[string]any{"setup_completed": done, "password_managed": a.Auth.PasswordManaged(), "mfa_required": mfa.Required})
}

func (a *Admin) setup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SetupToken     string `json:"setup_token"`
		Password       string `json:"password"`
		PublicEndpoint string `json:"public_endpoint"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if err := a.Auth.Setup(r.Context(), a.Network.ClientIP(r), req.SetupToken, req.Password, req.PublicEndpoint); err != nil {
		a.failAuth(w, err)
		return
	}
	OK(w, map[string]any{"setup_completed": true})
}

func (a *Admin) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	sess, err := a.Auth.Login(r.Context(), a.Network.ClientIP(r), req.Password, req.Code)
	if err != nil {
		a.failAuth(w, err)
		return
	}
	a.setCookie(w, sess)
	OK(w, map[string]any{"session": sessionJSON(sess)})
}

func (a *Admin) logout(w http.ResponseWriter, r *http.Request) {
	if err := a.Auth.Logout(r.Context(), sessionFrom(r)); err != nil {
		a.failAuth(w, err)
		return
	}
	a.clearCookie(w)
	OK(w, nil)
}

func (a *Admin) sessionInfo(w http.ResponseWriter, r *http.Request) {
	OK(w, map[string]any{"session": sessionJSON(sessionFrom(r)), "password_managed": a.Auth.PasswordManaged()})
}

func (a *Admin) mfaStatus(w http.ResponseWriter, r *http.Request) {
	st, err := a.Auth.MFAStatus(r.Context())
	if err != nil {
		a.failAuth(w, err)
		return
	}
	OK(w, map[string]any{"mfa": st})
}

func (a *Admin) mfaBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	secret, uri, err := a.Auth.BeginEnrolment(r.Context(), a.Network.ClientIP(r), req.Password)
	if err != nil {
		a.failAuth(w, err)
		return
	}
	OK(w, map[string]any{"secret": secret, "otpauth_uri": uri})
}

func (a *Admin) mfaConfirm(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	codes, err := a.Auth.ConfirmEnrolment(r.Context(), a.Network.ClientIP(r), req.Code)
	if err != nil {
		a.failAuth(w, err)
		return
	}
	// Every session, including this one, was invalidated: log in again.
	a.clearCookie(w)
	OK(w, map[string]any{"recovery_codes": codes, "relogin_required": true})
}

type reauthRequest struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

func (a *Admin) mfaDisable(w http.ResponseWriter, r *http.Request) {
	var req reauthRequest
	if !a.decode(w, r, &req) {
		return
	}
	if err := a.Auth.DisableMFA(r.Context(), a.Network.ClientIP(r), req.Password, req.Code); err != nil {
		a.failAuth(w, err)
		return
	}
	a.clearCookie(w)
	OK(w, map[string]any{"relogin_required": true})
}

func (a *Admin) mfaRegenerate(w http.ResponseWriter, r *http.Request) {
	var req reauthRequest
	if !a.decode(w, r, &req) {
		return
	}
	codes, err := a.Auth.RegenerateRecoveryCodes(r.Context(), a.Network.ClientIP(r), req.Password, req.Code, sessionFrom(r))
	if err != nil {
		a.failAuth(w, err)
		return
	}
	OK(w, map[string]any{"recovery_codes": codes})
}

func (a *Admin) changePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if err := a.Auth.ChangePassword(r.Context(), a.Network.ClientIP(r), req.CurrentPassword, req.NewPassword); err != nil {
		a.failAuth(w, err)
		return
	}
	a.clearCookie(w)
	OK(w, map[string]any{"relogin_required": true})
}
