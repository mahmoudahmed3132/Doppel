// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package auth implements admin setup, login, lockouts, sessions and the
// MFA flows of §6.3 around the PORTED TOTP/recovery-code core.
package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ids"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
)

// Policy constants.
const (
	MinPasswordRunes   = 12
	MaxPasswordBytes   = 1024
	RecoveryCodeCount  = 10
	SettingEndpoint    = "public_endpoint"
	sessionTouchPeriod = 15 * time.Second
	totpIssuer         = "TrueSignal"
	totpAccount        = "admin"
)

// Errors returned by the service. The HTTP layer maps them to codes.
var (
	ErrSetupCompleted     = errors.New("setup already completed")
	ErrSetupRequired      = errors.New("setup not completed")
	ErrInvalidSetupToken  = errors.New("invalid setup token")
	ErrWeakPassword       = fmt.Errorf("password must be at least %d characters", MinPasswordRunes)
	ErrInvalidEndpoint    = errors.New("public endpoint must be an http(s) URL without credentials, query or fragment")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidCode        = errors.New("invalid or already used code")
	ErrMFARequired        = errors.New("MFA code required")
	ErrMFAUnavailable     = errors.New("MFA module not installed")
	ErrMFAEnabled         = errors.New("MFA is already enabled")
	ErrMFANotEnabled      = errors.New("MFA is not enabled")
	ErrMFAMandatory       = errors.New("MFA is required by configuration and cannot be disabled")
	ErrNoPendingEnrolment = errors.New("no MFA enrolment in progress")
	ErrPasswordManaged    = errors.New("the admin password is managed by TS_DASHBOARD_PASSWORD")
	ErrSessionInvalid     = errors.New("session invalid or expired")
)

// LockedError is returned while a lockout is active.
type LockedError struct{ RetryAfter time.Duration }

func (e *LockedError) Error() string { return "too many failed attempts" }

// Store is the persistence the service needs.
type Store interface {
	Admin(ctx context.Context) (*store.Admin, error)
	AdminExists(ctx context.Context) (bool, error)
	CreateAdmin(ctx context.Context, passwordHash string, settings map[string]string) error
	SetPasswordHash(ctx context.Context, hash string) error
	SetPendingMFASecret(ctx context.Context, secret string) error
	EnableMFA(ctx context.Context, pendingSecret string, step int64, hashedCodes []string) error
	DisableMFA(ctx context.Context) error
	AdvanceMFAStep(ctx context.Context, step int64) (bool, error)
	ReplaceRecoveryCodes(ctx context.Context, old, replacement []string) (bool, error)
	CreateSession(ctx context.Context, s store.Session) error
	SessionByHash(ctx context.Context, hash []byte) (*store.Session, error)
	TouchSession(ctx context.Context, hash []byte, at time.Time) error
	DeleteSession(ctx context.Context, hash []byte) error
	DeleteSessionsExcept(ctx context.Context, keep []byte) error
	PurgeExpiredSessions(ctx context.Context, absBefore, idleBefore time.Time) (int64, error)
}

// Service is the admin authentication service.
type Service struct {
	store      Store
	hasher     *Hasher
	totp       ported.TOTP // nil: MFA unavailable
	lockout    *Lockout
	log        *slog.Logger
	now        func() time.Time
	ttl        time.Duration
	idle       time.Duration
	requireMFA bool
	override   string // TS_DASHBOARD_PASSWORD

	mu         sync.Mutex
	setupToken string
}

// Options configures a Service.
type Options struct {
	Store              Store
	Hasher             *Hasher
	TOTP               ported.TOTP
	Log                *slog.Logger
	Now                func() time.Time
	SessionTTL         time.Duration
	SessionIdle        time.Duration
	RequireMFA         bool
	PasswordOverride   string
	SetupTokenOverride string
}

// New constructs the service. RequireMFA without a TOTP module is refused:
// nobody could ever complete enrolment (fail closed).
func New(o Options) (*Service, error) {
	if o.RequireMFA && o.TOTP == nil {
		return nil, errors.New("TS_REQUIRE_MFA is set but the TOTP module is not installed")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Service{
		store: o.Store, hasher: o.Hasher, totp: o.TOTP, lockout: NewLockout(o.Now), log: o.Log, now: o.Now,
		ttl: o.SessionTTL, idle: o.SessionIdle, requireMFA: o.RequireMFA, override: o.PasswordOverride,
		setupToken: o.SetupTokenOverride,
	}, nil
}

// Lockout exposes the lockout tracker (tests and other auth surfaces).
func (s *Service) Lockout() *Lockout { return s.lockout }

// Init prepares first start. With a password override it creates or updates
// the admin account to that password. Otherwise, when no admin exists and no
// token override was given, it generates a one-time setup token and returns
// it so the caller can print it once. It returns "" when nothing must be
// printed.
func (s *Service) Init(ctx context.Context) (string, error) {
	exists, err := s.store.AdminExists(ctx)
	if err != nil {
		return "", err
	}
	if s.override != "" {
		return "", s.applyOverride(ctx, exists)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if exists {
		s.setupToken = ""
		return "", nil
	}
	if s.setupToken != "" {
		return "", nil // supplied by the operator; do not print
	}
	s.setupToken = ids.Token(32)
	return s.setupToken, nil
}

func (s *Service) applyOverride(ctx context.Context, exists bool) error {
	if !exists {
		h, err := s.hasher.Hash(ctx, s.override)
		if err != nil {
			return err
		}
		err = s.store.CreateAdmin(ctx, h, nil)
		if errors.Is(err, domain.ErrConflict) {
			return s.applyOverride(ctx, true)
		}
		return err
	}
	a, err := s.store.Admin(ctx)
	if err != nil {
		return err
	}
	if ok, err := s.hasher.Verify(ctx, s.override, a.PasswordHash); err == nil && ok {
		return nil
	}
	h, err := s.hasher.Hash(ctx, s.override)
	if err != nil {
		return err
	}
	s.log.Warn("admin password replaced by TS_DASHBOARD_PASSWORD; all sessions invalidated")
	return s.store.SetPasswordHash(ctx, h)
}

// PasswordManaged reports whether the password comes from the environment.
func (s *Service) PasswordManaged() bool { return s.override != "" }

// SetupCompleted reports whether the admin account exists.
func (s *Service) SetupCompleted(ctx context.Context) (bool, error) {
	return s.store.AdminExists(ctx)
}

func (s *Service) checkLock(ip string) error {
	if locked, wait := s.lockout.Check(ip); locked {
		return &LockedError{RetryAfter: wait}
	}
	return nil
}

func validatePassword(p string) error {
	if len(p) > MaxPasswordBytes || !utf8.ValidString(p) || utf8.RuneCountInString(p) < MinPasswordRunes {
		return ErrWeakPassword
	}
	return nil
}

// NormalizeEndpoint validates a Hub public endpoint URL and returns its
// canonical form (scheme://host[:port][/path], no trailing slash).
func NormalizeEndpoint(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || len(raw) > 512 {
		return "", ErrInvalidEndpoint
	}
	u.Scheme, u.Host = strings.ToLower(u.Scheme), strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String(), nil
}

// Setup completes first-run setup.
func (s *Service) Setup(ctx context.Context, ip, token, password, endpoint string) error {
	if err := s.checkLock(ip); err != nil {
		return err
	}
	exists, err := s.store.AdminExists(ctx)
	if err != nil {
		return err
	}
	if exists || s.override != "" {
		return ErrSetupCompleted
	}
	s.mu.Lock()
	want := s.setupToken
	s.mu.Unlock()
	if want == "" || subtle.ConstantTimeCompare([]byte(token), []byte(want)) != 1 {
		s.lockout.Fail(ip)
		return ErrInvalidSetupToken
	}
	if err := validatePassword(password); err != nil {
		return err
	}
	ep, err := NormalizeEndpoint(endpoint)
	if err != nil {
		return err
	}
	h, err := s.hasher.Hash(ctx, password)
	if err != nil {
		return err
	}
	if err := s.store.CreateAdmin(ctx, h, map[string]string{SettingEndpoint: ep}); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return ErrSetupCompleted
		}
		return err
	}
	s.mu.Lock()
	s.setupToken = ""
	s.mu.Unlock()
	s.lockout.Success(ip)
	return nil
}

// Session describes an authenticated session.
type Session struct {
	Token      string // only set on creation
	hash       []byte
	EnrolOnly  bool
	CreatedAt  time.Time
	ExpiresAt  time.Time
	IdleExpiry time.Time
}

// Hash returns the stored token hash (used to keep the current session).
func (s *Session) Hash() []byte { return s.hash }

func tokenHash(token string) []byte { h := sha256.Sum256([]byte(token)); return h[:] }

func (s *Service) newSession(ctx context.Context, enrolOnly bool) (*Session, error) {
	now := s.now().UTC()
	tok := ids.Token(32)
	h := tokenHash(tok)
	if err := s.store.CreateSession(ctx, store.Session{TokenHash: h, CreatedAt: now, LastSeenAt: now, EnrolOnly: enrolOnly}); err != nil {
		return nil, err
	}
	return &Session{Token: tok, hash: h, EnrolOnly: enrolOnly, CreatedAt: now, ExpiresAt: now.Add(s.ttl), IdleExpiry: now.Add(s.idle)}, nil
}

// Login verifies the password and, when MFA is enrolled, a TOTP or recovery
// code. Missing code with a correct password returns ErrMFARequired without
// counting a failure. In require-MFA mode an unenrolled admin receives an
// enrolment-only session.
func (s *Service) Login(ctx context.Context, ip, password, code string) (*Session, error) {
	if err := s.checkLock(ip); err != nil {
		return nil, err
	}
	a, err := s.store.Admin(ctx)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, ErrSetupRequired
	}
	if err != nil {
		return nil, err
	}
	if len(password) > MaxPasswordBytes {
		s.lockout.Fail(ip)
		return nil, ErrInvalidCredentials
	}
	ok, err := s.hasher.Verify(ctx, password, a.PasswordHash)
	if err != nil {
		return nil, err
	}
	if !ok {
		s.lockout.Fail(ip)
		return nil, ErrInvalidCredentials
	}
	if a.MFAEnabled {
		if s.totp == nil {
			return nil, ErrMFAUnavailable
		}
		if strings.TrimSpace(code) == "" {
			return nil, ErrMFARequired
		}
		if err := s.verifySecondFactor(ctx, a, code, true); err != nil {
			if errors.Is(err, ErrInvalidCode) {
				s.lockout.Fail(ip)
			}
			return nil, err
		}
	}
	sess, err := s.newSession(ctx, s.requireMFA && !a.MFAEnabled)
	if err != nil {
		return nil, err
	}
	s.lockout.Success(ip)
	return sess, nil
}

var totpCodeRE = regexp.MustCompile(`^[0-9]{6}$`)

// verifySecondFactor accepts a TOTP code, or a recovery code when
// allowRecovery. Both paths use compare-and-swap updates so a code cannot
// be used twice even by concurrent requests.
func (s *Service) verifySecondFactor(ctx context.Context, a *store.Admin, code string, allowRecovery bool) error {
	code = strings.TrimSpace(code)
	if totpCodeRE.MatchString(code) {
		step, ok := s.totp.Verify(a.MFASecret, code, a.MFALastStep, s.now())
		if !ok {
			return ErrInvalidCode
		}
		advanced, err := s.store.AdvanceMFAStep(ctx, step)
		if err != nil {
			return err
		}
		if !advanced {
			return ErrInvalidCode // replay
		}
		return nil
	}
	if !allowRecovery || len(code) > 128 {
		return ErrInvalidCode
	}
	remaining, ok := s.totp.ConsumeRecoveryCode(a.RecoveryCodes, code)
	if !ok {
		return ErrInvalidCode
	}
	swapped, err := s.store.ReplaceRecoveryCodes(ctx, a.RecoveryCodes, remaining)
	if err != nil {
		return err
	}
	if !swapped {
		return ErrInvalidCode
	}
	s.log.Warn("recovery code used", "remaining", len(remaining))
	return nil
}

// Authenticate validates a session token, enforcing absolute and idle
// expiry, and refreshes its idle timer.
func (s *Service) Authenticate(ctx context.Context, token string) (*Session, error) {
	if token == "" || len(token) > 128 {
		return nil, ErrSessionInvalid
	}
	h := tokenHash(token)
	rec, err := s.store.SessionByHash(ctx, h)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, ErrSessionInvalid
	}
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	if now.Sub(rec.CreatedAt) >= s.ttl || now.Sub(rec.LastSeenAt) >= s.idle {
		if err := s.store.DeleteSession(ctx, h); err != nil {
			return nil, err
		}
		return nil, ErrSessionInvalid
	}
	last := rec.LastSeenAt
	if now.Sub(last) >= sessionTouchPeriod {
		if err := s.store.TouchSession(ctx, h, now); err != nil {
			return nil, err
		}
		last = now
	}
	return &Session{hash: h, EnrolOnly: rec.EnrolOnly, CreatedAt: rec.CreatedAt,
		ExpiresAt: rec.CreatedAt.Add(s.ttl), IdleExpiry: last.Add(s.idle)}, nil
}

// Logout deletes the session.
func (s *Service) Logout(ctx context.Context, sess *Session) error {
	return s.store.DeleteSession(ctx, sess.hash)
}

// PurgeExpired removes expired sessions (housekeeping).
func (s *Service) PurgeExpired(ctx context.Context) (int64, error) {
	now := s.now().UTC()
	return s.store.PurgeExpiredSessions(ctx, now.Add(-s.ttl), now.Add(-s.idle))
}

// verifyPassword checks the admin password for an authenticated
// re-confirmation and counts failures toward the lockout.
func (s *Service) verifyPassword(ctx context.Context, ip, password string) (*store.Admin, error) {
	if err := s.checkLock(ip); err != nil {
		return nil, err
	}
	a, err := s.store.Admin(ctx)
	if err != nil {
		return nil, err
	}
	ok := false
	if len(password) <= MaxPasswordBytes {
		if ok, err = s.hasher.Verify(ctx, password, a.PasswordHash); err != nil {
			return nil, err
		}
	}
	if !ok {
		s.lockout.Fail(ip)
		return nil, ErrInvalidCredentials
	}
	return a, nil
}

// ChangePassword replaces the admin password and invalidates every session.
func (s *Service) ChangePassword(ctx context.Context, ip, current, next string) error {
	if s.override != "" {
		return ErrPasswordManaged
	}
	if _, err := s.verifyPassword(ctx, ip, current); err != nil {
		return err
	}
	if err := validatePassword(next); err != nil {
		return err
	}
	h, err := s.hasher.Hash(ctx, next)
	if err != nil {
		return err
	}
	return s.store.SetPasswordHash(ctx, h)
}

// MFAStatus describes the MFA state for the UI.
type MFAStatus struct {
	Available              bool `json:"available"`
	Enabled                bool `json:"enabled"`
	EnrolmentPending       bool `json:"enrolment_pending"`
	Required               bool `json:"required"`
	RecoveryCodesRemaining int  `json:"recovery_codes_remaining"`
}

// MFAStatus returns the current MFA state.
func (s *Service) MFAStatus(ctx context.Context) (MFAStatus, error) {
	a, err := s.store.Admin(ctx)
	if err != nil {
		return MFAStatus{}, err
	}
	return MFAStatus{Available: s.totp != nil, Enabled: a.MFAEnabled, EnrolmentPending: a.MFAPendingSecret != "",
		Required: s.requireMFA, RecoveryCodesRemaining: len(a.RecoveryCodes)}, nil
}

// BeginEnrolment re-checks the password and returns a new secret and its
// otpauth URI. A previous unconfirmed secret is replaced.
func (s *Service) BeginEnrolment(ctx context.Context, ip, password string) (secret, uri string, err error) {
	if s.totp == nil {
		return "", "", ErrMFAUnavailable
	}
	a, err := s.verifyPassword(ctx, ip, password)
	if err != nil {
		return "", "", err
	}
	if a.MFAEnabled {
		return "", "", ErrMFAEnabled
	}
	secret, uri, err = s.totp.GenerateSecret(totpAccount, totpIssuer)
	if err != nil {
		return "", "", err
	}
	if err := s.store.SetPendingMFASecret(ctx, secret); err != nil {
		return "", "", err
	}
	return secret, uri, nil
}

// ConfirmEnrolment verifies a code against the pending secret, enables MFA,
// invalidates every session and returns the recovery codes (shown once).
func (s *Service) ConfirmEnrolment(ctx context.Context, ip, code string) ([]string, error) {
	if s.totp == nil {
		return nil, ErrMFAUnavailable
	}
	if err := s.checkLock(ip); err != nil {
		return nil, err
	}
	a, err := s.store.Admin(ctx)
	if err != nil {
		return nil, err
	}
	if a.MFAEnabled {
		return nil, ErrMFAEnabled
	}
	if a.MFAPendingSecret == "" {
		return nil, ErrNoPendingEnrolment
	}
	step, ok := s.totp.Verify(a.MFAPendingSecret, strings.TrimSpace(code), 0, s.now())
	if !ok {
		s.lockout.Fail(ip)
		return nil, ErrInvalidCode
	}
	plain, hashed, err := s.totp.GenerateRecoveryCodes(RecoveryCodeCount)
	if err != nil {
		return nil, err
	}
	if err := s.store.EnableMFA(ctx, a.MFAPendingSecret, step, hashed); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, ErrNoPendingEnrolment // raced with another confirmation
		}
		return nil, err
	}
	return plain, nil
}

func (s *Service) reauthWithCode(ctx context.Context, ip, password, code string) (*store.Admin, error) {
	if s.totp == nil {
		return nil, ErrMFAUnavailable
	}
	a, err := s.verifyPassword(ctx, ip, password)
	if err != nil {
		return nil, err
	}
	if !a.MFAEnabled {
		return nil, ErrMFANotEnabled
	}
	if err := s.verifySecondFactor(ctx, a, code, false); err != nil {
		if errors.Is(err, ErrInvalidCode) {
			s.lockout.Fail(ip)
		}
		return nil, err
	}
	return a, nil
}

// DisableMFA requires the password and a current TOTP code, and invalidates
// every session. Refused in require-MFA mode.
func (s *Service) DisableMFA(ctx context.Context, ip, password, code string) error {
	if s.requireMFA {
		return ErrMFAMandatory
	}
	if _, err := s.reauthWithCode(ctx, ip, password, code); err != nil {
		return err
	}
	return s.store.DisableMFA(ctx)
}

// RegenerateRecoveryCodes requires the password and a current TOTP code,
// replaces the recovery codes and invalidates every other session.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, ip, password, code string, current *Session) ([]string, error) {
	a, err := s.reauthWithCode(ctx, ip, password, code)
	if err != nil {
		return nil, err
	}
	plain, hashed, err := s.totp.GenerateRecoveryCodes(RecoveryCodeCount)
	if err != nil {
		return nil, err
	}
	swapped, err := s.store.ReplaceRecoveryCodes(ctx, a.RecoveryCodes, hashed)
	if err != nil {
		return nil, err
	}
	if !swapped {
		return nil, errors.New("recovery codes changed concurrently; retry")
	}
	var keep []byte
	if current != nil {
		keep = current.hash
	}
	if err := s.store.DeleteSessionsExcept(ctx, keep); err != nil {
		return nil, err
	}
	return plain, nil
}

// ConfirmPassword re-checks the admin password for a dangerous operation
// (factory reset). Failures count toward the lockout.
func (s *Service) ConfirmPassword(ctx context.Context, ip, password string) error {
	_, err := s.verifyPassword(ctx, ip, password)
	return err
}

// ResetSetupToken prepares first-run setup again after a factory reset
// and returns the new one-time token to print ("" with an override).
func (s *Service) ResetSetupToken(ctx context.Context) (string, error) {
	s.mu.Lock()
	s.setupToken = ""
	s.mu.Unlock()
	return s.Init(ctx)
}

// Check validates a session token without refreshing its idle timer, so a
// long-lived connection (live feed) cannot keep an idle session alive.
func (s *Service) Check(ctx context.Context, token string) error {
	if token == "" || len(token) > 128 {
		return ErrSessionInvalid
	}
	rec, err := s.store.SessionByHash(ctx, tokenHash(token))
	if errors.Is(err, domain.ErrNotFound) {
		return ErrSessionInvalid
	}
	if err != nil {
		return err
	}
	now := s.now().UTC()
	if rec.EnrolOnly || now.Sub(rec.CreatedAt) >= s.ttl || now.Sub(rec.LastSeenAt) >= s.idle {
		return ErrSessionInvalid
	}
	return nil
}
