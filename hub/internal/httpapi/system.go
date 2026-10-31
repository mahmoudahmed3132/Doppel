// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/auth"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/domain"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/hubsettings"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/ported"
)

// ConfirmFactoryReset must be sent to reset the Hub.
const ConfirmFactoryReset = "FACTORY RESET"

// ResetFunc performs a factory reset after the audit record was delivered.
type ResetFunc func(ctx context.Context, purgeHoneytokens bool) error

// AuditDeliverer delivers one audit record synchronously to the SIEM.
type AuditDeliverer interface {
	DeliverNow(ctx context.Context, rec domain.Record) error
}

// System serves settings, assets, beacons, factory reset and the CLI
// release notice.
type System struct {
	Settings *hubsettings.Service
	Auth     *auth.Service
	Beacons  ported.BeaconService // nil: create/artefact unavailable
	BeaconDB ported.BeaconStore
	SIEM     AuditDeliverer
	Reset    ResetFunc
	Network  Network
	Log      *slog.Logger
	Now      func() time.Time

	admin *Admin // set by Register
}

// Register mounts the routes.
func (s *System) Register(a *Admin) {
	s.admin = a
	a.RouteFull("GET /api/v3/settings", "", s.getSettings)
	a.RouteFull("PATCH /api/v3/settings", "config.update", s.patchSettings)
	a.RouteFull("GET /api/v3/assets", "", s.getAssets)
	a.RouteFull("PUT /api/v3/assets", "assets.replace", s.putAssets)
	a.RouteFull("GET /api/v3/beacons", "", s.listBeacons)
	a.RouteFull("POST /api/v3/beacons", "beacon.create", s.createBeacon)
	a.RouteFull("GET /api/v3/beacons/{id}/artefact", "beacon.download", s.beaconArtefact)
	a.RouteFull("DELETE /api/v3/beacons/{id}", "beacon.delete", s.deleteBeacon)
	a.RouteFull("POST /api/v3/system/cli-notice/ack", "system.cli_notice_ack", s.ackCLINotice)
	a.RouteFull("POST /api/v3/system/factory-reset", "system.factory_reset", s.factoryReset)
}

func (s *System) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, hubsettings.ErrInvalid):
		Fail(w, http.StatusBadRequest, CodeInvalid, err.Error())
	case errors.Is(err, hubsettings.ErrUnavailable):
		Fail(w, http.StatusServiceUnavailable, "module_unavailable", "the required module is not installed")
	case errors.Is(err, domain.ErrNotFound):
		Fail(w, http.StatusNotFound, CodeNotFound, "not found")
	default:
		s.Log.Error("system operation failed", "error", err.Error())
		Fail(w, http.StatusInternalServerError, CodeInternal, "internal error")
	}
}

func (s *System) getSettings(w http.ResponseWriter, r *http.Request) {
	OK(w, map[string]any{"settings": s.Settings.Get(r.Context())})
}

func (s *System) patchSettings(w http.ResponseWriter, r *http.Request) {
	var p hubsettings.Patch
	if !decodeInto(w, r, &p) {
		return
	}
	v, err := s.Settings.Update(r.Context(), p)
	if err != nil {
		s.fail(w, err)
		return
	}
	OK(w, map[string]any{"settings": v})
}

func (s *System) getAssets(w http.ResponseWriter, r *http.Request) {
	OK(w, map[string]any{"assets": s.Settings.AssetsRaw(r.Context()), "editable": s.Settings.Assets != nil})
}

func (s *System) putAssets(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Assets json.RawMessage `json:"assets"`
	}
	if !decodeInto(w, r, &req) {
		return
	}
	norm, err := s.Settings.ReplaceAssets(r.Context(), req.Assets)
	if err != nil {
		s.fail(w, err)
		return
	}
	OK(w, map[string]any{"assets": norm})
}

func (s *System) listBeacons(w http.ResponseWriter, r *http.Request) {
	l, err := s.BeaconDB.ListBeacons(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	OK(w, map[string]any{"beacons": l, "available": s.Beacons != nil}) // Token has json:"-"
}

var beaconIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func (s *System) createBeacon(w http.ResponseWriter, r *http.Request) {
	if s.Beacons == nil {
		s.fail(w, hubsettings.ErrUnavailable)
		return
	}
	var req struct {
		Type string `json:"type"`
		Name string `json:"name"`
		Memo string `json:"memo"`
	}
	if !decodeInto(w, r, &req) {
		return
	}
	if !catalogueNameRE.MatchString(req.Type) || strings.TrimSpace(req.Name) == "" || len(req.Name) > 128 || len(req.Memo) > 1024 {
		Fail(w, http.StatusBadRequest, CodeInvalid, "type (kebab-case), name (1..128) and memo (≤ 1024) required")
		return
	}
	b, err := s.Beacons.Create(r.Context(), req.Type, strings.TrimSpace(req.Name), req.Memo)
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeInvalid, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "beacon": b})
}

func (s *System) beaconArtefact(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !beaconIDRE.MatchString(id) {
		s.fail(w, domain.ErrNotFound)
		return
	}
	if s.Beacons == nil {
		s.fail(w, hubsettings.ErrUnavailable)
		return
	}
	art, err := s.Beacons.Artefact(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	name := strings.Map(func(c rune) rune {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' {
			return c
		}
		return '_'
	}, art.Filename)
	attachment(w, name, "application/octet-stream") // never rendered inline
	w.Write(art.Body)
}

func (s *System) deleteBeacon(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !beaconIDRE.MatchString(id) {
		s.fail(w, domain.ErrNotFound)
		return
	}
	var err error
	if s.Beacons != nil {
		err = s.Beacons.Delete(r.Context(), id)
	} else {
		err = s.BeaconDB.DeleteBeacon(r.Context(), id)
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	OK(w, nil)
}

var versionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

func (s *System) ackCLINotice(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Version string `json:"version"`
	}
	if !decodeInto(w, r, &req) {
		return
	}
	if !versionRE.MatchString(req.Version) {
		Fail(w, http.StatusBadRequest, CodeInvalid, "version must be X.Y.Z")
		return
	}
	if err := s.Settings.AckCLINotice(r.Context(), req.Version); err != nil {
		s.fail(w, err)
		return
	}
	OK(w, map[string]any{"acknowledged": req.Version})
}

// factoryReset requires the password and a typed confirmation; the audit
// record is delivered to the current SIEM output before anything is
// deleted (§6.13).
func (s *System) factoryReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password         string `json:"password"`
		Confirm          string `json:"confirm"`
		PurgeHoneytokens bool   `json:"purge_honeytokens"`
	}
	if !decodeInto(w, r, &req) {
		return
	}
	if req.Confirm != ConfirmFactoryReset {
		Fail(w, http.StatusBadRequest, "confirmation_required", `send {"confirm": "`+ConfirmFactoryReset+`"}`)
		return
	}
	ip := s.Network.ClientIP(r)
	if err := s.Auth.ConfirmPassword(r.Context(), ip, req.Password); err != nil {
		var le *auth.LockedError
		if errors.As(err, &le) {
			w.Header().Set("Retry-After", retryAfterSeconds(le.RetryAfter))
			Fail(w, http.StatusTooManyRequests, "locked", "too many failed attempts")
			return
		}
		Fail(w, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")
		return
	}
	pre := domain.AuditRecord{Time: s.Now().UTC(), Action: "system.factory_reset", Method: r.Method,
		Route: "/api/v3/system/factory-reset", Path: r.URL.Path, Status: http.StatusOK, Outcome: "success", ActorIP: ip}
	if s.SIEM != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		err := s.SIEM.DeliverNow(ctx, domain.Record{Kind: domain.RecordAudit, Audit: &pre})
		cancel()
		if err != nil {
			s.Log.Error("factory reset audit not delivered to the SIEM; reset refused", "error", err.Error())
			Fail(w, http.StatusBadGateway, "audit_undeliverable", "the audit record could not be delivered to the SIEM output; reset refused")
			return
		}
	}
	s.Log.Warn("audit", "action", "system.factory_reset", "outcome", "starting", "actor_ip", ip, "purge_honeytokens", req.PurgeHoneytokens)
	if err := s.Reset(r.Context(), req.PurgeHoneytokens); err != nil {
		s.fail(w, err)
		return
	}
	s.admin.clearCookie(w) // same attributes as the session cookie (Secure outside development)
	OK(w, map[string]any{"reset": true, "setup_required": true})
}
