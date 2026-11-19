// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/siem"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/webhook"
)

// Outputs serves SIEM, webhook and armed-state settings. Secrets (SIEM
// token, webhook URL) are write-only: responses report only "*_set".
type Outputs struct {
	SIEM    *siem.Service
	Store   siem.SettingsStore
	Webhook *webhook.Notifier
	Network Network
	Log     *slog.Logger
	Now     func() time.Time
}

const (
	routeSIEM = "/api/v3/settings/siem"
)

// Register mounts the routes.
func (o *Outputs) Register(a *Admin) {
	a.RouteFull("GET "+routeSIEM, "", needAdmin, o.getSIEM)
	a.RouteFull("PUT "+routeSIEM, "siem.update", needAdmin, o.putSIEM)
	a.RouteFull("POST "+routeSIEM+"/test", "siem.test", needAdmin, o.testSIEM)
	a.RouteFull("GET /api/v3/settings/webhook", "", needAdmin, o.getWebhook)
	a.RouteFull("PUT /api/v3/settings/webhook", "webhook.update", needAdmin, o.putWebhook)
	a.RouteFull("POST /api/v3/settings/webhook/test", "webhook.test", needAdmin, o.testWebhook)
	a.RouteFull("GET /api/v3/system/armed", "", needViewer, o.getArmed)
	a.RouteFull("PUT /api/v3/system/armed", "system.arm", needAdmin, o.putArmed)
}

func (o *Outputs) siemState() map[string]any {
	depth, dropped := o.SIEM.Stats()
	caps := o.SIEM.Capabilities()
	return map[string]any{
		"siem":         o.SIEM.Config().Public(),
		"capabilities": map[string]bool{"ecs": caps.ECS, "http_transports": caps.HTTP},
		"queue":        map[string]any{"depth": depth, "dropped": dropped},
	}
}

func (o *Outputs) getSIEM(w http.ResponseWriter, _ *http.Request) { OK(w, o.siemState()) }

func (o *Outputs) putSIEM(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Protocol string  `json:"protocol"`
		Address  string  `json:"address"`
		Format   string  `json:"format"`
		Token    *string `json:"token"` // null/absent: keep; "": clear
	}
	if !decodeInto(w, r, &req) {
		return
	}
	cur := o.SIEM.Config()
	next := siem.Config{Protocol: req.Protocol, Address: req.Address, Format: req.Format, Token: cur.Token}
	if req.Token != nil {
		next.Token = *req.Token
	}
	next, err := next.Normalize(o.SIEM.Capabilities())
	if err != nil {
		Fail(w, http.StatusBadRequest, "invalid_siem_config", err.Error())
		return
	}
	// The previous destination receives this audit record before the
	// switch; the regular post-request audit reaches the new one.
	pre := domain.AuditRecord{Time: o.Now().UTC(), Action: "siem.update", Method: r.Method, Route: routeSIEM,
		Path: r.URL.Path, Status: http.StatusOK, Outcome: "success", ActorIP: o.Network.ClientIP(r),
		Actor: sessionFrom(r).Username, ActorID: sessionFrom(r).UserID}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := o.SIEM.Switch(ctx, next, &pre); err != nil {
		Fail(w, http.StatusUnprocessableEntity, "siem_unavailable", err.Error())
		return
	}
	if err := siem.SaveConfig(r.Context(), o.Store, next); err != nil {
		o.Log.Error("SIEM output active but not persisted", "error", err.Error())
		Fail(w, http.StatusInternalServerError, CodeInternal, "the new output is active but could not be saved")
		return
	}
	OK(w, o.siemState())
}

// testRecord is the synthetic event sent by the test buttons.
func (o *Outputs) testRecord(trigger, target string) domain.EnrichedEvent {
	now := o.Now().UTC()
	return domain.EnrichedEvent{NodeAlias: "TrueSignal Hub", Event: domain.Event{
		EventID: "00000000-0000-7000-8000-000000000000", NodeID: "-", SensorID: "-", Trigger: trigger,
		Severity: domain.SeverityInfo, OccurredAt: now, ReceivedAt: now, Source: domain.HubSource, Target: target,
		Details: []byte(`{"test":true}`)}}
}

func (o *Outputs) testSIEM(w http.ResponseWriter, r *http.Request) {
	ev := o.testRecord("siem_test", "SIEM output test")
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := o.SIEM.Test(ctx, domain.Record{Kind: domain.RecordEvent, Event: &ev}); err != nil {
		Fail(w, http.StatusBadGateway, "siem_test_failed", err.Error())
		return
	}
	OK(w, map[string]any{"delivered": true})
}

func (o *Outputs) webhookState() map[string]any {
	return map[string]any{"webhook": o.Webhook.Config().Public(), "dropped": o.Webhook.Dropped(), "armed": o.Webhook.Armed()}
}

func (o *Outputs) getWebhook(w http.ResponseWriter, _ *http.Request) { OK(w, o.webhookState()) }

func (o *Outputs) putWebhook(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type       string            `json:"type"`
		URL        *string           `json:"url"` // null/absent: keep
		Severities []domain.Severity `json:"severities"`
	}
	if !decodeInto(w, r, &req) {
		return
	}
	next := webhook.Config{Type: req.Type, Severities: req.Severities, URL: o.Webhook.Config().URL}
	if req.URL != nil {
		next.URL = *req.URL
	}
	if _, err := o.Webhook.Update(r.Context(), next); err != nil {
		if errors.Is(err, webhook.ErrInvalid) {
			Fail(w, http.StatusBadRequest, "invalid_webhook_config", err.Error())
			return
		}
		o.Log.Error("storing webhook configuration failed", "error", err.Error())
		Fail(w, http.StatusInternalServerError, CodeInternal, "internal error")
		return
	}
	OK(w, o.webhookState())
}

func (o *Outputs) testWebhook(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	if err := o.Webhook.Test(ctx); err != nil {
		Fail(w, http.StatusBadGateway, "webhook_test_failed", err.Error())
		return
	}
	OK(w, map[string]any{"delivered": true})
}

func (o *Outputs) getArmed(w http.ResponseWriter, _ *http.Request) {
	OK(w, map[string]any{"armed": o.Webhook.Armed()})
}

func (o *Outputs) putArmed(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Armed *bool `json:"armed"`
	}
	if !decodeInto(w, r, &req) {
		return
	}
	if req.Armed == nil {
		Fail(w, http.StatusBadRequest, CodeInvalid, "armed (true or false) is required")
		return
	}
	if err := o.Webhook.SetArmed(r.Context(), *req.Armed); err != nil {
		o.Log.Error("storing armed state failed", "error", err.Error())
		Fail(w, http.StatusInternalServerError, CodeInternal, "internal error")
		return
	}
	OK(w, map[string]any{"armed": *req.Armed})
}
