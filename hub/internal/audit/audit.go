// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package audit delivers administrative audit records (§6.10) to the Hub
// log and to the SIEM output. Audit records are not stored in the database.
package audit

import (
	"context"
	"log/slog"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
)

// SIEM accepts records for SIEM delivery. It must not block.
type SIEM interface {
	Enqueue(rec domain.Record)
}

// Recorder writes every audit record to the log and, when configured, the
// SIEM queue. It never includes request bodies.
type Recorder struct {
	Log  *slog.Logger
	SIEM SIEM // nil until the SIEM output is wired
}

// Record implements httpapi.AuditSink.
func (r *Recorder) Record(_ context.Context, rec domain.AuditRecord) {
	r.Log.Info("audit",
		"action", rec.Action, "method", rec.Method, "route", rec.Route, "path", rec.Path,
		"status", rec.Status, "outcome", rec.Outcome, "actor_ip", rec.ActorIP, "actor", rec.Actor)
	if r.SIEM != nil {
		a := rec
		r.SIEM.Enqueue(domain.Record{Kind: domain.RecordAudit, Audit: &a})
	}
}
