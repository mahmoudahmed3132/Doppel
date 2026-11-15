// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package ecs

import (
	"errors"
	"fmt"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
)

var _ ported.ECSRenderer = Renderer{}

// Render renders one SIEM record. Exactly one payload must be set.
func (r Renderer) Render(rec domain.Record) (map[string]any, error) {
	switch {
	case rec.Kind == domain.RecordEvent && rec.Event != nil:
		return r.ecsEvent(*rec.Event), nil
	case rec.Kind == domain.RecordAudit && rec.Audit != nil:
		return r.ecsAudit(*rec.Audit), nil
	case rec.Kind == domain.RecordHoneytoken && rec.Honeytoken != nil:
		return r.ecsHoneytoken(*rec.Honeytoken), nil
	case rec.Kind == domain.RecordHeartbeat && rec.Heartbeat != nil:
		return r.ecsHeartbeat(*rec.Heartbeat), nil
	}
	return nil, errors.New("ecs: record kind and payload do not match")
}

// ecsHeartbeat renders the Hub's periodic health record (§6.6) as an ECS
// metric event, so a SIEM rule can alert when heartbeats stop.
func (r Renderer) ecsHeartbeat(h domain.HubHeartbeat) map[string]any {
	at := h.Time
	if at.IsZero() {
		at = r.now()
	}
	return map[string]any{
		"@timestamp": at.UTC().Format(time.RFC3339Nano),
		"ecs":        map[string]any{"version": ecsVersion},
		"message": fmt.Sprintf("TrueSignal hub heartbeat: %d/%d nodes, %d/%d sensors online, SIEM queue %d",
			h.NodesOnline, h.NodesTotal, h.SensorsOnline, h.SensorsTotal, h.SIEMQueueDepth),
		"event": map[string]any{
			"kind":     "metric",
			"category": []string{"host"},
			"type":     []string{"info"},
			"action":   "hub_heartbeat",
			"dataset":  "truesignal.heartbeat",
			"module":   "truesignal",
		},
		"service":    map[string]any{"type": "truesignal-hub", "version": h.Version},
		"observer":   map[string]any{"type": "honeypot", "vendor": "TrueSignal", "product": "TrueSignal"},
		"tags":       []string{"truesignal", "heartbeat"},
		"truesignal": map[string]any{"heartbeat": h},
	}
}
