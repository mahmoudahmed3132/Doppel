// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package siem

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
)

// Intervals (§6.6, §6.9).
const (
	HeartbeatInterval = 5 * time.Minute
	InventoryInterval = 24 * time.Hour
	nodeOnlineWindow  = 90 * time.Second
)

// Sink receives records (the Service).
type Sink interface {
	Enqueue(rec domain.Record)
	Stats() (depth int, dropped uint64)
}

// FleetCounter provides fleet totals for the heartbeat.
type FleetCounter interface {
	Nodes(ctx context.Context) ([]domain.Node, error)
	Sensors(ctx context.Context, nodeID string) ([]domain.Sensor, error)
}

// Heartbeat emits the Hub heartbeat record. It is SIEM-only: never stored
// as an event and never sent to webhooks.
type Heartbeat struct {
	Sink      Sink
	Fleet     FleetCounter
	Version   string
	StartedAt time.Time
	Log       *slog.Logger
	Now       func() time.Time
}

// Build assembles one heartbeat record.
func (h *Heartbeat) Build(ctx context.Context) (domain.HubHeartbeat, error) {
	now := h.Now().UTC()
	hb := domain.HubHeartbeat{Time: now, Version: h.Version, UptimeSeconds: int64(now.Sub(h.StartedAt) / time.Second)}
	nodes, err := h.Fleet.Nodes(ctx)
	if err != nil {
		return hb, err
	}
	sensors, err := h.Fleet.Sensors(ctx, "")
	if err != nil {
		return hb, err
	}
	hb.NodesTotal, hb.SensorsTotal = len(nodes), len(sensors)
	for _, n := range nodes {
		if n.LastSeenAt != nil && now.Sub(*n.LastSeenAt) <= nodeOnlineWindow {
			hb.NodesOnline++
		}
	}
	for _, s := range sensors {
		if s.Status == domain.StatusOnline {
			hb.SensorsOnline++
		}
	}
	depth, dropped := h.Sink.Stats()
	hb.SIEMQueueDepth, hb.SIEMDropped = depth, dropped
	return hb, nil
}

// Emit sends one heartbeat now.
func (h *Heartbeat) Emit(ctx context.Context) {
	hb, err := h.Build(ctx)
	if err != nil {
		h.Log.Warn("hub heartbeat incomplete", "error", err.Error())
	}
	h.Sink.Enqueue(domain.Record{Kind: domain.RecordHeartbeat, Heartbeat: &hb})
}

// Run emits a heartbeat every interval until ctx ends.
func (h *Heartbeat) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.Emit(ctx)
		}
	}
}

// InventoryHoneytokens wraps the PORTED honeytoken service so that every
// newly created credential is reported to the SIEM at once, and the full
// inventory at start and every 24 h. Records never contain the secret.
type InventoryHoneytokens struct {
	ported.HoneytokenService
	Sink Sink
	Log  *slog.Logger
	Now  func() time.Time

	mu    sync.Mutex
	known map[string]bool
}

// Ensure implements ported.HoneytokenService and reports new tokens.
func (i *InventoryHoneytokens) Ensure(ctx context.Context, nodeID, sensorID string) (ported.Honeytoken, error) {
	ht, err := i.HoneytokenService.Ensure(ctx, nodeID, sensorID)
	if err != nil {
		return ht, err
	}
	i.mu.Lock()
	if i.known == nil {
		i.known = map[string]bool{}
	}
	isNew := !i.known[ht.ID]
	i.known[ht.ID] = true
	i.mu.Unlock()
	if isNew {
		i.Sink.Enqueue(domain.Record{Kind: domain.RecordHoneytoken, Honeytoken: &domain.HoneytokenInventory{
			Time: i.Now().UTC(), HoneytokenID: ht.ID, Username: ht.Username, PlantedNodeID: ht.PlantedNodeID,
			PlantedSensorID: ht.PlantedSensorID, CreatedAt: ht.CreatedAt, Status: ht.Status,
		}})
	}
	return ht, nil
}

// EmitInventory sends the full inventory and records the known ids.
func (i *InventoryHoneytokens) EmitInventory(ctx context.Context) {
	inv, err := i.HoneytokenService.Inventory(ctx, i.Now().UTC())
	if err != nil {
		i.Log.Warn("honeytoken inventory unavailable", "error", err.Error())
		return
	}
	i.mu.Lock()
	if i.known == nil {
		i.known = map[string]bool{}
	}
	for _, r := range inv {
		i.known[r.HoneytokenID] = true
	}
	i.mu.Unlock()
	for _, r := range inv {
		r := r
		i.Sink.Enqueue(domain.Record{Kind: domain.RecordHoneytoken, Honeytoken: &r})
	}
}

// Run emits the inventory now and every interval.
func (i *InventoryHoneytokens) Run(ctx context.Context, interval time.Duration) {
	for {
		i.EmitInventory(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}
