// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package liveness tracks sensor and node status from heartbeats, events,
// stop notices and container restart reports and raises the Hub liveness
// events of §6.6 and F-005 (PCI DSS 10.7.2).
//
// Alert-once rule: an outage is alerted when OutageAlertedAt (or the node's
// OfflineAlertedAt / DriftAlertedAt) is nil; the field is persisted, so a
// restart never repeats an alert. A restart also grants every sensor and node
// one timeout of grace from Hub start (a Hub outage is not a sensor outage),
// and outages whose last sign of life is older than RealertWindow are recorded
// silently.
package liveness

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
)

// Defaults from the specification (§6.6 and F-005).
const (
	HeartbeatInterval    = 30 * time.Second
	HeartbeatTimeout     = 2 * HeartbeatInterval // 60 s
	NodeOfflineTimeout   = 3 * HeartbeatInterval // 90 s
	StopEscalation       = 5 * time.Minute
	ConfigDriftTimeout   = 15 * time.Minute
	RealertWindow        = 24 * time.Hour
	DefaultRestartLimit  = 3
	DefaultRestartWindow = 5 * time.Minute
)

// Store is the persistence liveness needs.
type Store interface {
	Node(ctx context.Context, id string) (*domain.Node, error)
	Nodes(ctx context.Context) ([]domain.Node, error)
	SaveNodeLiveness(ctx context.Context, id string, l store.NodeLiveness) error
	Sensor(ctx context.Context, nodeID, id string) (*domain.Sensor, error)
	Sensors(ctx context.Context, nodeID string) ([]domain.Sensor, error)
	SaveSensorLiveness(ctx context.Context, nodeID, id string, l store.SensorLiveness, at time.Time) error
	SetSensorSilence(ctx context.Context, nodeID, id string, silenced bool, reason string, until *time.Time) error
}

// Raiser raises Hub events through the event pipeline.
type Raiser interface {
	RaiseHubEvent(ctx context.Context, nodeID, sensorID, trigger string, sev domain.Severity, source, target string, details map[string]any) (*domain.Event, error)
}

// StatusPublisher receives status changes for the live feed. Optional.
type StatusPublisher interface {
	PublishStatus(nodeID, sensorID string, status domain.SensorStatus, at time.Time)
}

// AuditSink records system/administrative audit records (e.g. silence expiry). Optional.
type AuditSink interface {
	Record(ctx context.Context, rec domain.AuditRecord)
}

type restartSample struct {
	at    time.Time
	delta int
}

type restartHistory struct {
	seen           bool
	lastCount      int
	alertedAtCount int
	samples        []restartSample
}

// Service is the liveness tracker. Operations are serialised.
type Service struct {
	Store     Store
	Raiser    Raiser
	Publisher StatusPublisher
	Audit     AuditSink
	Log       *slog.Logger
	Now       func() time.Time
	StartedAt time.Time

	// Optional configuration overrides (zero values use specification defaults).
	Interval         time.Duration                       // default HeartbeatInterval (30 s)
	DriftTimeout     func(context.Context) time.Duration // default ConfigDriftTimeout (15 min)
	RestartThreshold int                                 // default DefaultRestartLimit (3)
	RestartWindow    time.Duration                       // default DefaultRestartWindow (5 min)
	NodeOfflineSev   domain.Severity                     // default high
	SensorOfflineSev domain.Severity                     // default medium
	TamperSev        domain.Severity                     // default high
	ConfigDriftSev   domain.Severity                     // default medium
	OnHeartbeatLag   func(time.Duration)

	mu       sync.Mutex
	restarts map[string]*restartHistory
}

func (s *Service) interval() time.Duration {
	if s.Interval > 0 {
		return s.Interval
	}
	return HeartbeatInterval
}

func (s *Service) sensorTimeout() time.Duration { return 2 * s.interval() }
func (s *Service) nodeTimeout() time.Duration   { return 3 * s.interval() }

func (s *Service) driftTimeout(ctx context.Context) time.Duration {
	if s.DriftTimeout != nil {
		if d := s.DriftTimeout(ctx); d > 0 {
			return d
		}
	}
	return ConfigDriftTimeout
}

func (s *Service) restartThreshold() int {
	if s.RestartThreshold > 0 {
		return s.RestartThreshold
	}
	return DefaultRestartLimit
}

func (s *Service) restartWindow() time.Duration {
	if s.RestartWindow > 0 {
		return s.RestartWindow
	}
	return DefaultRestartWindow
}

func (s *Service) nodeOfflineSev() domain.Severity {
	if s.NodeOfflineSev != "" {
		return s.NodeOfflineSev
	}
	return domain.SeverityHigh
}

func (s *Service) sensorOfflineSev() domain.Severity {
	if s.SensorOfflineSev != "" {
		return s.SensorOfflineSev
	}
	return domain.SeverityMedium
}

func (s *Service) tamperSev() domain.Severity {
	if s.TamperSev != "" {
		return s.TamperSev
	}
	return domain.SeverityHigh
}

func (s *Service) configDriftSev() domain.Severity {
	if s.ConfigDriftSev != "" {
		return s.ConfigDriftSev
	}
	return domain.SeverityMedium
}

func (s *Service) publish(n, id string, st domain.SensorStatus, at time.Time) {
	if s.Publisher != nil {
		s.Publisher.PublishStatus(n, id, st, at)
	}
}

func fromSensor(sn *domain.Sensor) store.SensorLiveness {
	return store.SensorLiveness{
		Status:          sn.Status,
		LastHeartbeatAt: sn.LastHeartbeatAt,
		EverOnline:      sn.EverOnline,
		StoppedAt:       sn.StoppedAt,
		OutageAlertedAt: sn.OutageAlertedAt,
	}
}

// Heartbeat records a heartbeat. A heartbeat from an offline sensor that
// had been online before raises sensor_recovered; a heartbeat on a node
// that had gone node_offline raises node_online. The first heartbeat of a
// new sensor or node does not raise recovery events. dropped is the SDK's
// dropped_events since its last acknowledged heartbeat; it is added to the
// sensor's cumulative count in the same transaction.
func (s *Service) Heartbeat(ctx context.Context, nodeID, sensorID, revision, sdkVersion string, dropped int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.Now().UTC()
	sn, err := s.Store.Sensor(ctx, nodeID, sensorID)
	if err != nil {
		return err
	}
	if s.OnHeartbeatLag != nil && sn.LastHeartbeatAt != nil {
		s.OnHeartbeatLag(now.Sub(*sn.LastHeartbeatAt))
	}
	l := fromSensor(sn)
	recovered := sn.Status == domain.StatusOffline && sn.EverOnline
	l.Status = domain.StatusOnline
	l.StatusChanged = sn.Status != domain.StatusOnline
	l.LastHeartbeatAt = &now
	l.EverOnline = true
	l.StoppedAt = nil
	l.OutageAlertedAt = nil
	l.SDKVersion = sdkVersion
	l.DroppedDelta = dropped
	if err := s.Store.SaveSensorLiveness(ctx, nodeID, sensorID, l, now); err != nil {
		return err
	}
	if l.StatusChanged {
		s.publish(nodeID, sensorID, domain.StatusOnline, now)
	}

	var nodeRecovered bool
	if n, err := s.Store.Node(ctx, nodeID); err == nil {
		nodeRecovered = n.OfflineAlertedAt != nil && n.EverOnline
		nl := store.NodeLiveness{
			LastSeenAt:       &now,
			EverOnline:       true,
			OfflineAlertedAt: nil,
			DriftSince:       n.DriftSince,
			DriftAlertedAt:   n.DriftAlertedAt,
		}
		if err := s.Store.SaveNodeLiveness(ctx, nodeID, nl); err != nil {
			return err
		}
	}

	var errs []error
	if recovered {
		if _, err := s.Raiser.RaiseHubEvent(ctx, nodeID, sensorID, domain.TriggerSensorRecovered, domain.SeverityInfo,
			domain.HubSource, sensorID, map[string]any{"config_revision": revision}); err != nil {
			errs = append(errs, err)
		}
	}
	if nodeRecovered {
		if _, err := s.Raiser.RaiseHubEvent(ctx, nodeID, "", domain.TriggerNodeOnline, domain.SeverityInfo,
			domain.HubSource, nodeID, map[string]any{"sensor_id": sensorID, "config_revision": revision}); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Stopped records a stop notice: the sensor goes offline immediately and
// sensor_stopped is raised. Escalation happens in Sweep.
func (s *Service) Stopped(ctx context.Context, nodeID, sensorID, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.Now().UTC()
	sn, err := s.Store.Sensor(ctx, nodeID, sensorID)
	if err != nil {
		return err
	}
	l := fromSensor(sn)
	l.StatusChanged = sn.Status != domain.StatusOffline
	l.Status = domain.StatusOffline
	l.StoppedAt = &now
	l.OutageAlertedAt = nil
	if err := s.Store.SaveSensorLiveness(ctx, nodeID, sensorID, l, now); err != nil {
		return err
	}
	if l.StatusChanged {
		s.publish(nodeID, sensorID, domain.StatusOffline, now)
	}
	_, err = s.Raiser.RaiseHubEvent(ctx, nodeID, sensorID, domain.TriggerSensorStopped, domain.SeverityLow,
		domain.HubSource, sensorID, map[string]any{"reason": reason})
	return err
}

// ReportContainerRestarts records container restart counts reported by the
// node CLI agent (F-005 / F-505). When a sensor container restarts more than
// RestartThreshold times within RestartWindow, sensor_tamper_suspected is
// raised.
func (s *Service) ReportContainerRestarts(ctx context.Context, nodeID string, restarts map[string]int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(restarts) == 0 {
		return nil
	}
	now := s.Now().UTC()
	if s.restarts == nil {
		s.restarts = map[string]*restartHistory{}
	}
	window := s.restartWindow()
	threshold := s.restartThreshold()

	ids := make([]string, 0, len(restarts))
	for id := range restarts {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var errs []error
	for _, sensorID := range ids {
		count := restarts[sensorID]
		if count < 0 {
			continue
		}
		key := nodeID + "/" + sensorID
		h := s.restarts[key]
		if h == nil {
			h = &restartHistory{}
			s.restarts[key] = h
		}
		var delta int
		switch {
		case !h.seen:
			h.seen = true
			delta = count
			h.lastCount = count
		case count > h.lastCount:
			delta = count - h.lastCount
			h.lastCount = count
		case count < h.lastCount:
			h.samples = nil
			h.alertedAtCount = 0
			delta = count
			h.lastCount = count
		}
		if delta > 0 {
			h.samples = append(h.samples, restartSample{at: now, delta: delta})
		}
		kept := h.samples[:0]
		total := 0
		for _, sm := range h.samples {
			if now.Sub(sm.at) <= window {
				kept = append(kept, sm)
				total += sm.delta
			}
		}
		h.samples = kept
		if total > threshold && count > h.alertedAtCount {
			h.alertedAtCount = count
			details := map[string]any{
				"reason":        "excessive_restarts",
				"restarts":      total,
				"restart_count": count,
				"threshold":     threshold,
				"window_sec":    int(window / time.Second),
			}
			if _, err := s.Raiser.RaiseHubEvent(ctx, nodeID, sensorID, domain.TriggerSensorTamperSuspected, s.tamperSev(),
				domain.HubSource, sensorID, details); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// Sweep applies sensor and node timeouts, config-drift detection, and
// silence-window expiry. Call it periodically (every few seconds).
func (s *Service) Sweep(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.Now().UTC()
	nodes, err := s.Store.Nodes(ctx)
	if err != nil {
		return err
	}
	sensors, err := s.Store.Sensors(ctx, "")
	if err != nil {
		return err
	}
	nodeByID := make(map[string]*domain.Node, len(nodes))
	for i := range nodes {
		nodeByID[nodes[i].ID] = &nodes[i]
	}
	var errs []error
	for i := range sensors {
		sn := &sensors[i]
		if sn.Silenced && sn.SilencedUntil != nil && !now.Before(*sn.SilencedUntil) {
			if err := s.Store.SetSensorSilence(ctx, sn.NodeID, sn.ID, false, "", nil); err != nil {
				errs = append(errs, err)
			} else {
				sn.Silenced = false
				sn.SilencedReason = ""
				sn.SilencedUntil = nil
				if s.Audit != nil {
					s.Audit.Record(ctx, domain.AuditRecord{
						Time:    now,
						Action:  "sensor.silence_expired",
						Method:  "SYSTEM",
						Route:   "POST /api/v3/nodes/{node}/sensors/{sensor}/unsilence",
						Path:    "/api/v3/nodes/" + sn.NodeID + "/sensors/" + sn.ID + "/unsilence",
						Status:  200,
						Outcome: "success",
						ActorIP: "local",
						Actor:   "system",
					})
				}
			}
		}
	}
	byNode := make(map[string][]domain.Sensor, len(nodes))
	for _, sn := range sensors {
		byNode[sn.NodeID] = append(byNode[sn.NodeID], sn)
	}
	for i := range sensors {
		sn := &sensors[i]
		if err := s.sweepOne(ctx, sn, nodeByID[sn.NodeID], byNode[sn.NodeID], now); err != nil {
			errs = append(errs, err)
		}
	}
	for i := range nodes {
		if err := s.sweepNode(ctx, &nodes[i], byNode[nodes[i].ID], now); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func lastSign(sn *domain.Sensor) time.Time {
	var t time.Time
	if sn.LastHeartbeatAt != nil {
		t = *sn.LastHeartbeatAt
	}
	if sn.LastActivityAt != nil && sn.LastActivityAt.After(t) {
		t = *sn.LastActivityAt
	}
	return t
}

// nodeKeptHeartbeating reports whether the node continued heartbeating after
// refTime (when sensorID last showed life or stopped). To avoid mistaking
// container phase skew on an unplugged node for tampering, a peer signal must
// either be within one interval of now or at least one interval after refTime.
func (s *Service) nodeKeptHeartbeating(node *domain.Node, peers []domain.Sensor, sensorID string, refTime, now time.Time) bool {
	iv := s.interval()
	timeout := s.sensorTimeout()
	activeAfter := func(t time.Time) bool {
		if t.IsZero() || !t.After(refTime) {
			return false
		}
		return now.Sub(t) <= iv || (t.Sub(refTime) >= iv && now.Sub(t) <= timeout)
	}
	for i := range peers {
		if peers[i].ID == sensorID {
			continue
		}
		if activeAfter(lastSign(&peers[i])) {
			return true
		}
	}
	if node != nil && node.LastSeenAt != nil && activeAfter(*node.LastSeenAt) {
		return true
	}
	return false
}

func (s *Service) sweepOne(ctx context.Context, sn *domain.Sensor, node *domain.Node, peers []domain.Sensor, now time.Time) error {
	timeout := s.sensorTimeout()
	switch {
	case sn.Status == domain.StatusOnline:
		last := lastSign(sn)
		effective := last
		if s.StartedAt.After(effective) {
			effective = s.StartedAt
		}
		if now.Sub(effective) <= timeout {
			return nil
		}
		l := fromSensor(sn)
		l.Status, l.StatusChanged = domain.StatusOffline, true
		l.OutageAlertedAt = &now
		if err := s.Store.SaveSensorLiveness(ctx, sn.NodeID, sn.ID, l, now); err != nil {
			return err
		}
		s.publish(sn.NodeID, sn.ID, domain.StatusOffline, now)
		if now.Sub(last) > RealertWindow {
			s.Log.Info("sensor offline since before the re-alert window; not alerting", "node_id", sn.NodeID, "sensor_id", sn.ID)
			return nil
		}
		if s.nodeKeptHeartbeating(node, peers, sn.ID, last, now) {
			details := map[string]any{
				"reason":      "heartbeat_timeout_node_active",
				"stop_notice": false,
				"timeout_sec": int(timeout / time.Second),
			}
			if sn.LastHeartbeatAt != nil {
				details["last_heartbeat"] = sn.LastHeartbeatAt.Format(time.RFC3339Nano)
			} else {
				details["last_heartbeat"] = nil
			}
			_, err := s.Raiser.RaiseHubEvent(ctx, sn.NodeID, sn.ID, domain.TriggerSensorTamperSuspected, s.tamperSev(),
				domain.HubSource, sn.ID, details)
			return err
		}
		details := map[string]any{"reason": "heartbeat_timeout", "timeout_sec": int(timeout / time.Second)}
		if sn.LastHeartbeatAt != nil {
			details["last_heartbeat"] = sn.LastHeartbeatAt.Format(time.RFC3339Nano)
		} else {
			details["last_heartbeat"] = nil
		}
		_, err := s.Raiser.RaiseHubEvent(ctx, sn.NodeID, sn.ID, domain.TriggerSensorHeartbeatLost, s.sensorOfflineSev(),
			domain.HubSource, sn.ID, details)
		return err

	case sn.Status == domain.StatusOffline && sn.StoppedAt != nil && sn.OutageAlertedAt == nil:
		// If a sensor container was stopped (e.g. `docker stop` sending SIGTERM)
		// and not restarted within 2 intervals while its node keeps heartbeating,
		// escalate as suspected tampering (F-005).
		if now.Sub(*sn.StoppedAt) > timeout && s.nodeKeptHeartbeating(node, peers, sn.ID, *sn.StoppedAt, now) {
			l := fromSensor(sn)
			l.OutageAlertedAt = &now
			if err := s.Store.SaveSensorLiveness(ctx, sn.NodeID, sn.ID, l, now); err != nil {
				return err
			}
			if now.Sub(*sn.StoppedAt) > RealertWindow {
				return nil
			}
			details := map[string]any{
				"reason":      "stopped_not_restarted_node_active",
				"stop_notice": true,
				"timeout_sec": int(timeout / time.Second),
			}
			if sn.LastHeartbeatAt != nil {
				details["last_heartbeat"] = sn.LastHeartbeatAt.Format(time.RFC3339Nano)
			}
			_, err := s.Raiser.RaiseHubEvent(ctx, sn.NodeID, sn.ID, domain.TriggerSensorTamperSuspected, s.tamperSev(),
				domain.HubSource, sn.ID, details)
			return err
		}
		if now.Sub(*sn.StoppedAt) < StopEscalation {
			return nil
		}
		l := fromSensor(sn)
		l.OutageAlertedAt = &now
		if err := s.Store.SaveSensorLiveness(ctx, sn.NodeID, sn.ID, l, now); err != nil {
			return err
		}
		if now.Sub(*sn.StoppedAt) > RealertWindow {
			return nil
		}
		details := map[string]any{"reason": "not_restarted_after_stop", "timeout_sec": int(StopEscalation / time.Second)}
		if sn.LastHeartbeatAt != nil {
			details["last_heartbeat"] = sn.LastHeartbeatAt.Format(time.RFC3339Nano)
		}
		_, err := s.Raiser.RaiseHubEvent(ctx, sn.NodeID, sn.ID, domain.TriggerSensorHeartbeatLost, s.sensorOfflineSev(),
			domain.HubSource, sn.ID, details)
		return err
	}
	return nil
}

func (s *Service) sweepNode(ctx context.Context, n *domain.Node, sensors []domain.Sensor, now time.Time) error {
	var errs []error
	nl := store.NodeLiveness{
		LastSeenAt:       n.LastSeenAt,
		EverOnline:       n.EverOnline,
		OfflineAlertedAt: n.OfflineAlertedAt,
		DriftSince:       n.DriftSince,
		DriftAlertedAt:   n.DriftAlertedAt,
	}
	dirty := false

	// 1. Node-level liveness: emit node_offline when no heartbeat arrives from
	// any sensor on the node for 3 * interval.
	var (
		lastSensorSign         time.Time
		anyUnstoppedEverOnline bool
	)
	for i := range sensors {
		sn := &sensors[i]
		if sn.EverOnline || sn.LastHeartbeatAt != nil {
			if sn.StoppedAt == nil {
				anyUnstoppedEverOnline = true
			}
		}
		if ls := lastSign(sn); ls.After(lastSensorSign) {
			lastSensorSign = ls
		}
	}
	if anyUnstoppedEverOnline && !lastSensorSign.IsZero() && nl.OfflineAlertedAt == nil {
		effective := lastSensorSign
		if s.StartedAt.After(effective) {
			effective = s.StartedAt
		}
		nodeTimeout := s.nodeTimeout()
		if now.Sub(effective) > nodeTimeout {
			nl.EverOnline = true
			nl.OfflineAlertedAt = &now
			dirty = true
			if now.Sub(lastSensorSign) <= RealertWindow {
				details := map[string]any{
					"reason":         "heartbeat_timeout",
					"timeout_sec":    int(nodeTimeout / time.Second),
					"last_heartbeat": lastSensorSign.Format(time.RFC3339Nano),
				}
				if _, err := s.Raiser.RaiseHubEvent(ctx, n.ID, "", domain.TriggerNodeOffline, s.nodeOfflineSev(),
					domain.HubSource, n.ID, details); err != nil {
					errs = append(errs, err)
				}
			} else {
				s.Log.Info("node offline since before the re-alert window; not alerting", "node_id", n.ID)
			}
		}
	}

	// 2. Config drift: emit config_drift when applied_revision != desired_revision
	// for longer than the configured period (default 15 min).
	if n.DesiredRevision != "" && n.AppliedRevision != n.DesiredRevision {
		if nl.DriftSince == nil {
			nl.DriftSince = &now
			dirty = true
		} else if nl.DriftAlertedAt == nil {
			dt := s.driftTimeout(ctx)
			if now.Sub(*nl.DriftSince) >= dt {
				nl.DriftAlertedAt = &now
				dirty = true
				details := map[string]any{
					"desired_revision": n.DesiredRevision,
					"applied_revision": n.AppliedRevision,
					"drift_since":      nl.DriftSince.Format(time.RFC3339Nano),
					"timeout_sec":      int(dt / time.Second),
				}
				if _, err := s.Raiser.RaiseHubEvent(ctx, n.ID, "", domain.TriggerConfigDrift, s.configDriftSev(),
					domain.HubSource, n.ID, details); err != nil {
					errs = append(errs, err)
				}
			}
		}
	} else if nl.DriftSince != nil || nl.DriftAlertedAt != nil {
		nl.DriftSince = nil
		nl.DriftAlertedAt = nil
		dirty = true
	}

	if dirty {
		if err := s.Store.SaveNodeLiveness(ctx, n.ID, nl); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Run sweeps every interval until ctx ends.
func (s *Service) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Sweep(ctx); err != nil && ctx.Err() == nil {
				s.Log.Error("liveness sweep failed", "error", err.Error())
			}
		}
	}
}
