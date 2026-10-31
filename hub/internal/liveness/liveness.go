// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

// Package liveness tracks sensor status from heartbeats, events and stop
// notices and raises the Hub liveness events of §6.6.
//
// Alert-once rule: an outage is alerted when OutageAlertedAt is nil; the
// field is persisted, so a restart never repeats an alert. A restart also
// grants every sensor one timeout of grace from Hub start (a Hub outage is
// not a sensor outage), and outages whose last sign of life is older than
// RealertWindow are recorded silently.
package liveness

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/domain"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/store"
)

// Defaults from the specification.
const (
	HeartbeatTimeout = 60 * time.Second
	StopEscalation   = 5 * time.Minute
	RealertWindow    = 24 * time.Hour
)

// Store is the persistence liveness needs.
type Store interface {
	Sensor(ctx context.Context, nodeID, id string) (*domain.Sensor, error)
	Sensors(ctx context.Context, nodeID string) ([]domain.Sensor, error)
	SaveSensorLiveness(ctx context.Context, nodeID, id string, l store.SensorLiveness, at time.Time) error
}

// Raiser raises Hub events through the event pipeline.
type Raiser interface {
	RaiseHubEvent(ctx context.Context, nodeID, sensorID, trigger string, sev domain.Severity, source, target string, details map[string]any) (*domain.Event, error)
}

// StatusPublisher receives status changes for the live feed. Optional.
type StatusPublisher interface {
	PublishStatus(nodeID, sensorID string, status domain.SensorStatus, at time.Time)
}

// Service is the liveness tracker. Operations are serialised.
type Service struct {
	Store     Store
	Raiser    Raiser
	Publisher StatusPublisher
	Log       *slog.Logger
	Now       func() time.Time
	StartedAt time.Time

	mu sync.Mutex
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
// had been online before raises sensor_recovered; the first heartbeat of a
// new sensor does not.
func (s *Service) Heartbeat(ctx context.Context, nodeID, sensorID, revision, sdkVersion string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.Now().UTC()
	sn, err := s.Store.Sensor(ctx, nodeID, sensorID)
	if err != nil {
		return err
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
	if err := s.Store.SaveSensorLiveness(ctx, nodeID, sensorID, l, now); err != nil {
		return err
	}
	if l.StatusChanged {
		s.publish(nodeID, sensorID, domain.StatusOnline, now)
	}
	if recovered {
		_, err := s.Raiser.RaiseHubEvent(ctx, nodeID, sensorID, domain.TriggerSensorRecovered, domain.SeverityInfo,
			domain.HubSource, sensorID, map[string]any{"config_revision": revision})
		return err
	}
	return nil
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

// Sweep applies timeouts. Call it periodically (every few seconds).
func (s *Service) Sweep(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.Now().UTC()
	sensors, err := s.Store.Sensors(ctx, "")
	if err != nil {
		return err
	}
	var errs []error
	for i := range sensors {
		if err := s.sweepOne(ctx, &sensors[i], now); err != nil {
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

func (s *Service) sweepOne(ctx context.Context, sn *domain.Sensor, now time.Time) error {
	switch {
	case sn.Status == domain.StatusOnline:
		last := lastSign(sn)
		effective := last
		if s.StartedAt.After(effective) {
			effective = s.StartedAt
		}
		if now.Sub(effective) <= HeartbeatTimeout {
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
		details := map[string]any{"reason": "heartbeat_timeout", "timeout_sec": int(HeartbeatTimeout / time.Second)}
		if sn.LastHeartbeatAt != nil {
			details["last_heartbeat"] = sn.LastHeartbeatAt.Format(time.RFC3339Nano)
		} else {
			details["last_heartbeat"] = nil
		}
		_, err := s.Raiser.RaiseHubEvent(ctx, sn.NodeID, sn.ID, domain.TriggerSensorHeartbeatLost, domain.SeverityHigh,
			domain.HubSource, sn.ID, details)
		return err

	case sn.Status == domain.StatusOffline && sn.StoppedAt != nil && sn.OutageAlertedAt == nil:
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
		_, err := s.Raiser.RaiseHubEvent(ctx, sn.NodeID, sn.ID, domain.TriggerSensorHeartbeatLost, domain.SeverityHigh,
			domain.HubSource, sn.ID, details)
		return err
	}
	return nil
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
