// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package liveness

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
)

type raised struct {
	nodeID   string
	sensorID string
	target   string
	trigger  string
	sev      domain.Severity
	details  map[string]any
}

type fakeRaiser struct{ events []raised }

func (f *fakeRaiser) RaiseHubEvent(_ context.Context, nodeID, sensorID, trig string, sev domain.Severity, src, tgt string, d map[string]any) (*domain.Event, error) {
	if src != domain.HubSource {
		panic("wrong source: " + src)
	}
	if sensorID != "" && tgt != sensorID {
		panic("wrong sensor target: " + tgt)
	}
	if sensorID == "" && tgt != nodeID {
		panic("wrong node target: " + tgt)
	}
	f.events = append(f.events, raised{nodeID: nodeID, sensorID: sensorID, target: tgt, trigger: trig, sev: sev, details: d})
	return &domain.Event{}, nil
}

type fakeAudit struct{ records []domain.AuditRecord }

func (a *fakeAudit) Record(_ context.Context, rec domain.AuditRecord) {
	a.records = append(a.records, rec)
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func setup(t *testing.T) (*Service, *fakeRaiser, *clock, *store.DB) {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "ts.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	c := &clock{t: time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)}
	ctx := context.Background()
	db.CreateNode(ctx, &domain.Node{ID: "node-00000001", Alias: "n", KeyHash: []byte("k"), CreatedAt: c.t})
	db.CreateSensor(ctx, &domain.Sensor{NodeID: "node-00000001", ID: "ts-sensor-a", CatalogueName: "x", Version: "1", CreatedAt: c.t})
	r := &fakeRaiser{}
	s := &Service{Store: db, Raiser: r, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: c.now, StartedAt: c.t}
	return s, r, c, db
}

func status(t *testing.T, db *store.DB) domain.SensorStatus {
	s, err := db.Sensor(context.Background(), "node-00000001", "ts-sensor-a")
	if err != nil {
		t.Fatal(err)
	}
	return s.Status
}

func TestFirstHeartbeatIsNotRecovery(t *testing.T) {
	s, r, _, db := setup(t)
	if err := s.Heartbeat(context.Background(), "node-00000001", "ts-sensor-a", "rev_1", "3.0.0", 0); err != nil {
		t.Fatal(err)
	}
	if status(t, db) != domain.StatusOnline || len(r.events) != 0 {
		t.Fatalf("status %s events %v", status(t, db), r.events)
	}
}

func TestTimeoutAlertsOnceThenRecovers(t *testing.T) {
	s, r, c, db := setup(t)
	ctx := context.Background()
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-a", "rev_1", "3.0.0", 0)

	c.advance(59 * time.Second)
	s.Sweep(ctx)
	if len(r.events) != 0 {
		t.Fatal("alerted before timeout")
	}
	// At 61s (> 2 * interval = 60s, <= 3 * interval = 90s): sensor offline (medium).
	c.advance(2 * time.Second)
	s.Sweep(ctx)
	c.advance(10 * time.Second)
	s.Sweep(ctx)
	if len(r.events) != 1 || r.events[0].trigger != domain.TriggerSensorHeartbeatLost || r.events[0].sev != domain.SeverityMedium {
		t.Fatalf("events %+v", r.events)
	}
	if d := r.events[0].details; d["reason"] != "heartbeat_timeout" || d["timeout_sec"] != 60 || d["last_heartbeat"] == nil {
		t.Fatalf("details %v", d)
	}
	if status(t, db) != domain.StatusOffline {
		t.Fatal("not offline")
	}

	// At 121s (> 3 * interval = 90s): node_offline (high) emitted once.
	c.advance(50 * time.Second)
	s.Sweep(ctx)
	s.Sweep(ctx)
	if len(r.events) != 2 || r.events[1].trigger != domain.TriggerNodeOffline || r.events[1].sev != domain.SeverityHigh || r.events[1].target != "node-00000001" {
		t.Fatalf("node_offline %+v", r.events)
	}

	// Recovery heartbeat raises both sensor_recovered and node_online.
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-a", "rev_2", "3.0.0", 0)
	if len(r.events) != 4 || r.events[2].trigger != domain.TriggerSensorRecovered || r.events[2].details["config_revision"] != "rev_2" ||
		r.events[3].trigger != domain.TriggerNodeOnline || r.events[3].sev != domain.SeverityInfo || r.events[3].target != "node-00000001" {
		t.Fatalf("recovery %+v", r.events)
	}
}

func TestEventsCountAsActivity(t *testing.T) {
	s, r, c, db := setup(t)
	ctx := context.Background()
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-a", "rev_1", "3.0.0", 0)
	c.advance(50 * time.Second)
	db.TouchSensorActivity(ctx, "node-00000001", "ts-sensor-a", c.t)
	c.advance(50 * time.Second)
	s.Sweep(ctx)
	if len(r.events) != 0 {
		t.Fatal("event activity ignored")
	}
}

func TestStopThenEscalation(t *testing.T) {
	s, r, c, db := setup(t)
	ctx := context.Background()
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-a", "rev_1", "3.0.0", 0)
	if err := s.Stopped(ctx, "node-00000001", "ts-sensor-a", "received SIGTERM"); err != nil {
		t.Fatal(err)
	}
	if status(t, db) != domain.StatusOffline || len(r.events) != 1 || r.events[0].trigger != domain.TriggerSensorStopped ||
		r.events[0].sev != domain.SeverityLow || r.events[0].details["reason"] != "received SIGTERM" {
		t.Fatalf("stop %+v", r.events)
	}
	c.advance(4 * time.Minute)
	s.Sweep(ctx)
	if len(r.events) != 1 {
		t.Fatal("escalated early")
	}
	c.advance(61 * time.Second)
	s.Sweep(ctx)
	s.Sweep(ctx)
	if len(r.events) != 2 || r.events[1].details["reason"] != "not_restarted_after_stop" || r.events[1].details["timeout_sec"] != 300 ||
		r.events[1].sev != domain.SeverityMedium {
		t.Fatalf("escalation %+v", r.events)
	}
}

func TestStopThenQuickRestartNoEscalation(t *testing.T) {
	s, r, c, _ := setup(t)
	ctx := context.Background()
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-a", "rev_1", "3.0.0", 0)
	s.Stopped(ctx, "node-00000001", "ts-sensor-a", "upgrade")
	c.advance(20 * time.Second)
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-a", "rev_2", "3.0.0", 0)
	c.advance(10 * time.Minute)
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-a", "rev_2", "3.0.0", 0)
	s.Sweep(ctx)
	if len(r.events) != 2 || r.events[1].trigger != domain.TriggerSensorRecovered {
		t.Fatalf("%+v", r.events)
	}
}

func TestRestartDoesNotRealertOldOutages(t *testing.T) {
	s, r, c, db := setup(t)
	ctx := context.Background()
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-a", "rev_1", "3.0.0", 0)
	c.advance(2 * time.Minute)
	s.Sweep(ctx) // sensor_heartbeat_lost + node_offline alerted once
	if len(r.events) != 2 {
		t.Fatalf("expected sensor + node outage alerts, got %+v", r.events)
	}

	// Simulated restart: a new Service over the same DB.
	c.advance(time.Hour)
	s2 := &Service{Store: db, Raiser: r, Log: s.Log, Now: c.now, StartedAt: c.t}
	c.advance(5 * time.Minute)
	s2.Sweep(ctx)
	if len(r.events) != 2 {
		t.Fatalf("outage re-alerted after restart: %+v", r.events)
	}
}

func TestRestartGraceAndWindow(t *testing.T) {
	s, r, c, db := setup(t)
	ctx := context.Background()
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-a", "rev_1", "3.0.0", 0)

	// Hub was down 10 minutes; DB still says online. Grace from start.
	c.advance(10 * time.Minute)
	s2 := &Service{Store: db, Raiser: r, Log: s.Log, Now: c.now, StartedAt: c.t}
	c.advance(30 * time.Second)
	s2.Sweep(ctx)
	if len(r.events) != 0 {
		t.Fatal("alerted during restart grace")
	}
	c.advance(31 * time.Second)
	s2.Sweep(ctx)
	if len(r.events) != 1 {
		t.Fatal("recent outage not alerted after grace")
	}

	// A sensor silent for > 24 h before restart goes offline without alert.
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-a", "rev_1", "3.0.0", 0) // recovered (event 2)
	c.advance(25 * time.Hour)
	s3 := &Service{Store: db, Raiser: r, Log: s.Log, Now: c.now, StartedAt: c.t}
	c.advance(2 * time.Minute)
	s3.Sweep(ctx)
	if len(r.events) != 2 || status(t, db) != domain.StatusOffline {
		t.Fatalf("old outage alerted: %+v", r.events)
	}
}

func TestSensorTamperSuspectedWhenNodeKeepsHeartbeating(t *testing.T) {
	s, r, c, db := setup(t)
	ctx := context.Background()
	if err := db.CreateSensor(ctx, &domain.Sensor{NodeID: "node-00000001", ID: "ts-sensor-b", CatalogueName: "x", Version: "1", CreatedAt: c.t}); err != nil {
		t.Fatal(err)
	}

	// Both sensors online at t=0.
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-a", "rev_1", "3.0.0", 0)
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-b", "rev_1", "3.0.0", 0)

	// Case 1: ts-sensor-a stops WITHOUT a stop notice while ts-sensor-b keeps heartbeating.
	c.advance(30 * time.Second)
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-b", "rev_1", "3.0.0", 0)
	s.Sweep(ctx)
	if len(r.events) != 0 {
		t.Fatalf("alerted at 1 interval: %+v", r.events)
	}

	c.advance(31 * time.Second) // 61s since ts-sensor-a's last heartbeat (2 intervals)
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-b", "rev_1", "3.0.0", 0)
	s.Sweep(ctx)
	if len(r.events) != 1 || r.events[0].trigger != domain.TriggerSensorTamperSuspected ||
		r.events[0].sev != domain.SeverityHigh || r.events[0].target != "ts-sensor-a" ||
		r.events[0].details["stop_notice"] != false {
		t.Fatalf("expected sensor_tamper_suspected without stop notice within 2 intervals, got %+v", r.events)
	}

	// Case 2: ts-sensor-a recovers, then receives `docker stop` (SIGTERM -> Stopped)
	// and is not restarted within 2 intervals while ts-sensor-b keeps heartbeating.
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-a", "rev_1", "3.0.0", 0) // event 2: sensor_recovered
	r.events = nil
	if err := s.Stopped(ctx, "node-00000001", "ts-sensor-a", "received SIGTERM"); err != nil {
		t.Fatal(err)
	}
	if len(r.events) != 1 || r.events[0].trigger != domain.TriggerSensorStopped {
		t.Fatalf("expected sensor_stopped, got %+v", r.events)
	}
	c.advance(30 * time.Second)
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-b", "rev_1", "3.0.0", 0)
	s.Sweep(ctx)
	if len(r.events) != 1 {
		t.Fatalf("escalated before 2 intervals: %+v", r.events)
	}
	c.advance(31 * time.Second) // 61s after Stopped (2 intervals)
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-b", "rev_1", "3.0.0", 0)
	s.Sweep(ctx)
	if len(r.events) != 2 || r.events[1].trigger != domain.TriggerSensorTamperSuspected ||
		r.events[1].sev != domain.SeverityHigh || r.events[1].target != "ts-sensor-a" ||
		r.events[1].details["stop_notice"] != true {
		t.Fatalf("expected sensor_tamper_suspected after docker stop within 2 intervals, got %+v", r.events)
	}
}

func TestSensorTamperSuspectedOnContainerRestartLoop(t *testing.T) {
	s, r, c, _ := setup(t)
	ctx := context.Background()

	// 3 restarts in 5 minutes (<= threshold 3): no alert.
	if err := s.ReportContainerRestarts(ctx, "node-00000001", map[string]int{"ts-sensor-a": 2}); err != nil {
		t.Fatal(err)
	}
	c.advance(time.Minute)
	if err := s.ReportContainerRestarts(ctx, "node-00000001", map[string]int{"ts-sensor-a": 3}); err != nil {
		t.Fatal(err)
	}
	if len(r.events) != 0 {
		t.Fatalf("alerted at threshold: %+v", r.events)
	}

	// 4th restart within 5 minutes (> 3): raises sensor_tamper_suspected once.
	c.advance(time.Minute)
	if err := s.ReportContainerRestarts(ctx, "node-00000001", map[string]int{"ts-sensor-a": 4}); err != nil {
		t.Fatal(err)
	}
	if len(r.events) != 1 || r.events[0].trigger != domain.TriggerSensorTamperSuspected ||
		r.events[0].sev != domain.SeverityHigh || r.events[0].details["reason"] != "excessive_restarts" ||
		r.events[0].details["restarts"] != 4 {
		t.Fatalf("expected excessive_restarts tamper event, got %+v", r.events)
	}
	// Repeating the same restart count does not re-alert.
	if err := s.ReportContainerRestarts(ctx, "node-00000001", map[string]int{"ts-sensor-a": 4}); err != nil {
		t.Fatal(err)
	}
	if len(r.events) != 1 {
		t.Fatalf("duplicate restart alert: %+v", r.events)
	}
}

func TestConfigDriftAlertAndRecovery(t *testing.T) {
	s, r, c, db := setup(t)
	ctx := context.Background()

	if err := db.SetNodeRevisions(ctx, "node-00000001", "rev_11111111", "rev_00000000"); err != nil {
		t.Fatal(err)
	}
	// First sweep records drift_since.
	s.Sweep(ctx)
	c.advance(14 * time.Minute)
	s.Sweep(ctx)
	if len(r.events) != 0 {
		t.Fatalf("drift alerted before 15m: %+v", r.events)
	}

	c.advance(2 * time.Minute)
	s.Sweep(ctx)
	s.Sweep(ctx)
	if len(r.events) != 1 || r.events[0].trigger != domain.TriggerConfigDrift ||
		r.events[0].target != "node-00000001" ||
		r.events[0].details["desired_revision"] != "rev_11111111" ||
		r.events[0].details["applied_revision"] != "rev_00000000" {
		t.Fatalf("expected config_drift, got %+v", r.events)
	}

	// Node applies the desired revision -> drift clears; a later drift alerts again.
	if err := db.SetNodeRevisions(ctx, "node-00000001", "rev_11111111", "rev_11111111"); err != nil {
		t.Fatal(err)
	}
	s.Sweep(ctx)
	if err := db.SetNodeRevisions(ctx, "node-00000001", "rev_22222222", "rev_11111111"); err != nil {
		t.Fatal(err)
	}
	s.Sweep(ctx)
	c.advance(15 * time.Minute)
	s.Sweep(ctx)
	if len(r.events) != 2 || r.events[1].trigger != domain.TriggerConfigDrift ||
		r.events[1].details["desired_revision"] != "rev_22222222" {
		t.Fatalf("expected second config_drift after re-drift, got %+v", r.events)
	}
}

func TestExpiredSilenceAutoUnsilencesWithAudit(t *testing.T) {
	s, _, c, db := setup(t)
	aud := &fakeAudit{}
	s.Audit = aud
	ctx := context.Background()

	until := c.t.Add(2 * time.Hour)
	if err := db.SetSensorSilence(ctx, "node-00000001", "ts-sensor-a", true, "maintenance window", &until); err != nil {
		t.Fatal(err)
	}

	c.advance(time.Hour)
	s.Sweep(ctx)
	sn, _ := db.Sensor(ctx, "node-00000001", "ts-sensor-a")
	if !sn.Silenced || sn.SilencedReason != "maintenance window" || len(aud.records) != 0 {
		t.Fatalf("unsilenced early: %+v aud=%+v", sn, aud.records)
	}

	c.advance(time.Hour + time.Second)
	s.Sweep(ctx)
	sn, _ = db.Sensor(ctx, "node-00000001", "ts-sensor-a")
	if sn.Silenced || sn.SilencedReason != "" || sn.SilencedUntil != nil {
		t.Fatalf("expired silence not cleared: %+v", sn)
	}
	if len(aud.records) != 1 || aud.records[0].Action != "sensor.silence_expired" ||
		aud.records[0].Path != "/api/v3/nodes/node-00000001/sensors/ts-sensor-a/unsilence" {
		t.Fatalf("missing silence expiry audit record: %+v", aud.records)
	}
}
