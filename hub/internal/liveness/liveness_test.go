// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package liveness

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/domain"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/store"
)

type raised struct {
	trigger string
	sev     domain.Severity
	details map[string]any
}

type fakeRaiser struct{ events []raised }

func (f *fakeRaiser) RaiseHubEvent(_ context.Context, _, _, trig string, sev domain.Severity, src, tgt string, d map[string]any) (*domain.Event, error) {
	if src != domain.HubSource || tgt != "ts-sensor-a" {
		panic("wrong source/target")
	}
	f.events = append(f.events, raised{trig, sev, d})
	return &domain.Event{}, nil
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
	if err := s.Heartbeat(context.Background(), "node-00000001", "ts-sensor-a", "rev_1", "3.0.0"); err != nil {
		t.Fatal(err)
	}
	if status(t, db) != domain.StatusOnline || len(r.events) != 0 {
		t.Fatalf("status %s events %v", status(t, db), r.events)
	}
}

func TestTimeoutAlertsOnceThenRecovers(t *testing.T) {
	s, r, c, db := setup(t)
	ctx := context.Background()
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-a", "rev_1", "3.0.0")

	c.advance(59 * time.Second)
	s.Sweep(ctx)
	if len(r.events) != 0 {
		t.Fatal("alerted before timeout")
	}
	c.advance(2 * time.Second)
	s.Sweep(ctx)
	c.advance(time.Minute)
	s.Sweep(ctx)
	if len(r.events) != 1 || r.events[0].trigger != domain.TriggerSensorHeartbeatLost || r.events[0].sev != domain.SeverityHigh {
		t.Fatalf("events %+v", r.events)
	}
	if d := r.events[0].details; d["reason"] != "heartbeat_timeout" || d["timeout_sec"] != 60 || d["last_heartbeat"] == nil {
		t.Fatalf("details %v", d)
	}
	if status(t, db) != domain.StatusOffline {
		t.Fatal("not offline")
	}

	s.Heartbeat(ctx, "node-00000001", "ts-sensor-a", "rev_2", "3.0.0")
	if len(r.events) != 2 || r.events[1].trigger != domain.TriggerSensorRecovered || r.events[1].details["config_revision"] != "rev_2" {
		t.Fatalf("recovery %+v", r.events)
	}
}

func TestEventsCountAsActivity(t *testing.T) {
	s, r, c, db := setup(t)
	ctx := context.Background()
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-a", "rev_1", "3.0.0")
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
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-a", "rev_1", "3.0.0")
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
	if len(r.events) != 2 || r.events[1].details["reason"] != "not_restarted_after_stop" || r.events[1].details["timeout_sec"] != 300 {
		t.Fatalf("escalation %+v", r.events)
	}
}

func TestStopThenQuickRestartNoEscalation(t *testing.T) {
	s, r, c, _ := setup(t)
	ctx := context.Background()
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-a", "rev_1", "3.0.0")
	s.Stopped(ctx, "node-00000001", "ts-sensor-a", "upgrade")
	c.advance(20 * time.Second)
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-a", "rev_2", "3.0.0")
	c.advance(10 * time.Minute)
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-a", "rev_2", "3.0.0")
	s.Sweep(ctx)
	if len(r.events) != 2 || r.events[1].trigger != domain.TriggerSensorRecovered {
		t.Fatalf("%+v", r.events)
	}
}

func TestRestartDoesNotRealertOldOutages(t *testing.T) {
	s, r, c, db := setup(t)
	ctx := context.Background()
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-a", "rev_1", "3.0.0")
	c.advance(2 * time.Minute)
	s.Sweep(ctx) // alerted once
	if len(r.events) != 1 {
		t.Fatal("no alert")
	}

	// Simulated restart: a new Service over the same DB.
	c.advance(time.Hour)
	s2 := &Service{Store: db, Raiser: r, Log: s.Log, Now: c.now, StartedAt: c.t}
	c.advance(5 * time.Minute)
	s2.Sweep(ctx)
	if len(r.events) != 1 {
		t.Fatalf("outage re-alerted after restart: %+v", r.events)
	}
}

func TestRestartGraceAndWindow(t *testing.T) {
	s, r, c, db := setup(t)
	ctx := context.Background()
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-a", "rev_1", "3.0.0")

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
	s.Heartbeat(ctx, "node-00000001", "ts-sensor-a", "rev_1", "3.0.0") // recovered (event 2)
	c.advance(25 * time.Hour)
	s3 := &Service{Store: db, Raiser: r, Log: s.Log, Now: c.now, StartedAt: c.t}
	c.advance(2 * time.Minute)
	s3.Sweep(ctx)
	if len(r.events) != 2 || status(t, db) != domain.StatusOffline {
		t.Fatalf("old outage alerted: %+v", r.events)
	}
}
