// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
)

func openTest(t *testing.T) (*DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "truesignal.db")
	db, err := Open(context.Background(), path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, path
}

func TestMigrationSnapshotAndNewerSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ts.db")
	fixed := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

	v1 := []Migration{{Version: 1, SQL: `CREATE TABLE t (x INTEGER);`}}
	db, err := Open(ctx, path, Options{Migrations: v1, Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.ExecContext(ctx, `INSERT INTO t VALUES (42)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if m, _ := filepath.Glob(path + ".pre-*"); len(m) != 0 {
		t.Fatalf("fresh database must not be snapshotted: %v", m)
	}

	v2 := append(v1, Migration{Version: 2, SQL: `ALTER TABLE t ADD COLUMN y INTEGER;`})
	db, err = Open(ctx, path, Options{Migrations: v2, Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	snap := path + ".pre-v2-20261031T120000Z.bak"
	sdb, err := Open(ctx, snap, Options{Migrations: v1})
	if err != nil {
		t.Fatalf("snapshot not usable: %v", err)
	}
	var x int
	if err := sdb.sql.QueryRowContext(ctx, `SELECT x FROM t`).Scan(&x); err != nil || x != 42 {
		t.Fatalf("snapshot content: %d %v", x, err)
	}
	if v, _ := sdb.schemaVersion(ctx); v != 1 {
		t.Fatalf("snapshot version %d", v)
	}
	sdb.Close()

	// A Hub that knows only v1 must refuse the v2 database.
	_, err = Open(ctx, path, Options{Migrations: v1})
	if !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("expected ErrSchemaTooNew, got %v", err)
	}
}

func TestFailedMigrationRollsBack(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ts.db")
	v1 := []Migration{{Version: 1, SQL: `CREATE TABLE t (x INTEGER);`}}
	db, err := Open(ctx, path, Options{Migrations: v1})
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	bad := append(v1, Migration{Version: 2, SQL: `CREATE TABLE u (x INTEGER); SELECT nosuchfn();`})
	if _, err := Open(ctx, path, Options{Migrations: bad}); err == nil {
		t.Fatal("bad migration succeeded")
	}
	db, err = Open(ctx, path, Options{Migrations: v1})
	if err != nil {
		t.Fatalf("database left inconsistent: %v", err)
	}
	defer db.Close()
	var n int
	db.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE name = 'u'`).Scan(&n)
	if n != 0 {
		t.Fatal("partial migration persisted")
	}
}

func seedNode(t *testing.T, db *DB, id string) {
	t.Helper()
	ctx := context.Background()
	if err := db.CreateNode(ctx, &domain.Node{ID: id, Alias: id, KeyHash: []byte(id), CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateSensor(ctx, &domain.Sensor{NodeID: id, ID: "ts-sensor-a", CatalogueName: "tcp-tarpit", Version: "1.0.0", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

func TestEventsSurviveNodeAndSensorDeletion(t *testing.T) {
	db, _ := openTest(t)
	ctx := context.Background()
	seedNode(t, db, "node-0000000a")
	seedNode(t, db, "node-0000000b")

	for _, n := range []string{"node-0000000a", "node-0000000b"} {
		ok, err := db.InsertEvent(ctx, &domain.Event{EventID: "e1", NodeID: n, SensorID: "ts-sensor-a", Trigger: "x",
			Severity: "high", OccurredAt: time.Now(), ReceivedAt: time.Now(), Source: "s", Target: "t", Details: []byte("{}")})
		if err != nil || !ok {
			t.Fatal(ok, err)
		}
	}
	if err := db.DeleteSensor(ctx, "node-0000000b", "ts-sensor-a"); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteNode(ctx, "node-0000000a"); err != nil {
		t.Fatal(err)
	}
	if s, _ := db.Sensors(ctx, "node-0000000a"); len(s) != 0 {
		t.Fatal("sensor not cascaded with node")
	}
	ev, err := db.Events(ctx, EventFilter{})
	if err != nil || len(ev) != 2 {
		t.Fatalf("events lost: %d %v", len(ev), err)
	}
}

func TestInsertEventIdempotent(t *testing.T) {
	db, _ := openTest(t)
	ctx := context.Background()
	e := func() *domain.Event {
		return &domain.Event{EventID: "dup", NodeID: "node-00000001", SensorID: "ts-sensor-a", Trigger: "x", Severity: "low",
			OccurredAt: time.Now(), ReceivedAt: time.Now(), Source: "s", Target: "t", Details: []byte("{}")}
	}
	first := e()
	if ok, err := db.InsertEvent(ctx, first); !ok || err != nil || first.Seq == 0 {
		t.Fatal(ok, err)
	}
	if ok, err := db.InsertEvent(ctx, e()); ok || err != nil {
		t.Fatalf("duplicate stored: %v %v", ok, err)
	}
	other := e()
	other.NodeID = "node-00000002"
	if ok, _ := db.InsertEvent(ctx, other); !ok {
		t.Fatal("same event id on another node must be stored")
	}
}

func TestEventFiltersAndFlags(t *testing.T) {
	db, _ := openTest(t)
	ctx := context.Background()
	base := time.Now().Add(-time.Hour)
	for i, sev := range []domain.Severity{"low", "high", "critical", "high"} {
		src := "10.0.0." + string(rune('1'+i))
		if i == 3 {
			src = "50%_off"
		}
		db.InsertEvent(ctx, &domain.Event{EventID: string(rune('a' + i)), NodeID: "node-00000001", SensorID: "ts-sensor-a",
			Trigger: "tcp_connection", Severity: sev, OccurredAt: base, ReceivedAt: base.Add(time.Duration(i) * time.Minute),
			Source: src, Target: "SSH", Details: []byte("{}")})
	}
	ev, _ := db.Events(ctx, EventFilter{Severities: []domain.Severity{"high", "critical"}})
	if len(ev) != 3 || ev[0].Seq < ev[1].Seq {
		t.Fatalf("severity filter/order: %+v", ev)
	}
	ev, _ = db.Events(ctx, EventFilter{Text: "%_"})
	if len(ev) != 1 || ev[0].Source != "50%_off" {
		t.Fatalf("LIKE not escaped: %d", len(ev))
	}
	page1, _ := db.Events(ctx, EventFilter{Limit: 2})
	page2, _ := db.Events(ctx, EventFilter{Limit: 2, BeforeSeq: page1[1].Seq})
	if len(page2) != 2 || page2[0].Seq >= page1[1].Seq {
		t.Fatal("cursor pagination broken")
	}
	if n, _ := db.UnreadCount(ctx); n != 4 {
		t.Fatalf("unread %d", n)
	}
	db.MarkRead(ctx, page1[0].Seq)
	if n, _ := db.UnreadCount(ctx); n != 3 {
		t.Fatalf("unread after mark one %d", n)
	}
	db.Archive(ctx, 0)
	f := false
	if ev, _ := db.Events(ctx, EventFilter{Archived: &f}); len(ev) != 0 {
		t.Fatal("archive all failed")
	}
	if n, _ := db.PurgeArchivedOlderThan(ctx, base.Add(2*time.Minute)); n != 2 {
		t.Fatalf("purge removed %d", n)
	}
}

func TestSettingsAndNodeKeyRotation(t *testing.T) {
	db, _ := openTest(t)
	ctx := context.Background()
	v := "on"
	if err := db.PutSettings(ctx, map[string]*string{"armed": &v}); err != nil {
		t.Fatal(err)
	}
	if got, ok, _ := db.Setting(ctx, "armed"); !ok || got != "on" {
		t.Fatal("setting not stored")
	}
	db.PutSettings(ctx, map[string]*string{"armed": nil})
	if _, ok, _ := db.Setting(ctx, "armed"); ok {
		t.Fatal("setting not deleted")
	}

	seedNode(t, db, "node-00000001")
	if err := db.SetNodeKeyHash(ctx, "node-00000001", []byte("new")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.NodeIDByKeyHash(ctx, []byte("node-00000001")); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("old key hash still resolves")
	}
	if id, _ := db.NodeIDByKeyHash(ctx, []byte("new")); id != "node-00000001" {
		t.Fatal("new key hash not resolvable")
	}
	if err := db.DeleteNode(ctx, "node-00000009"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("delete unknown node: %v", err)
	}
}

func TestStatusHistory(t *testing.T) {
	db, _ := openTest(t)
	ctx := context.Background()
	seedNode(t, db, "node-00000001")
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	hb := t0
	for i, st := range []domain.SensorStatus{"online", "offline", "online"} {
		at := t0.Add(time.Duration(i) * time.Hour)
		if err := db.SaveSensorLiveness(ctx, "node-00000001", "ts-sensor-a", SensorLiveness{Status: st, StatusChanged: true, LastHeartbeatAt: &hb, EverOnline: true}, at); err != nil {
			t.Fatal(err)
		}
	}
	h, err := db.StatusHistory(ctx, t0.Add(90*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 2 || h[0].Status != "offline" || h[1].Status != "online" {
		t.Fatalf("history %+v", h)
	}
	s, _ := db.Sensor(ctx, "node-00000001", "ts-sensor-a")
	if s.Status != "online" || !s.EverOnline {
		t.Fatalf("sensor %+v", s)
	}
	if n, _ := db.PurgeStatusHistory(ctx, t0.Add(30*time.Minute)); n != 1 {
		t.Fatalf("purged %d", n)
	}
}

func TestAdminCompareAndSwap(t *testing.T) {
	db, _ := openTest(t)
	ctx := context.Background()
	if err := db.CreateAdmin(ctx, "h", nil); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateAdmin(ctx, "h2", nil); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second admin: %v", err)
	}
	for _, c := range []struct {
		step int64
		ok   bool
	}{{5, true}, {5, false}, {4, false}, {6, true}} {
		if ok, err := db.AdvanceMFAStep(ctx, c.step); err != nil || ok != c.ok {
			t.Fatalf("step %d: %v %v", c.step, ok, err)
		}
	}
	db.ReplaceRecoveryCodes(ctx, nil, []string{"a", "b"})
	if ok, _ := db.ReplaceRecoveryCodes(ctx, []string{"a", "b"}, []string{"b"}); !ok {
		t.Fatal("CAS with current value failed")
	}
	if ok, _ := db.ReplaceRecoveryCodes(ctx, []string{"a", "b"}, []string{"b"}); ok {
		t.Fatal("CAS with stale value succeeded")
	}
}

func TestMigrationV1ToCurrentKeepsData(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ts.db")
	db, err := Open(ctx, path, Options{Migrations: migrations[:1]})
	if err != nil {
		t.Fatal(err)
	}
	seedNode(t, db, "node-00000001")
	now := time.Now().UTC().Truncate(time.Millisecond)
	preRows := []struct {
		id  string
		src string
	}{
		{"e-v4", "203.0.113.9:51234"},
		{"e-v6", "[2001:db8::1%eth0]:443"},
		{"e-map", "[::ffff:192.168.65.1]:50000"},
		{"e-drill", "Fire drill"},
		{"e-local", "local"},
		{"e-other", "scanner.example.com"},
	}
	for i, r := range preRows {
		if _, err := db.sql.ExecContext(ctx, `INSERT INTO events (event_id, node_id, sensor_id, trigger, severity, occurred_at,
			received_at, source, target, details) VALUES (?, 'node-00000001', 'ts-sensor-a', 'tcp_connection', 'high', ?, ?, ?, 'SSH', '{}')`,
			r.id, ms(now), ms(now.Add(time.Duration(i)*time.Second)), r.src); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	db, err = Open(ctx, path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if v, _ := db.schemaVersion(ctx); v != SchemaVersion() {
		t.Fatalf("schema v%d", v)
	}
	if snaps, _ := filepath.Glob(path + ".pre-v*.bak"); len(snaps) != 1 {
		t.Fatalf("snapshots %v", snaps)
	}
	if _, err := db.Node(ctx, "node-00000001"); err != nil {
		t.Fatal("data lost across migration")
	}
	if err := db.PutCachedManifest(ctx, CachedManifest{Name: "x", Version: "1.0.0", Manifest: []byte("{}"), FetchedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if c, _ := db.CachedManifests(ctx); len(c) != 1 || c[0].Verified {
		t.Fatalf("%+v", c)
	}

	evs, err := db.Events(ctx, EventFilter{Limit: 10})
	if err != nil || len(evs) != len(preRows) {
		t.Fatalf("backfilled events = %d, err = %v", len(evs), err)
	}
	byID := map[string]domain.Event{}
	for _, e := range evs {
		byID[e.EventID] = e
	}
	if e := byID["e-v4"]; e.SourceIP != "203.0.113.9" || e.SourcePort == nil || *e.SourcePort != 51234 || e.SourceKind != domain.SourceKindIP {
		t.Fatalf("e-v4 backfill = %+v", e)
	}
	if e := byID["e-v6"]; e.SourceIP != "2001:db8::1" || e.SourcePort == nil || *e.SourcePort != 443 || e.SourceKind != domain.SourceKindIP {
		t.Fatalf("e-v6 backfill = %+v", e)
	}
	if e := byID["e-map"]; e.SourceIP != "192.168.65.1" || e.SourcePort == nil || *e.SourcePort != 50000 || e.SourceKind != domain.SourceKindIP || len(e.Labels) != 1 || e.Labels[0] != "host_local" {
		t.Fatalf("e-map backfill = %+v", e)
	}
	if e := byID["e-drill"]; e.SourceIP != "" || e.SourcePort != nil || e.SourceKind != domain.SourceKindDrill {
		t.Fatalf("e-drill backfill = %+v", e)
	}
	if e := byID["e-local"]; e.SourceIP != "" || e.SourcePort != nil || e.SourceKind != domain.SourceKindLocal {
		t.Fatalf("e-local backfill = %+v", e)
	}
	if e := byID["e-other"]; e.SourceIP != "" || e.SourcePort != nil || e.SourceKind != domain.SourceKindOther {
		t.Fatalf("e-other backfill = %+v", e)
	}
}

func TestBeaconHoneytokenStoresAndFactoryReset(t *testing.T) {
	db, _ := openTest(t)
	ctx := context.Background()
	now := time.Now()
	if err := db.InsertBeacon(ctx, ported.Beacon{ID: "b1", Token: "tok", Type: "dns", Name: "n", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if b, _ := db.BeaconByToken(ctx, "tok"); b == nil || b.ID != "b1" {
		t.Fatal("beacon lookup")
	}
	if b, err := db.BeaconByToken(ctx, "nope"); b != nil || err != nil {
		t.Fatal("unknown token must be nil, nil")
	}
	db.IncrementBeaconUse(ctx, "b1", now)
	if l, _ := db.ListBeacons(ctx); len(l) != 1 || l[0].UseCount != 1 || l[0].LastUsedAt == nil {
		t.Fatalf("%+v", l)
	}
	db.InsertHoneytoken(ctx, ported.Honeytoken{ID: "h1", Username: "svc", Secret: "s", PlantedNodeID: "node-00000001", PlantedSensorID: "ts-sensor-f", CreatedAt: now})
	if err := db.InsertHoneytoken(ctx, ported.Honeytoken{ID: "h2", Username: "svc", Secret: "s", PlantedNodeID: "node-00000001", PlantedSensorID: "ts-sensor-f", CreatedAt: now}); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("two tokens for one sensor")
	}
	if h, _ := db.HoneytokenForSensor(ctx, "node-00000001", "ts-sensor-f"); h == nil || h.Status != "active" {
		t.Fatal("honeytoken lookup")
	}

	seedNode(t, db, "node-00000001")
	db.InsertEvent(ctx, &domain.Event{EventID: "e", NodeID: "node-00000001", SensorID: "ts-sensor-a", Trigger: "x", Severity: "critical",
		OccurredAt: now, ReceivedAt: now, Source: "s", Target: "t", Details: []byte("{}")})
	v := "x"
	db.PutSettings(ctx, map[string]*string{"public_endpoint": &v})
	db.CreateAdmin(ctx, "h", nil)

	sev, _ := db.SeverityCounts(ctx, now.Add(-time.Hour), false)
	total, unread, recent, crit, _ := db.EventCounts(ctx, now.Add(-time.Hour), false)
	if sev["critical"] != 1 || sev["low"] != 0 || total != 1 || unread != 1 || recent != 1 || crit != 1 {
		t.Fatalf("%v %d %d %d %d", sev, total, unread, recent, crit)
	}
	vel, _ := db.Velocity(ctx, now.Add(-time.Hour), time.Hour, false)
	if len(vel) != 1 {
		t.Fatalf("%v", vel)
	}

	if err := db.FactoryReset(ctx, false); err != nil {
		t.Fatal(err)
	}
	if ok, _ := db.AdminExists(ctx); ok {
		t.Fatal("admin kept")
	}
	if n, _ := db.Nodes(ctx); len(n) != 0 {
		t.Fatal("nodes kept")
	}
	if e, _ := db.Events(ctx, EventFilter{}); len(e) != 0 {
		t.Fatal("events kept")
	}
	if s, _ := db.Settings(ctx); len(s) != 0 {
		t.Fatal("settings kept")
	}
	if l, _ := db.ListBeacons(ctx); len(l) != 0 {
		t.Fatal("beacons kept")
	}
	if l, _ := db.ListHoneytokens(ctx); len(l) != 1 {
		t.Fatal("honeytokens must survive a reset without purge")
	}
	db.FactoryReset(ctx, true)
	if l, _ := db.ListHoneytokens(ctx); len(l) != 0 {
		t.Fatal("honeytokens not purged")
	}
}

func TestSensorSilenceAndNodeLiveness(t *testing.T) {
	db, _ := openTest(t)
	ctx := context.Background()
	seedNode(t, db, "node-00000001")
	now := time.Now().UTC().Truncate(time.Millisecond)
	until := now.Add(2 * time.Hour)

	if err := db.SetSensorSilence(ctx, "node-00000001", "ts-sensor-a", true, "Planned maintenance", &until); err != nil {
		t.Fatal(err)
	}
	s, err := db.Sensor(ctx, "node-00000001", "ts-sensor-a")
	if err != nil || !s.Silenced || s.SilencedReason != "Planned maintenance" || s.SilencedUntil == nil || !s.SilencedUntil.Equal(until) {
		t.Fatalf("silenced sensor: %+v err=%v", s, err)
	}
	if err := db.SetSensorSilence(ctx, "node-00000001", "ts-sensor-a", false, "", nil); err != nil {
		t.Fatal(err)
	}
	s, _ = db.Sensor(ctx, "node-00000001", "ts-sensor-a")
	if s.Silenced || s.SilencedReason != "" || s.SilencedUntil != nil {
		t.Fatalf("unsilenced sensor: %+v", s)
	}

	if err := db.SaveNodeLiveness(ctx, "node-00000001", NodeLiveness{
		EverOnline:       true,
		OfflineAlertedAt: &now,
		DriftSince:       &now,
		DriftAlertedAt:   &now,
	}); err != nil {
		t.Fatal(err)
	}
	n2, err := db.Node(ctx, "node-00000001")
	if err != nil || !n2.EverOnline || n2.OfflineAlertedAt == nil || n2.DriftSince == nil || n2.DriftAlertedAt == nil {
		t.Fatalf("node liveness: %+v err=%v", n2, err)
	}
	// SetNodeRevisions clears drift state when desired and applied match.
	if err := db.SetNodeRevisions(ctx, "node-00000001", "rev_11112222", "rev_11112222"); err != nil {
		t.Fatal(err)
	}
	n3, _ := db.Node(ctx, "node-00000001")
	if n3.DriftSince != nil || n3.DriftAlertedAt != nil {
		t.Fatalf("drift state not cleared on revision sync: %+v", n3)
	}
}
