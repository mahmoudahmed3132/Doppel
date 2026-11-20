// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ids"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ingest"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/liveness"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/nodekey"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ratelimit"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
	"github.com/mahmoudahmed3132/Doppel/sdk/go/sensor"
)

type hubFixture struct {
	srv  *httptest.Server
	db   *store.DB
	keyA string
	keyB string
	lim  *ratelimit.Keyed
	auth *nodekey.Authenticator
	h    *Ingest
}

func newHub(t *testing.T, rate float64, burst int) *hubFixture {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "ts.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	keyA, hashA := nodekey.Generate()
	keyB, hashB := nodekey.Generate()
	now := time.Now()
	db.CreateNode(ctx, &domain.Node{ID: "node-0000000a", Alias: "a", KeyHash: hashA, CreatedAt: now})
	db.CreateNode(ctx, &domain.Node{ID: "node-0000000b", Alias: "b", KeyHash: hashB, CreatedAt: now})
	db.CreateSensor(ctx, &domain.Sensor{NodeID: "node-0000000a", ID: "ts-sensor-demo", CatalogueName: "x", Version: "1", CreatedAt: now})
	db.CreateSensor(ctx, &domain.Sensor{NodeID: "node-0000000b", ID: "ts-sensor-other", CatalogueName: "x", Version: "1", CreatedAt: now})

	pipe := &ingest.Pipeline{Store: db, Log: log, Now: time.Now}
	live := &liveness.Service{Store: db, Raiser: pipe, Log: log, Now: time.Now, StartedAt: now}
	auth := nodekey.NewAuthenticator(db)
	lim := ratelimit.NewKeyed(rate, burst)
	h := &Ingest{Auth: auth, Limiter: lim, Store: db, Pipeline: pipe, Liveness: live,
		Version: Version{"truesignal-hub", "3.0.0", 3, Capabilities()}, Log: log, Now: time.Now}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &hubFixture{srv: srv, db: db, keyA: keyA, keyB: keyB, lim: lim, auth: auth, h: h}
}

func (f *hubFixture) post(t *testing.T, path, key, body string) (int, map[string]any, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+path, strings.NewReader(body))
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, resp.Header
}

func evJSON(sensorID, trigger string, extra string) string {
	return fmt.Sprintf(`{"event_id":%q,"sensor_id":%q,"trigger":%q,"severity":"high","occurred_at":%q,"source":"198.51.100.4","target":"SSH (port 22)","details":{"k":1}%s}`,
		ids.UUIDv7(time.Now()), sensorID, trigger, time.Now().Format(time.RFC3339), extra)
}

func TestVersion(t *testing.T) {
	f := newHub(t, 50, 200)
	resp, err := http.Get(f.srv.URL + "/v3/version")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if strings.TrimSpace(string(b)) != `{"product":"truesignal-hub","version":"3.0.0","contract":3,"capabilities":["event.drill"]}` {
		t.Fatalf("%s", b)
	}
}

func TestEventsBatchSemantics(t *testing.T) {
	f := newHub(t, 50, 200)
	dupe := evJSON("ts-sensor-demo", "ssh_login_attempt", "")
	batch := `{"events":[` + strings.Join([]string{
		dupe,
		`{"event_id":"x"}`, // invalid
		evJSON("ts-sensor-demo", "honeytoken_used", ""),
		evJSON("ts-sensor-other", "ssh_login_attempt", ""),
		evJSON("ts-sensor-demo", "x", `,"bogus":1`),
		dupe,
	}, ",") + `]}`
	code, out, _ := f.post(t, "/v3/ingest/events", f.keyA, batch)
	if code != 200 || out["accepted"] != 1.0 || out["duplicates"] != 1.0 {
		t.Fatalf("%d %v", code, out)
	}
	rej := out["rejected"].([]any)
	want := []string{"invalid_event_id", "reserved_trigger", "sensor_not_registered", "invalid_event"}
	if len(rej) != len(want) {
		t.Fatalf("rejected %v", rej)
	}
	for i, r := range rej {
		if r.(map[string]any)["error"] != want[i] {
			t.Fatalf("rejected[%d] = %v want %s", i, r, want[i])
		}
	}
	ev, _ := f.db.Events(context.Background(), store.EventFilter{})
	if len(ev) != 1 {
		t.Fatalf("stored %d events", len(ev))
	}
}

func TestEventsWholeBatchStatuses(t *testing.T) {
	f := newHub(t, 50, 200)
	code, out, _ := f.post(t, "/v3/ingest/events", f.keyA, `{"events":[`+evJSON("ts-sensor-demo", "sensor_stopped", "")+`]}`)
	if code != 403 || out["error"] != "reserved_trigger" {
		t.Fatalf("%d %v", code, out)
	}
	code, out, _ = f.post(t, "/v3/ingest/events", f.keyA, `{"events":[`+evJSON("ts-sensor-other", "x", "")+`]}`)
	if code != 404 || out["error"] != "sensor_not_registered" {
		t.Fatalf("%d %v", code, out)
	}
	code, out, _ = f.post(t, "/v3/ingest/events", f.keyA, `{"events":[],"extra":true}`)
	if code != 400 || out["error"] != "unknown_field" {
		t.Fatalf("%d %v", code, out)
	}
	code, _, _ = f.post(t, "/v3/ingest/events", f.keyA, `{"events":[]}`)
	if code != 400 {
		t.Fatal("empty batch accepted")
	}
	big := `{"events":[` + evJSON("ts-sensor-demo", "x", `,"pad":"`+strings.Repeat("a", 300<<10)+`"`) + `]}`
	code, out, _ = f.post(t, "/v3/ingest/events", f.keyA, big)
	if code != 413 {
		t.Fatalf("oversized body: %d %v", code, out)
	}
}

func TestAuthAndRotation(t *testing.T) {
	f := newHub(t, 50, 200)
	body := `{"events":[` + evJSON("ts-sensor-demo", "x", "") + `]}`
	if code, _, _ := f.post(t, "/v3/ingest/events", "", body); code != 401 {
		t.Fatal("no key accepted")
	}
	if code, _, _ := f.post(t, "/v3/ingest/events", "tsk_"+strings.Repeat("0", 64), body); code != 401 {
		t.Fatal("unknown key accepted")
	}
	if code, _, _ := f.post(t, "/v3/ingest/events", f.keyA, body); code != 200 {
		t.Fatal("valid key refused")
	}
	// Rotate: DB first, then cache invalidation; no restart.
	newKey, newHash := nodekey.Generate()
	f.db.SetNodeKeyHash(context.Background(), "node-0000000a", newHash)
	f.auth.Invalidate("node-0000000a")
	body = `{"events":[` + evJSON("ts-sensor-demo", "x", "") + `]}`
	if code, _, _ := f.post(t, "/v3/ingest/events", f.keyA, body); code != 401 {
		t.Fatal("old key still valid after rotation")
	}
	if code, _, _ := f.post(t, "/v3/ingest/events", newKey, body); code != 200 {
		t.Fatal("new key refused")
	}
	f.db.DeleteNode(context.Background(), "node-0000000a")
	f.auth.Invalidate("node-0000000a")
	if code, _, _ := f.post(t, "/v3/ingest/events", newKey, body); code != 401 {
		t.Fatal("deleted node's key still valid")
	}
}

func TestRateLimit(t *testing.T) {
	f := newHub(t, 1, 2)
	hb := `{"sensor_id":"ts-sensor-demo","config_revision":"rev_00000000","sdk_version":"3.0.0"}`
	for i := 0; i < 2; i++ {
		if code, out, _ := f.post(t, "/v3/ingest/heartbeats", f.keyA, hb); code != 200 {
			t.Fatalf("%d %v", code, out)
		}
	}
	code, out, hdr := f.post(t, "/v3/ingest/heartbeats", f.keyA, hb)
	if code != 429 || out["error"] != "rate_limited" || hdr.Get("Retry-After") == "" {
		t.Fatalf("%d %v %v", code, out, hdr)
	}
	// Per node: node B is unaffected.
	if code, _, _ := f.post(t, "/v3/ingest/heartbeats", f.keyB, strings.Replace(hb, "ts-sensor-demo", "ts-sensor-other", 1)); code != 200 {
		t.Fatal("rate limit not per node")
	}
}

// TestEventsOverloaded: when every ingest slot is busy past the admission
// wait, a batch is refused with 429 overloaded and Retry-After, nothing of
// it is stored, and heartbeats are not gated (liveness must not flap under
// event load). The batch is accepted once a slot frees (F-603).
func TestEventsOverloaded(t *testing.T) {
	f := newHub(t, 50, 200)
	f.h.Admission = ratelimit.NewGate(1, 0)
	hold, ok := f.h.Admission.Enter(context.Background())
	if !ok {
		t.Fatal("could not take the only slot")
	}
	batch := `{"events":[` + evJSON("ts-sensor-demo", "ssh_login_attempt", "") + `]}`
	code, out, hdr := f.post(t, "/v3/ingest/events", f.keyA, batch)
	if code != 429 || out["error"] != CodeOverloaded || hdr.Get("Retry-After") != "1" {
		t.Fatalf("%d %v %v", code, out, hdr)
	}
	if ev, _ := f.db.Events(context.Background(), store.EventFilter{}); len(ev) != 0 {
		t.Fatalf("refused batch stored %d events", len(ev))
	}
	hb := `{"sensor_id":"ts-sensor-demo","config_revision":"rev_00000000","sdk_version":"3.0.0"}`
	if code, out, _ := f.post(t, "/v3/ingest/heartbeats", f.keyA, hb); code != 200 {
		t.Fatalf("heartbeat gated by event admission: %d %v", code, out)
	}
	hold()
	if code, out, _ := f.post(t, "/v3/ingest/events", f.keyA, batch); code != 200 || out["accepted"] != 1.0 {
		t.Fatalf("retry after overload: %d %v", code, out)
	}
	if f.h.Admission.Refused() != 1 || f.h.Admission.InFlight() != 0 {
		t.Fatalf("refused %d in-flight %d", f.h.Admission.Refused(), f.h.Admission.InFlight())
	}
}

func TestHeartbeatAndStopping(t *testing.T) {
	f := newHub(t, 50, 200)
	ctx := context.Background()
	code, out, _ := f.post(t, "/v3/ingest/heartbeats", f.keyA, `{"sensor_id":"ts-sensor-demo","config_revision":"rev_00000000","sdk_version":"3.0.0","dropped_events":3}`)
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	s, _ := f.db.Sensor(ctx, "node-0000000a", "ts-sensor-demo")
	if s.Status != domain.StatusOnline || s.SDKVersion != "3.0.0" || s.DroppedEvents != 3 {
		t.Fatalf("%+v", s)
	}
	// dropped_events is a delta since the last acknowledged heartbeat; the
	// Hub keeps the cumulative count (F-603). Absent means zero.
	f.post(t, "/v3/ingest/heartbeats", f.keyA, `{"sensor_id":"ts-sensor-demo","config_revision":"rev_00000000","sdk_version":"3.0.0","dropped_events":4}`)
	f.post(t, "/v3/ingest/heartbeats", f.keyA, `{"sensor_id":"ts-sensor-demo","config_revision":"rev_00000000","sdk_version":"3.0.0"}`)
	if s, _ = f.db.Sensor(ctx, "node-0000000a", "ts-sensor-demo"); s.DroppedEvents != 7 {
		t.Fatalf("cumulative dropped_events = %d, want 7", s.DroppedEvents)
	}
	if code, out, _ := f.post(t, "/v3/ingest/heartbeats", f.keyA, `{"sensor_id":"ts-sensor-demo","config_revision":"","sdk_version":"","dropped_events":-1}`); code != 400 {
		t.Fatalf("negative dropped_events accepted: %d %v", code, out)
	}
	n, _ := f.db.Node(ctx, "node-0000000a")
	if n.LastSeenAt == nil {
		t.Fatal("node last-seen not updated")
	}
	if code, out, _ := f.post(t, "/v3/ingest/heartbeats", f.keyA, `{"sensor_id":"ts-sensor-other","config_revision":"","sdk_version":""}`); code != 404 || out["error"] != "sensor_not_registered" {
		t.Fatalf("%d %v", code, out)
	}
	if code, _, _ := f.post(t, "/v3/ingest/heartbeats", f.keyA, `{"sensor_id":"ts-sensor-demo","x":1}`); code != 400 {
		t.Fatal("unknown heartbeat field accepted")
	}
	code, _, _ = f.post(t, "/v3/ingest/stopping", f.keyA, `{"sensor_id":"ts-sensor-demo","reason":"`+strings.Repeat("r", 500)+`"}`)
	if code != 200 {
		t.Fatal("stop refused")
	}
	ev, _ := f.db.Events(ctx, store.EventFilter{})
	if len(ev) != 1 || ev[0].Trigger != domain.TriggerSensorStopped {
		t.Fatalf("%+v", ev)
	}
	var d map[string]string
	json.Unmarshal(ev[0].Details, &d)
	if len(d["reason"]) != 128 {
		t.Fatalf("reason not clamped: %d", len(d["reason"]))
	}
}

// TestSDKEndToEnd runs the real Go SDK against the real ingest stack.
func TestSDKEndToEnd(t *testing.T) {
	f := newHub(t, 50, 200)
	ctx := context.Background()
	env := map[string]string{
		sensor.EnvHubEndpoint: f.srv.URL, sensor.EnvNodeKey: f.keyA,
		sensor.EnvSensorID: "ts-sensor-demo", sensor.EnvConfigRevision: "rev_12345678",
	}
	getenv := func(k string) string { return env[k] }
	drill := sensor.Drill{Trigger: "demo_drill", Target: "demo"}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	legacyBefore := ingest.LegacyDrills()

	// Test mode.
	env[sensor.EnvTestMode] = "true"
	if code := sensor.Run(ctx, sensor.Spec{Drill: drill}, sensor.Options{Getenv: getenv, Logger: quiet}); code != 0 {
		t.Fatalf("test mode exit %d", code)
	}
	delete(env, sensor.EnvTestMode)

	// Service mode: events, fire drill, graceful stop.
	sigs := make(chan os.Signal, 2)
	done := make(chan int, 1)
	go func() {
		done <- sensor.Run(ctx, sensor.Spec{Drill: drill, Run: func(ctx context.Context, s *sensor.Sensor) error {
			for i := 0; i < 5; i++ {
				s.Report("tcp_connection", "192.0.2.1:4000", "port 22", sensor.Fields{sensor.F("i", i)})
			}
			<-ctx.Done()
			return nil
		}}, sensor.Options{Getenv: getenv, Signals: sigs, Logger: quiet, BatchDelay: 20 * time.Millisecond})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		ev, _ := f.db.Events(ctx, store.EventFilter{Trigger: "tcp_connection"})
		if len(ev) == 5 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("events not delivered")
		}
		time.Sleep(10 * time.Millisecond)
	}
	sigs <- syscall.SIGUSR1
	sigs <- syscall.SIGTERM
	if code := <-done; code != 0 {
		t.Fatalf("exit %d", code)
	}

	all, _ := f.db.Events(ctx, store.EventFilter{Limit: 100})
	counts := map[string]int{}
	for _, e := range all {
		counts[e.Trigger]++
		if e.Trigger == "demo_drill" && (e.Source != "Fire drill" || !e.Drill || e.Severity != domain.SeverityInfo) {
			t.Fatalf("drill %+v", e)
		}
		if e.Trigger == "tcp_connection" && e.Drill {
			t.Fatalf("real event stored as a drill: %+v", e)
		}
	}
	if counts["demo_drill"] != 2 || counts["tcp_connection"] != 5 || counts["sensor_stopped"] != 1 {
		t.Fatalf("counts %v", counts)
	}
	// The SDK feature-detected event.drill and sent the flag: the legacy
	// source shim was never needed (F-001).
	if n := ingest.LegacyDrills() - legacyBefore; n != 0 {
		t.Fatalf("legacy drill shim used %d times by the current SDK", n)
	}
	s, _ := f.db.Sensor(ctx, "node-0000000a", "ts-sensor-demo")
	if s.Status != domain.StatusOffline || !s.EverOnline {
		t.Fatalf("sensor %+v", s)
	}
}
