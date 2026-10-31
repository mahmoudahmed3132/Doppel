// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

package sensor

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

var uuidV7RE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestUUIDv7FormatAndOrder(t *testing.T) {
	fixed := time.UnixMilli(1_790_000_000_000)
	g := newUUIDGen(func() time.Time { return fixed })
	prev := ""
	for i := 0; i < 10000; i++ {
		id := g.next()
		if !uuidV7RE.MatchString(id) {
			t.Fatalf("not a v7 uuid: %s", id)
		}
		if id <= prev {
			t.Fatalf("not monotonic: %s after %s", id, prev)
		}
		prev = id
	}
}

func TestFieldsKeepOrder(t *testing.T) {
	b, err := encodeDetails(Fields{F("z", 1), F("a", "x"), F("m", true), F("a", "y")})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), `{"z":1,"a":"y","m":true}`; got != want {
		t.Fatalf("got %s want %s", got, want)
	}
	b, _ = encodeDetails(nil)
	if string(b) != "{}" {
		t.Fatalf("nil details: %s", b)
	}
}

func TestLoadConfig(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	if _, err := LoadConfig(env(nil)); err == nil {
		t.Fatal("empty env accepted")
	}
	_, err := LoadConfig(env(map[string]string{EnvHubEndpoint: "https://hub"}))
	if err == nil || !strings.Contains(err.Error(), EnvNodeKey) || !strings.Contains(err.Error(), EnvSensorID) {
		t.Fatalf("missing key/id not reported: %v", err)
	}
	// Test mode needs only the endpoint.
	c, err := LoadConfig(env(map[string]string{EnvHubEndpoint: "https://hub/", EnvTestMode: "true"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.SensorID != testModeSensorID || c.HubEndpoint.String() != "https://hub" {
		t.Fatalf("unexpected config %+v", c)
	}
	if _, err := LoadConfig(env(map[string]string{EnvHubEndpoint: "ftp://hub", EnvTestMode: "true"})); err == nil {
		t.Fatal("ftp endpoint accepted")
	}
	if _, err := LoadConfig(env(map[string]string{EnvHubEndpoint: "https://u:p@hub", EnvTestMode: "true"})); err == nil {
		t.Fatal("credentials in endpoint accepted")
	}
	if _, err := LoadConfig(env(map[string]string{EnvHubEndpoint: "https://hub", EnvTestMode: "true", EnvDefaultSeverity: "urgent"})); err == nil {
		t.Fatal("bad severity accepted")
	}
	c, _ = LoadConfig(env(map[string]string{EnvHubEndpoint: "https://hub", EnvTestMode: "true", "TS_PORTS": "22", EnvNodeKey: "k"}))
	if v, ok := c.Setting("TS_PORTS"); !ok || v != "22" {
		t.Fatal("setting not readable")
	}
	if _, ok := c.Setting(EnvNodeKey); ok {
		t.Fatal("reserved key exposed through Setting")
	}
}

func TestRingDropsOldest(t *testing.T) {
	r := newRing(3)
	for i := 0; i < 5; i++ {
		r.push(wireEvent{Trigger: string(rune('a' + i))})
	}
	got := r.pop(10)
	if len(got) != 3 || got[0].Trigger != "c" || got[2].Trigger != "e" {
		t.Fatalf("unexpected contents %+v", got)
	}
	if d := r.takeDropped(); d != 2 {
		t.Fatalf("dropped=%d", d)
	}
	if d := r.takeDropped(); d != 0 {
		t.Fatalf("dropped not reset: %d", d)
	}
}

// mockHub records requests and answers events with a programmable status.
type mockHub struct {
	t  *testing.T
	mu sync.Mutex

	eventStatus []int // consumed per events request; empty = 200
	batches     [][]wireEvent
	heartbeats  []heartbeatBody
	stops       []stoppingBody
	auth        []string
	srv         *httptest.Server
}

func newMockHub(t *testing.T) *mockHub {
	h := &mockHub{t: t}
	h.srv = httptest.NewServer(http.HandlerFunc(h.serve))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *mockHub) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.auth = append(h.auth, r.Header.Get("Authorization"))
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case pathEvents:
		status := 200
		if len(h.eventStatus) > 0 {
			status, h.eventStatus = h.eventStatus[0], h.eventStatus[1:]
		}
		var b eventBatch
		if err := json.Unmarshal(body, &b); err != nil {
			h.t.Errorf("bad events body: %v", err)
		}
		if status != 200 {
			w.WriteHeader(status)
			io.WriteString(w, `{"ok":false,"error":"test","message":"test"}`)
			return
		}
		h.batches = append(h.batches, b.Events)
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "accepted": len(b.Events), "duplicates": 0, "rejected": []any{}})
	case pathHeartbeats:
		var hb heartbeatBody
		json.Unmarshal(body, &hb)
		h.heartbeats = append(h.heartbeats, hb)
		io.WriteString(w, `{"ok":true}`)
	case pathStopping:
		var sb stoppingBody
		json.Unmarshal(body, &sb)
		h.stops = append(h.stops, sb)
		io.WriteString(w, `{"ok":true}`)
	default:
		w.WriteHeader(404)
	}
}

func (h *mockHub) events() []wireEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []wireEvent
	for _, b := range h.batches {
		out = append(out, b...)
	}
	return out
}

func (h *mockHub) env(extra map[string]string) func(string) string {
	m := map[string]string{
		EnvHubEndpoint:    h.srv.URL,
		EnvNodeKey:        "tsk_test",
		EnvSensorID:       "ts-sensor-demo",
		EnvConfigRevision: "rev_0000abcd",
	}
	for k, v := range extra {
		m[k] = v
	}
	return func(k string) string { return m[k] }
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

var drill = Drill{Trigger: "demo_touched", Target: "demo", Details: Fields{F("drill", true)}}

func TestTestModeSuccessAndFailure(t *testing.T) {
	h := newMockHub(t)
	spec := Spec{Drill: drill}
	code := Run(context.Background(), spec, Options{Getenv: h.env(map[string]string{EnvTestMode: "true"}), Logger: quietLogger()})
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	ev := h.events()
	if len(ev) != 1 || ev[0].Source != DrillSource || ev[0].Trigger != "demo_touched" || ev[0].Severity != SeverityMedium {
		t.Fatalf("unexpected drill event %+v", ev)
	}
	if !uuidV7RE.MatchString(ev[0].EventID) {
		t.Fatalf("bad event id %s", ev[0].EventID)
	}
	if _, err := time.Parse(time.RFC3339Nano, ev[0].OccurredAt); err != nil {
		t.Fatalf("bad occurred_at: %v", err)
	}

	h.eventStatus = []int{403}
	code = Run(context.Background(), spec, Options{Getenv: h.env(map[string]string{EnvTestMode: "true"}), Logger: quietLogger()})
	if code != 1 {
		t.Fatalf("expected failure exit, got %d", code)
	}
}

func TestMissingConfigExitsNonZero(t *testing.T) {
	code := Run(context.Background(), Spec{Drill: drill, Run: func(context.Context, *Sensor) error { return nil }},
		Options{Getenv: func(string) string { return "" }, Logger: quietLogger()})
	if code == 0 {
		t.Fatal("expected non-zero exit")
	}
}

func fastOpts(env func(string) string, sigs chan os.Signal) Options {
	return Options{
		Getenv:            env,
		Signals:           sigs,
		Logger:            quietLogger(),
		BatchDelay:        20 * time.Millisecond,
		HeartbeatInterval: 50 * time.Millisecond,
		BackoffBase:       5 * time.Millisecond,
		BackoffCap:        20 * time.Millisecond,
		FlushTimeout:      2 * time.Second,
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestServiceLifecycle(t *testing.T) {
	h := newMockHub(t)
	h.eventStatus = []int{500, 503} // first two deliveries fail transiently
	sigs := make(chan os.Signal, 4)

	spec := Spec{
		Drill: drill,
		Run: func(ctx context.Context, s *Sensor) error {
			for i := 0; i < 150; i++ {
				s.ReportSeverity(SeverityHigh, "tcp_connection", "10.0.0.5:4444", "SSH (port 22)", Map{"i": i})
			}
			<-ctx.Done()
			// Events reported during shutdown are still flushed.
			s.Report("late_event", "10.0.0.5", "x", nil)
			return nil
		},
	}
	done := make(chan int, 1)
	go func() { done <- Run(context.Background(), spec, fastOpts(h.env(nil), sigs)) }()

	waitFor(t, func() bool { return len(h.events()) == 150 })
	sigs <- syscall.SIGUSR1
	waitFor(t, func() bool { return len(h.events()) == 151 })
	sigs <- syscall.SIGTERM

	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sensor did not stop")
	}

	ev := h.events()
	if len(ev) != 152 {
		t.Fatalf("got %d events", len(ev))
	}
	if ev[150].Source != DrillSource || ev[151].Trigger != "late_event" {
		t.Fatalf("unexpected tail %+v %+v", ev[150], ev[151])
	}
	seen := map[string]bool{}
	for _, e := range ev {
		if seen[e.EventID] {
			t.Fatalf("duplicate event id %s", e.EventID)
		}
		seen[e.EventID] = true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, b := range h.batches {
		if len(b) > 100 {
			t.Fatalf("batch of %d", len(b))
		}
	}
	if len(h.heartbeats) == 0 || h.heartbeats[0].ConfigRevision != "rev_0000abcd" || h.heartbeats[0].SDKVersion != SDKVersion {
		t.Fatalf("heartbeats %+v", h.heartbeats)
	}
	if len(h.stops) != 1 || h.stops[0].Reason != "received SIGTERM" {
		t.Fatalf("stop notices %+v", h.stops)
	}
	for _, a := range h.auth {
		if a != "Bearer tsk_test" {
			t.Fatalf("bad auth header %q", a)
		}
	}
}

func TestNonRetryableDroppedAndReported(t *testing.T) {
	h := newMockHub(t)
	h.eventStatus = []int{400}
	sigs := make(chan os.Signal, 1)
	spec := Spec{Drill: drill, Run: func(ctx context.Context, s *Sensor) error {
		s.Report("x", "1.2.3.4", "t", nil)
		<-ctx.Done()
		return nil
	}}
	opts := fastOpts(h.env(nil), sigs)
	done := make(chan int, 1)
	go func() { done <- Run(context.Background(), spec, opts) }()

	waitFor(t, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		for _, hb := range h.heartbeats {
			if hb.DroppedEvents == 1 {
				return true
			}
		}
		return false
	})
	sigs <- syscall.SIGINT
	<-done
	if n := len(h.events()); n != 0 {
		t.Fatalf("400 batch should not be retried, got %d delivered", n)
	}
}

func TestBodyFailureExitsOne(t *testing.T) {
	h := newMockHub(t)
	spec := Spec{Drill: drill, Run: func(context.Context, *Sensor) error { return io.ErrUnexpectedEOF }}
	if code := Run(context.Background(), spec, fastOpts(h.env(nil), make(chan os.Signal))); code != 1 {
		t.Fatalf("exit %d", code)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.stops) != 1 || !strings.HasPrefix(h.stops[0].Reason, "sensor failed") {
		t.Fatalf("stops %+v", h.stops)
	}
}

func TestBackoffBounds(t *testing.T) {
	s := &Sensor{opts: Options{BackoffBase: time.Second, BackoffCap: 60 * time.Second}}
	for attempt := 1; attempt <= 40; attempt++ {
		d := s.backoff(attempt)
		if d < 500*time.Millisecond || d > 60*time.Second {
			t.Fatalf("attempt %d: %v out of bounds", attempt, d)
		}
	}
}
