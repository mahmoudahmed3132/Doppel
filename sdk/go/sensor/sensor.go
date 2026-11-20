// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package sensor is the TrueSignal Go Sensor SDK (contract v3).
//
// A sensor program defines a Spec and calls Main. The SDK loads its
// configuration from TS_ environment variables, delivers events to the Hub
// through a bounded queue with batching and retries, sends heartbeats,
// handles SIGTERM/SIGINT (flush, stop notice, exit 0) and SIGUSR1 (fire
// drill), and implements test mode.
package sensor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mahmoudahmed3132/Doppel/sdk/go/envcompat"
)

// Drill is the synthetic event a sensor emits for fire drills and test mode.
// Its source is always "Fire drill".
type Drill struct {
	Trigger  string
	Target   string
	Severity Severity // empty = sensor default severity
	Details  Details
}

// DrillSource is the source of every synthetic event.
const DrillSource = "Fire drill"

// Spec describes a sensor program.
type Spec struct {
	// Drill is required: it is sent on SIGUSR1 and in test mode.
	Drill Drill
	// Run is the sensor body. It must return promptly once ctx is
	// cancelled. Returning a non-nil error before cancellation shuts the
	// sensor down with exit code 1. Run is not called in test mode.
	Run func(ctx context.Context, s *Sensor) error
}

// Reporter is the narrow interface consumed by add-on packages (such as the
// decoy helper) so they can be wired to the SDK without the SDK depending
// on them. *Sensor implements it.
type Reporter interface {
	ReportSeverity(sev Severity, trigger, source, target string, details Details)
	Setting(name string) (string, bool)
}

var _ Reporter = (*Sensor)(nil)

// Options tune the runtime. The zero value gives the contract defaults;
// non-zero fields exist mainly for tests.
type Options struct {
	Getenv  func(string) string // default os.Getenv
	Signals <-chan os.Signal    // default: OS signals
	Logger  *slog.Logger        // default: JSON on stderr

	QueueSize         int           // default 1000
	BatchSize         int           // default 100
	BatchDelay        time.Duration // default 1 s
	HeartbeatInterval time.Duration // default 30 s
	MaxAttempts       int           // default 7
	BackoffBase       time.Duration // default 1 s
	BackoffCap        time.Duration // default 60 s
	FlushTimeout      time.Duration // default 5 s
	TestModeTimeout   time.Duration // default 10 s
}

func (o *Options) withDefaults() {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	if o.Getenv == nil {
		// DOPPEL_* wins over TS_*; a used TS_* logs a deprecation (F-004).
		log := o.Logger
		o.Getenv = envcompat.OS(func(msg string) { log.Warn(msg) })
	}
	if o.QueueSize <= 0 {
		o.QueueSize = 1000
	}
	if o.BatchSize <= 0 || o.BatchSize > 100 {
		o.BatchSize = 100
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = 7
	}
	def(&o.BatchDelay, time.Second)
	def(&o.HeartbeatInterval, 30*time.Second)
	def(&o.BackoffBase, time.Second)
	def(&o.BackoffCap, 60*time.Second)
	def(&o.FlushTimeout, 5*time.Second)
	def(&o.TestModeTimeout, 10*time.Second)
}

// Sensor is the handle passed to Spec.Run.
type Sensor struct {
	cfg    *Config
	log    *slog.Logger
	opts   Options
	q      *ring
	client *hubClient
	ids    *uuidGen
	now    func() time.Time
}

// Main runs the sensor and exits the process with the resulting code.
func Main(spec Spec) {
	os.Exit(Run(context.Background(), spec, Options{}))
}

// Run runs the sensor until shutdown and returns the process exit code:
// 0 on graceful shutdown or test-mode success, 1 on failure, 2 on
// configuration errors.
func Run(ctx context.Context, spec Spec, opts Options) int {
	opts.withDefaults()
	log := opts.Logger

	if spec.Drill.Trigger == "" {
		log.Error("sensor spec has no fire-drill trigger")
		return 2
	}
	cfg, err := LoadConfig(opts.Getenv)
	if err != nil {
		log.Error("invalid sensor configuration", "error", err.Error())
		return 2
	}
	client, err := newHubClient(cfg)
	if err != nil {
		log.Error("invalid TLS configuration", "error", err.Error())
		return 2
	}
	s := &Sensor{
		cfg:    cfg,
		log:    log.With("sensor_id", cfg.SensorID),
		opts:   opts,
		q:      newRing(opts.QueueSize),
		client: client,
		ids:    newUUIDGen(nil),
		now:    time.Now,
	}
	if cfg.TestMode {
		return s.runTestMode(ctx, spec.Drill)
	}
	if spec.Run == nil {
		log.Error("sensor spec has no Run function")
		return 2
	}
	return s.runService(ctx, spec)
}

// Config returns the loaded SDK configuration.
func (s *Sensor) Config() *Config { return s.cfg }

// Logger returns the sensor's structured logger.
func (s *Sensor) Logger() *slog.Logger { return s.log }

// Setting returns a manifest-declared configuration value (TS_ variable).
func (s *Sensor) Setting(name string) (string, bool) { return s.cfg.Setting(name) }

// Report queues an event with the sensor's default severity.
func (s *Sensor) Report(trigger, source, target string, details Details) {
	s.ReportSeverity(s.cfg.DefaultSeverity, trigger, source, target, details)
}

// ReportSeverity queues an event with an explicit severity. It never
// blocks; when the queue is full the oldest event is dropped and counted.
func (s *Sensor) ReportSeverity(sev Severity, trigger, source, target string, details Details) {
	s.q.push(s.build(sev, trigger, source, target, details))
}

func (s *Sensor) build(sev Severity, trigger, source, target string, details Details) wireEvent {
	if !sev.Valid() {
		s.log.Warn("invalid severity, using default", "severity", string(sev))
		sev = s.cfg.DefaultSeverity
	}
	raw, err := encodeDetails(details)
	if err != nil {
		s.log.Warn("event details not encodable, sending empty details", "trigger", trigger, "error", err.Error())
		raw = []byte(`{"details_encode_error":true}`)
	}
	if len(raw) > MaxDetailsBytes {
		// The Hub would replace them with the same marker; dropping them here
		// keeps the queue's memory bounded (see MaxDetailsBytes).
		s.log.Warn("event details too large, sending marker", "trigger", trigger, "bytes", len(raw), "limit", MaxDetailsBytes)
		raw = []byte(`{"details_dropped":true}`)
	}
	return wireEvent{
		EventID:    s.ids.next(),
		SensorID:   s.cfg.SensorID,
		Trigger:    trigger,
		Severity:   sev,
		OccurredAt: s.now().UTC().Format(time.RFC3339Nano),
		Source:     clampField(source),
		Target:     clampField(target),
		Details:    raw,
	}
}

func (s *Sensor) drillEvent(d Drill) wireEvent {
	sev := d.Severity
	if sev == "" {
		sev = s.cfg.DefaultSeverity
	}
	return s.build(sev, d.Trigger, DrillSource, d.Target, d.Details)
}

func (s *Sensor) runTestMode(ctx context.Context, d Drill) int {
	ctx, cancel := context.WithTimeout(ctx, s.opts.TestModeTimeout)
	defer cancel()
	ev := s.drillEvent(d)
	var resp ingestResponse
	if err := s.client.post(ctx, pathEvents, eventBatch{Events: []wireEvent{ev}}, &resp); err != nil {
		s.log.Error("test mode: delivery failed", "error", err.Error())
		return 1
	}
	if resp.Accepted+resp.Duplicates != 1 {
		code := ""
		if len(resp.Rejected) > 0 {
			code = resp.Rejected[0].Error
		}
		s.log.Error("test mode: hub rejected the synthetic event", "error", code)
		return 1
	}
	s.log.Info("test mode: synthetic event acknowledged", "event_id", ev.EventID, "trigger", ev.Trigger)
	return 0
}

func (s *Sensor) runService(parent context.Context, spec Spec) int {
	sigs := s.opts.Signals
	if sigs == nil {
		ch, stop := notifySignals()
		defer stop()
		sigs = ch
	}

	sendCtx, cancelSend := context.WithCancel(context.WithoutCancel(parent))
	defer cancelSend()
	flush := make(chan struct{})
	senderDone := make(chan struct{})
	go func() {
		defer close(senderDone)
		s.runSender(sendCtx, flush)
	}()

	runCtx, cancelRun := context.WithCancel(parent)
	defer cancelRun()
	var hbWG sync.WaitGroup
	hbWG.Add(1)
	go func() {
		defer hbWG.Done()
		s.runHeartbeats(runCtx)
	}()

	runErr := make(chan error, 1)
	go func() { runErr <- spec.Run(runCtx, s) }()

	s.log.Info("sensor started", "sdk_version", SDKVersion, "config_revision", s.cfg.ConfigRevision)

	exitCode := 0
	var reason string
	bodyDone := false
loop:
	for {
		select {
		case sig := <-sigs:
			if isDrillSignal(sig) {
				s.q.push(s.drillEvent(spec.Drill))
				s.log.Info("fire drill triggered", "trigger", spec.Drill.Trigger)
				continue
			}
			reason = "received " + signalName(sig)
			break loop
		case err := <-runErr:
			bodyDone = true
			if err != nil && !errors.Is(err, context.Canceled) {
				reason = "sensor failed: " + err.Error()
				exitCode = 1
			} else {
				reason = "sensor finished"
			}
			break loop
		case <-parent.Done():
			reason = "context cancelled"
			break loop
		}
	}
	s.log.Info("sensor stopping", "reason", reason)

	deadline := time.Now().Add(s.opts.FlushTimeout)
	cancelRun()
	if !bodyDone {
		select {
		case <-runErr:
		case <-time.After(time.Until(deadline) / 2):
			s.log.Warn("sensor body did not stop in time")
		}
	}
	hbWG.Wait()

	// Flush: the sender drains the queue without batching delay until the
	// deadline, then the send context is cancelled.
	close(flush)
	select {
	case <-senderDone:
	case <-time.After(time.Until(deadline)):
		cancelSend()
		<-senderDone
	}
	if n := s.q.len(); n > 0 {
		s.log.Warn("events lost at shutdown", "count", n)
	}

	stopCtx, cancelStop := context.WithTimeout(context.WithoutCancel(parent), 2*time.Second)
	defer cancelStop()
	if err := s.client.post(stopCtx, pathStopping, stoppingBody{SensorID: s.cfg.SensorID, Reason: truncate(reason, 128)}, nil); err != nil {
		s.log.Warn("stop notice not delivered", "error", err.Error())
	}
	return exitCode
}

func (s *Sensor) runHeartbeats(ctx context.Context) {
	t := time.NewTicker(s.opts.HeartbeatInterval)
	defer t.Stop()
	for {
		s.heartbeat(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Sensor) heartbeat(ctx context.Context) {
	dropped := s.q.takeDropped()
	body := heartbeatBody{
		SensorID:       s.cfg.SensorID,
		ConfigRevision: s.cfg.ConfigRevision,
		SDKVersion:     SDKVersion,
		DroppedEvents:  dropped,
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	if err := s.client.post(ctx, pathHeartbeats, body, nil); err != nil {
		s.q.addDropped(dropped) // report again next time
		if ctx.Err() == nil {
			s.log.Warn("heartbeat failed", "error", err.Error())
		}
	}
}

// runSender batches queued events and delivers them until ctx ends. After
// flush is closed it drains the queue without waiting and returns.
func (s *Sensor) runSender(ctx context.Context, flush <-chan struct{}) {
	flushing := false
	for {
		if !flushing {
			// Wait for the first event, then up to BatchDelay for a full batch.
			for s.q.len() == 0 {
				select {
				case <-ctx.Done():
					return
				case <-flush:
					flushing = true
				case <-s.q.notify:
				}
				if flushing {
					break
				}
			}
			if !flushing {
				timer := time.NewTimer(s.opts.BatchDelay)
			fill:
				for s.q.len() < s.opts.BatchSize {
					select {
					case <-ctx.Done():
						timer.Stop()
						return
					case <-flush:
						flushing = true
						break fill
					case <-s.q.notify:
					case <-timer.C:
						break fill
					}
				}
				timer.Stop()
			}
		}
		batch := s.q.pop(s.opts.BatchSize)
		if len(batch) == 0 {
			if flushing {
				return
			}
			continue
		}
		s.deliver(ctx, batch)
		if ctx.Err() != nil {
			return
		}
	}
}

// deliver sends one batch with retries. Undeliverable events are counted as
// dropped.
func (s *Sensor) deliver(ctx context.Context, batch []wireEvent) {
	for attempt := 1; ; attempt++ {
		var resp ingestResponse
		err := s.client.post(ctx, pathEvents, eventBatch{Events: batch}, &resp)
		if err == nil {
			for _, r := range resp.Rejected {
				trig := ""
				if r.Index >= 0 && r.Index < len(batch) {
					trig = batch[r.Index].Trigger
				}
				s.log.Warn("hub rejected event", "index", r.Index, "trigger", trig, "error", r.Error)
			}
			return
		}
		if !retryable(err) {
			s.log.Error("event batch refused, dropping", "events", len(batch), "error", err.Error())
			s.q.addDropped(uint64(len(batch)))
			return
		}
		if attempt >= s.opts.MaxAttempts || ctx.Err() != nil {
			s.log.Error("event batch undeliverable, dropping", "events", len(batch), "attempts", attempt, "error", err.Error())
			s.q.addDropped(uint64(len(batch)))
			return
		}
		wait := s.backoff(attempt)
		var he *hubError
		if errors.As(err, &he) && he.RetryAfter > wait {
			wait = min(he.RetryAfter, s.opts.BackoffCap)
		}
		s.log.Warn("event delivery failed, retrying", "attempt", attempt, "wait", wait.String(), "error", err.Error())
		select {
		case <-ctx.Done():
			s.q.addDropped(uint64(len(batch)))
			return
		case <-time.After(wait):
		}
	}
}

// backoff returns an exponential delay with jitter in [d/2, d], d capped.
func (s *Sensor) backoff(attempt int) time.Duration {
	d := s.opts.BackoffBase << (attempt - 1)
	if d <= 0 || d > s.opts.BackoffCap {
		d = s.opts.BackoffCap
	}
	half := d / 2
	return half + rand.N(half+1)
}

// truncate cuts s to at most n bytes without leaving a partial UTF-8 sequence.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

// String renders a Drill for logs.
func (d Drill) String() string { return fmt.Sprintf("%s on %s", d.Trigger, d.Target) }
