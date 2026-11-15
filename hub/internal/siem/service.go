// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/siem/syslog"
)

// Delivery defaults (§6.9).
const (
	DefaultQueueSize   = 5000
	DefaultMaxAttempts = 10
	switchAuditTimeout = 10 * time.Second
)

// Service is the SIEM output. Enqueue never blocks.
type Service struct {
	Renderer ported.ECSRenderer       // nil: ECS unavailable
	HTTP     ported.HTTPSIEMTransport // nil: elastic/logscale unavailable
	PEN      int
	CABundle string
	Log      *slog.Logger

	QueueSize   int
	MaxAttempts int
	BackoffBase time.Duration
	BackoffCap  time.Duration
	// ReconnectGap is the minimum time between stream reconnects (default 2 s).
	ReconnectGap time.Duration
	// SwitchAuditTimeout bounds delivery of the pre-switch audit record to
	// the previous destination (default 10 s).
	SwitchAuditTimeout time.Duration

	mu       sync.Mutex
	queue    []domain.Record
	cfg      Config
	tr       Transport
	notify   chan struct{}
	control  chan *switchReq
	dropped  atomic.Uint64
	inflight atomic.Int32 // records popped but not yet finished
	done     chan struct{}
	cancel   context.CancelFunc
}

type switchReq struct {
	cfg      Config
	tr       Transport
	preAudit *domain.AuditRecord
	done     chan struct{}
}

// Capabilities reports installed PORTED modules.
func (s *Service) Capabilities() Capabilities {
	return Capabilities{ECS: s.Renderer != nil, HTTP: s.HTTP != nil}
}

func (s *Service) defaults() {
	if s.QueueSize <= 0 {
		s.QueueSize = DefaultQueueSize
	}
	if s.MaxAttempts <= 0 {
		s.MaxAttempts = DefaultMaxAttempts
	}
	if s.BackoffBase <= 0 {
		s.BackoffBase = 500 * time.Millisecond
	}
	if s.BackoffCap <= 0 {
		s.BackoffCap = 30 * time.Second
	}
	if s.SwitchAuditTimeout <= 0 {
		s.SwitchAuditTimeout = switchAuditTimeout
	}
}

// Start begins delivery to cfg.
func (s *Service) Start(cfg Config) error {
	s.defaults()
	tr, err := s.transport(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.cfg, s.tr, s.cancel = cfg, tr, cancel
	s.notify = make(chan struct{}, 1)
	s.control = make(chan *switchReq)
	s.done = make(chan struct{})
	s.mu.Unlock()
	go s.run(ctx)
	return nil
}

// Config returns the active configuration.
func (s *Service) Config() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// Enqueue queues a record. With protocol none it is discarded; when the
// queue is full the new record is dropped and counted (§6.9).
func (s *Service) Enqueue(rec domain.Record) {
	s.mu.Lock()
	if s.cfg.Protocol == ProtoNone || s.cfg.Protocol == "" {
		s.mu.Unlock()
		return
	}
	if len(s.queue) >= s.QueueSize {
		s.mu.Unlock()
		if s.dropped.Add(1)%100 == 1 {
			s.Log.Warn("SIEM queue full; dropping new records", "dropped_total", s.dropped.Load())
		}
		return
	}
	s.queue = append(s.queue, rec)
	s.mu.Unlock()
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// Stats returns queue depth and the cumulative drop count.
func (s *Service) Stats() (depth int, dropped uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.queue), s.dropped.Load()
}

// Switch changes the destination. The pre-switch audit record is delivered
// to the previous destination first (bounded wait); queued records then go
// to the new one. The caller's own post-request audit reaches the new
// destination through the queue.
func (s *Service) Switch(ctx context.Context, cfg Config, preAudit *domain.AuditRecord) error {
	tr, err := s.transport(cfg)
	if err != nil {
		return err
	}
	req := &switchReq{cfg: cfg, tr: tr, preAudit: preAudit, done: make(chan struct{})}
	select {
	case s.control <- req:
	case <-ctx.Done():
		if tr != nil {
			tr.Close()
		}
		return ctx.Err()
	}
	select {
	case <-req.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) transport(c Config) (Transport, error) {
	switch c.Protocol {
	case ProtoNone, "":
		return nil, nil
	case ProtoTCP, ProtoUDP, ProtoTLS:
		t, err := newStream(c, s.CABundle)
		if err == nil && s.ReconnectGap > 0 {
			t.gap = s.ReconnectGap
		}
		return t, err
	case ProtoElastic, ProtoLogScale:
		if s.HTTP == nil {
			return nil, fmt.Errorf("%s transport not installed", c.Protocol)
		}
		return &httpTransport{t: s.HTTP, proto: c.Protocol, addr: c.Address, token: c.Token}, nil
	}
	return nil, fmt.Errorf("unknown protocol %q", c.Protocol)
}

// httpTransport adapts the PORTED HTTP transport.
type httpTransport struct {
	t                  ported.HTTPSIEMTransport
	proto, addr, token string
}

func (h *httpTransport) Send(ctx context.Context, doc []byte) error {
	outcome, err := h.t.Send(ctx, h.proto, h.addr, h.token, doc)
	switch outcome {
	case ported.SendSuccess:
		return nil
	case ported.SendTerminal:
		if err == nil {
			err = errors.New("rejected by the SIEM")
		}
		return terminal(err)
	default:
		if err == nil {
			err = errors.New("transient failure")
		}
		return transient(err)
	}
}

func (h *httpTransport) Close() error { return nil }

// Render produces the wire bytes of rec for cfg.
func (s *Service) Render(cfg Config, rec domain.Record) ([]byte, error) {
	if cfg.Format == FormatRFC5424 {
		return syslog.Format(rec, s.PEN)
	}
	if s.Renderer == nil {
		return nil, errors.New("ECS renderer not installed")
	}
	doc, err := s.Renderer.Render(rec)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func describe(rec domain.Record) []any {
	switch rec.Kind {
	case domain.RecordEvent:
		return []any{"kind", "event", "event_id", rec.Event.EventID}
	case domain.RecordAudit:
		return []any{"kind", "audit", "action", rec.Audit.Action}
	case domain.RecordHoneytoken:
		return []any{"kind", "honeytoken", "honeytoken_id", rec.Honeytoken.HoneytokenID}
	}
	return []any{"kind", "heartbeat"}
}

func (s *Service) pop() (domain.Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.queue) == 0 {
		return domain.Record{}, false
	}
	rec := s.queue[0]
	s.queue[0] = domain.Record{}
	s.queue = s.queue[1:]
	return rec, true
}

func (s *Service) pushFront(rec domain.Record) {
	s.mu.Lock()
	s.queue = append([]domain.Record{rec}, s.queue...)
	s.mu.Unlock()
}

func (s *Service) run(ctx context.Context) {
	defer close(s.done)
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-s.control:
			s.applySwitch(ctx, req)
			continue
		default:
		}
		rec, ok := s.pop()
		if !ok {
			select {
			case <-ctx.Done():
				return
			case req := <-s.control:
				s.applySwitch(ctx, req)
			case <-s.notify:
			}
			continue
		}
		s.inflight.Add(1)
		req := s.deliver(ctx, rec)
		s.inflight.Add(-1)
		if req != nil {
			// A switch interrupted the retries: the record goes to the
			// new destination.
			s.pushFront(rec)
			s.applySwitch(ctx, req)
		}
	}
}

// deliver sends rec with retries. It returns a pending switch request if
// one arrived while waiting to retry.
func (s *Service) deliver(ctx context.Context, rec domain.Record) *switchReq {
	s.mu.Lock()
	cfg, tr := s.cfg, s.tr
	s.mu.Unlock()
	if tr == nil {
		return nil
	}
	line, err := s.Render(cfg, rec)
	if err != nil {
		s.Log.Error("SIEM record could not be rendered; dropped", append(describe(rec), "error", err.Error())...)
		return nil
	}
	for attempt := 1; ; attempt++ {
		err := tr.Send(ctx, line)
		if err == nil {
			return nil
		}
		if IsTerminal(err) {
			s.Log.Error("SIEM rejected record; dropped", append(describe(rec), "error", err.Error())...)
			return nil
		}
		if attempt >= s.MaxAttempts {
			s.Log.Error("SIEM record undeliverable after retries; dropped", append(describe(rec), "attempts", attempt, "error", err.Error())...)
			return nil
		}
		select {
		case <-ctx.Done():
			s.pushFront(rec)
			return nil
		case req := <-s.control:
			return req
		case <-time.After(s.backoff(attempt)):
		}
	}
}

func (s *Service) backoff(attempt int) time.Duration {
	d := s.BackoffBase << (attempt - 1)
	if d <= 0 || d > s.BackoffCap {
		d = s.BackoffCap
	}
	half := d / 2
	return half + rand.N(half+1)
}

func (s *Service) applySwitch(ctx context.Context, req *switchReq) {
	defer close(req.done)
	s.mu.Lock()
	oldCfg, oldTr := s.cfg, s.tr
	s.mu.Unlock()
	if oldTr != nil && req.preAudit != nil {
		actx, cancel := context.WithTimeout(ctx, s.SwitchAuditTimeout)
		if err := s.sendNow(actx, oldCfg, oldTr, domain.Record{Kind: domain.RecordAudit, Audit: req.preAudit}); err != nil {
			s.Log.Error("audit of SIEM output change not delivered to the previous destination", "error", err.Error())
		}
		cancel()
	}
	if oldTr != nil {
		oldTr.Close()
	}
	s.mu.Lock()
	s.cfg, s.tr = req.cfg, req.tr
	if req.cfg.Protocol == ProtoNone {
		s.queue = nil
	}
	s.mu.Unlock()
	s.Log.Info("SIEM output changed", "protocol", req.cfg.Protocol, "format", req.cfg.Format)
}

// sendNow delivers one record synchronously with retries until ctx ends.
func (s *Service) sendNow(ctx context.Context, cfg Config, tr Transport, rec domain.Record) error {
	line, err := s.Render(cfg, rec)
	if err != nil {
		return err
	}
	for attempt := 1; ; attempt++ {
		err := tr.Send(ctx, line)
		if err == nil || IsTerminal(err) || attempt >= s.MaxAttempts {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w (last error: %v)", ctx.Err(), err)
		case <-time.After(s.backoff(attempt)):
		}
	}
}

// Test sends a synthetic record to the active destination over a separate
// connection and reports the outcome.
func (s *Service) Test(ctx context.Context, rec domain.Record) error {
	cfg := s.Config()
	if cfg.Protocol == ProtoNone {
		return errors.New("no SIEM output configured")
	}
	tr, err := s.transport(cfg)
	if err != nil {
		return err
	}
	defer tr.Close()
	return s.sendNow(ctx, cfg, tr, rec)
}

// Shutdown flushes queued and in-flight records for at most the context
// deadline (§6.9: 5 s), then stops the worker.
func (s *Service) Shutdown(ctx context.Context) {
	if s.cancel == nil {
		return
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for flushing := true; flushing; {
		if depth, _ := s.Stats(); depth == 0 && s.inflight.Load() == 0 {
			break
		}
		select {
		case <-ctx.Done():
			depth, _ := s.Stats()
			s.Log.Warn("SIEM flush incomplete at shutdown", "records_lost", depth+int(s.inflight.Load()))
			flushing = false
		case <-ticker.C:
		}
	}
	s.cancel()
	<-s.done
	s.mu.Lock()
	if s.tr != nil {
		s.tr.Close()
	}
	s.mu.Unlock()
}

// DeliverNow sends one record synchronously to the active destination over
// a separate connection. With no output configured it succeeds (nothing to
// deliver). Used for audit records that must precede an action (§6.13).
func (s *Service) DeliverNow(ctx context.Context, rec domain.Record) error {
	if s.Config().Protocol == ProtoNone || s.Config().Protocol == "" {
		return nil
	}
	return s.Test(ctx, rec)
}
