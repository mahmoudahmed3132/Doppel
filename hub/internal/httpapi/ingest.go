// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ingest"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/nodekey"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ratelimit"
)

const (
	maxIngestBody  = 256 << 10
	maxBatchEvents = 100
	maxStopReason  = 128

	// IngestMaxInFlight and IngestAdmitWait bound Hub-wide concurrent event
	// batches (F-603). SQLite serialises writers on one connection, so more
	// concurrency only queues bodies in memory; a batch that cannot start
	// within the wait gets 429 overloaded and the SDK retries it.
	IngestMaxInFlight = 8
	IngestAdmitWait   = time.Second
	// overloadRetryAfter is the Retry-After (seconds) sent with 429 overloaded.
	overloadRetryAfter = 1
	overloadLogEvery   = 10 * time.Second
)

// Version information served at /v3/version.
type Version struct {
	Product  string `json:"product"`
	Version  string `json:"version"`
	Contract int    `json:"contract"`
}

// IngestStore is the persistence the ingest handlers need directly.
type IngestStore interface {
	SensorBelongsToNode(ctx context.Context, nodeID, id string) (bool, error)
	TouchNode(ctx context.Context, id string, at time.Time) error
}

// EventProcessor runs normalised events through the pipeline.
type EventProcessor interface {
	Process(ctx context.Context, ev *domain.Event) (ingest.Result, error)
}

// LivenessRecorder records heartbeats and stop notices.
type LivenessRecorder interface {
	Heartbeat(ctx context.Context, nodeID, sensorID, revision, sdkVersion string, dropped int64) error
	Stopped(ctx context.Context, nodeID, sensorID, reason string) error
}

// Ingest serves the sensor contract (§4).
type Ingest struct {
	Auth    *nodekey.Authenticator
	Limiter *ratelimit.Keyed
	// Admission bounds concurrent event batches Hub-wide; nil means
	// unbounded (tests only).
	Admission *ratelimit.Gate
	Store     IngestStore
	Pipeline  EventProcessor
	Liveness  LivenessRecorder
	Version   Version
	Log       *slog.Logger
	Now       func() time.Time

	lastOverloadLog atomic.Int64 // unix nanoseconds
	overloadLogged  atomic.Uint64
}

// Register mounts the handlers on mux.
func (h *Ingest) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v3/version", h.version)
	mux.HandleFunc("POST /v3/ingest/events", h.authenticated(h.events))
	mux.HandleFunc("POST /v3/ingest/heartbeats", h.authenticated(h.heartbeat))
	mux.HandleFunc("POST /v3/ingest/stopping", h.authenticated(h.stopping))
}

func (h *Ingest) version(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, h.Version)
}

type nodeHandler func(w http.ResponseWriter, r *http.Request, nodeID string)

// authenticated resolves the bearer node key and applies the per-node
// rate limit.
func (h *Ingest) authenticated(next nodeHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || key == "" {
			Fail(w, http.StatusUnauthorized, CodeUnauthorized, "missing node key")
			return
		}
		nodeID, err := h.Auth.Authenticate(r.Context(), strings.TrimSpace(key))
		if err != nil {
			if !errors.Is(err, nodekey.ErrInvalid) {
				h.Log.Error("node key lookup failed", "error", err.Error())
				Fail(w, http.StatusInternalServerError, CodeInternal, "authentication unavailable")
				return
			}
			Fail(w, http.StatusUnauthorized, CodeUnauthorized, "invalid node key")
			return
		}
		if ok, wait := h.Limiter.Allow(nodeID); !ok {
			secs := int(wait/time.Second) + 1
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			Fail(w, http.StatusTooManyRequests, CodeRateLimited, "rate limit exceeded")
			return
		}
		if err := h.Store.TouchNode(r.Context(), nodeID, h.Now()); err != nil {
			h.Log.Warn("updating node last-seen failed", "node_id", nodeID, "error", err.Error())
		}
		next(w, r, nodeID)
	}
}

type eventsRequest struct {
	Events []json.RawMessage `json:"events"`
}

type rejection struct {
	Index int    `json:"index"`
	Error string `json:"error"`
}

// admit takes an ingest slot or answers 429 overloaded with Retry-After.
// Events are acknowledged only after they are committed (fsynced), so a
// refused batch stays in the SDK queue and nothing acknowledged is lost.
func (h *Ingest) admit(w http.ResponseWriter, r *http.Request, nodeID string) (func(), bool) {
	if h.Admission == nil {
		return func() {}, true
	}
	release, ok := h.Admission.Enter(r.Context())
	if ok {
		return release, true
	}
	now := h.Now().UnixNano()
	if last := h.lastOverloadLog.Load(); now-last >= int64(overloadLogEvery) && h.lastOverloadLog.CompareAndSwap(last, now) {
		total := h.Admission.Refused()
		h.Log.Warn("ingest overloaded, event batches refused with 429",
			"refused_since_last_log", total-h.overloadLogged.Swap(total), "refused_total", total, "node_id", nodeID)
	}
	w.Header().Set("Retry-After", strconv.Itoa(overloadRetryAfter))
	Fail(w, http.StatusTooManyRequests, CodeOverloaded, "hub is overloaded, retry later")
	return nil, false
}

func (h *Ingest) events(w http.ResponseWriter, r *http.Request, nodeID string) {
	release, ok := h.admit(w, r, nodeID)
	if !ok {
		return
	}
	defer release()
	var req eventsRequest
	if err := DecodeStrict(w, r, maxIngestBody, &req); err != nil {
		FailDecode(w, err)
		return
	}
	if len(req.Events) < 1 || len(req.Events) > maxBatchEvents {
		Fail(w, http.StatusBadRequest, "invalid_batch", "a batch holds 1 to 100 events")
		return
	}

	ctx := r.Context()
	now := h.Now().UTC()
	belongs := map[string]bool{}
	var (
		accepted, duplicates int
		rejected             = []rejection{}
	)
	for i, rawEv := range req.Events {
		re, ok := ingest.DecodeRawEvent(rawEv)
		if !ok {
			rejected = append(rejected, rejection{i, ingest.CodeInvalidEvent})
			continue
		}
		ev, warns, code := ingest.Normalize(re, nodeID, now)
		if code != "" {
			rejected = append(rejected, rejection{i, code})
			continue
		}
		mine, cached := belongs[ev.SensorID]
		if !cached {
			var err error
			mine, err = h.Store.SensorBelongsToNode(ctx, nodeID, ev.SensorID)
			if err != nil {
				h.Log.Error("sensor lookup failed", "error", err.Error())
				Fail(w, http.StatusInternalServerError, CodeInternal, "storage unavailable")
				return
			}
			belongs[ev.SensorID] = mine
		}
		if !mine {
			rejected = append(rejected, rejection{i, ingest.CodeSensorNotRegistered})
			continue
		}
		for _, wn := range warns {
			h.Log.Warn("event normalised", "node_id", nodeID, "sensor_id", ev.SensorID, "trigger", ev.Trigger, "warning", string(wn))
		}
		res, err := h.Pipeline.Process(ctx, ev)
		if err != nil {
			h.Log.Error("event pipeline failed", "node_id", nodeID, "error", err.Error())
			// Not acknowledged: the SDK will retry the whole batch, and
			// already stored events are deduplicated.
			Fail(w, http.StatusInternalServerError, CodeInternal, "event processing failed")
			return
		}
		if res.Stored {
			accepted++
		} else {
			duplicates++
		}
	}

	if len(rejected) == len(req.Events) {
		if code := commonCode(rejected); code == ingest.CodeReservedTrigger {
			Fail(w, http.StatusForbidden, code, "trigger is reserved for the Hub")
			return
		} else if code == ingest.CodeSensorNotRegistered {
			Fail(w, http.StatusNotFound, code, "sensor is not registered on this node")
			return
		}
	}
	OK(w, map[string]any{"accepted": accepted, "duplicates": duplicates, "rejected": rejected})
}

func commonCode(r []rejection) string {
	code := r[0].Error
	for _, x := range r[1:] {
		if x.Error != code {
			return ""
		}
	}
	return code
}

type heartbeatRequest struct {
	SensorID       string `json:"sensor_id"`
	ConfigRevision string `json:"config_revision"`
	SDKVersion     string `json:"sdk_version"`
	DroppedEvents  *int64 `json:"dropped_events,omitempty"`
}

func (h *Ingest) sensorOf(w http.ResponseWriter, r *http.Request, nodeID, raw string) (string, bool) {
	id := ingest.Clamp(raw)
	if !domain.ValidSensorID(id) {
		Fail(w, http.StatusNotFound, ingest.CodeSensorNotRegistered, "sensor is not registered on this node")
		return "", false
	}
	ok, err := h.Store.SensorBelongsToNode(r.Context(), nodeID, id)
	if err != nil {
		h.Log.Error("sensor lookup failed", "error", err.Error())
		Fail(w, http.StatusInternalServerError, CodeInternal, "storage unavailable")
		return "", false
	}
	if !ok {
		Fail(w, http.StatusNotFound, ingest.CodeSensorNotRegistered, "sensor is not registered on this node")
		return "", false
	}
	return id, true
}

func (h *Ingest) heartbeat(w http.ResponseWriter, r *http.Request, nodeID string) {
	var req heartbeatRequest
	if err := DecodeStrict(w, r, maxIngestBody, &req); err != nil {
		FailDecode(w, err)
		return
	}
	if req.DroppedEvents != nil && *req.DroppedEvents < 0 {
		Fail(w, http.StatusBadRequest, CodeInvalid, "dropped_events must be >= 0")
		return
	}
	id, ok := h.sensorOf(w, r, nodeID, req.SensorID)
	if !ok {
		return
	}
	rev := ingest.Clamp(req.ConfigRevision)
	if len(rev) > 32 {
		rev = rev[:32]
	}
	sdk := ingest.Clamp(req.SDKVersion)
	if len(sdk) > 32 {
		sdk = sdk[:32]
	}
	if req.DroppedEvents != nil && *req.DroppedEvents > 0 {
		h.Log.Warn("sensor reported dropped events", "node_id", nodeID, "sensor_id", id, "dropped_events", *req.DroppedEvents)
	}
	var dropped int64
	if req.DroppedEvents != nil {
		dropped = *req.DroppedEvents
	}
	if err := h.Liveness.Heartbeat(r.Context(), nodeID, id, ingest.Clamp(rev), ingest.Clamp(sdk), dropped); err != nil {
		h.Log.Error("recording heartbeat failed", "error", err.Error())
		Fail(w, http.StatusInternalServerError, CodeInternal, "heartbeat not recorded")
		return
	}
	OK(w, nil)
}

type stoppingRequest struct {
	SensorID string `json:"sensor_id"`
	Reason   string `json:"reason"`
}

func (h *Ingest) stopping(w http.ResponseWriter, r *http.Request, nodeID string) {
	var req stoppingRequest
	if err := DecodeStrict(w, r, maxIngestBody, &req); err != nil {
		FailDecode(w, err)
		return
	}
	id, ok := h.sensorOf(w, r, nodeID, req.SensorID)
	if !ok {
		return
	}
	reason := ingest.Clamp(req.Reason)
	if len([]rune(reason)) > maxStopReason {
		reason = string([]rune(reason)[:maxStopReason])
	}
	if err := h.Liveness.Stopped(r.Context(), nodeID, id, reason); err != nil {
		h.Log.Error("recording stop notice failed", "error", err.Error())
		Fail(w, http.StatusInternalServerError, CodeInternal, "stop notice not recorded")
		return
	}
	OK(w, nil)
}
