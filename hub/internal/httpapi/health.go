// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

// ReadyChecker verifies that the Hub's backing store is reachable and at the
// current schema version.
type ReadyChecker interface {
	Ready(ctx context.Context) error
}

// Health serves unauthenticated liveness (/healthz) and readiness (/readyz)
// probes for load balancers such as F5 BIG-IP (H1 / WP-4A). Responses carry
// no internal detail.
type Health struct {
	Ready   ReadyChecker
	Log     *slog.Logger
	Timeout time.Duration // default 2 s
}

// Register mounts /healthz and /readyz on mux.
func (h *Health) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", h.healthz)
	mux.HandleFunc("GET /readyz", h.readyz)
}

func (h *Health) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Health) readyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if h.Ready == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	timeout := h.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	if err := h.Ready.Ready(ctx); err != nil {
		if h.Log != nil {
			h.Log.Warn("readiness check failed", "error", err.Error())
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
