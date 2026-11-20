// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/store"
)

type stubReady struct{ err error }

func (s stubReady) Ready(context.Context) error { return s.err }

func TestHealthProbes(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "health.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	mux := http.NewServeMux()
	(&Health{Ready: db}).Register(mux)

	for _, path := range []string{"/healthz", "/readyz"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: status %d want 200 (%s)", path, rec.Code, rec.Body.String())
		}
		if strings.TrimSpace(rec.Body.String()) != `{"status":"ok"}` {
			t.Fatalf("GET %s: body %q want minimal status ok", path, rec.Body.String())
		}
	}

	// Failing readiness must return 503 without leaking internal error details.
	failMux := http.NewServeMux()
	(&Health{Ready: stubReady{err: errors.New("sqlite secret internal error")}}).Register(failMux)
	rec := httptest.NewRecorder()
	failMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("failing /readyz: status %d want 503", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "sqlite") {
		t.Fatalf("failing /readyz leaked internal error: %s", rec.Body.String())
	}

	// Closed DB must fail /readyz.
	db.Close()
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed DB /readyz: status %d want 503", rec.Code)
	}
}
