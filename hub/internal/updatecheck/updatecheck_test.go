// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package updatecheck

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheck(t *testing.T) {
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		io.WriteString(w, `[{"tag_name":"hub/v3.2.0"},{"tag_name":"hub/v3.10.0"},{"tag_name":"hub/v4.0.0","prerelease":true},
		 {"tag_name":"cli/v3.1.1"},{"tag_name":"cli/v3.2.0","draft":true},{"tag_name":"sensor/tcp-tarpit/v9.0.0"},{"tag_name":"v99.0.0"}]`)
	}))
	defer srv.Close()
	c := &Checker{URL: srv.URL, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: time.Now,
		Interval: func(context.Context) time.Duration { return time.Hour }}
	st := c.Check(context.Background())
	if st.LatestHub != "3.10.0" || st.LatestCLI != "3.1.1" || st.LastError != "" || st.LastCheck == nil {
		t.Fatalf("%+v", st)
	}
	status = 500
	st = c.Check(context.Background())
	if st.LastError == "" || st.LatestHub != "3.10.0" {
		t.Fatalf("failure must keep the last known versions: %+v", st)
	}
}
