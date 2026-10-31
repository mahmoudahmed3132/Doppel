// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package webui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func get(t *testing.T, h http.Handler, method, p string) *http.Response {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, p, nil))
	return w.Result()
}

func body(r *http.Response) string { b, _ := io.ReadAll(r.Body); return string(b) }

func TestRouting(t *testing.T) {
	u := New(fstest.MapFS{
		"index.html":           {Data: []byte("<html>app</html>")},
		"assets/main-AB12.js":  {Data: []byte("console.log(1)")},
		"assets/main-AB12.css": {Data: []byte("body{}")},
		".placeholder":         {Data: []byte("x")},
	})
	cases := []struct {
		path, want string
		code       int
		cache      string
	}{
		{"/", "app", 200, "no-cache"},
		{"/fleet/node-0000000a", "app", 200, "no-cache"},
		{"/events?open=3", "app", 200, "no-cache"},
		{"/assets/main-AB12.js", "console.log", 200, "public, max-age=31536000, immutable"},
		{"/assets/missing.js", "", 404, ""},
		{"/favicon.ico", "", 404, ""},
		{"/.placeholder", "app", 200, "no-cache"},
		{"/api/v2/x", "not_found", 404, ""},
		{"/v3/node/unknown", "not_found", 404, ""},
		{"/../../etc/passwd", "app", 200, "no-cache"}, // cleaned; fs.FS cannot escape dist
		{"/../assets/main-AB12.js", "", 400, ""},      // ServeFileFS refuses ".." outright
	}
	for _, c := range cases {
		r := get(t, u, "GET", c.path)
		b := body(r)
		if r.StatusCode != c.code || !strings.Contains(b, c.want) {
			t.Errorf("%s: %d %q", c.path, r.StatusCode, b)
		}
		if c.cache != "" && r.Header.Get("Cache-Control") != c.cache {
			t.Errorf("%s: cache %q", c.path, r.Header.Get("Cache-Control"))
		}
	}
	if r := get(t, u, "GET", "/assets/main-AB12.css"); !strings.HasPrefix(r.Header.Get("Content-Type"), "text/css") {
		t.Errorf("css type %q", r.Header.Get("Content-Type"))
	}
	if r := get(t, u, "POST", "/"); r.StatusCode != 405 {
		t.Errorf("POST: %d", r.StatusCode)
	}
}

func TestNotBuilt(t *testing.T) {
	u := New(fstest.MapFS{".placeholder": {Data: []byte("x")}})
	if u.Built() {
		t.Fatal("built")
	}
	r := get(t, u, "GET", "/settings")
	if b := body(r); r.StatusCode != 200 || !strings.Contains(b, "not part of this build") || strings.Contains(b, "<script") || strings.Contains(b, "style") {
		t.Fatalf("%d %q", r.StatusCode, b)
	}
}

// The embedded build, when present, must reference only same-origin assets
// and contain no inline script or style (strict CSP, §7).
func TestEmbeddedBuildIsCSPClean(t *testing.T) {
	h := Handler()
	if !h.Built() {
		t.Skip("UI not built")
	}
	idx := string(h.index)
	for _, bad := range []string{"<style", "style=", "http://", "https://", "javascript:"} {
		if strings.Contains(idx, bad) {
			t.Errorf("index.html contains %q", bad)
		}
	}
	if strings.Count(idx, "<script") != 1 || !strings.Contains(idx, `<script type="module" src="/assets/`) {
		t.Errorf("unexpected scripts in index.html:\n%s", idx)
	}
}
