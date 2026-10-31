// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package webui serves the embedded admin UI (§7). The UI is built from
// ui/ into dist/ before the release build; a plain `go build` without it
// serves a short "not built" page so the Hub still runs.
//
// Routing: hashed files under /assets/ are immutable; any other path that
// is not a file and has no extension gets index.html (client-side routes);
// paths under /api/ and /v3/ never fall back to the UI.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

//go:embed all:dist
var embedded embed.FS

// Handler serves the UI from the embedded build.
func Handler() *UI { return New(mustSub(embedded, "dist")) }

func mustSub(f fs.FS, dir string) fs.FS {
	s, err := fs.Sub(f, dir)
	if err != nil {
		panic(err)
	}
	return s
}

// UI serves files from an fs.FS (exported for tests).
type UI struct {
	files fs.FS
	index []byte
}

// New returns a UI over files; index.html is read once.
func New(files fs.FS) *UI {
	u := &UI{files: files}
	if b, err := fs.ReadFile(files, "index.html"); err == nil {
		u.index = b
	}
	return u
}

// Built reports whether a UI build is embedded.
func (u *UI) Built() bool { return u.index != nil }

const notBuilt = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>TrueSignal</title></head>
<body><h1>TrueSignal Hub</h1><p>The admin UI is not part of this build. Build it with <code>make ui</code> before <code>go build</code>, or use a release image. The API is available under /api/v3/.</p></body></html>
`

func (u *UI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p := path.Clean("/" + r.URL.Path)
	if p == "/api" || p == "/v3" || strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/v3/") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"ok":false,"error":"not_found","message":"not found"}` + "\n"))
		return
	}
	name := strings.TrimPrefix(p, "/")
	if name != "" && name != "index.html" && !strings.HasPrefix(path.Base(name), ".") {
		if st, err := fs.Stat(u.files, name); err == nil && !st.IsDir() {
			if strings.HasPrefix(name, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			} else {
				w.Header().Set("Cache-Control", "no-cache")
			}
			http.ServeFileFS(w, r, u.files, name)
			return
		}
		if path.Ext(name) != "" {
			http.NotFound(w, r)
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	if u.index == nil {
		w.Write([]byte(notBuilt))
		return
	}
	http.ServeContent(w, r, "index.html", time.Time{}, strings.NewReader(string(u.index)))
}
