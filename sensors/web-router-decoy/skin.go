// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"bytes"
	"html/template"
	"net/http"
)

// Page kinds a skin renders.
const (
	PageLogin       = "login"
	PageLoginFailed = "login_failed"
	PageNotFound    = "not_found"
	PageBasicAuth   = "basic_auth_required"
)

// RequestContext is what a skin may use to render a page. All fields are
// attacker-controlled and must be escaped by the skin.
type RequestContext struct {
	Path      string
	Method    string
	Host      string
	UserAgent string
	Username  string
}

// Skin renders the decoy's pages.
type Skin interface {
	Name() string
	// LoginPaths are paths that show the login page (GET) and accept a
	// login form (POST).
	LoginPaths() []string
	Render(kind string, rc RequestContext) (status int, headers http.Header, body []byte)
}

// Skins selects a skin by name (TS_SKIN).
type Skins interface {
	Skin(name string) (Skin, bool)
}

type genericSkin struct{}

var genericTpl = template.Must(template.New("p").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Router Login</title></head>
<body><h1>Router administration</h1>
{{if .Failed}}<p role="alert">Invalid username or password.</p>{{end}}
{{if .NotFound}}<p>404 Not Found: {{.Path}}</p>{{else}}
<form method="post" action="/login">
<label>Username <input name="username" value="{{.Username}}" autocomplete="username"></label>
<label>Password <input name="password" type="password" autocomplete="current-password"></label>
<button type="submit">Log in</button></form>{{end}}
</body></html>`))

func (genericSkin) Name() string         { return "generic" }
func (genericSkin) LoginPaths() []string { return []string{"/", "/login", "/index.html"} }

func (genericSkin) Render(kind string, rc RequestContext) (int, http.Header, []byte) {
	h := http.Header{}
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Server", "httpd")
	data := map[string]any{"Path": rc.Path, "Username": rc.Username}
	status := http.StatusOK
	switch kind {
	case PageLoginFailed:
		data["Failed"] = true
	case PageNotFound:
		data["NotFound"], status = true, http.StatusNotFound
	case PageBasicAuth:
		h.Set("WWW-Authenticate", `Basic realm="Router"`)
		status = http.StatusUnauthorized
	}
	var buf bytes.Buffer
	genericTpl.Execute(&buf, data)
	return status, h, buf.Bytes()
}
