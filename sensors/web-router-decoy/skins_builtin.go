// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

// Built-in login skins behind the Skins seam (the PORTED web skins module).
// A login page is data (product, colours, fields, footer, headers), rendered
// by one html/template, so every value is auto-escaped and a new look needs
// no code.
//
// Imported from TrueSignal (see PROVENANCE.md): the skin data, the defaults
// and the templates are that module's. Changes: the brand-profile table and
// custom skins (TS_SKIN_JSON) are not imported; the webmail account field is
// named "username", which is what the decoy captures. The adapter below is new.

import (
	"bytes"
	"html/template"
	"net/http"
	"strings"
)

// Field is one input on the login form.
type Field struct {
	Name         string   `json:"name"`
	Label        string   `json:"label"`
	Type         string   `json:"type"` // text | password | email | select
	Autocomplete string   `json:"autocomplete,omitempty"`
	Options      []string `json:"options,omitempty"` // for select
}

// skinSpec describes one login surface.
type skinSpec struct {
	Name         string      `json:"name"`
	Product      string      `json:"product"`         // header brand text
	Title        string      `json:"title"`           // <title>
	PanelTitle   string      `json:"panel_title"`     // heading above the form
	Intro        string      `json:"intro"`           // text under the heading
	ErrorText    string      `json:"error_text"`      // shown after a failed login
	Button       string      `json:"button"`          // submit label
	Accent       string      `json:"accent"`          // #rrggbb
	Fields       []Field     `json:"fields"`          // form inputs, in order
	UserField    string      `json:"user_field"`      // field carrying the account name
	PassField    string      `json:"pass_field"`      // field carrying the password
	Footer       [][2]string `json:"footer"`          // label/value rows under the panel
	ServerHeader string      `json:"server_header"`   // HTTP Server header
	LoginPath    string      `json:"login_path"`      // form POST target
	Basic        bool        `json:"basic,omitempty"` // HTTP Basic auth instead of a form
	Realm        string      `json:"realm,omitempty"` // Basic auth realm
}

func userPassFields(userLabel string) []Field {
	return []Field{
		{Name: "username", Label: userLabel, Type: "text", Autocomplete: "username"},
		{Name: "password", Label: "Password", Type: "password", Autocomplete: "current-password"},
	}
}

// builtinSkin returns a named built-in skin. product overrides the product
// name when set; for the router skin, brand drives the model/firmware footer.
func builtinSkin(name, product, brand string) (skinSpec, bool) {
	var s skinSpec
	switch name {
	case "router":
		model, firmware := "GW-2200", "2.4.1"
		if brand == "" {
			brand = "Gateway"
		}
		s = skinSpec{
			Product: brand, Title: brand + " Router Login", PanelTitle: "Router Login",
			Intro:     "Enter administrator credentials to access the device management interface.",
			ErrorText: "Login failed. Incorrect username or password.", Button: "Login", Accent: "#2c5d90",
			Fields:       userPassFields("Username"),
			Footer:       [][2]string{{"Model", model}, {"Firmware Version", firmware}, {"Hardware Version", "1.0"}},
			ServerHeader: "httpd",
		}
	case "nas":
		s = skinSpec{
			Product: "Storage Manager", Title: "Storage Manager - Sign In", PanelTitle: "Sign in to Storage Manager",
			Intro:     "Use your NAS account to manage shared folders, backups and users.",
			ErrorText: "The account or password is invalid. Please try again.", Button: "Sign In", Accent: "#1f7a5c",
			Fields:       userPassFields("Account"),
			Footer:       [][2]string{{"Model", "NS-4200"}, {"Version", "7.2.1-69057 Update 3"}},
			ServerHeader: "nginx",
		}
	case "vpn":
		s = skinSpec{
			Product: "Secure Access Portal", Title: "Secure Access SSL VPN", PanelTitle: "SSL VPN Login",
			Intro:     "Authorized users only. All access is logged.",
			ErrorText: "Permission denied. Check your username, password and realm.", Button: "Login", Accent: "#8a1c1c",
			Fields:       append(userPassFields("Username"), Field{Name: "realm", Label: "Realm", Type: "select", Options: []string{"Employees", "Contractors", "Admins"}}),
			Footer:       [][2]string{{"Gateway", "SSLVPN-GW01"}, {"Build", "7.0.12 b0523"}},
			ServerHeader: "xxxxxxxx-xxxxx", LoginPath: "/remote/login",
		}
	case "webmail":
		s = skinSpec{
			Product: "Web Mail", Title: "Web Mail - Login", PanelTitle: "Sign in to your mailbox",
			Intro:     "Enter your email address and password.",
			ErrorText: "Login failed. Please check your email address and password.", Button: "Sign in", Accent: "#2b579a",
			Fields: []Field{
				{Name: "username", Label: "Email address", Type: "email", Autocomplete: "username"},
				{Name: "password", Label: "Password", Type: "password", Autocomplete: "current-password"},
			},
			Footer:       [][2]string{{"Server", "mail01"}},
			ServerHeader: "Apache", LoginPath: "/mail/login",
		}
	case "admin":
		s = skinSpec{
			Product: "Administration Console", Title: "Administration Console", PanelTitle: "Administrator sign-in",
			Intro:     "This system is for authorized administrators only.",
			ErrorText: "Invalid username or password.", Button: "Sign in", Accent: "#3d4b5c",
			Fields:       userPassFields("Username"),
			Footer:       [][2]string{{"Version", "4.12.3"}},
			ServerHeader: "Apache-Coyote/1.1", LoginPath: "/admin/login",
		}
	case "basic":
		s = skinSpec{
			Product: "Network Device", Title: "401 Unauthorized", Basic: true, Realm: "Device Configuration",
			ServerHeader: "GoAhead-Webs",
		}
	default:
		return skinSpec{}, false
	}
	s.Name = name
	if product != "" {
		s.Product = product
		if !s.Basic {
			s.Title = product
		} else {
			s.Realm = product
		}
	}
	return s.withDefaults(), true
}

func (s skinSpec) withDefaults() skinSpec {
	if s.LoginPath == "" {
		s.LoginPath = "/login"
	}
	if s.UserField == "" {
		s.UserField = "username"
	}
	if s.PassField == "" {
		s.PassField = "password"
	}
	if s.Button == "" {
		s.Button = "Login"
	}
	if s.Accent == "" {
		s.Accent = "#2c5d90"
	}
	if s.Title == "" {
		s.Title = s.Product
	}
	for i := range s.Fields {
		if s.Fields[i].Type == "" {
			s.Fields[i].Type = "text"
		}
	}
	return s
}

// pageData is what the template sees.
type pageData struct {
	skinSpec
	Failed bool
}

var loginTemplate = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{.Title}}</title>
<style>
* { box-sizing: border-box; }
body { margin: 0; font-family: Arial, Helvetica, sans-serif; background: #e4e7eb; color: #333; }
.header { height: 64px; background: {{.Accent}}; display: flex; align-items: center; padding: 0 24px; color: #fff; }
.brand { font-size: 22px; font-weight: bold; letter-spacing: 0.4px; }
.container { width: 100%; max-width: 480px; margin: 72px auto; }
.panel { background: #fff; border: 1px solid #c3c9d1; }
.panel-header { background: #f3f5f7; border-bottom: 1px solid #d5dae0; padding: 12px 16px; font-weight: bold; color: #444; }
.panel-body { padding: 24px; }
.info { margin-bottom: 20px; font-size: 13px; color: #666; line-height: 1.5; }
.error { background: #fff2f2; border: 1px solid #d77; color: #a00000; padding: 10px; margin-bottom: 18px; font-size: 13px; }
.form-row { margin-bottom: 16px; }
label { display: block; margin-bottom: 6px; font-size: 13px; font-weight: bold; }
input, select { width: 100%; height: 34px; padding: 0 10px; border: 1px solid #aeb6bf; font-size: 13px; background: #fff; }
button { min-width: 100px; height: 34px; border: 0; background: {{.Accent}}; color: #fff; font-weight: bold; cursor: pointer; margin-top: 4px; }
.footer { margin-top: 14px; padding: 12px; background: #f7f7f7; border: 1px solid #cfd4da; font-size: 12px; color: #666; line-height: 1.6; }
.footer-row { display: flex; justify-content: space-between; }
@media (max-width: 600px) { .container { margin: 20px; width: auto; } }
</style>
</head>
<body>
<div class="header"><div class="brand">{{.Product}}</div></div>
<div class="container">
  <div class="panel">
    <div class="panel-header">{{.PanelTitle}}</div>
    <div class="panel-body">
      {{if .Intro}}<div class="info">{{.Intro}}</div>{{end}}
      {{if .Failed}}<div class="error">{{.ErrorText}}</div>{{end}}
      <form method="post" action="{{.LoginPath}}">
        {{range .Fields}}<div class="form-row">
          <label for="{{.Name}}">{{.Label}}</label>
          {{if eq .Type "select"}}<select id="{{.Name}}" name="{{.Name}}">{{range .Options}}<option>{{.}}</option>{{end}}</select>
          {{else}}<input id="{{.Name}}" name="{{.Name}}" type="{{.Type}}"{{if .Autocomplete}} autocomplete="{{.Autocomplete}}"{{end}} required>{{end}}
        </div>
        {{end}}<button type="submit">{{.Button}}</button>
      </form>
    </div>
  </div>
  {{if .Footer}}<div class="footer">{{range .Footer}}<div class="footer-row"><span>{{index . 0}}</span><span>{{index . 1}}</span></div>{{end}}</div>{{end}}
</div>
</body>
</html>`))

// basicTemplate is the body sent with a Basic-auth challenge.
var basicTemplate = template.Must(template.New("basic").Parse(`<!DOCTYPE html>
<html><head><title>401 Unauthorized</title></head>
<body><h1>401 Unauthorized</h1><p>Authorization required to access {{.Realm}}.</p></body></html>`))

// builtinSkins implements Skins: "generic" (the base page) plus the
// imported router, nas, vpn, webmail, admin and basic skins.
type builtinSkins struct{}

var _ Skins = builtinSkins{}

// SkinNames lists the selectable skins (TS_SKIN).
var SkinNames = []string{"generic", "router", "nas", "vpn", "webmail", "admin", "basic"}

func (builtinSkins) Skin(name string) (Skin, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || name == "generic" {
		return genericSkin{}, true
	}
	s, ok := builtinSkin(name, "", "")
	if !ok {
		return nil, false
	}
	return specSkin{s}, true
}

type specSkin struct{ s skinSpec }

func (k specSkin) Name() string { return k.s.Name }

// LoginPaths are the root, /index.html and the form's POST target.
func (k specSkin) LoginPaths() []string {
	out := []string{"/", "/index.html"}
	if k.s.LoginPath != "/" && k.s.LoginPath != "/index.html" {
		out = append(out, k.s.LoginPath)
	}
	return out
}

func (k specSkin) Render(kind string, rc RequestContext) (int, http.Header, []byte) {
	h := http.Header{}
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	if k.s.ServerHeader != "" {
		h.Set("Server", k.s.ServerHeader)
	}
	var buf bytes.Buffer
	switch {
	case kind == PageNotFound:
		buf.WriteString("<!DOCTYPE html>\n<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>\n")
		return http.StatusNotFound, h, buf.Bytes()
	case k.s.Basic:
		h.Set("WWW-Authenticate", `Basic realm="`+strings.ReplaceAll(k.s.Realm, `"`, "'")+`"`)
		_ = basicTemplate.Execute(&buf, k.s)
		return http.StatusUnauthorized, h, buf.Bytes()
	}
	_ = loginTemplate.Execute(&buf, pageData{skinSpec: k.s, Failed: kind == PageLoginFailed})
	return http.StatusOK, h, buf.Bytes()
}
