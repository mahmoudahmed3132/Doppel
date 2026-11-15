// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Every built-in skin through the decoy (NewFromSettings → Skins seam): the
// login page renders, a form login is captured and always fails with the
// skin's error text, unknown paths are probes, and the basic skin answers
// with a Basic challenge and captures Basic credentials.
func TestBuiltinSkinsThroughDecoy(t *testing.T) {
	for _, name := range SkinNames {
		t.Run(name, func(t *testing.T) {
			srv, r := newServer(t, map[string]string{"TS_SKIN": name})
			resp, err := http.Get(srv.URL + "/")
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			low := strings.ToLower(string(body))
			if strings.Contains(low, "truesignal") || strings.Contains(low, "doppel") || strings.Contains(low, "honeypot") || strings.Contains(low, "decoy") {
				t.Fatalf("page names the product: %s", body)
			}
			if name == "basic" {
				if resp.StatusCode != 401 || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), `Basic realm="`) {
					t.Fatalf("basic: %d %v", resp.StatusCode, resp.Header)
				}
				req, _ := http.NewRequest("GET", srv.URL+"/", nil)
				req.SetBasicAuth("admin", "admin123")
				resp, _ = http.DefaultClient.Do(req)
				resp.Body.Close()
				if resp.StatusCode != 401 || len(r.of(TriggerLogin)) != 1 || r.of(TriggerLogin)[0]["username"] != "admin" {
					t.Fatalf("basic login: %d %v", resp.StatusCode, r.ev)
				}
				return
			}
			if resp.StatusCode != 200 || !strings.Contains(string(body), `name="username"`) || !strings.Contains(string(body), `name="password"`) {
				t.Fatalf("login page %d: %s", resp.StatusCode, body)
			}
			sk, _ := builtinSkins{}.Skin(name)
			paths := sk.LoginPaths()
			post := paths[len(paths)-1]
			resp, err = http.PostForm(srv.URL+post, url.Values{"username": {"<b>root</b>"}, "password": {"toor"}})
			if err != nil {
				t.Fatal(err)
			}
			body, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 || strings.Contains(string(body), "<b>root</b>") {
				t.Fatalf("failed login page %d: %s", resp.StatusCode, body)
			}
			if name != "generic" {
				if spec := sk.(specSkin).s; !strings.Contains(string(body), htmlEscape(spec.ErrorText)) {
					t.Fatalf("no error text: %s", body)
				}
			}
			logins := r.of(TriggerLogin)
			if len(logins) != 1 || logins[0]["username"] != "<b>root</b>" || logins[0]["password_hmac"] == nil {
				t.Fatalf("captured %v", r.ev)
			}
			resp, _ = http.Get(srv.URL + "/wp-admin/")
			resp.Body.Close()
			if resp.StatusCode != 404 || len(r.of(TriggerProbe)) != 1 {
				t.Fatalf("probe %d", resp.StatusCode)
			}
		})
	}
	if _, ok := (builtinSkins{}).Skin("fortinet"); ok {
		t.Fatal("unknown skin accepted")
	}
}

func htmlEscape(s string) string {
	return strings.NewReplacer("'", "&#39;", `"`, "&#34;", "&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
