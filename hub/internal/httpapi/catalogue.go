// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package httpapi

import (
	"log/slog"
	"net/http"
	"regexp"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/catalogue"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/semver"
)

// Catalogue serves the sensor catalogue API.
type Catalogue struct {
	Cat *catalogue.Catalogue
	Log *slog.Logger
}

var catalogueNameRE = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Register mounts the routes.
func (c *Catalogue) Register(a *Admin) {
	a.RouteFull("GET /api/v3/catalogue", "", c.list)
	a.RouteFull("GET /api/v3/catalogue/{name}/{version}", "", c.details)
	a.RouteFull("POST /api/v3/catalogue/refresh", "catalogue.refresh", c.refresh)
}

func (c *Catalogue) list(w http.ResponseWriter, r *http.Request) {
	sensors, st := c.Cat.List(r.Context())
	OK(w, map[string]any{"sensors": sensors, "status": st})
}

func (c *Catalogue) details(w http.ResponseWriter, r *http.Request) {
	name, version := r.PathValue("name"), r.PathValue("version")
	if !catalogueNameRE.MatchString(name) || !semver.Valid(version) {
		Fail(w, http.StatusNotFound, CodeNotFound, "not in the catalogue")
		return
	}
	v, m, ok := c.Cat.Details(r.Context(), name, version)
	if !ok {
		Fail(w, http.StatusNotFound, CodeNotFound, "not in the catalogue")
		return
	}
	// documentation is untrusted Markdown: clients must render it escaped.
	OK(w, map[string]any{"name": name, "version": v, "manifest": m})
}

func (c *Catalogue) refresh(w http.ResponseWriter, r *http.Request) {
	if err := c.Cat.Refresh(r.Context()); err != nil {
		Fail(w, http.StatusBadGateway, "registry_unavailable", err.Error())
		return
	}
	_, st := c.Cat.List(r.Context())
	OK(w, map[string]any{"status": st})
}
