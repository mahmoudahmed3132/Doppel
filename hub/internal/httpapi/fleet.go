// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/auth"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/fleet"
)

// Fleet serves the node and sensor admin API.
type Fleet struct {
	Svc      *fleet.Service
	Settings SettingsReader
	Log      *slog.Logger
}

// Register mounts the routes on the admin API.
func (f *Fleet) Register(a *Admin) {
	a.RouteFull("GET /api/v3/nodes", "", needViewer, f.listNodes)
	a.RouteFull("POST /api/v3/nodes", "node.create", needAdmin, f.createNode)
	a.RouteFull("GET /api/v3/nodes/{node}", "", needViewer, f.getNode)
	a.RouteFull("PATCH /api/v3/nodes/{node}", "node.update", needAdmin, f.updateNode)
	a.RouteFull("DELETE /api/v3/nodes/{node}", "node.delete", needAdmin, f.deleteNode)
	a.RouteFull("POST /api/v3/nodes/{node}/key", "node.rotate_key", needAdmin, f.rotateKey)
	a.RouteFull("POST /api/v3/nodes/{node}/upgrade", "node.upgrade", needAdmin, f.upgradeNode)
	a.RouteFull("GET /api/v3/nodes/{node}/compose", "", needAnalyst, f.compose)
	a.RouteFull("POST /api/v3/nodes/{node}/compose/preview", "", needAnalyst, f.preview)
	a.RouteFull("POST /api/v3/nodes/{node}/sensors", "sensor.create", needAdmin, f.addSensor)
	a.RouteFull("PATCH /api/v3/nodes/{node}/sensors/{sensor}", "sensor.update", needAdmin, f.updateSensor)
	a.RouteFull("DELETE /api/v3/nodes/{node}/sensors/{sensor}", "sensor.delete", needAdmin, f.deleteSensor)
	a.RouteFull("POST /api/v3/nodes/{node}/sensors/{sensor}/upgrade", "sensor.upgrade", needAdmin, f.upgradeSensor)
	a.RouteFull("POST /api/v3/nodes/{node}/sensors/{sensor}/silence", "sensor.silence", needAnalyst, f.silence(true))
	a.RouteFull("POST /api/v3/nodes/{node}/sensors/{sensor}/unsilence", "sensor.unsilence", needAnalyst, f.silence(false))
}

// ids extracts and validates path ids; invalid ids are reported as 404.
func (f *Fleet) nodeID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("node")
	if !domain.ValidNodeID(id) {
		Fail(w, http.StatusNotFound, CodeNotFound, "node not found")
		return "", false
	}
	return id, true
}

func (f *Fleet) sensorIDs(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	node, ok := f.nodeID(w, r)
	if !ok {
		return "", "", false
	}
	id := r.PathValue("sensor")
	if !domain.ValidSensorID(id) {
		Fail(w, http.StatusNotFound, CodeNotFound, "sensor not found")
		return "", "", false
	}
	return node, id, true
}

func (f *Fleet) fail(w http.ResponseWriter, err error) {
	var (
		re *fleet.RenderError
		ie *fleet.InputError
	)
	switch {
	case errors.As(err, &re):
		failRender(w, re)
	case errors.As(err, &ie):
		Fail(w, http.StatusBadRequest, CodeInvalid, ie.Message)
	case errors.Is(err, domain.ErrNotFound):
		Fail(w, http.StatusNotFound, CodeNotFound, "not found")
	case errors.Is(err, fleet.ErrSensorExists):
		Fail(w, http.StatusConflict, "sensor_exists", err.Error())
	default:
		f.Log.Error("fleet operation failed", "error", err.Error())
		Fail(w, http.StatusInternalServerError, CodeInternal, "internal error")
	}
}

func failRender(w http.ResponseWriter, re *fleet.RenderError) {
	writeJSON(w, re.Status, map[string]any{"ok": false, "error": re.Code, "message": re.Message, "sensor_id": re.SensorID})
}

func decodeInto(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := DecodeStrict(w, r, maxAdminBody, dst); err != nil {
		FailDecode(w, err)
		return false
	}
	return true
}

func renderJSON(r fleet.Rendered) map[string]any {
	warnings := r.Warnings
	if warnings == nil {
		warnings = []string{}
	}
	return map[string]any{"revision": r.Revision, "warnings": warnings}
}

func (f *Fleet) listNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := f.Svc.ListNodes(r.Context())
	if err != nil {
		f.fail(w, err)
		return
	}
	OK(w, map[string]any{"nodes": nodes})
}

func (f *Fleet) getNode(w http.ResponseWriter, r *http.Request) {
	id, ok := f.nodeID(w, r)
	if !ok {
		return
	}
	d, err := f.Svc.GetNode(r.Context(), id)
	if err != nil {
		f.fail(w, err)
		return
	}
	OK(w, map[string]any{"node": d})
}

func (f *Fleet) hubURL(ctx context.Context) string {
	if ep, ok, err := f.Settings.Setting(ctx, auth.SettingEndpoint); err == nil && ok {
		return ep
	}
	return ""
}

// keyResponse returns a freshly issued node key. It is shown exactly once.
func (f *Fleet) keyResponse(ctx context.Context, node any, key string) map[string]any {
	link := map[string]any{"key_env": "TS_NODE_KEY", "hub_url": f.hubURL(ctx)}
	if u := f.hubURL(ctx); u != "" {
		// The key is passed via the environment, never argv (§8).
		link["command"] = "TS_NODE_KEY=" + shellQuote(key) + " doppel link " + shellQuote(u)
	}
	return map[string]any{"node": node, "node_key": key, "link": link,
		"warning": "The node key is shown only once. Store it now; it cannot be retrieved later."}
}

func (f *Fleet) createNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Alias string   `json:"alias"`
		Tags  []string `json:"tags"`
	}
	if !decodeInto(w, r, &req) {
		return
	}
	n, key, err := f.Svc.CreateNode(r.Context(), req.Alias, req.Tags)
	if err != nil {
		f.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, withOK(f.keyResponse(r.Context(), n, key)))
}

// shellQuote quotes s for POSIX sh.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func withOK(m map[string]any) map[string]any { m["ok"] = true; return m }

func (f *Fleet) updateNode(w http.ResponseWriter, r *http.Request) {
	id, ok := f.nodeID(w, r)
	if !ok {
		return
	}
	var req struct {
		Alias *string   `json:"alias"`
		Tags  *[]string `json:"tags"`
	}
	if !decodeInto(w, r, &req) {
		return
	}
	n, err := f.Svc.UpdateNode(r.Context(), id, req.Alias, req.Tags)
	if err != nil {
		f.fail(w, err)
		return
	}
	OK(w, map[string]any{"node": n})
}

func (f *Fleet) deleteNode(w http.ResponseWriter, r *http.Request) {
	id, ok := f.nodeID(w, r)
	if !ok {
		return
	}
	if err := f.Svc.DeleteNode(r.Context(), id); err != nil {
		f.fail(w, err)
		return
	}
	OK(w, map[string]any{"events_kept": true})
}

func (f *Fleet) rotateKey(w http.ResponseWriter, r *http.Request) {
	id, ok := f.nodeID(w, r)
	if !ok {
		return
	}
	key, err := f.Svc.RotateKey(r.Context(), id)
	if err != nil {
		f.fail(w, err)
		return
	}
	OK(w, f.keyResponse(r.Context(), map[string]string{"id": id}, key))
}

func (f *Fleet) upgradeNode(w http.ResponseWriter, r *http.Request) {
	id, ok := f.nodeID(w, r)
	if !ok {
		return
	}
	changed, rd, err := f.Svc.UpgradeNode(r.Context(), id)
	if err != nil {
		f.fail(w, err)
		return
	}
	if changed == nil {
		changed = []string{}
	}
	OK(w, map[string]any{"upgraded": changed, "render": renderJSON(rd)})
}

func (f *Fleet) compose(w http.ResponseWriter, r *http.Request) {
	id, ok := f.nodeID(w, r)
	if !ok {
		return
	}
	rd, err := f.Svc.Compose(r.Context(), id)
	if err != nil {
		f.fail(w, err)
		return
	}
	OK(w, map[string]any{"compose": string(rd.Compose), "render": renderJSON(rd), "redacted": true})
}

type sensorSpecJSON struct {
	Name          string            `json:"name"`
	CatalogueName string            `json:"catalogue_name"`
	Version       string            `json:"version"`
	Config        map[string]string `json:"config"`
}

func (s sensorSpecJSON) spec() fleet.SensorSpec {
	return fleet.SensorSpec{Name: s.Name, CatalogueName: s.CatalogueName, Version: s.Version, Config: s.Config}
}

func (f *Fleet) preview(w http.ResponseWriter, r *http.Request) {
	id, ok := f.nodeID(w, r)
	if !ok {
		return
	}
	var req struct {
		Add      *sensorSpecJSON    `json:"add"`
		SensorID string             `json:"sensor_id"`
		Config   map[string]*string `json:"config"`
	}
	if !decodeInto(w, r, &req) {
		return
	}
	var add *fleet.SensorSpec
	if req.Add != nil {
		s := req.Add.spec()
		add = &s
	}
	if req.SensorID != "" && !domain.ValidSensorID(req.SensorID) {
		Fail(w, http.StatusNotFound, CodeNotFound, "sensor not found")
		return
	}
	rd, err := f.Svc.PreviewChange(r.Context(), id, add, req.SensorID, fleet.ConfigPatch(req.Config))
	if err != nil {
		f.fail(w, err)
		return
	}
	OK(w, map[string]any{"compose": string(rd.Compose), "render": renderJSON(rd), "redacted": true})
}

func (f *Fleet) addSensor(w http.ResponseWriter, r *http.Request) {
	id, ok := f.nodeID(w, r)
	if !ok {
		return
	}
	var req sensorSpecJSON
	if !decodeInto(w, r, &req) {
		return
	}
	v, rd, err := f.Svc.AddSensor(r.Context(), id, req.spec())
	if err != nil {
		f.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "sensor": v, "render": renderJSON(rd)})
}

func (f *Fleet) updateSensor(w http.ResponseWriter, r *http.Request) {
	node, id, ok := f.sensorIDs(w, r)
	if !ok {
		return
	}
	var req struct {
		Config map[string]*string `json:"config"`
	}
	if !decodeInto(w, r, &req) {
		return
	}
	if req.Config == nil {
		Fail(w, http.StatusBadRequest, CodeInvalid, "config is required (null values keep the current value)")
		return
	}
	v, rd, err := f.Svc.UpdateSensorConfig(r.Context(), node, id, fleet.ConfigPatch(req.Config))
	if err != nil {
		f.fail(w, err)
		return
	}
	OK(w, map[string]any{"sensor": v, "render": renderJSON(rd)})
}

func (f *Fleet) upgradeSensor(w http.ResponseWriter, r *http.Request) {
	node, id, ok := f.sensorIDs(w, r)
	if !ok {
		return
	}
	var req struct {
		Version string `json:"version"`
	}
	if !decodeInto(w, r, &req) {
		return
	}
	v, rd, err := f.Svc.UpgradeSensor(r.Context(), node, id, req.Version)
	if err != nil {
		f.fail(w, err)
		return
	}
	OK(w, map[string]any{"sensor": v, "render": renderJSON(rd)})
}

func (f *Fleet) deleteSensor(w http.ResponseWriter, r *http.Request) {
	node, id, ok := f.sensorIDs(w, r)
	if !ok {
		return
	}
	rd, err := f.Svc.DeleteSensor(r.Context(), node, id)
	if err != nil {
		f.fail(w, err)
		return
	}
	OK(w, map[string]any{"events_kept": true, "render": renderJSON(rd)})
}

func (f *Fleet) silence(v bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		node, id, ok := f.sensorIDs(w, r)
		if !ok {
			return
		}
		if err := f.Svc.SetSilenced(r.Context(), node, id, v); err != nil {
			f.fail(w, err)
			return
		}
		OK(w, map[string]any{"silenced": v})
	}
}
