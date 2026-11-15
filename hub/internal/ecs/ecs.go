// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package ecs renders SIEM records as Elastic Common Schema documents for the
// ECS output format and the Elastic / LogScale HTTP transports. Top-level
// fields follow ECS 8.x so Elastic Security, LogScale and other ECS-aware
// parsers use them without custom parsing; the full record stays under
// truesignal.* (truesignal.details is free-form per sensor: map it as
// `flattened` in Elastic). The truesignal namespace and vendor strings are
// wire identifiers (QUESTIONS Q66).
//
// Imported from TrueSignal (see PROVENANCE.md): the field mapping is that
// module's; it is adapted to domain.Record, and the Hub heartbeat document
// is new.
package ecs

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/attack"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
)

const ecsVersion = "8.11.0"

// Renderer implements ported.ECSRenderer.
type Renderer struct {
	Now func() time.Time // event.created; nil means time.Now
}

func (r Renderer) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

// ecsSeverity maps the TrueSignal severity to event.severity, using the same
// scale Elastic Security uses for rule severity.
func ecsSeverity(sev string) int {
	switch sev {
	case "critical":
		return 99
	case "high":
		return 73
	case "medium":
		return 47
	case "low":
		return 21
	default:
		return 1
	}
}

// ecsClassify returns event.kind and event.category for a trigger. allowed
// marks a whitelisted or known-scanner source.
func ecsClassify(trigger string, allowed bool) (string, []string) {
	kind := "alert"
	if allowed {
		// Archived evidence from an allow-listed source, not an alert.
		kind = "event"
	}
	switch {
	case strings.HasPrefix(trigger, "sensor_"):
		// Hub-generated liveness (sensor_stopped, sensor_heartbeat_lost, ...).
		return "event", []string{"host"}
	case strings.HasSuffix(trigger, "_login") || strings.HasPrefix(trigger, "web_login") || trigger == "honeytoken_used":
		return kind, []string{"intrusion_detection", "authentication"}
	case strings.HasPrefix(trigger, "decoy_file_"):
		return kind, []string{"intrusion_detection", "file"}
	case strings.HasPrefix(trigger, "web_"):
		return kind, []string{"intrusion_detection", "web"}
	default:
		return kind, []string{"intrusion_detection", "network"}
	}
}

// ecsEvent renders one event as an ECS document.
func (r Renderer) ecsEvent(event domain.EnrichedEvent) map[string]any {
	nodeAlias := event.NodeAlias
	if nodeAlias == "" {
		nodeAlias = event.NodeID
	}
	ts := event.OccurredAt.UTC()
	severity := string(event.Severity)

	var details map[string]any
	if len(event.Details) > 0 {
		_ = json.Unmarshal(event.Details, &details)
	}
	if details == nil {
		details = map[string]any{}
	}

	kind, category := ecsClassify(event.Trigger, event.Whitelisted || event.KnownScanner)
	ev := map[string]any{
		"kind":     kind,
		"category": category,
		"type":     []string{"info"},
		"action":   event.Trigger,
		"severity": ecsSeverity(severity),
		"dataset":  "truesignal.alert",
		"module":   "truesignal",
		"provider": event.SensorID,
		"created":  r.now().Format(time.RFC3339Nano),
	}
	if event.EventID != "" {
		ev["id"] = event.EventID
	}
	if category[len(category)-1] == "authentication" {
		// Decoys never grant access.
		ev["outcome"] = "failure"
	}

	doc := map[string]any{
		"@timestamp": ts.Format(time.RFC3339Nano),
		"ecs":        map[string]any{"version": ecsVersion},
		"message":    fmt.Sprintf("TrueSignal %s %s from %s on %s (%s)", severity, event.Trigger, event.Source, nodeAlias, event.Target),
		"event":      ev,
		"log":        map[string]any{"level": severity},
		"observer": map[string]any{
			"type":     "honeypot",
			"vendor":   "TrueSignal",
			"product":  "TrueSignal",
			"hostname": nodeAlias,
		},
		"host": map[string]any{"name": nodeAlias, "id": event.NodeID},
		"tags": ecsTags(event.Whitelisted, event.KnownScanner),
		"truesignal": map[string]any{
			"event_id":    event.EventID,
			"seq":         event.Seq,
			"node_id":     event.NodeID,
			"node":        nodeAlias,
			"sensor_id":   event.SensorID,
			"trigger":     event.Trigger,
			"severity":    severity,
			"source":      event.Source,
			"target":      event.Target,
			"whitelisted": event.Whitelisted,
			// Added 2026-10-26; additive.
			"known_scanner": event.KnownScanner,
			"details":       details,
		},
	}

	if event.Enrichment.Asset != nil {
		doc["truesignal"].(map[string]any)["source_asset"] = event.Enrichment.Asset
	}
	if event.Enrichment.Location != nil {
		doc["truesignal"].(map[string]any)["source_geo"] = event.Enrichment.Location
	}
	// Mapped when the Hub's ATT&CK enrichment mapped it; names and
	// references come from the ATT&CK module's table.
	if event.Enrichment.Attack != nil {
		if m, ok := attack.For(event.Trigger); ok {
			doc["threat"] = ecsThreat(m)
			doc["truesignal"].(map[string]any)["attack"] = m
		}
	}

	// source.ip is an ip-typed field: only set it from a parseable address,
	// or Elastic rejects the whole document.
	if ip := net.ParseIP(event.Source); ip != nil {
		doc["source"] = map[string]any{"ip": ip.String()}
	} else if event.Source != "" {
		doc["source"] = map[string]any{"address": event.Source}
	}
	// source.geo describes source.ip only. A DNS beacon located by its
	// client subnet stays in truesignal.source_geo (basis client_subnet).
	if g := event.Enrichment.Location; g != nil && g.Basis == "source" {
		if src, ok := doc["source"].(map[string]any); ok {
			src["geo"] = ecsGeo(g)
		}
	}
	if port, ok := asPort(details["dst_port"]); ok {
		doc["destination"] = map[string]any{"port": port}
	}
	if user := ecsUser(details); user != nil {
		doc["user"] = user
	}
	if p, ok := details["path"].(string); ok && p != "" {
		if strings.HasPrefix(event.Trigger, "decoy_file_") {
			doc["file"] = map[string]any{"path": p}
		} else if strings.HasPrefix(event.Trigger, "web_") {
			doc["url"] = map[string]any{"path": p}
		}
	}
	if ua, ok := details["user_agent"].(string); ok && ua != "" {
		doc["user_agent"] = map[string]any{"original": ua}
	}
	if m, ok := details["method"].(string); ok && m != "" {
		doc["http"] = map[string]any{"request": map[string]any{"method": m}}
	}
	return doc
}

// ecsUser extracts the attempted account. Secrets (passwords, HMACs, NTLM
// responses) stay under truesignal.details only.
func ecsUser(details map[string]any) map[string]any {
	for _, key := range []string{"honeytoken_username", "username", "attempted_username", "bind_dn"} {
		name, ok := details[key].(string)
		if !ok || name == "" {
			continue
		}
		user := map[string]any{"name": name}
		// DOMAIN\user splits into user.domain / user.name whatever field it
		// came in (AD accepts it as a simple-bind name too), so joins with
		// Windows logs on user.name work. A real DN (cn=…,dc=…) stays whole.
		if !strings.Contains(name, "=") {
			if dom, u, found := strings.Cut(name, `\`); found && dom != "" && u != "" {
				user["domain"] = dom
				user["name"] = u
			}
		}
		return user
	}
	return nil
}

func asPort(v any) (int, bool) {
	f, ok := v.(float64) // JSON numbers decode as float64
	if !ok || f < 1 || f > 65535 || f != float64(int(f)) {
		return 0, false
	}
	return int(f), true
}

// ecsThreat renders an ATT&CK mapping as ECS threat.* fields. Sub-techniques
// go under threat.technique.subtechnique with their parent in
// threat.technique, as ECS specifies. The primary technique comes first;
// tactics are the primary technique's.
func ecsThreat(m attack.Mapping) map[string]any {
	var techIDs, techNames, techRefs, subIDs, subNames, subRefs []string
	seen := map[string]bool{}
	for _, t := range append([]attack.Technique{m.Primary}, m.Secondary...) {
		parentID, parentName, subName := t.ID, t.Name, ""
		if i := strings.IndexByte(t.ID, '.'); i > 0 {
			parentID = t.ID[:i]
			if j := strings.Index(t.Name, ": "); j > 0 {
				parentName, subName = t.Name[:j], t.Name[j+2:]
			}
			subIDs = append(subIDs, t.ID)
			subNames = append(subNames, subName)
			subRefs = append(subRefs, t.Reference())
		}
		if !seen[parentID] {
			seen[parentID] = true
			techIDs = append(techIDs, parentID)
			techNames = append(techNames, parentName)
			techRefs = append(techRefs, "https://attack.mitre.org/techniques/"+parentID+"/")
		}
	}
	technique := map[string]any{"id": techIDs, "name": techNames, "reference": techRefs}
	if len(subIDs) > 0 {
		technique["subtechnique"] = map[string]any{"id": subIDs, "name": subNames, "reference": subRefs}
	}
	var tacIDs, tacNames, tacRefs []string
	for _, tc := range m.Primary.Tactics {
		tacIDs = append(tacIDs, tc.ID)
		tacNames = append(tacNames, tc.Name)
		tacRefs = append(tacRefs, "https://attack.mitre.org/tactics/"+tc.ID+"/")
	}
	return map[string]any{
		"framework": attack.Framework,
		"technique": technique,
		"tactic":    map[string]any{"id": tacIDs, "name": tacNames, "reference": tacRefs},
	}
}

// ecsGeo renders a location as ECS geo fields (source.geo.*).
func ecsGeo(g *domain.Location) map[string]any {
	out := map[string]any{"country_iso_code": g.CountryCode}
	if g.Country != "" {
		out["country_name"] = g.Country
	}
	if g.Region != "" {
		out["region_name"] = g.Region
	}
	if g.City != "" {
		out["city_name"] = g.City
	}
	if g.Lat != 0 || g.Lon != 0 {
		out["location"] = map[string]any{"lat": g.Lat, "lon": g.Lon}
	}
	return out
}

func ecsTags(whitelisted, knownScanner bool) []string {
	tags := []string{"truesignal", "deception"}
	if whitelisted {
		tags = append(tags, "whitelisted")
	}
	if knownScanner {
		tags = append(tags, "known_scanner")
	}
	return tags
}

// ecsAudit renders an administrative action as an ECS document.
func (r Renderer) ecsAudit(rec domain.AuditRecord) map[string]any {
	if rec.Time.IsZero() {
		rec.Time = r.now()
	}
	outcome := "success"
	if rec.Status >= 400 || rec.Outcome == "failure" {
		outcome = "failure"
	}
	category, typ := []string{"configuration"}, []string{"change"}
	if strings.HasSuffix(rec.Path, "/login") || strings.HasSuffix(rec.Path, "/logout") || strings.HasSuffix(rec.Path, "/setup") {
		category, typ = []string{"authentication"}, []string{"info"}
	}
	doc := map[string]any{
		"@timestamp": rec.Time.UTC().Format(time.RFC3339Nano),
		"ecs":        map[string]any{"version": ecsVersion},
		"message":    fmt.Sprintf("TrueSignal audit %s -> %d", rec.Action, rec.Status),
		"event": map[string]any{
			"kind":     "event",
			"category": category,
			"type":     typ,
			"action":   rec.Action,
			"outcome":  outcome,
			"dataset":  "truesignal.audit",
			"module":   "truesignal",
		},
		"url":        map[string]any{"path": rec.Path},
		"truesignal": map[string]any{"audit": rec},
		"http":       map[string]any{"response": map[string]any{"status_code": rec.Status}},
		"observer": map[string]any{
			"type":    "honeypot",
			"vendor":  "TrueSignal",
			"product": "TrueSignal",
		},
		"tags": []string{"truesignal", "audit"},
	}
	if ip := net.ParseIP(rec.ActorIP); ip != nil {
		doc["source"] = map[string]any{"ip": ip.String()}
	}
	return doc
}

// ecsHoneytoken renders a honeytoken inventory record as an ECS enrichment
// document: the indicator a SIEM rule matches real authentication logs
// against (docs/siem/honeytoken-detection.md).
func (r Renderer) ecsHoneytoken(h domain.HoneytokenInventory) map[string]any {
	at := h.Time
	if at.IsZero() {
		at = r.now()
	}
	return map[string]any{
		"@timestamp": at.UTC().Format(time.RFC3339Nano),
		"ecs":        map[string]any{"version": ecsVersion},
		"message":    fmt.Sprintf("TrueSignal honeytoken %s planted by %s on %s", h.Username, h.PlantedSensorID, h.PlantedNodeID),
		"event": map[string]any{
			"kind":     "enrichment",
			"category": []string{"threat"},
			"type":     []string{"indicator"},
			"action":   "honeytoken_planted",
			"dataset":  "truesignal.honeytoken",
			"module":   "truesignal",
		},
		"user": map[string]any{"name": h.Username},
		"threat": map[string]any{
			"indicator": map[string]any{
				"type":        "user-account",
				"description": "TrueSignal honeytoken: fabricated account planted in a lure. Any authentication by it is malicious.",
				"provider":    "TrueSignal",
			},
		},
		"observer":   map[string]any{"type": "honeypot", "vendor": "TrueSignal", "product": "TrueSignal"},
		"tags":       []string{"truesignal", "honeytoken"},
		"truesignal": map[string]any{"honeytoken": h},
	}
}
