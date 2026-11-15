// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package httpapi

import (
	"testing"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/projections"
)

// The real projections (merge import H11) mounted on the Hub's projection
// route: the status lists them and each builds from the window.
func TestRealProjectionModules(t *testing.T) {
	h := newInsightHubWith(t, func(in *Insights) {
		in.Projections = map[string]ported.Projection{}
		for _, p := range []ported.Projection{projections.Sources{}, projections.GeoMap{}, projections.AttackPath{}, projections.Report{}} {
			in.Projections[p.Name()] = p
		}
	})
	_, out, _ := h.c.do("GET", "/api/v3/system/status", nil)
	if mods := out["status"].(map[string]any)["modules"].(map[string]any); len(mods["projections"].([]any)) != 4 {
		t.Fatalf("modules %v", mods)
	}
	for _, name := range []string{"sources", "geo_map", "attack_path?source=s", "report"} {
		code, out, _ := h.c.do("GET", "/api/v3/analytics/projections/"+name, nil)
		if code != 200 || out["data"] == nil {
			t.Fatalf("%s: %d %v", name, code, out)
		}
	}
	if code, _, _ := h.c.do("GET", "/api/v3/analytics/projections/report?from=nonsense", nil); code != 400 {
		t.Fatalf("bad report range: %d", code)
	}
}
