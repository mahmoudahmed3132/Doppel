// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package httpapi

import (
	"encoding/json"
	"testing"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/attack"
	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
)

// The real ATT&CK module (merge import H3/H4) behind the Hub's routes: the
// status reports it, the Navigator layer is a valid 4.5 layer listing the
// covered techniques, and attack_matrix is mounted as a projection.
func TestRealAttackModule(t *testing.T) {
	h := newInsightHubWith(t, func(in *Insights) {
		in.Attack = attack.Mapper{}
		in.Projections = map[string]ported.Projection{"attack_matrix": attack.MatrixProjection{}}
	})
	_, out, _ := h.c.do("GET", "/api/v3/system/status", nil)
	if mods := out["status"].(map[string]any)["modules"].(map[string]any); mods["attack"] != true {
		t.Fatalf("modules %v", mods)
	}
	code, layer, _ := h.c.do("GET", "/api/v3/analytics/attack/navigator?days=30", nil)
	if techs, _ := layer["techniques"].([]any); code != 200 || layer["domain"] != "enterprise-attack" || len(techs) != len(attack.Covered()) {
		t.Fatalf("navigator %d %v", code, layer)
	}
	code, out, _ = h.c.do("GET", "/api/v3/analytics/projections/attack_matrix?days=30", nil)
	if code != 200 {
		t.Fatalf("attack_matrix %d %v", code, out)
	}
	b, _ := json.Marshal(out["data"])
	var d attack.DTO
	if err := json.Unmarshal(b, &d); err != nil || d.TechniquesCovered != len(attack.Covered()) || len(d.Tactics) != 14 {
		t.Fatalf("matrix %+v %v", d, err)
	}
}
