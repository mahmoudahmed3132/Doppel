// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package ecs

import (
	"slices"
	"testing"
)

// TestDrillDocument: a fire drill reaches the SIEM labelled (F-001):
// event.kind pipeline_test, labels.drill true, tag "drill". Other events
// carry none of these.
func TestDrillDocument(t *testing.T) {
	e := ldapLoginEvent()
	e.Drill, e.Severity, e.Source = true, "info", "Fire drill"
	doc := roundTrip(t, Renderer{}.ecsEvent(e))
	if get(doc, "event.kind") != "pipeline_test" || get(doc, "labels.drill") != true {
		t.Fatalf("drill: kind %v labels %v", get(doc, "event.kind"), get(doc, "labels"))
	}
	tags, _ := doc["tags"].([]any)
	if !slices.Contains(tags, any("drill")) {
		t.Fatalf("tags %v", tags)
	}

	plain := roundTrip(t, Renderer{}.ecsEvent(ldapLoginEvent()))
	if get(plain, "event.kind") != "alert" || plain["labels"] != nil || slices.Contains(plain["tags"].([]any), any("drill")) {
		t.Fatalf("non-drill labelled: %v", plain)
	}
}
