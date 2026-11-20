// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package syslog

import (
	"bytes"
	"testing"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/domain"
)

// TestDrillParam: a fire drill carries drill="1" as the last SD parameter;
// other events do not carry it (F-001).
func TestDrillParam(t *testing.T) {
	e := event("Fire drill")
	e.Drill = true
	line, err := Format(domain.Record{Kind: domain.RecordEvent, Event: e}, DefaultPEN)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(line, []byte(`source_geo_basis="" drill="1"] {`)) {
		t.Fatalf("drill param missing or not last: %s", line)
	}
	line, _ = Format(domain.Record{Kind: domain.RecordEvent, Event: event("203.0.113.9")}, DefaultPEN)
	if bytes.Contains(line, []byte(`drill="`)) {
		t.Fatalf("non-drill carries drill param: %s", line)
	}
}
