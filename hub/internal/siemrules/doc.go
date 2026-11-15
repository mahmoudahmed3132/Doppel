// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package siemrules holds the tests that keep the shipped SIEM detection
// rules (docs/siem/) in step with what the Hub emits: the sample corpus
// docs/siem/testdata/detection-samples.ndjson is generated through the real
// ingest pipeline, enrichment modules and SIEM ECS output, and every field a
// rule references must exist in it. See docs/siem/detection-rules.md.
package siemrules
