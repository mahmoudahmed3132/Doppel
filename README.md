# TrueSignal

Self-hosted deception platform: a Hub, node agent CLI, Go sensor SDK and
containerised decoy sensors. Clean-room implementation of specification v1.

| Path | Contents | Status |
|---|---|---|
| `sdk/go` | Go Sensor SDK (contract v3) | implemented |
| `sensors/template` | reference sensor + Dockerfile | implemented |
| `sensors/{tcp-tarpit,icmp-canary,network-scan-detector,file-canary,web-router-decoy}` | §11 sensors (lure content and web skins are PORTED seams with stubs) | implemented |
| `hub/` | Hub server | storage, ingest API, pipeline, liveness, syslog formatter, admin auth + MFA flows, nodes/sensors API, compose compiler + manifest v3, catalogue, SIEM output, webhooks, audit delivery, events/settings/analytics/system APIs, retention, factory reset, update check, live feed done |
| `cli/` | node agent CLI `truesignal` + `install.sh` | implemented (tested with simulated Docker) |
| `ui/` | admin web UI (Preact + TypeScript, embedded in the Hub) | done (§7); PORTED pages are shells |
| `docs/` | contract, manifest schema, API, operations | partial |

Governance files: `PROVENANCE.md`, `QUESTIONS.md`, `THIRD_PARTY.md`.

## Development

Requires Go 1.26+.

```sh
make            # header check, go vet, go test -race in every module
make ui         # admin UI: npm ci, type-check, safety lint, build (Node 22+)
make hub-bin    # UI + Hub binary with the UI embedded -> bin/truesignal-hub
```

A Hub built without `make ui` runs normally and serves a placeholder page
instead of the UI.
