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
| `.github/`, `scripts/release/` | CI, CodeQL, publish (Hub, CLI, sensors), registry rollback | done (§10); not yet run on GitHub |
| `deploy/` | production Hub compose | done |
| `docs/`, `THREATMODEL.md` | contract, manifest schema, API, registry, SIEM, CLI, sensors, operations, threat model | done |

Governance files: `PROVENANCE.md`, `QUESTIONS.md`, `THIRD_PARTY.md`.

## Development

Requires Go 1.26.10+ (the `toolchain` directive enforces it; earlier 1.26 patches carry HIGH stdlib CVEs).

```sh
make            # header check, go vet, go test -race in every module
make ui         # admin UI: npm ci, type-check, safety lint, build (Node 22+)
make hub-bin    # UI + Hub binary with the UI embedded -> bin/truesignal-hub
```

Releases: `docs/operations.md` §8 (`make tag-hub`, `tag-cli`, `tag-sensor NAME=…`).

A Hub built without `make ui` runs normally and serves a placeholder page
instead of the UI.
