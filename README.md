# TrueSignal

Self-hosted deception platform: a Hub, node agent CLI, Go sensor SDK and
containerised decoy sensors. Clean-room implementation of specification v1.

| Path | Contents | Status |
|---|---|---|
| `sdk/go` | Go Sensor SDK (contract v3) | implemented |
| `sensors/template` | reference sensor + Dockerfile | implemented |
| `sdk/python` | Python SDK (§11.6, stdlib only) + template sensor | implemented |
| `sensors/{tcp-tarpit,icmp-canary,network-scan-detector,file-canary,web-router-decoy}` | §11 sensors (lure content and web skins are PORTED seams with stubs) | implemented |
| `hub/` | Hub server | storage, ingest API, pipeline, liveness, syslog formatter, admin auth + MFA flows, nodes/sensors API, compose compiler + manifest v3, catalogue, SIEM output, webhooks, audit delivery, events/settings/analytics/system APIs, retention, factory reset, update check, live feed done; PORTED step 1 installed (Sigstore manifest verifier, source-list matcher); merged modules: File Canary lure content, projections (sources, geo map, attack path, report), Elastic/LogScale outputs, ECS output, beacons, honeytokens, ATT&CK mapping and Navigator layer, asset inventory, GeoIP, TOTP and recovery codes |
| `cli/` | node agent CLI `truesignal` + `install.sh` | implemented (tested with simulated and real Docker; `cli/v3.0.0` released) |
| `ui/` | admin web UI (Preact + TypeScript, embedded in the Hub) | done (§7); PORTED pages are shells |
| `.github/`, `scripts/release/` | CI, CodeQL, publish (Hub, CLI, sensors), registry rollback | done (§10); publish-hub (`hub/v3.0.0-rc.1`), publish-cli (`cli/v3.0.0`) and publish-sensor (five sensors at `1.0.0`) have run on GitHub; registry-rollback has not been run yet |
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

Releases: `docs/operations.md` §9 (`make tag-hub`, `tag-cli`, `tag-sensor NAME=…`).
This repository is private: releases, `install.sh` and the sensor registry are
published to the public repository `mahmoudahmed3132/truesignal-releases`
(setup and migration: `docs/operations.md` §9.1).

A Hub built without `make ui` runs normally and serves a placeholder page
instead of the UI.
