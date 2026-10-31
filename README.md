# TrueSignal

Self-hosted deception platform: a Hub, node agent CLI, Go sensor SDK and
containerised decoy sensors. Clean-room implementation of specification v1.

| Path | Contents | Status |
|---|---|---|
| `sdk/go` | Go Sensor SDK (contract v3) | implemented |
| `sensors/template` | reference sensor + Dockerfile | implemented |
| `hub/` | Hub server | storage, ingest API, pipeline, liveness, syslog formatter, admin auth + MFA flows, nodes/sensors API, compose compiler + manifest v3 done; catalogue, SIEM transport, webhooks, audit pending |
| `cli/` | node agent CLI `truesignal` | not started |
| `ui/` | admin web UI | not started |
| `docs/` | contract, manifest schema, API, operations | partial |

Governance files: `PROVENANCE.md`, `QUESTIONS.md`, `THIRD_PARTY.md`.

## Development

Requires Go 1.26+.

```sh
make            # header check, go vet, go test -race in every module
```
