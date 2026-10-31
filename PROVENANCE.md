# Provenance log

Rule source: Clean-Room Implementation Specification v1, §0.6.

Every entry records date, implementer, component, sources used, and incidents
under §0.1. Entries are append-only.

## Implementer disclosure (applies to every entry by "AI agent")

The AI agent is a large language model. Its training data is a broad crawl of
public text and code and **may** include public repositories named in §0.1.
The agent cannot inspect or exclude specific items of its training data. To
comply with §0.2 the agent:

- uses only the specification, public RFCs/standards and public library
  documentation as design inputs;
- did not open, search, clone or fetch any repository, image or package named
  in §0.1 during the session (GitHub access for the session was scoped to
  `mahmoudahmed3132/TrueSignal-Rewrite` only);
- designs package layout, identifiers and algorithms from the specification
  text, not from recollection of any existing implementation.

Counsel should weigh this disclosure when assessing §0.2; the similarity
analysis of §14.14 is the objective control.

## Entries

| Date | Implementer | Component | Sources used | Incidents |
|---|---|---|---|---|
| 2026-10-31 | AI agent, session `session_01TGdGKDp6wnhogyaRQY1eEm` | Repository scaffolding, `PROVENANCE.md`, `QUESTIONS.md`, `THIRD_PARTY.md`, `Makefile`, `go.work` | Spec §0, §2, §10, §15 | None |
| 2026-10-31 | AI agent, session `session_01TGdGKDp6wnhogyaRQY1eEm` | `sdk/go` (Go Sensor SDK), `sensors/template` | Spec §4, §5; RFC 9562 (UUIDv7); Go standard library docs | None |
| 2026-10-31 | AI agent, session `session_01TGdGKDp6wnhogyaRQY1eEm` | `docs/contract-v3.md` | Spec §4 | None |
| 2026-10-31 | AI agent, session `session_01TGdGKDp6wnhogyaRQY1eEm` | `hub/internal/{domain,ported,ported/stub,store,ids,nodekey,ingest}` | Spec §3, §4.2, §6.2, §6.3 (node keys), §6.5, §12; SQLite docs (`PRAGMA user_version`, `VACUUM INTO`, UPSERT/RETURNING); modernc.org/sqlite docs | None |
| 2026-10-31 | AI agent, session `session_01TGdGKDp6wnhogyaRQY1eEm` | `hub/internal/siem/syslog` | Spec §6.9; RFC 5424 §6 | None |
| 2026-10-31 | AI agent, session `session_01TGdGKDp6wnhogyaRQY1eEm` | `hub/internal/{config,liveness,ratelimit,httpapi}`, `hub/cmd/truesignal-hub`, `docs/acceptance.md` | Spec §4.1, §4.3, §4.4, §6.1, §6.3 (break-glass), §6.6, §14; Go `net/http` docs | None |
| 2026-10-31 | AI agent, session `session_01TGdGKDp6wnhogyaRQY1eEm` | `hub/internal/{auth,audit}`, admin routes in `hub/internal/httpapi`, `docs/audit-actions.md`, `docs/openapi.yaml` | Spec §6.3, §6.4 (session/MFA/system password rows), §6.10, §13; RFC 9106 (argon2 parameters); RFC 6238 (step semantics only — TOTP core is PORTED); OWASP guidance on CSRF Origin checks; `golang.org/x/crypto/argon2` docs | None |
| 2026-10-31 | AI agent, session `session_01TGdGKDp6wnhogyaRQY1eEm` | `hub/internal/fleet`, fleet routes in `hub/internal/httpapi`, `store.ApplySensorChanges` | Spec §3 (node, sensor instance), §6.4 (Nodes, Sensors rows), §6.12 rules 6, 9, 11 (seam only), §7 item 5, §8 (`link` via env var); SemVer 2.0.0 precedence | None |
| 2026-10-31 | AI agent, session `session_01TGdGKDp6wnhogyaRQY1eEm` | `hub/internal/{manifest,compose,secrets}`, `sensors/template/manifest.json`, `docs/manifest-v3.md`, `docs/manifest-v3.schema.json` | Spec §6.12, §9, §11.4 (mount design), §12 (honeytoken seam); Compose Specification (long-syntax volumes/ports, `depends_on` conditions, extension fields); JSON Schema 2020-12; Linux capabilities(7) | None |
| 2026-10-31 | AI agent, session `session_01TGdGKDp6wnhogyaRQY1eEm` | `hub/internal/{catalogue,semver}`, catalogue routes, schema v2, `docs/registry.md` | Spec §6.7, §10 (immutable versions, registry branch, rollback), §12 (verifier seam); SemVer 2.0.0 §11 precedence | None |
| 2026-10-31 | AI agent, session `session_01TGdGKDp6wnhogyaRQY1eEm` | `hub/internal/{siem,webhook,enrich}`, output routes, `docs/siem-integration.md` | Spec §6.5 (steps 6, 8, 11), §6.6 (Hub heartbeat), §6.8, §6.9, §6.10; RFC 5424; Discord (allowed_mentions, embed limits), Slack (message escaping) and ntfy/gotify public API docs | None |
| 2026-10-31 | AI agent, session `session_01TGdGKDp6wnhogyaRQY1eEm` | `cli/` (node agent), `install.sh`, node endpoints `hub/internal/httpapi/node.go`, `fleet.Deploy`, `docs/cli.md` | Spec §4.4, §8, §6.12 (compose contract); proc(5) (`/proc/net/tcp`, `/proc/<pid>/fd`, `comm`); Docker Compose CLI reference (`pull`, `up`, `down`, `ps --format json`); flock(2); cosign `verify-blob` docs | None |
| 2026-10-31 | AI agent, session `session_01TGdGKDp6wnhogyaRQY1eEm` | `sensors/{tcp-tarpit,icmp-canary,network-scan-detector,file-canary,web-router-decoy}`, `node_apply_failed`, `listen_ports.container_port`, `docs/sensors.md` | Spec §11, §12 (lure and skin seams); RFC 792/4443 (ICMP types), RFC 9293 (TCP header/flags/options); packet(7), inotify(7), capabilities(7), open(2) `O_EXCL`/`O_NOFOLLOW`; public scanner fingerprints (nmap SYN window/options, masscan window, ZMap IP-ID 54321); Docker capability/user semantics | None |
| 2026-10-31 | AI agent, session `session_01TGdGKDp6wnhogyaRQY1eEm` | `hub/internal/{hubsettings,analytics,updatecheck,livefeed}`, events/system/insights routes, store extras | Spec §6.2 (retention), §6.4 (events, analytics, honeytokens, beacons, assets, settings, system, live feed), §6.11, §6.13; RFC 6455 (WebSocket framing, handshake, §1.3 example); RFC 4180 (CSV) and OWASP CSV-injection guidance; GitHub REST releases docs | None |
| 2026-10-31 | AI agent, session `session_01TGdGKDp6wnhogyaRQY1eEm` | `ui/` (admin SPA), `hub/internal/webui` (embedded static handler) | Spec §6.4 (API surface), §7, §13 (CSP, headers); this repository's `docs/openapi.yaml`; Preact, esbuild and TypeScript public docs; HTML `<dialog>` and WAI-ARIA authoring practices; CSP Level 3 (`connect-src 'self'` and WebSocket); RFC 6238 `otpauth` URI format | None |
| 2026-10-31 | AI agent, session `session_01TGdGKDp6wnhogyaRQY1eEm` | `.github/` (CI, CodeQL, publish-hub/cli/sensor, registry-rollback, Dependabot), `scripts/release/`, `scripts/{compose-guard.sh,validate-docs.py}`, `hub/Dockerfile`, `hub/cmd/ts-registry`, `hub/internal/registrytool`, `deploy/compose.yaml`, `docs/operations.md`, image rename (Q60) | Spec §0, §10, §13; GitHub Actions workflow syntax and OIDC docs; `action.yml` of each pinned action read at its pinned commit (inputs only); cosign `sign`/`sign-blob`/`verify` docs; Docker Buildx and Compose docs; crane docs; Trivy CLI docs | None. Tag→commit lookups used `git ls-remote` on the public action repositories only. An attempt to install actionlint from source was blocked by the session's permission policy and not pursued |
| 2026-10-31 | AI agent, session `session_01TGdGKDp6wnhogyaRQY1eEm` | Security fixes from the first CI run: Go toolchain 1.26.2 → 1.26.10 (20 HIGH stdlib CVEs reported by Trivy), `toolchain` directives, `golang` base-image digest, preact 10.27.2 → 10.28.4 (CVE-2026-22028), sensor-image scanning, `make fmt` | GitHub Actions logs of run 41223540669; Docker Hub registry API (manifest digest lookup only); Go module proxy toolchain list | None |
| 2026-10-31 | AI agent, session `session_01TGdGKDp6wnhogyaRQY1eEm` | `THREATMODEL.md`; correction in `docs/operations.md` (secrets at rest are plaintext, not encrypted) | Spec §13, §15; this repository's code | None |
| 2026-10-31 | AI agent, session `session_01TGdGKDp6wnhogyaRQY1eEm` | `sdk/python` (Python SDK, template sensor, tests), CI job `python-sdk` | Spec §4, §5, §11.6; this repository's Go SDK and contract docs; RFC 9562 (UUIDv7); Python standard library docs (`urllib.request`, `ssl`, `signal`, `threading`, `http.server`) | None |
