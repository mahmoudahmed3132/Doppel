# Handoff: merging TrueSignal-Rewrite with TrueSignal into a new repository

**For:** the agent that builds the merged repository (Claude Fable), and the owner.
**From:** the implementing agent of `mahmoudahmed3132/TrueSignal-Rewrite` (Claude Code session `session_01TGdGKDp6wnhogyaRQY1eEm`).
**State described:** `TrueSignal-Rewrite` `main` at `650c285`, 2026-11-15.
**Read with:** `docs/merge/FABLE-PROMPT.md`, the task prompt.

## 0. Read this first: what the merge puts at risk

`TrueSignal-Rewrite` is a **clean-room** implementation. Its specification
(*TrueSignal-CleanRoom-Spec-v1*, §0) prohibited any access to:

- `mahmoudahmed3132/TrueSignal`;
- `andreicscs/HoneyWire` and any project named HoneyWire;
- the `ghcr.io/mahmoudahmed3132/truesignal-*` images.

`PROVENANCE.md` and `HANDOVER.md` attest that this was honoured, and §14.14
(an independence check run by the specification team) is the objective
control. The clean room exists because earlier code may derive from HoneyWire.

Merging the old `TrueSignal` code **ends the clean room for whatever is
merged**. That is the owner's call to make, but it has consequences:

1. **Code derived from HoneyWire must not enter the new repository** unless
   the owner has HoneyWire's licence, or other rights, to it. Merging such code
   reintroduces exactly what the rewrite was built to remove, and turns the
   §14.14 result for the merged repository into a finding.
2. **Code the owner wrote independently** in `TrueSignal` is the owner's to
   use. The rewrite already has a channel for it: **PORTED modules** (spec §12;
   `docs/ported-seams.md`). Each is delivered as an owner-attested inbox, and
   integrating one is mechanical. Step 1 (the Sigstore verifier and the
   source-list matcher) arrived exactly that way (`PROVENANCE.md`, 2026-11-01).
3. **The agent that reads `TrueSignal` is contaminated** for any feature it
   reads there that turns out to derive from HoneyWire. It must not write a
   clean replacement for that feature itself. It writes a prose specification,
   and a separate session that has never seen either codebase implements it
   (two-room clean room).

The prompt therefore sets up a **gated merge**:

- the new repository starts from `TrueSignal-Rewrite`, history included, so
  provenance carries over;
- every file or feature taken from `TrueSignal` passes a provenance gate and
  is recorded;
- anything that fails the gate is specified in prose for a clean
  reimplementation, or dropped.

If the owner wants an **ungated** merge instead, accepting HoneyWire-derived
code, that is a legal decision. Make it in writing before work starts and
record it in `PROVENANCE.md` and `QUESTIONS.md` of the new repository. The
prompt has a switch for it (§ "Owner decisions").

## 1. What TrueSignal-Rewrite is

TrueSignal Core is a deception platform: a Hub, per-node agents, and decoy sensors.

| Path | Contents |
|---|---|
| `hub/` | Go Hub. SQLite (modernc, pure Go) with snapshot-before-migrate; node ingest API (contract v3, `tsk_` node keys, UUIDv7); event pipeline and enrichment seams; liveness; admin auth (argon2id, lockouts, MFA flows, sessions, CSRF); nodes and sensors API; compose compiler with the §6.12 hard rules; signed sensor catalogue (Sigstore, verified **before** parsing); SIEM (RFC 5424 syslog, ECS seam), webhooks, audit; events, analytics, retention, factory reset, update check, live feed (WebSocket); embedded admin UI (`go:embed`) |
| `cli/` | Node agent `truesignal`: link, apply (docker compose, with rollback), discover, firedrill, status, uninstall |
| `install.sh` | Verified installer: SHA256SUMS, optional `--sha256` pin, cosign identity check |
| `sdk/go`, `sdk/python` | Sensor SDKs (zero third-party dependencies; Python standard library only) |
| `sensors/` | tcp-tarpit, icmp-canary, network-scan-detector, file-canary, web-router-decoy, template |
| `ui/` | Preact 11 + TypeScript 7 + esbuild. Strict CSP: no inline script or style, enforced by a safety lint |
| `.github/workflows/` | CI, CodeQL (gated in the job, Q65), publish-hub, publish-cli, publish-sensor, registry-rollback. Every action pinned by commit SHA |
| `scripts/` | Licence-header check, compose guard, docs/OpenAPI validator, release scripts with a self-test, CodeQL gate, real-Docker end-to-end test |
| `docs/` | Contract v3, OpenAPI, manifest v3 and its JSON Schema, registry, SIEM, CLI, sensors, operations guide, PORTED seams, acceptance mapping |
| Governance | `PROVENANCE.md` (append-only), `QUESTIONS.md` (Q1–Q65), `THIRD_PARTY.md`, `THREATMODEL.md`, `HANDOVER.md`, proprietary `LICENSE` |

**Toolchain:**
- Go 1.26.10, pinned in `go.work` and every `go.mod`; `CGO_ENABLED=0`; one `go.work` monorepo.
- Node 22 for the UI.
- Python 3 for the SDK and validators.

**Quality bar, which the merged repository must keep:**
- `make` runs header check, gofmt, vet and `-race` tests on every module.
- Other gates:
  - `make ui`;
  - `python3 scripts/validate-docs.py`, which checks manifests against the schema and OpenAPI against the registered routes;
  - `scripts/compose-guard.sh`;
  - `scripts/release/selftest.sh`.
- CI also runs:
  - Trivy, failing on fixable HIGH/CRITICAL in dependencies and every image;
  - the CodeQL gate;
  - a real-Docker end-to-end test (`scripts/e2e/real-docker.sh`).
- Every source file starts with
  `Copyright (c) 2026 TrueSignal Deception. All rights reserved.`
- Dependencies must use permissive licences only (MIT, BSD, Apache-2.0, ISC,
  MPL-2.0 file-level), each recorded in `THIRD_PARTY.md`. No GPL, AGPL or LGPL.

## 2. Interfaces the merge must fit

- **PORTED seams.** `hub/internal/ported/ported.go` and `docs/ported-seams.md`.
  Each module has:
  - an interface;
  - the field it is wired into (in `hub/cmd/truesignal-hub/main.go`);
  - fail-closed or feature-off behaviour while absent;
  - a test stub.

  **Installed:** the Sigstore manifest verifier and the source-list matcher.

  **Still open:**
  - GeoIP, asset inventory, ATT&CK mapping, TOTP and recovery codes;
  - beacons, honeytokens, ECS renderer, HTTP SIEM transports, analytics projections;
  - file-canary lures, web-router skins, the SDK decoy helper;
  - five additional decoys, SIEM detection rules.

  These are the natural landing places for code from `TrueSignal`: a module
  that implements the seam needs no other change.
- **Contracts that must not drift:**
  - `docs/contract-v3.md` (node API);
  - `docs/manifest-v3.md` plus its schema;
  - `docs/openapi.yaml`, which CI checks against the routes;
  - `docs/audit-actions.md`;
  - the §6.12 compose rules in `hub/internal/compose`, mutation-tested.

  A feature from `TrueSignal` that needs a contract change goes through a
  `QUESTIONS.md` entry with the conservative default, not a silent edit.

## 3. Release and supply chain: what the new repository name breaks

Signing identities embed the **repository name**:
`https://github.com/<repo>/.github/workflows/publish-{hub,cli,sensor}.yml@refs/tags/...`.
A new repository therefore changes every identity:

| Consumer | Current value | Action in the new repository |
|---|---|---|
| Hub manifest verifier | `signing.DefaultSignerRepo` = `mahmoudahmed3132/TrueSignal-Rewrite` | Set to the new repository. Existing registry manifests (five sensors at `1.0.0`) will **no longer verify**: republish each sensor from the new repository at a new version (`1.0.1`, or whatever the owner prefers) |
| `install.sh` | `SIGNER_REPO` | New repository; existing `cli/v3.0.0` assets keep verifying only under the old identity, so cut a new CLI release |
| Docs (`docs/operations.md` §1, §7, §9.1; `docs/cli.md`) and `QUESTIONS.md` Q46 | old identity | New repository. Workflows and `hub-latest.sh` derive it from `github.repository` and follow automatically |
| Test fixtures | `hub/internal/signing/testdata/registry` holds real bundles signed by the old identity, and `TestRealPublishedManifestsVerify` pins that identity | Keep them as historical fixtures with the old repository passed explicitly; add fixtures from the first new publish |
| Public artefacts | `mahmoudahmed3132/truesignal-releases`: registry branch, releases, `install.sh` (Q64; `docs/operations.md` §9.1) | Keep this repository; repoint the GitHub App installation and the `RELEASES_APP_*` variable and secret to the new source repository |
| GHCR images | `ghcr.io/mahmoudahmed3132/ts-hub`, `ts-sensor-<name>` (Q60) | Keep the names. Never use the `truesignal-*` image names, which are in the prohibited namespace |

**Release status:**
- Hub `3.0.0-rc.1`: pre-release only.
- CLI `3.0.0`.
- Five sensors at `1.0.0`.
- **Not yet done by the owner:** setting up `truesignal-releases` and running
  `scripts/release/migrate-releases-repo.sh` (operations §9.1, steps 1–6).
  Until then, Hubs cannot load the catalogue anonymously.

## 4. Decisions already taken (keep them unless the owner changes them)

See `QUESTIONS.md` for all 65. The ones a merge is most likely to collide with:

| Q | Decision |
|---|---|
| Q1 | Proprietary licence; repository private |
| Q27 | The CLI injects the node key; it is never written into the rendered compose |
| Q32/Q64 | Registry served from `truesignal-releases`, branch `registry`, via raw.githubusercontent |
| Q46 | CLI asset names and signing identity |
| Q47 | Privileged sensors run as UID 0 with `cap_drop: ALL` plus one capability |
| Q52 | Factory reset is refused if its audit record cannot be delivered |
| Q56 | Projection names |
| Q60 | Image names `ts-hub`, `ts-sensor-<name>` |
| Q61/Q63 | Publish guards; sensor versions are plain `X.Y.Z` |
| Q65 | No GitHub code scanning; CodeQL gated in the job against `.github/codeql/accepted-findings.json` (rule + file + line fingerprint + reason) |

## 5. Residual risks carried into the new repository

The full list is in `THREATMODEL.md`. The main ones:

- **R1:** Hub secrets are stored in plaintext in SQLite. Protect the volume
  and backups.
- **R2:** an `http://` Hub endpoint is accepted; the CLI only warns.
- **Development flags:** `TS_DEV_ALLOW_UNSIGNED_MANIFESTS` and
  `TS_DEV_ALLOW_UNPINNED_IMAGES`. They must never be set in production.
- **App key:** a leaked `truesignal-releases` App key allows rollback or
  withholding of registry content and replacement of `install.sh`. It cannot
  forge signatures.
- **CodeQL acceptances:** the accepted log-injection findings rely on the Hub
  logging through `slog.NewJSONHandler` only. Changing the handler re-opens
  them.

## 6. What "done" looks like for the merge

1. **The new private repository** starts from `TrueSignal-Rewrite` history,
   and every quality gate in §1 passes in CI.
2. **`MERGE-INVENTORY.md`** has one row for each feature or module in
   `TrueSignal` that is not in `TrueSignal-Rewrite`, with:
   - its provenance class: owner-original, HoneyWire-derived, third-party or
     unknown;
   - the evidence;
   - the decision: imported, specified for clean reimplementation, or dropped.
3. **Imported code** arrives through the PORTED seams or new seams, with
   headers, tests, `THIRD_PARTY.md` rows, and one `PROVENANCE.md` row per
   import.
4. **Specs for clean reimplementation:** each feature that is HoneyWire-derived
   or of unknown provenance has a prose spec under `docs/clean-specs/`. The
   spec contains no code, identifiers or layout copied from the source.
5. **Signing identities and defaults** point at the new repository, with the
   republish plan in §3 written down for the owner.
6. **Nothing from `andreicscs/HoneyWire`** is copied into the new repository,
   unless the owner made the written ungated decision.
