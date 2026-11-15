# Doppel merge report

**Date:** 2026-11-15. **Session:** `session_01TGdGKVZG4Vx1K`.
See `docs/poc.md` to run a local POC.

**Base:** `TrueSignal-Rewrite` `main` at `cc05d14` (full history kept).
**Source of extra features:** `TrueSignal` at `f4455a0`; HoneyWire used for
similarity checks only, never copied.
**Rule:** only code Claude wrote new (HANDOFF §0); approvals in QUESTIONS
Q66–Q71; evidence in `MERGE-INVENTORY.md`; one `PROVENANCE.md` row per step.

## 1. Outcome

Doppel is the base plus every Claude-new TrueSignal feature behind the base's
PORTED seams. Every open seam except the four decoys is now installed. A
production Hub now has MFA, GeoIP, an asset inventory, ATT&CK enrichment
and Navigator export, honeytokens, beacons with a Token Receiver, ECS output
with Elastic and LogScale transports, six analytics projections, realistic
lures and web skins, and a tested set of 16 SIEM detection rules. The four
protocol decoys and the dedicated UI pages are written as clean specs for
separate sessions.

## 2. Branches (stacked, in merge order)

| # | Branch | Tip | Content |
|---|---|---|---|
| — | `main` | `b7834bb` | base + `fix/baseline-cves` + `merge/inventory` (approved and merged) |
| 1 | `rebrand/module-path` | `ad9b896` | Go module paths → `github.com/mahmoudahmed3132/Doppel` (**also contains 6 sensor binaries by mistake**, removed in #12) |
| 2 | `supply-chain/repoint` | `d66b603` | signer repository → Doppel; historical fixtures; republish plan |
| 3 | `import/totp` | `9b88051` | H5, H6 |
| 4 | `import/geoip` | `a2b71f7` | H1 |
| 5 | `import/assets` | `e81b8c2` | H2 |
| 6 | `import/attack` | `998f49d` | H3, H4 (+ `attack_matrix`) |
| 7 | `import/honeytokens` | `aa77a5a` | H8 |
| 8 | `import/beacons` | `6e6b741` | H7 |
| 9 | `import/ecs` | `e2198ca` | H9 |
| 10 | `import/siem-http` | `2cc251b` | H10 |
| 11 | `import/projections` | `7bb3879` | H11 |
| 12 | `import/lures` | `b015b0c` | binary removal (`227707d`), S1 |
| 13 | `import/skins` | `4def533` | S2 |
| 14 | `import/token-receiver` | `5ac2ab9` | S3, S4 |
| 15 | `import/siem-rules` | `af117ab` | R1, R2; compose test fix for S4 |
| 16 | `docs/clean-specs` | `f636a3e` | specs for S5–S8, H12, U1/U2 |
| 17 | `rebrand/doppel` | `df87f7b` | approved rebrand (Q66, Q71) |
| 18 | `docs/merge-report` | this | this report, `UPLOAD.md` |

## 3. Imported, specified, dropped

**Imported (claude-new, adapted through the seams):** TOTP and recovery codes,
GeoIP, asset inventory, ATT&CK mapper, Navigator layer and `attack_matrix`,
honeytoken service, beacon service, ECS renderer, Elastic/LogScale transports,
projections `sources` / `geo_map` / `attack_path` / `report`, File Canary
lures, web skins, the Go decoy helper `sdk/go/decoy`, the Token Receiver
sensor, and the SIEM detection rules with their harness. Per-step changes are
in `PROVENANCE.md`. Shared adaptations: HoneyWire-pattern stores, models and
retry loops were never imported, and keys, storage and event types are the
base's.

**Specified for clean implementation (`docs/clean-specs/`):** Identity,
Database, Remote Access and Network Service decoys (self-declared ports "in
concept" of Trapster Community, AGPL: Q68); the `insights` projection (built
on HoneyWire's projection structure: H12); dedicated analytics pages (Vue
code: Q69).

**Dropped:** the TrueSignal wizard, release workflows and scripts, Hub
hardening edits to HoneyWire code (the base has its own controls), TS
knowledge docs and SOC notices, the HoneyWire-pattern sensor `main.go`
files, TS custom skins (`TS_SKIN_JSON`) and the router brand table.

## 4. Class evidence (summary)

- 146 TrueSignal commits: 80 Claude-attributed, each with both trailers and on
  a `claude/*` branch; 8 owner commits (import, licence, CI, Makefile); bot
  registry commits. The HoneyWire import is `05d5203` + `e5362b4`.
- Per-file blame (`-w -M -C -C`) over significant lines; HoneyWire similarity
  against all 506 commits of its history. Every imported file is ≥ 95%
  Claude lines with ≤ 12% HoneyWire overlap, and the overlap is boilerplate.
  Mixed files are imported hunk by hunk (H6, H10) or not at all.
- PORTED step 1 traced to Claude commits `dde6819` and `e9a0d3e`/`bf73560`:
  byte-identical, claude-new, kept.
- Base: 13 unattributed commits = 11 Dependabot bumps + the owner's
  `LICENSE` and deploy-key commits (kept).

## 5. Gates

Tools: Go 1.26.10, Node 22.23, Python 3.13 (pyyaml 6.0.3, jsonschema
4.26.0), Docker 29.9 + compose 5.6, Trivy 0.70.0 (checksum verified), CodeQL
2.27.3 (the bundle pinned by `codeql.yml`, checksum verified). Local runner
`gates.sh` mirrors CI. One environment shim: in this cloud container the
image builds trust the session's TLS proxy CA in the Go **build** stage only,
via a scratch copy of each Dockerfile. Runtime stages and the repository
Dockerfiles are unchanged.

| Gate | Untouched base (`cc05d14`) | Tip (`rebrand/doppel`, `df87f7b`) |
|---|---|---|
| `make` (headers, gofmt, vet, `-race` tests, every module) | passed | passed |
| `make ui` | passed | passed |
| `validate-docs.py` | passed | passed (8 manifests, 74 routes) |
| `compose-guard.sh` | passed | passed |
| `release/selftest.sh` | passed | passed |
| Python SDK tests | passed | passed |
| `trivy fs` | **failed**: x/net CVE-2026-78661 (fixed on `main` by `fix/baseline-cves`) | passed |
| image builds + `trivy image` (Hub, every sensor, Python template) | **failed**: zlib in the Python template image (fixed on `main`) | passed (incl. `token-receiver`) |
| CodeQL security-extended (Go, JS/TS) + `codeql-gate.py` | passed | passed, no new findings |
| `e2e/real-docker.sh` | passed | passed |
| SIEM rules in Elasticsearch/Kibana 8.19.22 (`scripts/siem-rules/run-elastic.sh`) | n/a | passed: 59 documents, 16/16 rules exact |

Per branch (`make` + `validate-docs.py` on each tip): every branch passes,
**except `import/token-receiver`** (`TestRealManifestsRender`, fixed by
`af117ab` on the next branch). Trivy, CodeQL and the e2e test ran on `main`,
`fix/baseline-cves`, `merge/inventory` and the tip, not on every
intermediate branch.

**Not run:** the LogScale queries (no LogScale instance) and GitHub-hosted CI
(runs when you merge).


## 6. Open questions and risks

1. **Q67, AGPL origin.** TrueSignal as a whole is AGPL-3.0. The owner
   approved relicensing the claude-new files; counsel's confirmation is still
   recommended before external distribution.
2. **Clean specs** (Q68, Q69) wait for separate sessions (§8 of the task;
   prompt in `docs/clean-specs/README.md`).
3. **Q71:** the `siem_legacy_names` switch is deferred. Output keeps the
   legacy `truesignal` SIEM names, which is the approved default.
4. **Copyright holder** stays `TrueSignal Deception` until you name the legal
   entity (one mechanical commit plus `scripts/check-headers.sh`).
5. **History:** ~35 MB of sensor binaries in `ad9b896` (removed in
   `227707d`). A squash merge keeps them out of `main`.
6. **Branch-local test failure:** `import/token-receiver` and the first
   commit of `import/siem-rules` fail `TestRealManifestsRender`. Fixed in
   `af117ab`; every later branch is green.
7. **Signing identity changed:** a Doppel Hub shows an empty catalogue until
   the sensors are republished (`docs/operations.md` §9.2).
8. **17 Dependabot PRs** opened on Doppel when `main` was pushed. They are
   unreviewed.
9. **LogScale queries** are field-checked against the samples but were not
   run against a LogScale instance.

## 7. Rebrand status

Applied: product text, `doppel` CLI (with a `truesignal` link and legacy paths
for one release), `doppel-linux-<arch>` assets, `doppel-sdk` (with a
`truesignal_sdk` alias), Go module paths, and the signer repository. Kept as
approved: `TS_*`, `tsk_`, `io.truesignal.*`, `ts-hub` / `ts-sensor-*`,
`truesignal-releases`, the compose project name, and the SIEM names.

## 8. Release and republish checklist (owner)

1. Merge the branches (`UPLOAD.md` step 1); confirm CI, CodeQL and SIEM-rules
   workflows are green on `main`.
2. Tag ruleset, releases App variable and secret, App installation
   (`docs/operations.md` §9, §9.1, §9.2).
3. Bump the five published sensors to `1.0.1` in one PR (`token-receiver`
   ships as `1.0.0`), merge, `make tag-sensors`.
4. Bump the CLI (for example `3.1.0`), merge, `make tag-cli`.
5. Release Hub `3.0.0-rc.2` (or `3.0.0`), `make tag-hub`; verify with the
   `docs/operations.md` §1 commands.
6. Upgrade Hubs and nodes; archive `TrueSignal-Rewrite` when the last old
   Hub is gone.
