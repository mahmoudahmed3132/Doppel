# Doppel roadmap: decoys, secrets encryption, SSO, F5 HTTPS, backup/restore

Owner: Mahmoud. Planner/advisor: Fable 5.2. Executor: Sonnet 5.5.
Written 2026-11-15 against `main` at `007da6c` (schema version 2, Go 1.26.10).
Items marked **[default]** are decisions taken so work can start; the owner may override any of them.

## 0. Ground rules for every executor session

- Read first: `docs/clean-specs/README.md`, `docs/ported-seams.md`, `docs/sensors.md`, `docs/manifest-v3.md`, `QUESTIONS.md`, `THREATMODEL.md`. `HANDOVER.md` (31 Oct) predates the merge; do not plan from it.
- Gates before reporting done (each reported passed / failed with output / not run with reason): `make`, `make ui`, `python3 scripts/validate-docs.py`, `scripts/compose-guard.sh`, `scripts/release/selftest.sh`, Trivy, CodeQL gate, `scripts/e2e/real-docker.sh`.
- Every source file carries the licence header (`scripts/check-headers.sh`). Permissive deps only, each in `THIRD_PARTY.md`. Ambiguity goes to `QUESTIONS.md` (next free id: Q73) with the conservative default.
- No tag, publish or merge by an executor. Each package ends at a pushed branch for owner review.
- Clean-room (decoys): standards (RFCs, MS-* docs, vendor protocol docs) only. Do not open, search, clone or recall `TrueSignal`, `HoneyWire`, Trapster or any other honeypot project; if a web search returns one, do not open it and add a `PROVENANCE.md` row. Each decoy adds the row "clean implementation from spec docs/clean-specs/<spec>.md; implementer had no access to TrueSignal or HoneyWire".
- Dockerfile pins: copy from an existing sensor as they stand (Go 1.26.10 stays until Q72's move).
- New migrations get pre-assigned schema versions (below) so Hub branches do not collide.

## 1. Baseline findings that shape the plan

| Check | Result | Consequence |
|---|---|---|
| Manifest v3 `runtime.listen_ports` | supports `tcp`/`udp`, `cap_add` allows `NET_BIND_SERVICE`, `runtime.user` is settable | No schema or compiler change needed for decoys. Verify in P0 that a config-driven list of ports (enable flag + port per protocol) compiles and conflict-checks; fix in P0 if not. |
| `sdk/go/decoy` | `Accept` takes a `net.Listener`; no UDP helper, no BER reader | P0 adds both (shared by LDAP and SNMP, which are in different modules). |
| ATT&CK mapping | explicit rows for `ldap_*`, `rdp_login`, `ssh_login`, `snmp_query`, `dns_query`; suffix fallback maps every `<x>_login` (T1110) and `<x>_connection` (T1046) | Specs' claim holds. `ldaps_query` is mapped; all new triggers resolve. Add explicit rows for `mysql/postgres/mssql/ftp/telnet_login` only if the owner wants better technique detail. |
| Sensor registration surface | CI modules come from `go.work` (dynamic). Hand-edited: `go.work`, `docs/sensors.md`, `README.md`, `PROVENANCE.md`, `THIRD_PARTY.md`, `QUESTIONS.md`, `docs/siem/*` only if a new trigger. `publish-sensor.yml`/dependabot use globs | These are the merge-conflict files for parallel branches; keep edits append-only and expect trivial rebases. |
| Hub schema | linear migrations, v1-v2 exist. One `admin` row (`CHECK id=1`), sessions carry no user, audit has `ActorIP` only | Users/roles is a prerequisite for SSO (P2). |
| Health/metrics | no `/healthz`, no metrics. `GET /v3/version` is the only unauthenticated read | Add `/healthz` and `/readyz` in P2 (needed by the F5 monitor). |
| R1 (plaintext secrets) | master keys, SIEM token, webhook URL, TOTP seed, honeytoken secrets in SQLite plaintext | P1 encryption. |
| R2 (http accepted) | CLI warns on `http`; Hub accepts an `http` public endpoint | Closed in P2 (HTTPS). |
| Baseline `make` | green on `007da6c` (header check, gofmt, vet, `-race` tests in every module; exit 0) | Executors re-run before starting. |

## 2. Phase 0: serial prerequisites (one short session, merge before Phase 1 decoy work)

Branch `feat/decoy-foundations`.

1. `sdk/go/decoy`: add `ServePacket(ctx, pc net.PacketConn, handle func(addr net.Addr, b []byte))` with a bounded read buffer, per-source limiter hook and clean shutdown; tests.
2. Shared **strict BER reader** (definite lengths, max size, max depth, never allocates from an untrusted length) in `sdk/go/ber` (stdlib only, same module as the SDK). Needed by LDAP and SNMP. Includes a fuzz test.
3. Verify a decoy-style manifest (list of enabled protocols, ports below and above 1024, one UDP) passes `scripts/validate-docs.py` and the compose compiler's conflict rule; add a test fixture. Fix the compiler only if it fails.
4. Document the packet helper and BER reader in `docs/sensors.md`.

Done = `make` green, helpers fuzzed, no sensor code yet.

## 3. Phase 1: four decoys + secrets encryption (five parallel packages)

**Execution model [default, owner to confirm]:** four separate cloud sessions, one per decoy, prompt taken verbatim from `docs/clean-specs/README.md`, each on branch `clean/<spec>` from `main` after P0 merges. This session (or one more session) does encryption on its own branch. This honours the repo's own provenance rule.

### 3.1 Decoys (packages D1-D4, independent)

Common: `docs/clean-specs/common-decoy.md` plus the package spec. Per-sensor checklist: module under `sensors/<name>` + `go.work` entry; Dockerfile (distroless, static, read-only); `manifest.json` (config key per protocol: enable + port, `listen_ports` for each, `TS_PASSWORD_CAPTURE`, `TS_CAPTURE_KEY`); parsers with unit and fuzz tests; one end-to-end test per protocol through a fake `sensor.Reporter`; `docs/sensors.md` row; README row; `PROVENANCE.md` row; `THIRD_PARTY.md` row if a dependency is added; `scripts/e2e/real-docker.sh` only with high ports.

| Pkg | Sensor | Notes for the executor |
|---|---|---|
| D1 | `identity-decoy` (LDAP, LDAPS, RDP) | Largest: BER (P0), MS-NLMP, CredSSP/ASN.1 DER, TLS cert generated in memory. Build NTLM and RDP in separate files with their own fuzz tests. Ask (QUESTIONS) whether the cert should be stable across restarts (see 6.7). |
| D2 | `database-decoy` (MySQL, PostgreSQL, TDS) | Three independent parsers; TDS LOGIN7 de-obfuscation; exact error texts per spec. |
| D3 | `remote-access-decoy` (SSH, Telnet, FTP) | `golang.org/x/crypto/ssh` is already in the graph for the hub; add to the sensor's `go.mod` and `THIRD_PARTY.md`. Host key derived from the capture key; never on disk. |
| D4 | `network-service-decoy` (SNMP, DNS) | UDP: uses `ServePacket` and BER from P0. Anti-amplification is a tested requirement: reply size <= request size (+ fixed margin for SNMP), per-source reply limiter. |

Each decoy ends at a pushed branch with a gate report. Production Hubs will not list the sensors until the owner publishes signed manifests (`make tag-sensor NAME=<n>`); do not tag.

### 3.2 Secrets encryption at rest (package E1, closes R1)

Branch `feat/secrets-encryption`. Migration **v3**.

1. **Inventory first.** List every secret column/setting: `capture_master_key`, `beacon_master_key`, SIEM token/API key, webhook URL, `admin.mfa_secret`, `admin.mfa_pending_secret`, `honeytokens.secret`, and any secret-typed value inside `sensors.config`. Write the inventory into `docs/operations.md` and the threat model.
2. **Design.** A key-encryption key (KEK) from outside the DB behind a `KeyProvider` interface; default provider = key file or Docker secret (`TS_KEK_FILE`), not an env var. KEK wraps a random DEK stored in the DB. Stdlib AES-256-GCM, AAD = table/column/row id, versioned prefix (`enc:v1:`) so migration is idempotent and rollback-detectable.
3. **Fail closed.** In production the Hub refuses to start without a KEK; development may run with an explicit `TS_DEV_ALLOW_PLAINTEXT_SECRETS`.
4. **Migration traps (must be tested):** (a) snapshot-before-migrate leaves a plaintext `.bak`: encrypt the snapshot's secrets or delete it after success, and document it; (b) plaintext persists in free pages and the WAL: `VACUUM` and checkpoint after migration; (c) columns used for equality lookup (`beacons.token`) cannot use randomized encryption: scope them out explicitly and say why; (d) KEK rotation (rewrap DEK) command and test.
5. **Boundary statement** in `THREATMODEL.md`: protects backups, volume copies and DB-file theft; does not protect against root on the running host.
6. Tests: round trip, tamper detection (AAD mismatch), wrong KEK, partial migration resume, settings API still returns `*_set` only.

## 4. Phase 2: Hub hardening (serial after E1 merges)

Pre-assigned migrations: users/roles **v4**, SSO identities **v5**. One branch per package, merged in order U1 -> S1 -> H1 -> B1; H1 may start in parallel with U1 (no schema overlap).

### U1: users, roles, audit actor (prerequisite for SSO)

- **As built (Q75):** `users` holds principals; the bootstrap administrator's password and MFA stay in `admin` (E1 sealing is row-bound; migrations cannot re-seal). Sessions are bound to a user and the role is read per request. The first bullet below describes the original intent.
- Replace the single `admin` row with `users` (id, username, password_hash nullable, role, mfa fields, disabled, created_at) and bind `sessions` to a user. Migrate the existing admin to user `admin` with role `admin`. Do not hard-code singleton assumptions (`CHECK id=1` goes away).
- Roles **[default]**: `admin` (everything), `analyst` (read events/fleet, mark read, silence/unsilence), `viewer` (read-only). Each route in `Admin.Route`/`RouteFull` gets an explicit role; add a test that fails on any registered route (including WebSocket `/api/v3/live` and routes registered by other packages) without an explicit role.
- Audit records gain `actor` (user id/name); update `docs/audit-actions.md`, `docs/openapi.yaml`, Elastic and LogScale rules where fields are referenced.
- UI: users page (admin), role-aware navigation.
- Keep `TS_DASHBOARD_PASSWORD` and `mfa-reset` working for the bootstrap admin.

### S1: OIDC SSO (authorization code + PKCE; SAML out of scope [default])

- Settings: issuer URL, client id, client secret (stored via E1), scopes, group-claim name, group -> role mapping. No matching group = no access. Just-in-time user creation with the mapped role; role re-evaluated at every login.
- Redirect URI built from `public_endpoint`, never from `Host`. `state` + `nonce` + PKCE verifier in a short-lived cookie that must be `SameSite=Lax` (the session cookie is `Strict` and will not arrive on the IdP redirect).
- Verify ID token signature (JWKS, cached, rotation-safe), `iss`, `aud`, `exp`, `nonce`; allow only expected algorithms. Choose a permissive library or stdlib; record in `THIRD_PARTY.md`.
- Break-glass: local admin with TOTP stays, with a setting to restrict it to a configured source range. Enforce MFA at the IdP; do not add Doppel TOTP on top of SSO logins **[default]**.
- IdP endpoints are a new outbound destination: add to the Q55 list, `THREATMODEL.md`, `QUESTIONS.md` (no redirects to other hosts, size and time limits, SSRF guard against private ranges unless explicitly allowed).
- Docs: OpenAPI, `audit-actions.md`, a detection rule for SSO login failures and role changes (Elastic + LogScale), operations guide with Entra ID and Okta examples.

### H1: enforced HTTPS behind F5

`deploy/compose.yaml` binds `127.0.0.1:8080` for a same-host proxy. An F5 is off-host, so that hop would carry node keys and session cookies in clear. This is a code change, not just docs.

- Native TLS listener (`TS_TLS_CERT_FILE`, `TS_TLS_KEY_FILE`, TLS 1.2+ with a modern cipher list, optional hot reload on SIGHUP) for F5 server-side re-encryption. Compose binds the Hub to the VDC-internal interface, not loopback.
- Production refuses to start unless the effective scheme is https (native TLS, or a trusted proxy asserting `X-Forwarded-Proto: https`) and `public_endpoint` is https. Closes R2: the CLI and SDKs refuse `http` without an explicit dev flag; `scripts/e2e/real-docker.sh` sets that flag.
- `/healthz` (process up) and `/readyz` (DB reachable, migrations current), unauthenticated, no detail in the body, for the F5 monitor.
- Docs (`docs/operations.md` section "F5"): client-side and server-side SSL profiles; iRule or HTTP profile that **overwrites** `X-Forwarded-For` and `X-Forwarded-Proto`; WebSocket (`/api/v3/live`) with an adequate idle timeout; `TS_TRUSTED_PROXIES` = the self-IPs of both HA units (not the floating IP); monitor on `/readyz`; ASM/WAF policy relaxed on `/v3/events` ingest because event bodies contain attack strings by design (signature staging, then enforce on admin paths only); persistence not required (stateless cookies are validated in the DB).
- State plainly that CI can only test the Hub side; the F5 configuration is validated by the owner in staging. Provide an nginx TLS-passthrough/re-encrypt compose fixture in CI as a stand-in.

### B1: backup / restore

- CLI on the Hub host only (like `mfa-reset`): `truesignal-hub backup --out <dir>` and `restore --from <dir>`. No API download: it would be a full-secrets exfiltration path.
- Backup: online snapshot via `VACUUM INTO` plus `manifest.json` (schema version, SHA-256 of the DB, KEK fingerprint, created_at, Hub version). The KEK is backed up separately and never inside the same archive.
- Restore: offline only; verify checksum and schema version (refuse a newer schema), verify the DEK unwraps with the supplied KEK **before** swapping, keep the previous DB as `.pre-restore`, invalidate all sessions, write an audit record on next start.
- Document: nodes linked after the backup are orphaned and must be re-linked; backup retention and offsite copy are the operator's job; encrypt the backup medium.
- Gate: CI round-trip test (populate, backup, wipe, restore, compare), plus a wrong-KEK and corrupted-archive test.

## 5. Dependency graph

```
P0 foundations ──► D1 D2 D3 D4        (parallel, separate sessions)
main ───────────► E1 ──► U1 ──► S1
                    └──► H1 (parallel with U1) ──► B1 (needs E1 KEK fingerprint)
```

## 6. Production-readiness advice (ranked)

1. **IP hygiene (owner action).** Close Q1: the proprietary `LICENSE` vs "All rights reserved" headers is settled on paper, but counsel's confirmation of the relicensing of claude-new files is still outstanding (Q67). An accelerator's diligence will ask.
2. **Signing identity and ownership.** Images, releases and the Sigstore signing identity live under a personal account. Move to an organisation before the first external install; `docs/operations.md` section 9.2 shows what the last move cost.
3. **Release discipline.** Hub is still `3.0.0-rc.1`; `registry-rollback` has never run. Cut `3.0.0`, do one release and one rollback drill before a pilot.
4. **Front door.** README is partly stale (command names, "PORTED pages are shells"). Rewrite it around: what it is, 10-minute quickstart, architecture diagram, demo video/GIF.
5. **Scale limits.** Single SQLite, single Hub instance. State this as a documented limit and a roadmap item (Postgres, HA) rather than hiding it; do not bake singletons into the new users model.
6. **Observability.** Add `/readyz`, plus metrics (ingest rate, queue depth, SIEM/webhook delivery failures, sensor-dark count) exposed to an authenticated or loopback-only scraper. Ship an Elastic/LogScale dashboard.
7. **Fingerprintability.** Identical persona defaults across installs and an LDAPS/RDP certificate regenerated each restart are tells for scanners. Raise as `QUESTIONS.md` entries (per-node persona seeded from the capture key; certificate stable per node) rather than silently deviating from the specs.
8. **Demo vs pilot ordering.** `insights-projection` and `analytics-ui` are the demo-visible surface (accelerator pitch); SSO, backup and HTTPS enforcement serve pilots and security reviews. Recommended order: decoys + encryption now, then insights/analytics UI for the demo, then Phase 2 before the first paying pilot. **Owner to confirm.**
9. **Compliance mapping (your context).** Add a one-page PCI DSS / SOC 2 control map (10.x log delivery via SIEM, 8.x MFA/SSO, 3.x/4.x secrets and transport, 12.x change control through signed releases). Cheap to write, strong in diligence.
10. **Supply chain.** Keep the Dependabot 14-day cooldown; pin and sign everything as today; add SBOM (CycloneDX) generation to publish workflows and attach it to releases.

## 7. Status log

- 2026-11-15: baseline `make` green on `007da6c`. Owner chose four separate clean-room sessions for the decoys (one per spec, `clean/<spec>`).
- Not yet run in the baseline: `make ui`, validate-docs, compose-guard, selftest, Trivy, CodeQL, real-docker e2e (executors run these on their own branches).
- 2026-11-15: **P0 done** (`sdk/go/ber`, `decoy.ServePacket`, manifest `listen_ports[].enabled_key`, Q73). The conflict rule treated every declared port as claimed, so a disabled protocol held its default port; `enabled_key` fixes that. A Hub older than this change rejects manifests that use it: release the Hub before publishing a decoy.
- 2026-11-16: E1, P0 and the Go 1.27.3 move are merged to `main` (PRs #25, #26). Not yet exercised: the KEK compose secret's readability as uid 65532 on a real Docker host.
- 2026-11-16: **U1 built** on `claude/gifted-davinci-o9gzdg` (schema v4, role-per-route, users API, audit actor, UI users page); gates below.
- 2026-11-15: **E1 in progress** (implemented and tested on this branch; plaintext rollback snapshots are deleted after the first sealed start per the owner, Q74): `hub/internal/seal`, store migration **v3** (`crypto_meta`), `TS_KEK_FILE` required in production, `kek-generate` / `kek-rotate`, strict mode, VACUUM after migration, tests incl. plaintext-remnant scan, live smoke test. Q74 records the plaintext rollback snapshot, the required KEK and the scope. Users/roles therefore take schema **v4** and SSO **v5** as planned. Sensor config is not sealed (no manifest declares secret keys yet).
- 2026-11-15: **Go 1.27.3 move done** on this branch (go.work, every go.mod, CI/publish/CodeQL workflows, README) with sigstore-go 1.4.0, which supersedes Dependabot PR #25 (its checks failed only because it needs Go >= 1.27: `digitorus/pkcs7`). Go 1.27.3 was released 2026-10-19, so Q72's 14-day rule is met; the Dockerfiles already used golang:1.27.3.
- Still to run before E1 is merged: `make ui`, Trivy, CodeQL gate, `real-docker.sh` (CI). `make`, validate-docs, compose-guard and selftest pass locally.
