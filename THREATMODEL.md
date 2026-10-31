# Threat model

Scope: TrueSignal Hub, node CLI, sensors, sensor registry, admin UI and the
release pipeline as implemented in this repository. Modules marked PORTED
(§12) are seams here; their own threat models belong with them.

## Assets

| Asset | Why it matters |
|---|---|
| Event stream and audit records | The detection signal; tampering or loss blinds the SOC |
| Admin session / credentials / TOTP seed | Full control: disarm, delete events, reconfigure SIEM, factory reset |
| Node keys | Ingest as a node, fetch that node's unredacted compose |
| Hub master keys, SIEM token, webhook URL, honeytoken secrets | Forge honeytoken/beacon hits, read or poison downstream systems |
| Sensor catalogue (registry, manifests, images) | Code executed as root-equivalent containers on every node |
| Release artefacts (Hub image, CLI binaries) | Code executed on the Hub and as root on nodes |

## Adversaries

1. **Attacker interacting with decoys**: the expected adversary. Controls every
   byte a sensor reports (payloads, banners, usernames, paths, source fields).
2. **Network attacker** between nodes, Hub, SIEM and admins.
3. **Compromised node**: root on one node, holds its node key.
4. **Malicious or compromised admin browser context** (XSS, CSRF, clickjacking).
5. **Supply-chain attacker**: dependency, base image, CI action, registry or
   release tampering.
6. **Insider with Docker host access** on the Hub.

## Trust boundaries and controls

### B1: Decoy attacker → sensor → Hub (event content)
Event content is fully attacker-controlled and must never be interpreted.

| Threat | Control | Where |
|---|---|---|
| Stored XSS in the admin UI | Preact text rendering only; build-time lint forbids `dangerouslySetInnerHTML`/`innerHTML`/`eval`/inline style; strict CSP (`default-src 'self'`, no inline script) on every response | `ui/scripts/lint-safety.mjs`, `hub/internal/httpapi/middleware.go`, `hub/internal/webui` test |
| Syslog/SIEM injection (fake records, line breaks) | RFC 5424 SD-value escaping; one record per line | `hub/internal/siem/syslog` `TestHostileValueStaysOneLine` |
| CSV formula injection in exports | `'` prefix for `= + - @ \t \r` | `hub/internal/httpapi/events.go` `CSVSafe` |
| Webhook mention/markdown injection | Discord `allowed_mentions: {parse: []}` + Markdown escaping; Slack `&<>` escaping | `hub/internal/webhook` |
| Oversized/invalid input, resource exhaustion | Batch ≤ 100, body limits, details size cap, UTF-8 validation, per-key rate limit (50/s, burst 200), SIEM queue bounded (5000, drop-new, counted) | `hub/internal/ingest`, `httpapi/ingest.go`, `ratelimit` |
| Sensor-side flooding | Per-source limiter and cooldowns with suppressed counts | `sdk/go/sensor/limiter.go`, sensors |

### B2: Node ↔ Hub (node API)
| Threat | Control |
|---|---|
| Key theft at rest on the Hub | Keys stored as SHA-256 only; shown once; rotation/deletion effective immediately (generation-counter cache) |
| Cross-node access | Every node call scoped to the authenticated node; other node's sensor → 404; compose only for the caller's node (`TestNodeAPI`) |
| Reserved/forged triggers (e.g. `honeytoken_used`) from a sensor | Reserved triggers rejected with 403 at ingest |
| Key exposure via process list | CLI takes the key from the environment, never argv; config file 0600 |
| Network MITM | https endpoint with TLS verification (system roots; sensors also accept `TS_CA_BUNDLE`). Plain `http` is **accepted, not refused**: the CLI warns that it sends the node key in clear |

**Residual:** a compromised node can forge events *as itself* (any
non-reserved trigger, any severity) and read its own unredacted compose
(including derived keys for its sensors). It cannot act as other nodes. A Hub endpoint configured as `http://`
exposes node keys and events on the wire (R2); use https in production.

### B3: Admin browser ↔ Hub
| Threat | Control |
|---|---|
| Credential guessing | argon2id (64 MiB), lockout 5/IP and 10 account-wide per 15 min, TOTP with CAS replay protection, single-use recovery codes, optional required MFA with enrol-only sessions |
| Session theft | Opaque server-side session, `HttpOnly`, `SameSite=Strict`, `Secure` (except development), idle + absolute expiry; live feed rechecks the session every 15 s without refreshing it |
| CSRF | Origin/Referer must equal the Hub origin on every non-safe method; WebSocket Origin checked |
| Clickjacking / framing | `frame-ancestors 'none'`, `X-Frame-Options: DENY`, COOP |
| Destructive actions by mistake or by a hijacked session | Typed confirmations; factory reset requires password re-entry and is refused unless its audit record reaches the SIEM first |
| Secret disclosure via API | Secrets reported only as `*_set`; sensor secret config masked; SIEM token/webhook URL never logged |

**Residual:** an attacker with a live admin session can disarm webhooks,
reconfigure or disable the SIEM output and delete events. Each action is
audited to the SIEM **before** the change takes effect (SIEM switch sends the
audit to the old destination). Alert on `siem.update`, `system.arm`,
`events.delete_all`, `system.factory_reset` and `mfa.*` in the SIEM.

### B4: Hub → SIEM / webhooks / registry / update check (egress)
| Threat | Control |
|---|---|
| MITM of SIEM | TLS syslog with certificate verification (`TS_SIEM_CA_BUNDLE`); UDP/TCP flagged as unsafe in the UI |
| SSRF via configurable URLs | Admin-only settings; webhooks never follow redirects; registry fetches never follow redirects, size-capped, `https` only outside development |
| Silent loss | Peer-closed check before each stream write; retries with cap; drops counted and reported in the Hub heartbeat |

**Residual:** registry, webhook and SIEM destinations are admin-chosen; an
admin can point them at internal hosts (accepted: admin is trusted).

### B5: Registry / catalogue → nodes (sensor supply chain)
| Threat | Control |
|---|---|
| Malicious manifest or image | Manifests verified (Sigstore, identity = this repo's `publish-sensor.yml` at the sensor's tag) **before parsing**; production refuses unsigned manifests and images without `@sha256` digests |
| Privilege escalation through compose | Compiler rules: no `build:`, no Docker socket or ancestor mounts, `cap_drop: ALL` + allow-listed single capability, read-only rootfs, no-new-privileges, no interpolation (`$` escaped), Hub-reserved env enforced (`hub/internal/compose`, mutation-checked) |
| Rollback to a vulnerable version | Versions immutable; deprecation stops new deployments and "latest" |

**Residual:** until the PORTED verifier is installed the catalogue is empty in
production (fail closed). The development flags
`TS_DEV_ALLOW_UNSIGNED_MANIFESTS` / `TS_DEV_ALLOW_UNPINNED_IMAGES` disable
these controls and log a warning at every start; never set them in production.

### B6: Release pipeline
| Threat | Control |
|---|---|
| Compromised third-party action | All actions pinned by commit SHA; least-privilege `permissions:` per job; credentials not persisted except where a job pushes the registry branch |
| Tampered artefacts | Keyless Sigstore signatures bound to the workflow file and tag; consumers verify identity (install.sh, Hub verifier, `cosign verify` in docs) |
| Releasing unreviewed code / overwriting a release | Tag must equal code version and be on the default branch; existing versions are never rebuilt; `:latest` only moves to a signature-verified digest |
| Vulnerable dependencies | Trivy gates (fixable HIGH/CRITICAL) on the repo and on every image before push; CodeQL; Dependabot |

**Residual:** tag immutability and restricted pushes to `registry` depend on
repository rulesets (docs/operations.md §8); without them a maintainer token
can move a tag. GitHub and Sigstore themselves are trusted.

### B7: Hub host
**Residual (R1):** the Hub master keys, SIEM token, webhook URL and TOTP seed
are stored **in plaintext** in the SQLite database (the password and node keys
are hashed). Anyone with read access to the data volume or a backup can forge
honeytoken/beacon hits, push to the SIEM and webhook, and generate TOTP codes.
`truesignal-hub mfa-reset` likewise requires only Docker-host access. Mitigate
operationally: dedicated host, restricted Docker group, encrypted volume and
backups. Encrypting these settings at rest under a key outside the database
(KMS/TPM/env) is a recommended future change.

## Out of scope
PORTED modules (TOTP core, manifest verifier, ATT&CK/geo/asset enrichment,
honeytoken and beacon services, ECS/HTTP SIEM transports, projections, lure
content, web skins); denial of service by a volumetric network attacker
against the Hub (put it behind the reverse proxy / network controls).
