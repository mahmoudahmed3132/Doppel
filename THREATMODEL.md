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

The verifier is installed (PORTED step 1, `hub/internal/signing`): every
manifest must carry a Sigstore bundle whose Fulcio certificate is this
repository's `publish-sensor.yml` at `refs/tags/sensor/<name>/v<version>`,
with an SCT, a Rekor entry and a timestamp, checked offline against the
embedded public-good trusted root. A signature for one sensor or version is
refused for another (`signing` tests use the real published 1.0.0 bundles).

**Residual:** trust is rooted in GitHub Actions OIDC, Fulcio/Rekor (Sigstore
public good) and this repository's workflow file: anyone who can change
`publish-sensor.yml` on a release tag can sign manifests (tag ruleset). The development flags
`TS_DEV_ALLOW_UNSIGNED_MANIFESTS` / `TS_DEV_ALLOW_UNPINNED_IMAGES` disable
these controls and log a warning at every start; never set them in production.

### §6.12 compose rules: threat mitigated by each hard rule

The compose compiler (`hub/internal/compose`) is the boundary between
untrusted inputs (manifests from the registry, admin-entered values, attacker
influence on either) and root-equivalent container execution on every node.
Each rule rejects the whole render with `422` and a precise code; nothing is
silently dropped except undeclared config keys (rule 6, with a warning).

| Rule | Threat it mitigates | Test (mutation-checked where noted) |
|---|---|---|
| 1. Images pinned by `@sha256` from a verified manifest | Tag mutation or registry compromise swapping the code a node runs after review; a manifest pointing at an attacker image | `TestRuleDigest`, `TestRealManifestsRender` |
| 2. `read_only`, `cap_drop: ALL`, `no-new-privileges`; init containers `network_mode: none` | A compromised decoy persisting in its filesystem, gaining capabilities via setuid/file caps, or an init step exfiltrating | `TestPassingRenderHardening`, `TestRuleMounts` (init) |
| 3. Capabilities only `NET_RAW`/`NET_BIND_SERVICE`/`DAC_OVERRIDE`; `network_mode` only host/bridge/none | Container-to-host escape or network takeover via `SYS_ADMIN`, `NET_ADMIN`, `container:`/`service:` namespace joins | `TestRuleCapabilitiesAndNetwork` (incl. `NET_ADMIN`) |
| 4. Bind mounts absolute, normalised, outside `/run`, `/proc`, `/etc`, `/var/lib/docker`, … (including config-derived sources and their ancestors) | Docker-socket or host-config access = full host compromise; `..` traversal; mounting `/` or a parent of a forbidden path | `TestRuleMounts` (incl. `/run/docker.sock`, ancestors; mutation-checked) |
| 5. No `$`/`{{` in image, network, volume, init command; `$` → `$$` in env | Compose variable interpolation turning attacker-controlled strings into different images, mounts or secrets from the node's environment | `TestRuleInterpolation` (mutation-checked) |
| 6. Only declared config keys; reserved keys always Hub-set | Overriding `TS_HUB_ENDPOINT` (exfiltrate the node key), `TS_NODE_KEY`, `TS_SENSOR_ID` (impersonate another sensor) or `TS_TEST_MODE`; smuggling arbitrary env | `TestRuleConfigDeclaredAndReserved` (test-mode pinning mutation-checked) |
| 7. Port conflicts (any protocol) → `409` | Two decoys silently fighting over a port so one never runs: a blind spot the admin believes is covered | `TestRulePortConflict` (UDP vs TCP), `TestConcurrentAddsCannotBothClaimAPort` |
| 8. Default user `65532:65532`; container name = sensor id | Decoys running as root by default; name collisions hiding or replacing another sensor's container | `TestRealManifestsRender` (users per sensor), `TestPassingRenderHardening` |
| 9. Per-sensor secrets: node key, HMAC-derived capture key, honeytoken, beacon key; master keys never leave the Hub | A compromised node learning master keys and forging honeytoken/beacon hits fleet-wide; secrets shown in the UI or API | `TestSecretsAndRedaction`, `TestPreviewDoesNotSaveAndIsRedacted` |
| 10. Deterministic revision | Nodes re-applying (restart churn) or missing a change; inability to prove which configuration a node runs | `TestRevisionDeterministic` |
| 11. Render before save | A saved-but-unrenderable configuration leaving nodes stuck on stale decoys, or a partially applied change | `TestSensorAddRendersBeforeSaving`, `TestFailClosedWithoutCompiler` |

Rendered files never contain `build:` (compiler test in `TestRealManifestsRender`;
`scripts/compose-guard.sh` for checked-in compose files).

### B6: Release pipeline
| Threat | Control |
|---|---|
| Compromised third-party action | All actions pinned by commit SHA; least-privilege `permissions:` per job (`contents: read` on this repository for every publish job); checkout credentials never persisted |
| Tampering with the public releases repository (`truesignal-releases`: registry branch, releases, `install.sh`) | Written only with a GitHub App installation token minted per job (contents:write on that one repository, ≤ 1 h), passed to git through environment-only config (no argv, URL or `.git/config`) and masked; rulesets there allow updates and tag creation only by the App. Hosting is not trusted for integrity: manifests and CLI binaries are verified against the **source** repository's workflow identity, which nobody can obtain by writing to the releases repository |
| Tampered artefacts | Keyless Sigstore signatures bound to the workflow file and tag; consumers verify identity (install.sh, Hub verifier, `cosign verify` in docs) |
| Releasing unreviewed code / overwriting a release | Tag must equal code version and be on the default branch; existing versions are never rebuilt; `:latest` only moves to a signature-verified digest |
| Vulnerable dependencies | Trivy gates (fixable HIGH/CRITICAL) on the repo and on every image before push; CodeQL; Dependabot |

**Residual:** tag immutability and restricted pushes to `registry` depend on
repository rulesets in both repositories (docs/operations.md §9, §9.1);
without them a maintainer token can move a tag. A leaked App key lets an
attacker rewrite the releases repository: they can withhold or roll back
content (the Hub then keeps its last verified catalogue or sees older,
still-signed versions; deprecations could be hidden) and replace
`install.sh` on `main`, which an operator who pipes it to `sh` without
pinning would run. Mitigations: rotate the key, pin installs by version and
`--sha256` (docs/operations.md §5), and install cosign so binaries are
identity-checked. The source repository's name is public in every
certificate and in the Rekor log (accepted, Q64). GitHub and Sigstore themselves are trusted.

### B7: Hub host
**Residual (R1):** the Hub master keys, SIEM token, webhook URL and TOTP seed
are stored **in plaintext** in the SQLite database (the password and node keys
are hashed). Anyone with read access to the data volume or a backup can forge
honeytoken/beacon hits, push to the SIEM and webhook, and generate TOTP codes.
`truesignal-hub mfa-reset` likewise requires only Docker-host access. Mitigate
operationally: dedicated host, restricted Docker group, encrypted volume and
backups. Encrypting these settings at rest under a key outside the database
(KMS/TPM/env) is a recommended future change.

## Imported modules (merge from TrueSignal)

Modules imported through the PORTED seams are in scope from their import on.
Each row names the module and the control it carries; `MERGE-INVENTORY.md`
and `PROVENANCE.md` record its origin.

| Module | Controls and residual risk |
|---|---|
| TOTP and recovery codes (`hub/internal/totp`) | RFC 6238 SHA-1/6 digits/30 s, ±1 step, constant-time comparison over every window; replay refused for any step ≤ the stored last step (the Hub's CAS is the authority). Recovery codes: 50 bits each, only SHA-256 hashes stored, constant-time comparison over the full list, single use. Residual: the TOTP seed is stored in plaintext (R1) |
| GeoIP (`hub/internal/geoip`) | Internal addresses (private, CGNAT, loopback, link-local, ULA) are never looked up. The database is loaded from a private copy, so overwriting the file in place cannot corrupt the live mapping; a file that is not a City database is refused and the current one stays. Auto-update (off by default, Q70): HTTPS only, same-host redirects only, size limits, validated before the swap. Residual: DB-IP publishes no signature, so a compromised download host could feed false locations; locations are advisory enrichment and never drive a security decision |
| Asset inventory (`hub/internal/assets`) | Strict JSON (unknown fields refused), at most 5000 assets, 256-byte fields, 20 tags, duplicates and invalid IP/CIDR refused; a refused save keeps the current inventory. Lookups never resolve names (IP sources only). Residual: the inventory reveals the internal network layout to anyone with an admin session |
| ATT&CK mapping (`hub/internal/attack`) | A fixed table plus two suffix rules; no input reaches it except the trigger, which ingest has already validated (Q8). Unmapped triggers carry nothing rather than a guess. Hub-raised liveness and apply-failure events are excluded from the matrix. Residual: a wrong mapping misleads SOC triage; `TestDocMatchesCode` keeps `docs/siem/attack-mapping.md` and the code in step |

## Out of scope
PORTED modules not yet installed (honeytoken service, beacon service, ECS renderer, HTTP SIEM transports,
projections, lure content, web skins); denial of service by a volumetric network attacker
against the Hub (put it behind the reverse proxy / network controls).
