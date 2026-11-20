# Threat model

Scope: Doppel Hub, node CLI, sensors, sensor registry, admin UI and the
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
| Oversized/invalid input, resource exhaustion | Batch ≤ 100, body limits, details size cap, UTF-8 validation, per-key rate limit (50/s, burst 200), Hub-wide ingest admission (8 concurrent batches, 1 s wait, then `429 overloaded`; heartbeats not gated so liveness cannot be starved by event floods), node-reported `dropped_events` stored with a saturating add (no integer overflow into an unreadable row), SIEM queue bounded (5000, drop-new, counted). Residual: one authenticated node within its rate limit can occupy admission slots and delay other nodes' events (they retry; nothing acknowledged is lost) | `hub/internal/ingest`, `httpapi/ingest.go`, `ratelimit` |
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
**R1 (secrets at rest), mitigated by `hub/internal/seal`.** The Hub master
keys (`capture_master_key`, `beacon_master_key`), the SIEM token, the webhook
URL, the admin TOTP seed and pending seed, and honeytoken secrets are sealed
with AES-256-GCM under a data key (DEK). The DEK is stored wrapped by a
key-encryption key (KEK) read from `TS_KEK_FILE` (a file or Docker secret,
outside the database and its backups). Each value's authenticated data binds
it to its table, column and row, so ciphertext moved elsewhere does not open;
once sealing is recorded (`crypto_meta.sealed_at`) the Hub is strict from the
first read and refuses to start if a plaintext secret appears in the database
(locations are logged, never values). Sealing and the scrub are resumable. Production refuses to start without a KEK; an encrypted
database refuses to start without its KEK (no silent fallback). Older Hubs
refuse the database (schema v3), so they cannot misread sealed values.
**Protects:** a copy of the database file, a volume snapshot or a backup taken
without the KEK. The plaintext pre-migration snapshots are deleted after the
first sealed start (residual (a)); plaintext remnants are removed from free pages and the WAL at
migration (VACUUM, temporary copy placed next to the database; secure_delete is
on for later deletes). **Does not protect against:** root on the running Hub host
(the DEK is in process memory and the KEK file is readable by the Hub user),
nor `truesignal-hub mfa-reset`, which needs only Docker-host access.
**Residual:** (a) the pre-migration snapshots `<db>.pre-v*-<time>.bak` are
plaintext rollback copies. The Hub deletes every snapshot written before
sealing (modification time not after `sealed_at`) once sealing and the scrub
have completed, at every start, so a crash between the two is repaired. The
cost: rolling back to a Hub without encryption is impossible after the first
sealed start, and the window between the upgrade's snapshot and the first
sealed start is the exposure (Q74); a backup taken by hand inside that window
or before it still holds plaintext; (b) `beacons.token` is not sealed
(equality lookup; an identifier printed into artefacts, no authority by
itself); (c) sensor configuration is not sealed: no manifest declares a
`secret` key yet, and Hub-reserved keys are derived at render time, never
stored; (d) KEK loss means the sealed secrets are unrecoverable. Recovery is the
host-side `truesignal-hub secrets-reset --destroy-secrets` (Hub stopped; audited
on the next start as `secrets.reset_cli`): it deletes the sealed secrets, so the
SIEM token, webhook and MFA must be re-entered and planted honeytokens and
beacons are orphaned. Back the KEK up separately from the database.

## Imported modules (merge from Doppel)

Modules imported through the PORTED seams are in scope from their import on.
Each row names the module and the control it carries; `MERGE-INVENTORY.md`
and `PROVENANCE.md` record its origin.

| Module | Controls and residual risk |
|---|---|
| TOTP and recovery codes (`hub/internal/totp`) | RFC 6238 SHA-1/6 digits/30 s, ±1 step, constant-time comparison over every window; replay refused for any step ≤ the stored last step (the Hub's CAS is the authority). Recovery codes: 50 bits each, only SHA-256 hashes stored, constant-time comparison over the full list, single use. Residual: the TOTP seed is stored in plaintext (R1) |
| GeoIP (`hub/internal/geoip`) | Internal addresses (private, CGNAT, loopback, link-local, ULA) are never looked up. The database is loaded from a private copy, so overwriting the file in place cannot corrupt the live mapping; a file that is not a City database is refused and the current one stays. Auto-update (off by default, Q70): HTTPS only, same-host redirects only, size limits, validated before the swap. Residual: DB-IP publishes no signature, so a compromised download host could feed false locations; locations are advisory enrichment and never drive a security decision |
| Asset inventory (`hub/internal/assets`) | Strict JSON (unknown fields refused), at most 5000 assets, 256-byte fields, 20 tags, duplicates and invalid IP/CIDR refused; a refused save keeps the current inventory. Lookups never resolve names (IP sources only). Residual: the inventory reveals the internal network layout to anyone with an admin session |
| ATT&CK mapping (`hub/internal/attack`) | A fixed table plus two suffix rules; no input reaches it except the trigger, which ingest has already validated (Q8). Unmapped triggers carry nothing rather than a guess. Hub-raised liveness and apply-failure events are excluded from the matrix. Residual: a wrong mapping misleads SOC triage; `TestDocMatchesCode` keeps `docs/siem/attack-mapping.md` and the code in step |
| Honeytoken service (`hub/internal/honeytoken`) | Tokens are random (`svc_<word><4 hex>`, 15-character secret from a 57-symbol alphabet), one per File Canary instance, and stable. Secrets never leave the Hub except into that sensor's rendered compose (node-authenticated fetch only, Q26); the inventory, API listing and raised events never carry them. Password matching uses HMAC under the reporting node's capture key, compared with `hmac.Equal`, so a node can only test its own captures; usernames match fleet-wide. Hub-raised `honeytoken_used` is never re-matched and is reserved for sensors. Residual: secrets are sealed at rest (R1) but the Hub holds them in memory; a plaintext capture mode on a sensor exposes tried passwords to the Hub |
| Beacon service (`hub/internal/beacon`) | Tokens: 80 random bits plus a 40-bit HMAC tag under the receiver key, so receivers drop invented names offline; the Hub resolves only tokens it stored, and an unknown token is medium severity with `beacon_known: false`. The master key never leaves the Hub; the receiver key is shared by every receiver (a compromised receiver can mint valid-looking tokens, which still resolve to nothing). Artefacts carry neither the beacon name nor the memo nor the product name. Residual: web bugs are plain `http://` (an HTTPS front end is an operator choice); the shared receiver key is a single secret for every receiver |
| ECS renderer (`hub/internal/ecs`) | Output-only. `source.ip` is set only from a parseable address, so a sensor-controlled source string cannot break a typed SIEM field. Captured secrets stay in `truesignal.details`, never in `user.*`. Inventory documents never carry a honeytoken secret. Residual: `truesignal.details` passes sensor-supplied content to the SIEM as data; SIEM-side parsers must treat it as untrusted |
| HTTP SIEM transports (`hub/internal/siemhttp`) | HTTPS only (addresses without credentials), TLS 1.2+, system roots plus the optional SIEM CA bundle, redirects never followed (the token cannot leak to another host; a redirect is terminal), 10 s per request, responses read to 64 KiB. Outcomes: network, 5xx and 429 transient (retried by the SIEM service), everything else terminal. Residual: the API key or ingest token is sealed at rest (R1) |
| Analytics projections (`hub/internal/projections`) | Read-only aggregations over the Hub window (at most the Hub's projection event cap); parameters are bounded by the Hub (16 keys, 256 bytes) and validated per projection (`source` ≤ 256 bytes, report range ≤ 366 days). Hub-raised liveness is excluded. Residual: an attack-path timeline returns raw event details to the admin session, as the events API does |
| Lure content (`sensors/file-canary/lures_generated.go`) | Everything in a lure is fabricated: the honeytoken from the Hub plus random secrets, loopback hosts only, no product name, so a stolen lure leaks nothing real. Lures are created with `O_EXCL|O_NOFOLLOW` (never overwrite, never follow a link; base code). Residual: content shape may be fingerprinted by an attacker who knows the product |
| Web skins (`sensors/web-router-decoy/skins_builtin.go`) | Fixed skin data rendered by `html/template` (auto-escaped; the posted username is never echoed). Pages never name the product. The Basic realm comes from fixed data. Capture and rate limiting stay in the base decoy (hash capture, per-source limits). Residual: skins are generic look-alikes, not vendor copies; a careful attacker may recognise a decoy |
| Token Receiver (`sensors/token-receiver`) and decoy helper (`sdk/go/decoy`) | Internet-facing by design: authoritative-only DNS (no recursion or forwarding, REFUSED outside the zone, 50 replies/s per source, small answers, so no amplification), fixed HTTP response, TCP caps per source and in total, XFF trusted only from configured proxies, attacker input sanitised and capped. Tokens are verified offline before anything is reported. The helper's password capture defaults to keyed HMAC (never cleartext). Residual: the receiver key is shared by all receivers; a compromised receiver node can report forged-but-valid tokens, which the Hub resolves only if they exist |

## Out of scope
The four decoys awaiting clean implementation (`docs/clean-specs/`); denial of service by a volumetric network attacker
against the Hub (put it behind the reverse proxy / network controls).
