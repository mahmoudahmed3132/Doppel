# Questions for the specification team

Format: id, spec section, question, conservative choice taken meanwhile.
Answers are recorded here verbatim when received.

### Q1 — §0.8 / §15 — Licence conflict
The repository was created with an Apache-2.0 `LICENSE`, but §0.8 requires an
"All rights reserved" header on every file and §15 asks for a placeholder
`LICENSE`. These contradict each other.
**Meanwhile:** the existing `LICENSE` file is left untouched (owner's file);
every source file carries the §0.8 header verbatim.
**Answer (owner, 2026-10-31):** interim choice confirmed. Note: the Apache-2.0
grant in `LICENSE` and the "All rights reserved" headers still conflict
legally; whichever is intended should be settled before any public release.
**Answer (owner, 2026-10-31, final):** proprietary. The repository is private; `LICENSE` is replaced by a proprietary notice and every header names the owner, `TrueSignal Deception` (placeholder brackets removed). Counsel reviews the period when the repository was public with the Apache-2.0 file.

### Q2 — §2 — Go module path
The repository is `github.com/mahmoudahmed3132/TrueSignal-Rewrite`. Is that
the final import path, or will it move (rename/org transfer)?
**Meanwhile:** module paths use `github.com/mahmoudahmed3132/TrueSignal-Rewrite/<component>`.
**Answer (owner, 2026-11-15, Q66):** the repository is now `mahmoudahmed3132/Doppel`; module paths are `github.com/mahmoudahmed3132/Doppel/<component>`.

### Q3 — §4.1 vs §5.3 — `dropped_events` in heartbeats
§4.1 rejects unknown top-level fields; §4.3 lists the heartbeat body as
`sensor_id, config_revision, sdk_version`; §5.3 requires the SDK to send
`dropped_events` in the heartbeat.
**Meanwhile:** the contract defines `dropped_events` (integer, optional, ≥ 0)
as part of the heartbeat body; the Hub accepts it and still rejects any other
unknown field.

### Q4 — §5.1 — Environment variable names
Names for SDK configuration variables are not specified.
**Meanwhile:** `TS_HUB_ENDPOINT`, `TS_NODE_KEY`, `TS_SENSOR_ID`,
`TS_DEFAULT_SEVERITY`, `TS_CONFIG_REVISION`, `TS_TEST_MODE`, `TS_CA_BUNDLE`.
These are the Hub-reserved keys of §6.12.6 (plus `TS_CAPTURE_KEY`,
`TS_HONEYTOKEN`, `TS_BEACON_KEY`). Documented in `docs/contract-v3.md`.

### Q5 — §5.7 — Test-mode semantics of "delivery acknowledgement"
**Meanwhile:** success = the Hub answered `200` with the event counted in
`accepted` or `duplicates`. Any rejection, non-2xx, or timeout (10 s) = failure.

### Q6 — §5.5 — Stop notice when the Hub is unreachable
**Meanwhile:** the stop notice is attempted once with a 2 s timeout inside the
shutdown budget; failure is logged and the process still exits 0.

### Q7 — §4.1 — Error code for a valid node key with an unknown sensor in heartbeats
§4.1 gives `404 sensor_not_registered` for events. **Meanwhile:** the same code
is used for heartbeats and stop notices.

### Q8 — §4.2 — Strictness of `event_id` and `trigger`
The spec says `event_id` is a UUIDv7 and `trigger` is snake_case, but only
lists clamping as normalisation.
**Meanwhile:** events whose `event_id` is not a canonical UUIDv7 are rejected
(`invalid_event_id`); triggers not matching `^[a-z][a-z0-9]*(_[a-z0-9]+)*$`
(≤ 64 bytes) are rejected (`invalid_trigger`). Rationale: both flow into
SIEM fields and syslog parameters; rejecting is safer than rewriting. Sensor
ids not matching `ts-sensor-<kebab>` are rejected as `sensor_not_registered`.

### Q9 — §4.1 / §4.2 — HTTP status for a batch where every event fails the same way
§14.5 expects `403` for a reserved trigger and `404` for another node's
sensor, while §4.2 says one bad event must not reject the others.
**Meanwhile:** per-event failures are reported in `rejected` with `200`.
When **every** event of a batch is rejected with the same code
`reserved_trigger` or `sensor_not_registered`, the Hub answers `403` / `404`
with that code instead.

### Q10 — §6.9 — Content of the RFC 5424 MSG part
"the full record as single-line JSON": the ECS document from the PORTED
renderer, or the Hub's own record JSON?
**Meanwhile:** the Hub's own record JSON (event with enrichment, audit,
honeytoken inventory, heartbeat), so syslog output does not depend on the
PORTED renderer. No UTF-8 BOM is emitted before MSG.

### Q11 — §6.9 — Structured-data parameters for HONEYTOKEN and HEARTBEAT
Only EVENT and AUDIT parameter lists are specified.
**Meanwhile:** HONEYTOKEN: `honeytoken_id, username, planted_node_id,
planted_sensor_id, status`. HEARTBEAT: `version, uptime_seconds, nodes_total,
nodes_online, sensors_total, sensors_online, siem_queue_depth, siem_dropped`.
PRI severity for HEARTBEAT: 6. AUDIT `route` = `<METHOD> <route template>`.
`mitre_tactic` = primary technique tactics joined with `,`.

### Q12 — §6.3 — Encryption of the MFA secret at rest
Not required by the spec. **Meanwhile:** stored in the SQLite file, which is
protected by file permissions (0600) and the volume. Flagged in the threat model.

### Q13 — §4.1 — Rate limiting of unauthenticated ingest requests
The token bucket is per node key, so requests with invalid keys are not
limited by it. Keys are 256-bit, so guessing is infeasible; the residual risk
is load (one indexed lookup per request).
**Meanwhile:** no extra limiter. Proposal: a per-source-IP limiter on
authentication failures, applied together with the admin login limiter.

### Q14 — §6.3 — Setup when `TS_DASHBOARD_PASSWORD` is set
Setup sets both the password and the public endpoint; with the override the
password is given. **Meanwhile:** with the override the Hub creates (or
re-hashes) the admin at start, setup reports completed, and the public
endpoint is configured later through settings. If the override changes
between starts, the stored hash is replaced and all sessions are invalidated.

### Q15 — §6.3 — What an enrolment-only session may reach
"only the MFA status/enrol endpoints". **Meanwhile:** MFA status, begin
enrolment, confirm enrolment — and logout (it only reduces privilege).
Everything else answers `403 mfa_enrolment_required`.

### Q16 — §6.3 — Session invalidation scope for MFA changes
**Meanwhile:** enrol-confirm, disable and password change invalidate **all**
sessions (the caller logs in again with the new factor state). Regenerating
recovery codes invalidates all sessions **except** the caller's, so the new
codes can be shown and stored.

### Q17 — §6.3 — Lockout details
**Meanwhile:** counters are in memory; failures count within a 15-minute
window; reaching the threshold locks for 15 minutes. A successful login
clears only that IP's counter — never the account-wide counter, so a
distributed guessing campaign cannot be reset by the admin logging in.
Failures counted: login password/code, setup token, and password/code
re-confirmation on MFA and password-change endpoints. A correct password
without the required code (`mfa_required`) is not a failure.

### Q18 — §6.3 — "a current code" for disable / regenerate
**Meanwhile:** only a TOTP code is accepted there, not a recovery code.
An admin who lost the authenticator uses a recovery code to log in, or the
`mfa-reset` break-glass.

### Q19 — §6.3 — CSRF origin when no public endpoint is known yet
**Meanwhile:** the expected origin is the configured public endpoint's
origin; before setup (or with the password override and no endpoint) it is
the origin the request arrived on (scheme from TLS or a trusted proxy's
`X-Forwarded-Proto`, host from `Host` or a trusted proxy's
`X-Forwarded-Host`). Requests without `Origin` and `Referer` are refused.

### Q20 — §6.3 — Hub without the PORTED TOTP module
**Meanwhile:** MFA endpoints answer `503 mfa_unavailable`; an admin with MFA
enrolled cannot log in until the module is installed (break-glass:
`mfa-reset`); `TS_REQUIRE_MFA=true` refuses to start. All fail closed.

### Q21 — §6.4 — "mark node for upgrade of all sensors"
**Meanwhile:** the request immediately moves every sensor of the node to its
latest non-deprecated catalogue version as one rendered, atomic change; the
node picks it up on its next `apply`. No separate "marked" state is kept.
Requires the catalogue (503 `catalogue_unavailable` otherwise).
**Answer (owner, 2026-10-31):** accepted as the default.

### Q22 — §7 — Masking secret configuration values without a verified manifest
**Meanwhile:** values of keys the manifest marks secret are returned as
`********`. When the manifest is unknown or unverified, **all** values are
masked (`config_masked` lists them). Edits send `null` for a key to keep its
current value, so masked values never need to be re-entered.

### Q23 — §3 — Who chooses the sensor instance id
**Meanwhile:** the admin may give a kebab-case instance `name`; the id is
`ts-sensor-<name>`, defaulting to the catalogue name. A second instance of the
same sensor on one node needs an explicit name (`409 sensor_exists` otherwise).

### Q24 — §6.12.11 — Deleting a sensor when rendering is impossible
**Meanwhile:** add/edit/upgrade are refused without a successful render, but
deletion is always allowed (removing a decoy must never be blocked); if the
remaining set cannot be rendered, the node's desired revision is cleared.

### Q25 — §6.4 — Node health "online"
**Meanwhile:** a node is online when it made an authenticated request within
the last 90 s (three SDK heartbeat intervals); `in_sync` = desired revision
equals the revision last applied by the CLI.

### Q26 — §6.4 / §6.12.9 — Secrets in the admin compose preview
The rendered compose contains injected secrets (node key, capture key,
honeytoken, beacon key). **Meanwhile:** admin previews are always rendered
with secrets replaced by placeholders; only the node-authenticated CLI fetch
(to be built with §8) receives real values.

### Q27 — §6.3 vs §6.12.9 — Injecting the node key
§6.3 stores node keys only as SHA-256; §6.12.9 says the Hub injects the node
key into each sensor. The Hub cannot inject what it does not keep.
**Meanwhile:** the Hub omits `TS_NODE_KEY` and names it in
`x-truesignal.node_key_env`; the CLI adds the key from its 0600 config to
every service before writing the 0600 compose file. A user-supplied
`TS_NODE_KEY` config value is dropped like any reserved key.

### Q28 — §6.12.4 — Mounting an ancestor of a forbidden path
The rule forbids mounts *inside* `/run`, `/var/lib/docker`, …; mounting
`/var` or `/var/lib` would expose them just the same.
**Meanwhile:** ancestors of any forbidden prefix are refused too. Effect:
lures cannot live directly in `/` or `/var` (parent mounts), but `/var/www/…`,
`/srv/…`, `/home/…`, `/opt/…` work. Symlinks on the host cannot be resolved by
the Hub; the CLI will re-check resolved paths before `apply` (§8).

### Q29 — §6.12 — Compose output format
**Meanwhile:** JSON (a YAML subset accepted by Docker Compose), long-syntax
volumes/ports. Avoids YAML quoting/injection classes entirely and makes the
CLI's semantic comparison trivial.

### Q30 — §9 — Template defaults on the Hub
**Meanwhile:** the Hub does not evaluate discovery templates
(`free_port(…)` etc.); a key whose only default is a template needs an
explicit value, otherwise `422 missing_config`.

### Q31 — §6.12 — Hardening beyond the listed rules
**Meanwhile:** every container also gets `pids_limit: 256`, a memory limit
(manifest `memory_mb`, default 256 MiB), a 16 MiB `/tmp` tmpfs (the root FS is
read-only), bounded json-file logs, `restart: unless-stopped`, and bind mounts
with `create_host_path: false` (a missing lure directory fails the deploy
instead of Docker creating it as root). Tell us if any of these conflicts with
a PORTED decoy's needs (e.g. memory for the scan detector).

### Q32 — §6.7 / §10 — Registry location and index format
Neither the default URL nor the index format is specified.
**Meanwhile:** default `https://raw.githubusercontent.com/mahmoudahmed3132/TrueSignal-Rewrite/registry/`
(the publish workflow's `registry` branch), overridable by `TS_REGISTRY_URL`
and the `registry_url` setting; index format in `docs/registry.md`. Bundles are
`<manifest path>.sigstore.json`.
**Superseded by Q64 (2026-11-01):** the default is now
`https://raw.githubusercontent.com/mahmoudahmed3132/truesignal-releases/registry/`.

### Q33 — §6.7 — Which version is "latest"
The index carries `latest`, but the Hub may not have verified that version.
**Meanwhile:** the Hub computes latest = highest verified, listed,
non-deprecated version; the index value is advisory. Upgrades never move to an
unverified version even if the index points there.

### Q34 — §6.7 — Deprecated or removed versions with deployed instances
**Meanwhile:** they stay renderable (the deployed decoy keeps working and can
be edited) but are reported as deprecated and never offered as latest. Removal
from the index is treated as deprecation. New instances on a deprecated version
are still accepted — tell us if those should be refused.

### Q35 — §6.7 — Caching verified manifests
**Meanwhile:** verified manifest + bundle bytes are cached in the database
(schema v2) and re-verified on every start, so a registry outage does not stop
renders; a verifier that now rejects (revocation, module missing) unloads them.

### Q36 — §6.8 — Plain-HTTP webhooks
**Meanwhile:** webhook URLs must be `https://` (the URL carries tokens);
`http://` is accepted only with `TS_ENV=development`. Self-hosted ntfy/gotify
on plain HTTP need a TLS proxy.

### Q37 — §6.9 — Ordering versus "applies immediately" when switching SIEM output
**Meanwhile:** the switch interrupts retries against the old destination,
delivers the pre-switch `siem.update` audit to it with a 10 s bound (failure
logged), then swaps; queued and in-flight records go to the new destination.
The request answers only after the swap.

### Q38 — §6.9 — Unusable stored SIEM output at start
E.g. ECS selected but the renderer module is absent. **Meanwhile:** the Hub
starts with SIEM delivery off and logs an ERROR on every start until the output
is reconfigured; refusing to start would take down ingestion and liveness too.
Tell us if you prefer fail-to-start.

### Q39 — §6.8 — Default armed state and test buttons
**Meanwhile:** a fresh Hub is armed. Test buttons ignore armed state and the
severity filter (they verify connectivity). Test records use trigger
`siem_test` / `webhook_test`, severity `info`, source `truesignal-hub` and the
all-zero UUIDv7 `00000000-0000-7000-8000-000000000000`, so SIEM rules can
exclude them.

### Q40 — §6.9 — Honeytoken inventory "on creation"
Creation happens inside the PORTED honeytoken module. **Meanwhile:** the Hub
wraps the module's `Ensure` and emits an inventory record the first time it
sees a token id (seeded from the inventory at start).

### Q41 — §8 — Scheduling `apply`
The CLI is "on demand (not a daemon)". **Meanwhile:** no timer is installed;
operators run `truesignal apply` after changes (or schedule it, e.g. a systemd
timer or cron). Tell us if the installer should install a timer.

### Q42 — §8 / Q28 — Symbolic links in host paths
**Meanwhile:** `apply` refuses any bind source that resolves through a symlink,
is missing, or resolves into a forbidden tree. Stricter than needed for some
setups (e.g. `/home` as a symlink) but closes the gap the Hub cannot see.

### Q43 — §8 — Failed applies
**Meanwhile:** `rolled_back`/`failed` are reported to the Hub, which logs a
warning; the applied revision is not advanced, so the node shows `in_sync:
false`. Proposal: raise a Hub event (e.g. `node_apply_failed`, severity high) so
the SOC sees decoys that are not running as configured — needs your approval
since it adds a trigger.
**Answer (owner, 2026-10-31):** approved. Implemented as `node_apply_failed`
(Hub-raised, reserved, severity high, empty `sensor_id`, target = node id,
details `revision, desired_revision, result, message`), raised once per node and
revision; a successful apply re-arms it.

### Q44 — §4.4 — CLI requests without a version header
**Meanwhile:** node endpoints answer `426` when the header is missing or not
SemVer, not only on a major mismatch.

### Q45 — §8 — Admin session from the CLI (`discover`)
**Meanwhile:** the CLI logs in through the normal admin API, sending
`Origin: <hub endpoint>`; the CSRF check therefore requires the node to be
linked with the Hub's public URL. The session is logged out at the end;
credentials are never written.

### Q46 — §8 / §10 — Release asset names and signing identity
**Meanwhile:** assets `truesignal-linux-{amd64,arm64}`, `SHA256SUMS`,
`truesignal-linux-<arch>.sigstore.json`; cosign identity
`https://github.com/mahmoudahmed3132/TrueSignal-Rewrite/.github/workflows/publish-cli.yml@refs/tags/cli/vX.Y.Z`.
The release workflow (§10) must produce exactly these.
**Update (Q64, 2026-11-01):** assets and identity unchanged; the release is
now created in `mahmoudahmed3132/truesignal-releases`, which `install.sh`
downloads from.
**Update (Q66, 2026-11-15):** the source repository is `mahmoudahmed3132/Doppel`; the identity is
`https://github.com/mahmoudahmed3132/Doppel/.github/workflows/publish-cli.yml@refs/tags/cli/vX.Y.Z`.
Releases up to `cli/v3.0.0` keep the old identity (`docs/operations.md` §9.2).

### Q47 — §2 / §11 — Sensors that need a privilege run as UID 0
Docker grants `cap_add` capabilities only to UID 0 (no ambient capabilities in
Compose) and `no-new-privileges` disables file capabilities, so a UID-65532
sensor can never use `NET_RAW`/`NET_BIND_SERVICE`/`DAC_OVERRIDE`.
**Meanwhile:** tcp-tarpit, icmp-canary, network-scan-detector and file-canary
(sensor and init) run as UID 0 with `cap_drop: ALL` + one capability,
read-only root filesystem, no-new-privileges; each logs its uid and CapEff.
The web decoy stays unprivileged by publishing a host port to a fixed
container port (new manifest field `listen_ports[].container_port`).

### Q48 — §11.5 — Web decoy behind Docker port publishing
**Meanwhile:** bridge network + published port. Source IPs are preserved with
Docker's default iptables DNAT; hosts using the userland proxy will show the
Docker gateway as source. Host networking would preserve them but would need
UID 0 + NET_BIND_SERVICE for port 80.

### Q49 — §11.4 — File canary deployment prerequisites
**Meanwhile:** the File Canary declares `TS_HONEYTOKEN`, so the Hub refuses to
deploy it (`honeytoken_unavailable`) until the PORTED honeytoken module is
installed, and the stub lure content must be replaced by the PORTED lure
generator before production use. Lures are created owned by root, mode 0644;
tell us if they should take the directory owner's uid/gid.
**Update (merge imports H8, S1, 2026-11-15):** the honeytoken module and the lure generator are installed, so the File Canary deploys and plants realistic lures. Lure ownership (root, 0644) is unchanged.

### Q50 — §11.3 — Scan detector capture cost
**Meanwhile:** no kernel BPF filter; every inbound frame header is read in
user space and filtered there. Adequate for typical servers; a cBPF filter
(TCP without ACK/RST + UDP) is the planned optimisation.

### Q51 — §11.5 — Rate limiting login attempts
**Meanwhile:** every login attempt is reported by default
(`TS_LOGIN_COOLDOWN_SEC=0`) so a honeytoken attempt is never suppressed; the
SDK's bounded queue limits memory under brute force. Page views and probes are
rate-limited per source.

### Q52 — §6.13 — Factory reset when the audit cannot reach the SIEM
"Audited before execution to the current SIEM output." **Meanwhile:** the reset
is refused (`502 audit_undeliverable`) if that delivery fails, so a stolen
session cannot wipe the Hub while the SIEM is unreachable. An operator whose
SIEM is genuinely gone sets the SIEM output to `none` first (itself audited to
the old destination). The catalogue cache (signed public manifests) survives a
reset; Hub master keys are deleted with the settings.

### Q53 — §6.4 — Danger-zone confirmations and export auditing
**Meanwhile:** "delete all events" requires `{"confirm": "DELETE ALL EVENTS"}`
and factory reset `{"confirm": "FACTORY RESET"}` plus the password, so the
UI's confirm-by-typing is also enforced by the API. Event and honeytoken
exports are audited (`events.export`, `honeytokens.export`) although they are
GET requests. Exports are capped at 1 000 000 events per request.

### Q54 — §6.4 — Live feed and session lifetime
**Meanwhile:** an open live feed does not count as activity: the session is
re-validated every 15 s without refreshing its idle timer, so the 15-minute
idle timeout still applies to an unattended dashboard and logout, password or
MFA changes close open feeds within one tick. The UI's API calls refresh the
session as usual.

### Q55 — §6.11 — Update-check source
**Meanwhile:** `TS_UPDATE_CHECK_URL` (default: the GitHub releases API of this
repository); tags `hub/vX.Y.Z` and `cli/vX.Y.Z`, drafts and pre-releases
ignored; interval from `update_check_hours` (0 = off). This is the only
outbound call besides registry, SIEM and webhooks.
**Update (Q64, 2026-11-01):** the default is the releases API of
`mahmoudahmed3132/truesignal-releases`.

### Q56 — §7 item 6, §12 — Projection names used by the UI pages
The PORTED projection contract was not provided, so page → projection name is
an assumption: Attack path → `attack_path`, Scans → `sources`, Geo map →
`geo_map`, Report → `report`, ATT&CK matrix → `attack_matrix` (plus the
Navigator layer endpoint). The mapping is one constant
(`ui/src/pages/modules.tsx`, `PROJECTIONS`).
**Meanwhile:** a page whose projection is not registered (per
`/system/status` `modules.projections`) shows "module not installed"; an
installed projection's DTO is rendered generically (tables/key-value, as
text). Dedicated visualisations (matrix grid, map, path graph) need the DTO
contracts. Please confirm the names or supply the contracts.
**Answer (owner, 2026-10-31):** confirmed; the "Meanwhile" behaviour stands.

### Q57 — §6.3, §7 — No QR code for TOTP enrolment
Rendering a QR code needs either a third-party encoder or a hand-written one
(several hundred lines of Reed–Solomon/masking code to own and test).
**Meanwhile:** enrolment shows the base32 secret (grouped) and the
`otpauth://` URI with copy buttons; every mainstream authenticator accepts
manual entry. Say if a QR code is required; a permissive encoder would be
added to `THIRD_PARTY.md`.
**Answer (owner, 2026-10-31):** confirmed; the "Meanwhile" behaviour stands.

### Q58 — §7 item 6 — Beacon types
The beacon module's supported `type` values are part of its PORTED contract.
**Meanwhile:** the Beacons page takes the type as free text (≤ 32 chars) and
relies on the Hub/module to validate it.
**Answer (owner, 2026-10-31):** confirmed; the "Meanwhile" behaviour stands.
**Update (merge import H7, 2026-11-15):** with the beacon module installed the types are `dns`, `web-bug` and `kubeconfig` (kebab-case, as the API requires); the page offers them as a choice. A beacon points at the zone of the deployed Token Receiver (`TS_BEACON_DOMAIN`); creation is refused unless exactly one zone is deployed.

### Q59 — §7 — Hub upgrade notice
**Meanwhile:** "new Hub release" is a dismissible banner for the current page
view only (the Hub image is upgraded by the operator, not from the UI); the
CLI release notice is acknowledged per version via
`POST /system/cli-notice/ack` and stays hidden until the next CLI release.
**Answer (owner, 2026-10-31):** confirmed; the "Meanwhile" behaviour stands.

### Q60 — §0, §10 — Container image names
The names the earlier milestones used for sensor images
(`ghcr.io/mahmoudahmed3132/truesignal-sensor-*`) fall inside the namespace §0
forbids (`ghcr.io/mahmoudahmed3132/truesignal-*`): publishing there would push
into, and the "already published" guard would read from, the prior project's
packages. **Meanwhile:** images are `ghcr.io/<owner>/ts-hub` and
`ghcr.io/<owner>/ts-sensor-<name>` (manifests updated; a test pins the
prefix). No prior image was ever pulled or inspected. Confirm or choose
other names (one constant per workflow plus `sensors/*/manifest.json`).
**Answer (owner, 2026-10-31):** confirmed; the "Meanwhile" behaviour stands.

### Q61 — §10 — Extra publish guards
Beyond the spec, publish workflows also refuse (a) a tag whose commit is not
on the default branch (only reviewed code is released) and (b) a sensor whose
image tag already exists although the version is not in the registry (a
previous run died between push and registry commit). (b) keeps image tags
immutable; recovery is a deliberate deletion of that package version. Say if
either is unwanted.
**Answer (owner, 2026-10-31):** confirmed; the "Meanwhile" behaviour stands.

### Q62 — §10 — `:latest` and pre-releases
**Meanwhile:** `:latest` only ever points at a plain `X.Y.Z` release;
pre-release tags (`hub/v4.0.0-rc.1`) publish their version tag but are never
`:latest` candidates. The update check (Q55) ignores GitHub pre-releases too.
**Answer (owner, 2026-10-31):** confirmed; the "Meanwhile" behaviour stands.

### Q63 — §10, §12 — Sensor pre-release versions
The PORTED verifier accepts only plain `X.Y.Z` sensor versions (step-1 README,
note 3). **Meanwhile:** kept as is, and `scripts/release/check-tag.sh` now
refuses `sensor/<name>/vX.Y.Z-<pre>` tags, so a pre-release sensor manifest
that every Hub would reject is never published. Q62 (pre-releases) still
applies to the Hub only. Extend both together if sensor pre-releases are
wanted.

### Q64 — §8 / §10 / §6.11 — Public artefacts after the repository went private
With the source repository private, the default registry URL, `install.sh`
and the update check returned 404 to anonymous clients.
**Answer (owner, 2026-11-01):** publish the public artefacts from a separate
public repository `mahmoudahmed3132/truesignal-releases`; (1) a GitHub App,
not a fine-grained token, as the cross-repository credential; (2) serve the
registry from its `registry` branch through `raw.githubusercontent.com` (up to
about five minutes of staleness after a publish is accepted: the catalogue is
signed and versioned), not GitHub Pages; (3) the private repository's name
stays visible in signing certificates and the public Rekor log, accepted.
**Implemented:** building, signing, tags and `:latest` stay in the private
repository, so every signing identity is unchanged. The publish workflows mint
a per-job App installation token (contents:write on the releases repository
only) to push the `registry` branch and create releases there
(`scripts/release/publish-release.sh`, `registry-commit.sh` with
`REGISTRY_REMOTE`). Hub defaults and `install.sh` point at the releases
repository; `install.sh` keeps verifying the source repository's identity.
Setup and migration: `docs/operations.md` §9.1,
`scripts/release/migrate-releases-repo.sh`.

### Q65 — §10 — CodeQL without GitHub code scanning
Since the repository became private, uploading CodeQL results fails: code
scanning needs GitHub Code Security, which is not enabled.
**Answer (owner, 2026-11-01):** option 2, no licence. Run CodeQL without
uploading and gate in the job.
**Implemented:** `codeql.yml` analyses with `upload: never`;
`scripts/codeql-gate.py` fails on every result not listed in
`.github/codeql/accepted-findings.json`. Each entry names the rule, the file
and CodeQL's fingerprint of the flagged line, plus a reason, so a change to
that line or any new finding fails again until re-reviewed. The SARIF is kept
as a workflow artifact for 30 days. Dismissals made earlier in code scanning do
not carry over; any such finding that reappears is re-traced before it is
listed. If Code Security is enabled later, restore the upload and move the
accepted entries back to dismissals.


### Q66 — merge §6 — Rebrand of wire and operational identifiers to Doppel
The mapping and compatibility plan are in `MERGE-INVENTORY.md` §4.
**Meanwhile:** only user-facing text becomes "Doppel". Every wire and
operational identifier (CLI binary and paths, image names, `TS_*`, `tsk_`,
`io.truesignal.*` labels, SDK package names, syslog and ECS names, the
releases repository and the copyright holder) stays unchanged until the
owner approves the mapping.
**Answer (owner, 2026-11-15):** go with the recommendations in `MERGE-INVENTORY.md` §4. Change: Go module paths; the CLI binary, paths and asset names (with a one-release `truesignal` symlink and config fallback); SDK package names (with a one-release `truesignal_sdk` shim); syslog and ECS names behind `siem_legacy_names` (default on). Keep: `TS_*`, `tsk_`, `io.truesignal.*` labels, the `ts-hub` / `ts-sensor-*` image names and `truesignal-releases`. The copyright holder stays `TrueSignal Deception` until the owner names the legal entity.

### Q67 — merge §3 — Relicensing Claude-new files from an AGPL-3.0 work
`TrueSignal` as a whole is AGPL-3.0: it derives from HoneyWire (`NOTICE`,
`7679bcf`). The files classed claude-new were written in that repository,
against its interfaces.
**Meanwhile:** nothing from `TrueSignal` is merged into `main` until the owner
confirms, after counsel's advice, that those files can be relicensed under
the proprietary `LICENSE`. Import branches can be prepared and reviewed in
the meantime.
**Answer (owner, 2026-11-15):** approved. The owner relicenses the claude-new files under the proprietary `LICENSE`, as their copyright holder. Counsel's confirmation is still recommended before any external distribution.

### Q68 — merge §3 — Decoys "ported in concept" from Trapster Community (AGPL-3.0+)
The Identity, Database, Remote Access and Network Service decoys are
self-declared reimplementations of Trapster Community's concepts.
**Meanwhile:** they are not imported. Each becomes a clean spec, written from
public protocol specifications and Doppel's contracts, for a session with no
access to `TrueSignal`, HoneyWire or Trapster.
**Answer (owner, 2026-11-15):** approved; the four decoys are clean specs.

### Q69 — merge §3 / Q56 — Dedicated analytics pages
The `TrueSignal` pages for these are Vue code and cannot be imported into the
Preact UI.
**Meanwhile:** the generic projection rendering of Q56 stays. If the owner
wants dedicated pages (ATT&CK matrix, geo map, attack path, printable report,
asset editor), they become a clean spec for the UI.
**Answer (owner, 2026-11-15):** the owner wants every feature; the dedicated pages become a clean spec (`docs/clean-specs/analytics-ui.md`).

### Q70 — merge H1 — GeoIP database auto-update
Auto-update adds an outbound call (Q55 lists the allowed ones).
**Meanwhile:** `TS_GEOIP_AUTO_UPDATE` defaults to off. When it is on, it
fetches only the DB-IP Lite URL documented in `docs/operations.md`, over
HTTPS with no redirects to other hosts.
**Answer (owner, 2026-11-15):** the default (off) is approved.

### Q71 — Q66 follow-up — Rebrand items applied in this merge, and the one deferred
**Applied (branch `rebrand/doppel`):** product text (README, docs, UI, sensor
manifest authors, TOTP issuer); the CLI command `doppel` (directory
`cli/cmd/doppel`) with a `truesignal` link from `install.sh` and legacy-path
fallback; release assets `doppel-linux-<arch>`; the Python SDK `doppel-sdk` /
`doppel_sdk` with a warning `truesignal_sdk` alias. **Kept, as approved:**
`TS_*`, `tsk_`, `io.truesignal.*`, the compose project name `truesignal`,
`x-truesignal`, the `ts-hub` / `ts-sensor-*` images, `truesignal-releases`,
the `X-TrueSignal-CLI-Version` header, the User-Agent strings, the SIEM rule
IDs, and the copyright holder.
**Deferred:** the `siem_legacy_names` switch for syslog and ECS names. With the
approved default (on), output is exactly what Doppel emits today, so nothing
changes until the switch exists. Implementing it changes the SIEM contract,
the settings API and OpenAPI, and the detection rules. **Meanwhile:** legacy
names only; implement the switch in its own branch before announcing new
SIEM names.

### Q72 — Go 1.27 toolchain
sigstore-go 1.4.0 and later need Go 1.27, through `github.com/digitorus/pkcs7`.
Go 1.27.4 was released 2026-11-02.
**Meanwhile:** the repository stays on Go 1.26.10 with sigstore-go 1.3.0. Move
to Go 1.27 in one deliberate branch, once a Go 1.27 patch release is at least
14 days old: `go.work`, every `go.mod` (`go` and `toolchain`), CI and CodeQL
`setup-go`, the Dockerfiles' golang images and HANDOFF/README. Run all gates
before merging.
