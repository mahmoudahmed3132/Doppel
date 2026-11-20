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

### Q73 — clean specs, common-decoy — Per-protocol enable flags and conditional privilege
`common-decoy.md` wants one enable flag and one port per protocol, and UID 0 with `NET_BIND_SERVICE` only when a configured port is below 1024. A manifest is static, and rule 7 treated every declared port as claimed even when its protocol was off.
**Meanwhile:** manifest v3 gains the optional `listen_ports[].enabled_key` (a declared bool key; false means no conflict check and no publishing). The privilege cannot depend on config: a decoy whose default ports are below 1024 declares UID 0 plus `NET_BIND_SERVICE` (as `tcp-tarpit` does, Q47); one that is configured to high ports only still gets that capability. `cli/internal/discover` ignores `enabled_key` (discovery may propose a port for a protocol the operator later disables; harmless, the Hub does not claim it). A Hub older than this change rejects manifests carrying `enabled_key` (strict decoding), so release the Hub before publishing a decoy.

### Q74 — roadmap E1 — Secrets at rest: plaintext rollback snapshot, required KEK, scope
Closing THREATMODEL R1 changes three defaults.
1. **Required KEK.** Production refuses to start without `TS_KEK_FILE`; development needs `TS_DEV_ALLOW_PLAINTEXT_SECRETS=true`. Existing deployments must create a KEK before upgrading.
2. **Plaintext snapshot.** **Answer (owner, 2026-11-15):** delete automatically after the first sealed start; implemented as a purge of snapshots older than `sealed_at`, repeated at every start. Original text: the pre-migration snapshot (`<db>.pre-v3-*.bak`) is plaintext, mode 0600, because it is the rollback copy for a Hub without encryption (schema v3 blocks the old Hub from reading the new file). **Meanwhile:** documented, delete after verification. Alternative if preferred: seal the snapshot's secrets with the new DEK (rollback then needs the new Hub's tooling) or delete it automatically after the first successful start.
3. **Scope.** Sealed: the four secret settings, admin TOTP seeds, honeytoken secrets. Not sealed: `beacons.token` (equality lookup, no authority), sensor config (no manifest declares secret keys yet; when one does, seal `sensors.config` with a row-bound AAD in the same change).
**Meanwhile:** the above.
**Answer (owner, 2026-11-15; applied with the E1 branch):** moved to Go 1.27.3 (released 2026-10-19, so older than 14 days; the Dockerfiles already built with it) with sigstore-go 1.4.0, in `go.work`, every `go.mod`, the CI, publish and CodeQL workflows and the README. Dependabot PR #25 failed only for lack of this move.

### Q75 — roadmap U1 — Users and roles: local credentials stay in `admin`; role matrix
The roadmap said to replace the single `admin` row with users. Secrets at rest (E1) changes that: migrations are SQL-only and run before the sealer exists, and the MFA seeds are sealed under an AAD that is not row-bound, so copying them into a multi-row table would leave ciphertext swappable between users.
**Meanwhile:** `users` (schema v4) holds principals (id, username, role, source `local`|`oidc`, disabled). The bootstrap administrator is user `usr_admin`; its password and MFA stay in the `admin` table, and `admin` exists if and only if `usr_admin` does (created together in setup, backfilled by v4, deleted together by factory reset). Sessions are recreated with `user_id` (one forced re-login at upgrade) and the role is read on every request, so a demotion, disable or delete applies to the next call, and the live feed re-checks the user on every tick. Every admin route now declares a required privilege at registration (`needViewer`, `needAnalyst`, `needAdmin`, `needLocal`); a route without one does not compile.
Matrix: **viewer** reads dashboards, events, nodes, catalogue, analytics, live feed; **analyst** adds sensitive reads (event and honeytoken exports, beacons and their artefacts, assets, a node's compose and previews) and triage (mark read, archive, silence/unsilence); **admin** everything else, including settings, SIEM/webhook, nodes and sensors, beacons, assets, delete-all, factory reset, update check and the users API. Password and MFA routes act on the one local account, so they require the bootstrap user (`needLocal`) and an SSO administrator gets 403. The bootstrap administrator cannot be changed or deleted through the API, and the last enabled administrator cannot be demoted, disabled or deleted. Audit records carry `actor` (user name; `anonymous` before login, `local` for host commands) and `actor_id`; syslog gets an additive `actor` parameter and ECS `user.name`.
**Limits:** there is no way to create a non-admin user until SSO (S1) lands (tests seed users through the store), and the UI role gating is cosmetic (the server enforces). **Answer needed:** whether viewers may see `GET /nodes/{node}/compose` (redacted compose, deployment topology); it is analyst-only for now.

### Q76 — WP-1A (`remote-access-decoy`) — Host key fallback, event limiter burst, and FTP `AUTH TLS`
Three minor details in `docs/clean-specs/remote-access-decoy.md` admit choices:
1. **SSH host key when `TS_PASSWORD_CAPTURE` is `plain` or `none`:** the deterministic Ed25519 key is derived from `HMAC-SHA256(TS_CAPTURE_KEY, "doppel:ssh-host-key:v1:" + sensorID)`. If `TS_CAPTURE_KEY` is absent in a non-hash mode (e.g., standalone tests), **meanwhile:** fall back to an ephemeral in-memory Ed25519 key via `crypto/rand` rather than refusing to start (never written to disk). When `TS_CAPTURE_KEY` is present (all Hub-deployed instances), derivation is always deterministic.
2. **Per-source event limiter (`TS_EVENT_COOLDOWN_SEC`, default 10):** standard SSH clients often offer a public key before falling back to password in the same connection. **Meanwhile:** `*_connection` events use `decoy.NewLimiter(1, cooldown)` while `*_login` events use `decoy.NewLimiter(6, cooldown)` (matching `TS_SSH_MAX_AUTH_TRIES` default) so a single session's auth methods are not dropped while sprays remain bounded; setting `TS_EVENT_COOLDOWN_SEC=0` reports every attempt.
3. **FTP `AUTH TLS` / `AUTH SSL`:** the spec allows `534` or optional TLS. **Meanwhile:** reply `534 Policy requires plain authentication.` without a TLS upgrade setting so the sensor stays minimal and requires no certificate material.
**Answer (owner, 2026-11-18):** all three defaults confirmed.

### Q77 — WP-1B (`database-decoy`) — Default enabled listeners, TLS refusal, and PostgreSQL `CancelRequest`
Three minor details in `docs/clean-specs/database-decoy.md` admit choices:
1. **Default enabled listeners and unprivileged runtime:** all three default database ports (`3306`, `5432`, `1433`) are `>= 1024`. **Meanwhile:** `TS_ENABLE_MYSQL`, `TS_ENABLE_POSTGRES`, and `TS_ENABLE_MSSQL` all default to `true` (each bound via `listen_ports[].enabled_key` so disabling any protocol releases its port), and the container runs unprivileged (`65532:65532`, no Linux capabilities) with `min: 1024` on the port settings.
2. **Optional TLS support:** the spec allows refusing TLS or supporting it via a setting. **Meanwhile:** keep the sensor minimal with no certificate material — MySQL does not advertise `CLIENT_SSL` and closes cleanly on a client `SSLRequest` (emitting `mysql_connection` with `ssl_requested: true`), PostgreSQL answers `'N'` to `SSLRequest` and `GSSENCRequest`, and MS-TDS advertises `ENCRYPT_NOT_SUP (0x02)` in `PRELOGIN`.
3. **PostgreSQL `CancelRequest`:** the spec states "`CancelRequest` closes silently." **Meanwhile:** close immediately without a wire reply and without emitting an event so query-cancel probes do not generate noise.

### Q78 — WP-1C (`identity-decoy`) — Ephemeral TLS cert, SPNEGO/Sicily NTLM framing, and default listeners
Three minor details in `docs/clean-specs/identity-decoy.md` admit choices:
1. **Default enabled listeners and privileges:** LDAP (`389`) and LDAPS (`636`) are below 1024 while RDP (`3389`) is above 1024. **Meanwhile:** `TS_ENABLE_LDAP`, `TS_ENABLE_LDAPS`, and `TS_ENABLE_RDP` all default to `true` (each bound via `listen_ports[].enabled_key` so disabling any protocol releases its port), and the manifest declares `user: "0:0"` with `cap_add: ["NET_BIND_SERVICE"]` (per Q73).
2. **Ephemeral in-memory TLS certificate:** generated fresh at startup using ECDSA P-256 (`CN=<hostname>.<domain_dns>`, 365-day validity window starting 24 h prior, never written to disk) and shared between LDAPS and RDP NLA.
3. **NTLM framing in LDAP SASL / Sicily and RDP CredSSP:** real clients send either raw `NTLMSSP\x00` tokens or SPNEGO-wrapped (`NegTokenInit` / `NegTokenResp`) tokens. **Meanwhile:** `unwrapNTLMToken` accepts both raw and SPNEGO-wrapped tokens (parsed strictly via `sdk/go/ber`) and mirrors the client's framing on the Type 2 CHALLENGE; Sicily negotiate (`0x8A`) returns `resultCode=0` with `serverCreds` in element 2 per MS-ADTS §5.1.1.1.3, and Sicily response (`0x8B`) always returns `invalidCredentials (49)`. StartTLS and other LDAP ExtendedRequests return `unavailable (52)`.

### Q79 — WP-1D (`network-service-decoy`) — DNS TCP toggle, SNMPv3 engine ID, and anti-amplification margin
Three minor details in `docs/clean-specs/network-service-decoy.md` admit choices:
1. **Optional TCP DNS listener and `enabled_key`:** the spec calls for UDP 53 and optionally TCP 53 (for `AXFR`/`IXFR` detection). **Meanwhile:** `TS_ENABLE_SNMP`, `TS_ENABLE_DNS` (UDP), and `TS_ENABLE_DNS_TCP` (TCP) all default to `true`, each bound to its own `runtime.listen_ports[].enabled_key` entry so disabling any listener releases that port/protocol in Hub conflict checks.
2. **Deterministic SNMPv3 engine ID:** `Report` PDUs for USM unknown-engine-ID discovery require an authoritative engine ID. **Meanwhile:** derive an 11-byte RFC 3411 engine ID (`0x80001f88` Net-SNMP enterprise + format `0x05` + 6 bytes from `HMAC-SHA256(TS_CAPTURE_KEY, "doppel:snmp-engine-id:v1:" + TS_SENSOR_ID)`, falling back to `SHA-256` with `TS_SNMP_SYS_NAME` when `TS_CAPTURE_KEY` is absent in `plain`/`none` mode) so each node has a stable, unique engine ID.
3. **SNMP anti-amplification guard (`len(reply) <= len(req) + 64`):** if an operator configures a long `TS_SNMP_SYS_DESCR` or a client sends a minimal request whose system-group response would exceed `len(req) + 64` bytes, **meanwhile:** trim `OCTET STRING` response values to fit within the budget, and drop the reply silently if it still cannot fit. Per-source UDP replies are additionally rate-limited separately from events (`TS_REPLY_RATE_PER_SEC`, default `10`/s).

### Q80 — WP-2A (`insights` projection) — Window propagation, deleted-sensor attribution, and ratio rounding
Three minor details in `docs/clean-specs/insights-projection.md` admit choices:
1. **Reporting `window` (days) without passing `days` in `params`:** `httpapi.Insights.projection` strips `days` from the pass-through `params` map (enforced by `TestProjectionsAndNavigatorWithModules`), while `insights` must report the Hub's window length as `window`. **Meanwhile:** attach `days` to `ctx` via `ported.WithWindowDays` / `ported.WindowDays` in `httpapi.Insights.projection`; direct callers without a context value may pass `params["days"]` (1..365), defaulting to `30`.
2. **Events from deleted/unlisted sensors and inactive honeytokens:** attacker events from a `(node_id, sensor_id)` not currently in the fleet are still aggregated into `by_type` (under `strings.TrimPrefix(sensor_id, "ts-sensor-")`, or `"unknown"` when empty) and `top_triggers`, but do not increment `touched.instances` so `0 <= touched.instances <= touched.total` always holds. `coverage.honeytokens_planted` counts tokens whose `Status` is `""` or `"active"`.
3. **`touched.ratio` precision:** **meanwhile:** report `touched.ratio` as a fraction in `[0, 1]` rounded to 4 decimal places (`0` when `total == 0`).

### Q81 — WP-2C (anti-fingerprinting personas, auto-blend discovery, demo simulator) — Persona defaults, scoring weights, and local demo execution
Three minor details in WP-2C admit choices:
1. **`identity-decoy` derived NTLM persona defaults vs manifest static defaults:** the Hub compose compiler injects static `default` values from `manifest.json` into container environment variables. **Meanwhile:** omit static `default` on `TS_DOMAIN_DNS`, `TS_DOMAIN_NETBIOS`, and `TS_HOSTNAME` in `sensors/identity-decoy/manifest.json` so Hub-deployed instances receive deterministic per-node/per-sensor defaults derived via `decoy.DeriveKey(TS_CAPTURE_KEY, "doppel:identity-persona:v1:" + TS_SENSOR_ID)` (explicit operator overrides still take precedence; absent `TS_CAPTURE_KEY` falls back to `corp.local`/`CORP`/`DC01`; TLS certificates remain ephemeral per start).
2. **`doppel discover` scoring & backward compatibility:** **meanwhile:** `discover.BuildPlan` ranks manifests using passive `/proc` signals (`+30` per matching process, `+20` per occupied port, `+15` per unoccupied standard port in `discovery.listening_ports` to fill service gaps like `database-decoy` on `5432`, `+10` per matching file), skips `enabled_key=false` ports when tracking conflicts, and seeds `taken` from already-deployed sensors on the node. `--plan` prints the conflict-free mix without mutating the Hub; `--json` emits clean JSON (implying `--plan`); `--apply` registers confirmed proposals and runs `apply`.
3. **`scripts/demo/run-demo.sh` runtime:** to work cleanly in ~60 seconds without requiring Docker or `sudo` (and without violating `scripts/compose-guard.sh`), **meanwhile:** compile and run the Hub and 6 demo decoys (`tcp-tarpit`, `remote-access-decoy`, `database-decoy`, `web-router-decoy`, `file-canary`, `token-receiver`) as local processes on high non-privileged ports using Hub-rendered `/v3/node/compose` environments, isolating `TS_ENV=development` and `TS_DEV_ALLOW_UNSIGNED_MANIFESTS=1` strictly to the ephemeral demo Hub.




### Q82 — F-004 — Signing-identity move and GA cut need the owner
Requirement 3 (move the signing identity to an organisation) and 4 (cut a signed `3.0.0` and run a rollback drill) need a real GitHub organisation, App credentials and a tag push. **Meanwhile:** no repository constants were changed (the organisation name is not known), `Version` stays `3.0.0-rc.1`, and `docs/operations.md` §9.5 is the owner runbook. The workflows already derive owner names from `github.repository_owner`, so the move does not need workflow edits.

### Q83 — F-004 — Image names and aliases for already-signed manifests
Released sensor manifests are signed and pin `image.repository = ghcr.io/<owner>/ts-sensor-<name>`. Renaming it would invalidate them. **Meanwhile:** `publish-sensor.yml` accepts either `doppel-sensor-<name>` or the legacy `ts-sensor-<name>` in the manifest, publishes under the declared name and pushes the other as a signed alias (same digest). The Hub publishes `doppel-hub` with the `ts-hub` alias. Sensor manifests move to `doppel-sensor-*` at their next version bump (not done here: it needs a version bump per sensor and a republish).

### Q84 — F-004 — SLSA generator is referenced by tag, not commit SHA
`slsa-github-generator` reusable workflows refuse to run when referenced by a commit SHA (they verify their own tag ref). **Meanwhile:** they are pinned to the immutable-by-convention tag `v2.1.0`; every other action stays SHA-pinned. Dependabot's `github_actions` ecosystem proposes bumps.

### Q85 — F-004 — Trivy gate scope and waivers
The release gate fails on any CRITICAL vulnerability, fixable or not (the existing PR-time scans stay HIGH/CRITICAL with `ignore-unfixed`). Waivers are JSON in `.github/trivy-waivers.json` (`id`, `statement`, `expired_at` ≤ 90 days, validated by `scripts/release/check-waivers.sh`). **Meanwhile:** the file ships empty. Binary SBOMs and the gate for CLI binaries use `trivy rootfs` on the binary's Go build info; the Hub also gets a binary SBOM extracted from the image. Sensor binaries are covered by the image SBOM only.

### Q86 — F-004 — `DOPPEL_*` scope and wire names
`DOPPEL_*` is accepted wherever the Hub, CLI and SDK read process configuration. Hub-rendered sensor keys stay `TS_*` (they are manifest keys, part of the signed contract). Wire and audit strings (`product: "truesignal-hub"`, audit route names, ECS module names, the version banner) are unchanged because SIEM rules and contract v3 consumers match on them. **Meanwhile:** rename them only with a contract bump.

### Q87 — F-603 — `429 overloaded`: no capability string, fixed limits, heartbeats not gated
The contract rules ask for a capability string per contract addition, but `/v3/version` has no capability list today and its body is pinned byte-for-byte by tests and older CLIs. Every SDK already retries any `429` and honours `Retry-After`, so no client needs to detect the new code. **Meanwhile:** `overloaded` is a new `429` error code documented in `docs/contract-v3.md` without a capability string. The admission limits are constants (`IngestMaxInFlight = 8`, `IngestAdmitWait = 1 s`, `Retry-After: 1`), not environment variables, because SQLite serialises writers on one connection and more concurrency only holds request bodies in memory; revisit with F-601 (PostgreSQL). Only event batches are gated: heartbeats and stop notices bypass admission so an event flood cannot make sensors look offline.

### Q88 — F-603 — `dropped_events` "in metrics" before `/metrics` exists
F-603 asks to expose `dropped_events` in metrics, but the Prometheus endpoint is F-003a, which is not merged. **Meanwhile:** the Hub persists a cumulative per-sensor count (schema v5, `sensors.dropped_events`, saturating add), serves it in the sensor view of `GET /api/v3/nodes/{node}`, shows it on the node page, and logs each non-zero report. F-003a should export it as `doppel_sensor_dropped_events{node,sensor}` from that column and the overload refusals (`ratelimit.Gate.Refused`) as `doppel_ingest_rejected_total{code="overloaded"}`. The count is at-least-once: if a heartbeat is committed but its reply is lost, the SDK reports the same drops again, so it can over-report, never under-report.

### Q89 — F-603 — What the kill -9 test proves, and the SDK memory bound
`kill -9` of the Hub process cannot lose data the kernel already holds, so the acceptance test proves that the Hub acknowledges only committed events (it fails, for example, when storage is made asynchronous). Survival of an OS crash or power loss rests on `synchronous=FULL`, which `TestDurabilityPragmas` pins; simulating it needs fault-injecting storage and belongs to F-608. SDK memory: the queue was bounded by count (1000) but not by size. **Meanwhile:** both SDKs apply the contract's per-event limits before queueing (details ≤ 64 KiB else `{"details_dropped":true}`, source/target ≤ 256 bytes), so the worst case is about 66 MiB for the default queue, under the 128 MB sensor limit but not by much. A byte budget for the queue is a follow-up, not part of this change.

### Q90 — F-002 — Schema v6 assignment, drill exclusion in projections, ASN DB configuration, and `docker_desktop` banner before F-505
Four details in F-002 admit choices:
1. **Schema version assignment (v6):** `docs/plan/EXECUTION-PLAN.md` §0 originally reserved schema v5 for F-002, but F-603 (`sensors.dropped_events`) landed on `main` using schema v5. **Meanwhile:** F-002 uses schema **v6** (`events.source_ip`, `events.source_port`, `events.source_kind`, index `events_source_ip`, and the batched Go migration hook `backfillEventSourcesTx` in batches of 5,000 rows).
2. **Drill exclusion and `source_kind` classification:** `sensors/file-canary/watch.go` emits literal `"local"` (`source_kind = "local"`), `doppel firedrill` emits `"Fire drill"` (`source_kind = "drill"`), and network connections from loopback (`127.0.0.0/8`, `::1`) or Docker Desktop NAT (`192.168.65.0/24`) are parseable IPs (`source_kind = "ip"`) tagged with `labels: ["host_local"]`. All analytics projections (`sources`, `attack_path`, `insights`, `report`, `geo_map`, and `attack_matrix`) key on `source_ip` when set (else `source`) and exclude `source_kind == "drill"` (`"Fire drill"`), while `/api/v3/events` continues to store and return drill events for operational verification.
3. **`group_by=asn` database configuration:** DB-IP Lite City (`dbip-city-lite.mmdb`) does not include `autonomous_system_number` records. **Meanwhile:** `hub/internal/geoip` loads an optional MaxMind/DB-IP ASN database from `TS_GEOIP_ASN_DB` (or `DOPPEL_GEOIP_ASN_DB`, defaulting to `<DataDir>/geoip/dbip-asn-lite.mmdb` when present) and exposes `LookupASN(addr) (asn, org)`; when no ASN database is loaded or an IP has no ASN record, `group_by=asn` falls back to `AS-unknown` for IP sources.
4. **Node page Docker Desktop banner ahead of F-505:** F-505 (node host facts reporting `docker_desktop=true`) is not merged yet. **Meanwhile:** `NodePage` (`ui/src/pages/fleet.tsx`) checks `n.host_facts?.docker_desktop === true || n.facts?.docker_desktop === true || n.docker_desktop === true || (n.tags ?? []).includes("docker_desktop=true")` and renders the warning banner `"source IPs on this node are not real client addresses"`.

