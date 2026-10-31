# Questions for the specification team

Format: id, spec section, question, conservative choice taken meanwhile.
Answers are recorded here verbatim when received.

### Q1 — §0.8 / §15 — Licence conflict
The repository was created with an Apache-2.0 `LICENSE`, but §0.8 requires an
"All rights reserved" header on every file and §15 asks for a placeholder
`LICENSE`. These contradict each other.
**Meanwhile:** the existing `LICENSE` file is left untouched (owner's file);
every source file carries the §0.8 header verbatim.

### Q2 — §2 — Go module path
The repository is `github.com/mahmoudahmed3132/TrueSignal-Rewrite`. Is that
the final import path, or will it move (rename/org transfer)?
**Meanwhile:** module paths use `github.com/mahmoudahmed3132/TrueSignal-Rewrite/<component>`.

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
