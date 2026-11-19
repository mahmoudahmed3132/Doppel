# Doppel simplification plan: dead code, duplication, stale assumptions

Owner: Mahmoud. Auditor: Fable 5.2. Executor: Sonnet 5.5.
Written 2026-11-16 against `main` at `b6ecbbd` (schema v3, Go 1.27.3).
**Status (2026-11-19):** S1–S5 executed (PR #36). §3 items 1 and 7 are resolved (the CLI command is `doppel`; the four decoys now call `sdk/go/ber` and `decoy.*`); items 2–6 and 8 are still open.

Baseline on that commit: `go build ./...` and `go test -count=1 ./...` in `hub/` are green.

This file is self-contained. Do the packages in order, one commit each. Every
package must leave the shipped Hub, CLI, sensors and the wire formats (admin
API JSON, contract v3, syslog/ECS output, compose output) byte-for-byte
unchanged unless the package says otherwise.

## 0. Rules for the executor

- Branch from `main`. One commit per package (S1, S2, ...). No tag, publish or merge.
- Gates after every package: `make` (headers, gofmt, vet, `-race` tests in
  every module). After S4 and S5 also `make ui` and
  `python3 scripts/validate-docs.py`. Report each as passed / failed with
  output / not run with reason.
- Before deleting any identifier, re-run the grep given as evidence. If it now
  finds a reference this file does not list, **stop and leave that item**; note
  it in the report. The repository moves; this file does not.
- Do not touch: `hub/internal/store/schema.go` (released migrations), any
  `manifest.json`, any `TS_*` name, `tsk_` prefix, `io.truesignal.*` labels,
  ECS/syslog field names, `docs/siem/**`, workflows, `scripts/release/**`.
- Do not "improve" anything not listed. No renames, no reformatting beyond gofmt.
- A test may be deleted only when the thing it tests is deleted in the same
  package. Never weaken an assertion to get green.
- Not sure whether a change preserves behaviour: skip it and say so.

## 1. Findings

### F1. The "module not installed" mode no longer exists, but its machinery does (largest item)

The Hub was built against interface seams (`hub/internal/ported`) for modules
that were to be delivered later. All of them are now in-tree and wired
unconditionally in `hub/cmd/truesignal-hub/main.go`:

| Seam | Wired at (`main.go`) | Implementation |
|---|---|---|
| TOTP | `auth.Options{TOTP: totp.Module{}}` | `internal/totp` |
| Source lists, assets | `hubsettings.Service{Parser: sourcelist.Parser{}, Assets: assets.Module{}}` | `internal/sourcelist`, `internal/assets` |
| ECS renderer, HTTP SIEM | `siem.Service{Renderer: ecs.Renderer{}, HTTP: httpSIEM}` | `internal/ecs`, `internal/siemhttp` |
| GeoIP, ATT&CK | `enrich.Enricher{Geo: ..., Attack: attack.Mapper{}}` | `internal/geoip`, `internal/attack` |
| Beacons, honeytokens | `beacon.Service`, `honeytoken.Service` | `internal/beacon`, `internal/honeytoken` |
| Compiler, catalogue | `fleet.Service{Compiler: compiler, Catalogue: cat}` | `internal/compose`, `internal/catalogue` |
| Projections | `installedProjections()` (5 fixed) | `internal/attack`, `internal/projections` |

No build tag, flag or config makes any of these nil. Yet the absent case is
still modelled end to end:

- Sentinels and their HTTP mappings: `auth.ErrMFAUnavailable` (4 checks,
  `auth.go:315,481,504,539`; mapped `httpapi/admin.go:212` → 503
  `mfa_unavailable`); `hubsettings.ErrUnavailable` (`hubsettings.go:343`;
  mapped `httpapi/system.go:67` → 503 `module_unavailable`, also raised at
  `system.go:126,156`); `fleet.ErrCompilerUnavailable` /
  `ErrCatalogueUnavailable` (`fleet.go:404,563,589,616,638`; mapped
  `httpapi/fleet.go:80-83`, `httpapi/node.go:91`) including a whole fallback
  path in `fleet.DeleteSensor`; compose `honeytoken_unavailable`
  (`compose.go:482`); ATT&CK 503 (`httpapi/insights.go` `navigator`).
- A capability-negotiation type: `siem.Capabilities`, `Service.Capabilities()`,
  `Config.Normalize(caps)` (`siem/config.go:63-106`, `siem/service.go:66-69,
  181-183,220-222`), surfaced as `capabilities` in `GET /settings/siem`.
- Constant-true API flags: `assets.editable` (`system.go:101`),
  `beacons.available` (`system.go:119`), `mfa.available` (`auth.go:474`),
  `status.modules.attack` (`insights.go:286`).
- UI that renders the absent case: `ModuleMissing` and its gates in
  `ui/src/pages/modules.tsx:15-25,114,182,241-262`; "— module not installed"
  options and the TOTP warning in `ui/src/pages/settings.tsx:215,216,230,352,380`.
- Docs that describe it as live behaviour: `docs/ported-seams.md` ("behaviour
  when absent" column), `docs/openapi.yaml:41` ("false until the PORTED TOTP
  module is installed"), header comments in `ported.go`, `stub.go`,
  `modules.tsx`, `siem/config.go`, `enrich/enrich.go`.

Cost: roughly 15 unreachable branches, 5 unreachable error codes, one UI
component, and a reader of any handler has to reason about a deployment shape
that cannot occur. The interfaces themselves are fine as test seams and stay.

### F2. Dead code (zero references in production and tests)

Evidence for each: `grep -rn '<name>' --include=*.go .` returns only the definition.

| Item | Where | Note |
|---|---|---|
| `(*DB).EachEvent` | `hub/internal/store/events.go:150` | Comment says "streams without loading all at once"; body collects everything first. Callers page with `Events` + `BeforeSeq` instead |
| `(*DB).DeleteCachedManifest`, `DeleteAllCachedManifests` | `store/catalogue.go:54,60` | Comment says "factory reset"; `FactoryReset` deliberately keeps the cache |
| `(*DB).UpdateSensorSpec` | `store/sensors.go:96` | Superseded by `ApplySensorChanges` |
| `(*DB).SetNodeUpgradeRequested`, `domain.Node.UpgradeRequested` | `store/nodes.go:123`, `domain/domain.go:110` | Field's own comment: "unused: node upgrades apply immediately (Q21)" |
| `ids.Short` | `hub/internal/ids/ids.go:58` | |
| `httpapi.CodeMethod` | `httpapi/respond.go:24` | |
| `httpapi.Outputs.CABundle` | `httpapi/outputs.go:26` | Never set, never read |
| `(*auth.Service).Lockout` | `auth/auth.go:129` | |
| `siem.InventoryInterval` | `siem/emitters.go:18` | `main.go` passes the literal `24*time.Hour` instead |
| `zone.isNS`, `config.enableDNS` | `sensors/token-receiver/dns.go:189`, `main.go:45` | |
| `stubSkins` | `sensors/web-router-decoy/skin.go:43-52` | `builtinSkins` replaced it; `genericSkin` is still used (`skins_builtin.go:234`) and stays |

Test-only (referenced by a test, never by production code):
`geoip.ClientSubnetDetails` (`geo.go:233`), `attack.Technique.TacticIDs`
(`attack.go:148`), `livefeed.Broker.Tick` (`livefeed.go:111`; the live handler
in `httpapi/insights.go` builds the same tick message itself).

### F3. Duplicated logic

| What | Copies | Evidence |
|---|---|---|
| Strict-decode helper | `(*Admin).decode` (`httpapi/admin.go`) and `decodeInto` (`httpapi/fleet.go`) | Identical bodies |
| Trivial wrappers | `Admin.ExpectedOrigin`→`expectedOrigin`; `fleet.semverLess`→`semver.Less`; `Pipeline.Process`→`process` | One-line forwards |
| "Node is online" rule (90 s) and online counting | `fleet.NodeOnlineAfter` + `fleet.health`; `siem.nodeOnlineWindow` + `Heartbeat.Build`; literal `90*time.Second` in `httpapi/insights.go` `summary` | Three constants, three loops; a change to one silently disagrees with the dashboard or the SIEM heartbeat |
| Semver regex | `semver/semver.go:13`, `manifest/manifest.go:212`, `catalogue/index.go:51`, `httpapi/node.go:52` | Same pattern string ×4; `semver.Valid` already exists |
| Trigger regex | `domain/domain.go:68`, `manifest/manifest.go:214` | Same pattern ×2; `domain.ValidTrigger` exists |
| Kebab-name regex | `signing.go:53`, `manifest.go:211`, `registrytool.go:28`, `catalogue/index.go:50`, `fleet.go:133`, `httpapi/catalogue.go:20` | Same pattern ×6 |
| `RenderError` → JSON | `httpapi/fleet.go` `fail`, `httpapi/node.go` `compose` | Same `writeJSON` line |
| Setting key `"public_endpoint"` | `auth.SettingEndpoint`, `compose.SettingEndpoint` | Two constants, must stay equal |
| Host-side audit queue | `admin.mfa_reset_pending` + `TakeMFAResetMarker` vs the newer generic `cli_audit` table + `TakeCLIAudits` | Two mechanisms for "audit on next start"; `main.go` drains both |
| MFA-clear `UPDATE admin SET mfa_secret='' ...` | `store.DisableMFA`, `ResetMFA`, `ResetSecrets` | Same statement ×3 |
| Sensor int/seconds setting parsers | `seconds` verbatim in `file-canary/main.go:37` and `web-router-decoy/main.go:37`; `atoi` (`network-scan-detector`), `intSetting` (`tcp-tarpit`), `portSetting` (`token-receiver`) | Same shape, differing error text |
| Password capture | `sensors/web-router-decoy/decoy.go` (`PasswordHMAC`, `Capture` string switch) vs `sdk/go/decoy.Capture` | SDK helper exists; the oldest decoy does not use it |

### F4. Assumptions that no longer hold

| Assumption in the code or docs | Reality |
|---|---|
| "Modules may be absent" (F1) | All installed, unconditionally |
| Hub tells operators to run `truesignal link` (`httpapi/fleet.go:140`, `ui/src/pages/fleet.tsx:32`, pinned by `fleet_test.go:118` and `ui/e2e/smoke.cjs:60`) | The binary is `doppel`; `truesignal` is a symlink `install.sh:144` creates "for one release" (Q66). When the symlink goes, the Hub hands out a broken command |
| CLI version-mismatch message says "a truesignal CLI" (`httpapi/node.go:67`) | Same |
| `HANDOVER.md`, `docs/merge/*`, `MERGE-INVENTORY.md` describe the current system | They describe `TrueSignal-Rewrite` before the merge. `docs/plan/ROADMAP.md` §0 already says "do not plan from" HANDOVER. `docs/ported-seams.md` and `docs/acceptance.md:44` still present seams as pending deliveries |
| `stub` package doc: "for running the Hub before the real modules are imported" | It is test-only; nothing outside `_test.go` imports it |
| `file-canary/lure.go`, `web-router-decoy/skin.go` comments: "until the PORTED module is imported" | Imported (`lures_generated.go`, `skins_builtin.go`) |
| Compatibility shims "for one release": `truesignal_sdk` Python alias, `/etc/truesignal` + `/opt/truesignal` legacy paths in `cli/internal/config`, `truesignal` symlink | Still correct today, but nothing records which release ends them. See §3 |

## 2. Work packages

### S1. Delete dead Hub code (F2) — no behaviour change

1. `store/events.go`: delete `EachEvent`.
2. `store/catalogue.go`: delete `DeleteCachedManifest`, `DeleteAllCachedManifests`.
3. `store/sensors.go`: delete `UpdateSensorSpec`.
4. `store/nodes.go`: delete `SetNodeUpgradeRequested`; remove
   `upgrade_requested` from `nodeCols`, and the `upgrade` variable, its `Scan`
   target and the `n.UpgradeRequested = ...` line in `scanNode`.
   `domain/domain.go`: delete the `UpgradeRequested` field. The column stays in
   the schema (released migration).
5. `ids/ids.go`: delete `Short` (drop the `fmt` import if now unused).
6. `httpapi/respond.go`: delete `CodeMethod`. `httpapi/outputs.go`: delete the
   `CABundle` field.
7. `auth/auth.go`: delete `(*Service).Lockout`.
8. `main.go`: replace the literal in `go honeytokens.Run(ctx, 24*time.Hour)`
   with `siem.InventoryInterval` (the constant becomes used; same value).
9. Test-only items: delete `geoip.ClientSubnetDetails` and
   `TestClientSubnetDetails`; delete `Technique.TacticIDs` and the two lines
   asserting it in `attack_test.go:64-65`. Leave `livefeed.Broker.Tick` alone: the tick in
   `httpapi/insights.go` is per connection, so the two are not interchangeable.

### S2. Remove duplication inside the Hub (F3) — no behaviour change

1. `httpapi`: delete `(*Admin).decode`; replace its call sites with
   `decodeInto(w, r, &req)`.
2. `httpapi/admin.go`: delete the unexported `expectedOrigin`, move its body
   into `ExpectedOrigin`, update the two internal callers.
3. `fleet/fleet.go`: delete `semverLess`; call `semver.Less` directly (also in
   `fleet_test.go:334`).
4. `ingest/pipeline.go`: delete the forwarding `Process`; rename `process` to
   `Process` (keep the doc comment of the old exported one); `RaiseHubEvent`
   calls `p.Process`.
5. Node-online rule: add to `domain/domain.go`
   ```go
   // NodeOnlineWindow is three SDK heartbeat intervals.
   const NodeOnlineWindow = 90 * time.Second

   // Online reports whether the node was seen within NodeOnlineWindow of now.
   func (n Node) Online(now time.Time) bool {
       return n.LastSeenAt != nil && now.Sub(*n.LastSeenAt) <= NodeOnlineWindow
   }
   ```
   Use it in `fleet.health`, `siem.Heartbeat.Build` and `httpapi.Insights.summary`.
   Delete `fleet.NodeOnlineAfter` and `siem.nodeOnlineWindow` (grep first; fix
   any test that names them). Do not merge the counting loops.
6. Semver regex: in `manifest/manifest.go`, `catalogue/index.go` and
   `httpapi/node.go` delete the local `semverRE` / `semverMajorRE` and call
   `semver.Valid(s)` where they called `MatchString(s)`. First confirm the
   pattern strings are identical to `semver/semver.go:13`; if any differs, skip
   that file.
7. Trigger regex: `manifest/manifest.go` delete `triggerRE`, call
   `domain.ValidTrigger`. Same identical-pattern precondition.
8. `httpapi`: add
   ```go
   func failRender(w http.ResponseWriter, re *fleet.RenderError) {
       writeJSON(w, re.Status, map[string]any{"ok": false, "error": re.Code, "message": re.Message, "sensor_id": re.SensorID})
   }
   ```
   and use it in `fleet.go` `fail` and `node.go` `compose`.

Not in S2 (leave as is): the kebab regex ×6 (touching `signing` and
`registrytool` for one line each is not worth the review), the `nonNil*`
helpers, the three MFA-clear statements, `compose.SettingEndpoint`.

### S3. Delete dead sensor code (F2) — no behaviour change, no version bump

1. `sensors/token-receiver/dns.go`: delete `zone.isNS`.
   `sensors/token-receiver/main.go`: delete the `enableDNS` field.
2. `sensors/web-router-decoy/skin.go`: delete `stubSkins` and its `Skin`
   method. Keep `genericSkin`, `genericTpl`, the `Skin`/`Skins` interfaces.
   Fix the comment on `Skin` (drop "PORTED").
3. `sensors/file-canary/lure.go`: `stubLures` is used by `canary_test.go:37`.
   Keep it; change its comment to say it is the plain generator used by tests.

Do not edit any `manifest.json` and do not tag: compiled behaviour is identical.

### S4. UI: stop rendering the absent-module case (F1) — no API change

The Hub keeps sending the flags (S5 makes them constants), so this is safe on
its own.

1. `ui/src/pages/modules.tsx`: delete `ModuleMissing`. Remove the gates at the
   lines listed in F1: `Beacons` (`list.data.available`), `Assets`
   (`data.data.editable`: keep only the editable branch), `Projection`
   (drop `installed`: always fetch and render; an unknown name already
   surfaces through the existing `ErrorBox`), `Attack` (`st.modules.attack` and
   `matrixInstalled`). Update the file header comment.
2. `ui/src/pages/settings.tsx`: remove `disabled={!caps...}` and the
   "— module not installed" suffixes (lines ~215, 216, 230); remove the
   `!mfa.available` alert (~352) and the `mfa.available &&` condition (~380).
   Drop `capabilities` from the local `SIEMState` type if nothing else reads it.
3. `ui/src/types.ts`: leave `modules` in the status type (the field is still sent).
4. `make ui` must pass (type-check, safety lint, build). `ui/e2e/smoke.cjs`:
   do not change expectations.

### S5. Hub: remove the absent-module branches (F1)

Behaviour contract: every response the shipped binary can produce today is
unchanged. The only responses that disappear are ones that required a nil
module. JSON flag fields stay, as constants.

Do each numbered item as its own sub-commit if that helps review. Where a test
built a service without a module and now panics, give it the matching fake
from `hub/internal/ported/stub` (or the real module). Delete a test only when
its sole purpose was the absent case (listed below).

1. **auth.** `New`: replace the `RequireMFA && TOTP == nil` check with
   `if o.TOTP == nil { return nil, errors.New("auth: TOTP is required") }`.
   Delete `ErrMFAUnavailable` and its 4 checks. `MFAStatus.Available` stays in
   the struct and JSON, set to `true`. `httpapi/admin.go`: delete the
   `ErrMFAUnavailable` case. Tests: `auth_test.go:292` (`New(Options{RequireMFA:
   true})` must error) still holds; any `auth.New` in tests without `TOTP`
   gets `stub.TOTP{}`.
2. **hubsettings.** Delete `ErrUnavailable`, the `s.Assets == nil` check in
   `ReplaceAssets`, the `if s.Assets != nil` wrapper in `Load`, and
   `s.Parser == nil ||` in `parse`. Keep the `storedParser` assertion. Update
   the two field comments. Tests: delete the `ErrUnavailable` assertions at
   `hubsettings_test.go:101` and `:151` (3 lines each); constructors without
   `Parser`/`Assets` (`hubsettings_test.go:27`, `httpapi/events_test.go:64`,
   `httpapi/insights_test.go:48`) get `sourcelist.Parser{}` and `stub.Assets{}`.
   If `hubsettings_test.go:27` exercises "lists stored but not applied",
   that behaviour is the nil-parser case: delete those assertions too and say
   so in the report.
3. **httpapi/system.go.** Delete the `ErrUnavailable` case in `fail`, the
   `s.Beacons == nil` checks in `createBeacon` and `beaconArtefact`, and the
   `else` branch in `deleteBeacon`. Responses keep `"editable": true` and
   `"available": true` as literals. Fix the struct comment. Tests:
   `events_test.go:215` (PUT `/assets` → 503 `module_unavailable`) is deleted;
   `events_test.go:69` `System{...}` gets `Beacons: stub.NewBeacons()`.
4. **httpapi/insights.go.** Delete the `in.Attack == nil` 503 in `navigator`;
   `"modules"` keeps `"attack": true`. Leave the `in.Updates == nil` checks and
   the `in.Enricher != nil` branches (those are optional collaborators, not
   absent modules). Tests constructing `Insights` without `Attack` get
   `attack.Mapper{}` or `stub.Attack{}`.
5. **siem.** Delete `type Capabilities`, `Service.Capabilities()`, the `caps`
   parameter of `Config.Normalize` and its two "not installed" returns, the
   `s.HTTP == nil` check in `transport`, the `s.Renderer == nil` check in
   `Render`. Callers: `main.go:271`, `httpapi/outputs.go:72`.
   `httpapi/outputs.go` `siemState` keeps
   `"capabilities": map[string]bool{"ecs": true, "http_transports": true}`.
   Tests: `siem/service_test.go:412-434` — drop the `caps` column and delete
   only the rows whose expected error was a missing capability;
   `ecs/seam_test.go:22-24` and `siemhttp/seam_test.go:43-45` delete the
   capability assertion; other `Normalize(...)` calls lose the argument. A
   test that renders ECS or uses elastic/logscale on a `Service` without
   `Renderer`/`HTTP` gets `stub.ECS{}` / `&stub.HTTPTransport{}`.
6. **fleet.** Delete `ErrCompilerUnavailable`, `ErrCatalogueUnavailable`, the
   nil checks in `render`, `Deploy`, `UpgradeSensor`, `UpgradeNode`, the
   `if s.Catalogue != nil` wrapper in `view`, and the
   `errors.Is(err, ErrCompilerUnavailable)` fallback block in `DeleteSensor`.
   `httpapi/fleet.go`: delete the two cases; `httpapi/node.go`: delete the one
   case. Fix the two field comments. Tests: delete
   `TestFailClosedWithoutCompiler` (`fleet_test.go:262`); `newService(t, false)`
   callers and `httpapi/fleet_test.go:75` (no `Catalogue`) get the existing
   fakes (`fakeCatalogue{}` exists in `fleet_test.go`; in `httpapi` write a
   5-line fake returning `"", false` / `nil, false`, which reproduces the nil
   behaviour exactly).
7. **compose.** Delete the `c.Honeytokens == nil` → `honeytoken_unavailable`
   branch (`compose.go:481-483`) and the test asserting it
   (`compose_test.go:394` and its setup). Remove `honeytoken_unavailable` from
   `docs/manifest-v3.md:92`.
8. **Leave nil-tolerant on purpose:** `ingest.Pipeline` (`Beacons`,
   `Honeytokens`, `Enricher`, `SIEM`, `Notifier`, `Live`, `Lists`) and
   `enrich.Enricher` (`Attack`, `Assets`, `Geo`, `Nodes`). They are one-line
   guards that many tests rely on, and none of them surfaces as API behaviour.
   Only correct their comments ("optional in tests", not "module not installed").
9. **stub package.** After 1-7, for each exported type in
   `hub/internal/ported/stub/stub.go`, grep for references; delete those with
   none. Rewrite the package comment: test fakes only.
10. **Docs and comments.** `docs/openapi.yaml`: for `mfa.available`,
    `capabilities`, `editable`, beacons `available`, `modules.attack` say
    "always true; retained for compatibility"; remove 503
    `module_unavailable` / `mfa_unavailable` / `compose_unavailable` /
    `catalogue_unavailable` where listed (line 460 and any other). Run
    `python3 scripts/validate-docs.py`. `docs/ported-seams.md`: replace the
    "behaviour when absent" and "stub" columns with one sentence at the top:
    all modules are in-tree and required; the interfaces remain as test seams.
    `ported/ported.go` package comment: same sentence. `docs/acceptance.md:44`:
    adjust the pointer text. `docs/audit-actions.md`: no change expected.

Verification specific to S5: `grep -rnE 'Unavailable|not installed|module_unavailable|Capabilit' hub/internal ui/src --include=*.go --include=*.ts --include=*.tsx`
must return only `compose.ErrManifestUnavailable` (a real runtime condition:
unknown or unverified manifest), `http.StatusServiceUnavailable` uses that
remain, `manifest.go` capability rules (Linux capabilities, unrelated), and
the `Updates == nil` message.

## 3. Findings that need the owner, not the executor

Do not implement these. They change observable behaviour or need a decision.

1. **`truesignal link` in Hub output** (`httpapi/fleet.go:140`,
   `httpapi/node.go:67`, `ui/src/pages/fleet.tsx:32`). Recommendation: switch
   to `doppel` now. It is a 3-string change plus `fleet_test.go:118` and
   `ui/e2e/smoke.cjs:60`, and it must land before the symlink is removed or
   every newly created node gets a command that does not exist.
2. **End date for the rename shims.** `truesignal_sdk` alias
   (`sdk/python/truesignal_sdk`, `pyproject.toml` packages, test
   `CompatibilityAliasTest`), legacy CLI paths
   (`cli/internal/config/config.go:23-26,50-52`), the installer symlink
   (`install.sh:144`, `cli/internal/app/app.go:401`). "One release" is not
   tied to a version anywhere. Recommendation: name the release in
   `QUESTIONS.md` Q66 and delete all three together in it. If no node was ever
   linked under `/etc/truesignal` outside your own lab, delete them now.
3. **Two host-side audit mechanisms** (`mfa_reset_pending` vs `cli_audit`).
   Fold `mfa-reset` into `cli_audit` in the next schema migration (v4): the
   migration copies a pending marker into `cli_audit`, `ResetMFA` inserts a row
   instead of setting the flag, `TakeMFAResetMarker` and its block in `main.go`
   go. Not worth a migration by itself, and doing it without one can lose a
   pending break-glass audit record across an upgrade. Note the audit
   timestamp would become the time of the reset, not of the next start (better,
   but a change `docs/siem` rules may key on).
4. **web-router-decoy capture vs `sdk/go/decoy.Capture`.** Switching removes a
   duplicate HMAC path but adds `password_length` to `web_login_attempt`
   events and a `none` mode: an event-schema change, needs a sensor version
   bump and a look at the Elastic/LogScale rules.
5. **Sensor setting parsers.** A shared `sensor.IntSetting` in the SDK would
   replace five local helpers, but error texts differ per sensor and it means
   an SDK surface change plus five republishes. Do it when the four roadmap
   decoys land and would otherwise add four more copies.
6. **Historical process docs at the repo root.** `HANDOVER.md`,
   `MERGE-INVENTORY.md`, `docs/merge/{FABLE-PROMPT,HANDOFF,REPORT,UPLOAD}.md`
   (about 1,000 lines) are provenance records for the clean-room and merge
   work, and `PROVENANCE.md`, `THREATMODEL.md:189`, `QUESTIONS.md` and two code
   comments cite them. Recommendation: keep the content (it is your clean-room
   evidence), move the two root files under `docs/merge/`, fix the five
   citations. Deleting them is a legal-evidence decision, not a code one.
7. **`sdk/go/ber` and `decoy.ServePacket`/`ParseServices`/`NewCapture`** have
   no production caller. They are ROADMAP Phase 0 foundations for the four
   planned decoys. Keep while that roadmap stands; delete if the decoys are cut.
8. **Projection DTO casing.** `internal/projections` emits camelCase
   (`countryCode`, `sourceCount`) while every other admin API object is
   snake_case. Not a simplification, but it is the kind of inconsistency that
   becomes permanent once a customer scripts against it. Decide before GA.

## 4. What was checked and found fine

So the executor does not go looking: the `ported` interfaces as test seams;
`ingest.Pipeline` ordering; the store's sealing code (`store/crypto.go`); the
SIEM queue/retry worker; the compose compiler rules; `ApplySensorChanges`;
Go and Python SDKs being parallel implementations (intended); the CLI
re-declaring manifest template regexes (`cli/internal/discover/match.go`: a
separate module that cannot import `hub/internal`).

## 5. Report format

Per package: commit hash, files changed, lines removed/added, each gate's
result, every item skipped with the reason, every test deleted with the
finding that justified it.
