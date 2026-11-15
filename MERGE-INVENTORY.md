# Merge inventory: TrueSignal → Doppel

**Status:** approved by the owner on 2026-11-15 (QUESTIONS Q66–Q70). Nothing listed
here has been imported yet.
**Base:** `TrueSignal-Rewrite` `main` at `cc05d14` (HANDOFF describes `650c285`;
the three later commits are documentation only).
**Source:** `TrueSignal` `origin/main` at `f4455a0`, every branch fetched.
Unmerged branches: `claude/intelligent-albattani-dbxcqn` has one extra
commit (`10f1d25`, docs only), and `registry-pages` has 22 bot registry
commits. Neither branch adds code.
**Rule:** HANDOFF §0. A file or hunk is imported only if it is both
Claude-authored and new. Where the evidence allows more than one class, the
most restrictive class is used.

## 1. Method and evidence

| Check | How | Raw output |
|---|---|---|
| Attribution | Every commit in `TrueSignal` (146, all refs). A commit counts as Claude's when it has a `Co-Authored-By: Claude` or `Claude-Session:` trailer. All 80 commits authored as `Claude` carry both trailers, and every one is on a `claude/*` branch. `05d5203` ("Initial import of TrueSignal (based on HoneyWire, AGPLv3)") and `e5362b4` ("Add Hub/") are classed as **import**. `35223c7` ("Rebrand HoneyWire to TrueSignal") is a Claude commit but a mechanical rename of imported code, so its lines are never counted as new | `git log --all --format=%B` |
| Line authorship | `git blame -w -M -C -C --line-porcelain` of every file at `origin/main`. Only significant lines are counted: at least 8 alphanumeric characters, and not `import`, `package`, a comment or a bare string. For lines that are not Claude's, the origin commit and file are recorded | §5 |
| Rename and copy | `git log --follow -M -C --diff-filter=A` for each file, and the `-C -C` origin of every blamed line | §5 |
| HoneyWire similarity | Lines are normalised: whitespace collapsed, `honeywire`/`truesignal`/`hw_`/`ts_` masked, and only lines with at least 12 alphanumeric characters kept. Each file's normalised lines are matched against the set of all such lines in **every blob of every commit** of `andreicscs/HoneyWire` (506 commits, 27 518 distinct lines) and against the import tree (`05d5203` + `e5362b4`) | §5 |
| Derivation language | The commit message of every feature commit was searched for port, migrate, rewrite, based on, derived, inspired, reimplement, translate, upstream and Trapster | §2 rows |

Translation from another language would not show up as line similarity.
That risk is covered only by the commit messages and by `NOTICE`. See §3
for the one case where it applies.

## 2. Rows

Classes: `claude-new`, `claude-edit`, `human`, `honeywire-derived`,
`third-party`, `unknown`.
Sessions: `B6fd` = `session_01B6fdXK6mHWahAAdPmkKqpz`, `Shqj` =
`session_01ShqjB3bGNWm4DuaY4aSC3X`, `GCyv` =
`session_01TGdGKGCyv2NrWYN6wmC2rH`, `GvaT` =
`session_01TGdGKGvaTu2vkcYL1GVqMi`, `3bfR` =
`session_013bfRtsz1pg4wYFMwN8oUKF`.
"HW%" is the share of a file's significant lines that also occur somewhere
in HoneyWire's history. "Clean" means blame finds no significant line from
a non-Claude commit.

### 2.0 PORTED step 1 (already in the base)

| # | What / where | Doppel seam | Class and evidence | Depends on excluded code | Decision |
|---|---|---|---|---|---|
| P1 | Sigstore manifest verifier. Base `hub/internal/signing`; TS `Hub/internal/signing/{signing.go,signing_test.go,trusted_root.json,testdata/…}` | `ported.ManifestVerifier` (installed) | **claude-new.** Created by `dde6819` (B6fd, `claude/beautiful-ptolemy-t0uxdm`) and never changed afterwards. The base's inbox `ce4c704` is **byte-identical** to TS at `2884102` for all five files. `--follow -M -C`: added in `dde6819`, no source file. Blame: 100% Claude. HW 2%, matching only `return nil, err`-style lines. The commit message describes new Sigstore verification; there is no port language | None. Only `sigstore-go` (Apache-2.0, already in `THIRD_PARTY.md`) | **Keep as is.** No stub restore is needed, and no Hub behaviour changes |
| P2 | Source-list matcher. Base `hub/internal/sourcelist`; TS `Hub/internal/services/sourcelist/` | `ported.SourceListParser` (installed) | **claude-new.** Created by `e9a0d3e` (Shqj); `bf73560` (Shqj) added 7 lines. Inbox byte-identical. Blame: 100% Claude. HW 0%. The message says "via the new sourcelist package". Exact-name matching existed in HoneyWire's whitelist check, but it was not moved: `-C` finds no source, and the new package parses IPs and CIDRs | None | **Keep as is** |

Consequence: the production Hub keeps verifying manifests, and the catalogue
works as it does today. The "refuses every manifest" scenario does **not**
arise.

### 2.1 Hub modules that map to open PORTED seams

| # | What / where (TS) | Doppel seam | Class and evidence | Depends on excluded code | Decision |
|---|---|---|---|---|---|
| H1 | GeoIP enrichment over DB-IP City Lite, with an optional auto-update. `Hub/internal/geo/{geo.go,update.go,testdata/gen}`, commits `0a0c093` and `9cda83a` (GCyv) | `ported.GeoLocator` → `enrich.Enricher.Geo`; config `TS_GEOIP_DB`, `TS_GEOIP_AUTO_UPDATE` | **claude-new.** Created by `0a0c093` ("GeoIP enrichment … phase 3, part 2"). Clean. HW 8%: struct, mutex and `os.IsNotExist` lines only | None in the package. External: `oschwald/maxminddb-golang/v2` (ISC); `maxmind/mmdbwriter` (Apache-2.0, test fixtures only) | **Import** via an adapter to `domain.Location`. The `THIRD_PARTY.md` rows go in the same branch. DB-IP CC BY 4.0 attribution goes in the docs and the UI, as new base UI code. The auto-update download host becomes a QUESTIONS entry (a new outbound call; Q55 lists the allowed ones) |
| H2 | Asset inventory: validate, index and look up a source's owning asset. `Hub/internal/assets/`, commit `5a6d62d` (Shqj) | `ported.AssetInventory` / `AssetIndex` | **claude-new.** Clean. HW 5% | None | **Import** with an adapter to `domain.AssetMatch` |
| H3 | ATT&CK technique mapping per trigger. `Hub/internal/attack/`, commit `f1a66ab` (Shqj) | `ported.AttackMapper.For` | **claude-new.** Clean. HW 5% (`ID`/`Name` struct tags) | None. The trigger names in the mapping table are TS triggers, and some come from HoneyWire sensors | **Import** the mapper, and re-key the table to Doppel's triggers (base sensors and `docs/contract-v3.md`). Triggers with no Doppel sensor are dropped |
| H4 | ATT&CK Navigator layer. `Hub/internal/projections/attackmap/attackmap.go` (`f1a66ab`) | `ported.AttackMapper.NavigatorLayer` | **claude-new** for the layer builder: created by Claude, 98% Claude lines (3 lines from the import), HW 9% | `models.Event` (HoneyWire-derived) and the `insights` types (row H10) | **Import only the Navigator-layer hunk**, adapted to `domain.EnrichedEvent`. Drop the matrix part that depends on `insights` |
| H5 | TOTP: secret, `otpauth` URI, HOTP/TOTP verification with step replay. `Hub/internal/services/auth/totp.go`, commit `6592b67` (B6fd) | `ported.TOTP.GenerateSecret` / `Verify` | **claude-new.** Clean. HW 6% (`return nil, err`) | None | **Import** |
| H6 | Recovery codes: generate, hash and consume. These are hunks of `Hub/internal/services/auth/mfa.go` (`6592b67`) | `ported.TOTP.GenerateRecoveryCodes` / `ConsumeRecoveryCode` | **Mixed file.** It was created by Claude, but it also holds HoneyWire's lockout logic (`authTracker`, `lockedUntil`, HoneyWire's audit log line): HW 11% across the file. The recovery-code hunks themselves have no HW lines. Class: the file is `claude-edit`; the recovery-code hunks are self-contained and new | The hunks are wired to HoneyWire's config store (`GetConfigValue` / `UpdateConfigValue`) | **Import only the recovery-code hunks**, as pure functions behind the seam. The store wiring stays the base's. The rest of `mfa.go` is excluded: the base has its own MFA flows |
| H7 | Beacon service: canary tokens with a 40-bit HMAC tag, artefact generation, resolve and record use. `Hub/internal/services/beacon/`, `Hub/internal/store/beacons.go`, commit `a3f2eb0` (GCyv) | `ported.BeaconService` over `ported.BeaconStore` (the base `store.DB` implements it) | `service.go`: **claude-new**, with 4 lines from the import and HW 7% (boilerplate). `store/beacons.go`: created by Claude, but HW 21% (HoneyWire store idioms) | `models`, `services/event`, and HoneyWire's `store` | **Import `service.go`** behind the seam. **Do not import `store/beacons.go`**: the base already implements `BeaconStore` |
| H8 | Honeytoken service: plant credentials in lures, match captures fleet-wide, per-node capture keys, inventory. `Hub/internal/services/honeytoken/service.go`, `Hub/internal/store/honeytokens.go`, commits `3c4ca4c` and `a616712` (B6fd) | `ported.HoneytokenService` over `HoneytokenStore` and `CaptureKeyFunc` | `service.go`: **claude-new**, 99% Claude lines, HW 11%. The HW lines are its `Store` interface on HoneyWire's config API and `NewService` boilerplate. `store/honeytokens.go`: HW 24% | `models`, `services/event`, and the HoneyWire config-store interface | **Import `service.go`** with the store interface replaced by `ported.HoneytokenStore`. **Do not import** the store file |
| H9 | ECS renderer for events, audit, honeytoken inventory and heartbeat. `Hub/internal/services/siem/ecs.go`, commit `ccfcae1` (B6fd) | `ported.ECSRenderer.Render(domain.Record)` | **claude-new.** Clean. HW 3% | `models` record types (HoneyWire-derived), `attack` (H3) and `geo` (H1) | **Import** with an adapter from `domain.Record`. The `truesignal.*` ECS namespace stays until the owner decides the rebrand (§4) |
| H10 | HTTP SIEM transports: Elastic `_bulk` and LogScale HEC. `Hub/internal/services/siem/http.go` (`ccfcae1`) | `ported.HTTPSIEMTransport.Send` | **Mixed.** `httpRequestBody`, `httpEndpoint`, `authHeader` and `sendHTTP` are new Claude hunks. `processHTTPWithRetry` follows HoneyWire's retry-policy loop (`siemPolicy`, `SiemRetry`/`SiemDrop`, HoneyWire's discard log line), so it is `claude-edit` of HoneyWire code. HW 12% across the file | `NetworkFact` and the retry-policy types (HoneyWire-derived) | **Import only the four request and send hunks**, mapping their result to `SendOutcome`. Retries stay in the base's `siem.Service`. The retry loop is excluded |
| H11 | Analytics projections: `sources` (`bf73560`), `geomap` (`0a0c093`), `path` (`b8a388e`) and `report` (`6ad2170`, `2069208`), all under `Hub/internal/projections/` | `ported.Projection`; names `sources`, `geo_map`, `attack_path`, `report` (Q56) | **claude-new.** Each is created by Claude and is 95–100% Claude lines, HW 2–8%. The few non-Claude lines are `-C` matches on struct tags | Every one reads `models.Event`. `path`, `report` and `attackmap` use `insights` types; `sources` uses a store query in `Hub/internal/store/events.go` (a Claude hunk inside a HoneyWire file) | **Import**, with each projection adapted to `domain.EnrichedEvent` and its `insights` dependency cut. Where a projection cannot be separated from `insights`, it moves to a clean spec instead. That is decided per projection on its import branch and recorded in `PROVENANCE.md` |
| H12 | `insights` projection (dashboard coverage and per-decoy-type counts) and `attack_matrix`. `Hub/internal/projections/insights/` (`0b14155`) | `ported.Projection` (`insights`, `attack_matrix`) | **claude-edit / honeywire-derived.** Claude created the files, but blame `-C` traces 18 lines of `projection.go` and 8 lines of `calculator.go` to HoneyWire's `projections/{severity,summary}` (same structure). It fails "new" | `models`, `store` | **Clean spec** (`docs/clean-specs/insights-projection.md`) |
| H13 | MFA break-glass `mfa-reset` command. `Hub/cmd/hub/commands.go` | — | claude-new (93%) | HoneyWire `cmd` | **Drop.** The base already has `mfa-reset` (Q20) |

### 2.2 Sensors and SDK

| # | What / where (TS) | Doppel seam | Class and evidence | Depends on excluded code | Decision |
|---|---|---|---|---|---|
| S1 | File Canary lure-content generator. `Sensors/official/FileCanary/lure.go`, commits `906ad85` (3bfR) and `81b1a03` (GCyv) | `sensors/file-canary` `LureGenerator` | **claude-new**, medium confidence. It was created in a commit that also removed 64 lines from HoneyWire's `main.go`, but `-C` finds **no** moved lines, it is 100% Claude lines, and HW is 1% | None (stdlib) | **Import** behind `LureGenerator`, with honeytoken embedding wired to the base's `TS_HONEYTOKEN` |
| S2 | Web Router decoy skin engine. `Sensors/official/WebRouterDecoy/skin.go`, commit `c16510a` (B6fd); docs `Docs/sensors/web-skins.md` | `sensors/web-router-decoy` `Skins` / `Skin` | **claude-new**, medium confidence. The same commit removed 273 lines from HoneyWire's `main.go`. `-C` finds no moved lines, it is 100% Claude lines, and HW is 5% | None | **Import** behind `Skins`. `dc1d411` (per-source login rate limit) is a `main.go` hunk: drop it, because the base already rate-limits (Q51) |
| S3 | Decoy helper: `TS_SERVICES` parsing, capture policy (HMAC or none), accept loop, sanitising, per-source event limiter. `SDKs/go-truesignal/decoy/decoy.go`, commits `ce9e4fd`, `028d226` and `d9671c5` (B6fd) | `sdk/go/sensor.Reporter` (Go). The Python twin stays unimplemented | **claude-new.** 99% Claude lines, with 4 lines from the import. HW 3% | It calls the HoneyWire-derived `SDKs/go-truesignal` (`sdk.go`, HW 99%) through a small interface | **Import** as `sdk/go/decoy`, adapted to `sensor.Reporter` |
| S4 | **Token Receiver** decoy: DNS/HTTP beacon receiver, client caps, token parsing. `Sensors/official/TokenReceiver/{dns,http,limit,token}.go` (`a3f2eb0`, `91279e1`, GCyv) | Five-decoys row (none beyond SDK, manifest v3 and §6.12); `TS_BEACON_KEY` | Protocol files: **claude-new**, clean, HW 0–4%. `main.go`: 90% Claude, but 19 lines come from the import's sensor skeleton. Manifest: 61% Claude, the rest from the HoneyWire manifest template | `main.go` and the manifest follow HoneyWire's sensor skeleton | **Import the four protocol files.** Write new `main.go` glue against `sdk/go` and S3, and a new manifest v3. Do not import TS `main.go` or the TS manifest |
| S5 | **Identity Decoy**: LDAP/LDAPS/RDP, NTLM, CredSSP/NLA, LDAP NTLM binds. `Sensors/official/IdentityDecoy/` (`7aa83a6`, `dbee4b9`, `897f3c8`) | Five-decoys row | Authored by Claude and line-clean (HW 0–7%). **But** the commit message says "**Ported in concept from Trapster Community (0xBallpoint, AGPLv3+)**", and `NOTICE` calls it "a Go reimplementation of the LDAP, LDAPS and RDP honeypot concepts from Trapster Community". Trapster is Python, so a translation would not show as line similarity. Class: **third-party-derived (AGPL), unknown depth** | HoneyWire SDK; `main.go` skeleton | **Clean spec** (`docs/clean-specs/identity-decoy.md`), written from the public protocol specifications (RFC 4511, MS-NLMP, MS-CSSP, MS-RDPBCGR) and from Doppel's contracts only |
| S6 | **Database Decoy**: MySQL, PostgreSQL, MSSQL/TDS login capture. `Sensors/official/DatabaseDecoy/` (`ce9e4fd`) | Five-decoys row | As S5: `NOTICE` says "likewise Go reimplementations of service concepts from Trapster Community" | HoneyWire SDK; S3 | **Clean spec** |
| S7 | **Remote Access Decoy**: SSH (`x/crypto/ssh`), Telnet, FTP. `Sensors/official/RemoteAccessDecoy/` (`ce9e4fd`) | Five-decoys row | As S6. It also has no unit tests (per its own commit message) | HoneyWire SDK; S3 | **Clean spec** |
| S8 | **Network Service Decoy**: SNMP v1/v2c/v3, log-only DNS. `Sensors/official/NetworkServiceDecoy/` (`79cb012`) | Five-decoys row | As S6 | HoneyWire SDK; S3 | **Clean spec** |
| S9 | Detection-fidelity changes and tests for the HoneyWire sensors (FileCanary, IcmpCanary, NetworkScanDetector, TcpTarpit, WebRouterDecoy `main.go` and `main_test.go`; `906ad85`, `81b1a03`) | — | **claude-edit** of honeywire-derived sensors; the tests exercise that code | Everything | **Drop.** The base has its own sensors |

### 2.3 SIEM content

| # | What / where (TS) | Doppel seam | Class and evidence | Depends on excluded code | Decision |
|---|---|---|---|---|---|
| R1 | Detection rules for Elastic and LogScale (17 + 15 rules), the rule docs, the ATT&CK mapping doc and the honeytoken detection doc. `Docs/siem/**` (`d2b3c0c` GvaT; `a616712`; `f1a66ab`) | "SIEM detection rules and test harness" row: ECS contract (`docs/siem-integration.md`), `docs/audit-actions.md` | **claude-new.** All clean. HW 0% | The rules query TS ECS fields and TS triggers and audit actions | **Import, re-keyed** to Doppel's ECS output (H9) and Doppel's audit action names. A rule whose trigger has no Doppel equivalent is dropped (S5–S8 decoys) and listed in `PROVENANCE.md` |
| R2 | Rule test harness: `scripts/siem-rules/{run-elastic.py,run-elastic.sh,expected-elastic.json}`, `.github/workflows/siem-rules.yml`, `Hub/internal/services/event/siem_samples_test.go` (sample generator) | Same | **claude-new.** Clean, HW 0–3%. The sample generator is 99% Claude, but it drives HoneyWire's event service | The sample generator uses HoneyWire's `event.Service` | **Import** the harness, **rewrite the sample generator against the base ingest pipeline** (new code), and pin the workflow's actions by SHA |
| R3 | SOC notices 2.3.0 and 2.4.0 (`Docs/siem/soc-notice-*.md`) | — | claude-new | TS release history | **Drop.** They describe TS releases |

### 2.4 UI

| # | What / where (TS) | Doppel seam | Class and evidence | Depends on excluded code | Decision |
|---|---|---|---|---|---|
| U1 | Vue views: Assets, Attack, AttackPath, GeoMap, Beacons, Honeytokens, Scans, Report; stores; utils (`csv.ts`, `ipTokens.ts`, `worldMap.ts`, …); MFA components; `SourceListEditor.vue`; `BrandMark.vue` | Base UI: Preact 11 + TS 7, generic projection pages (Q56) | Mostly **claude-new** (95–100%, HW 0–16%). Dashboard components are mixed (`DecoyCoverageChart.vue` has 37 HoneyWire lines) | The HoneyWire Vue app shell, Pinia stores and API client | **Drop the code.** It cannot run in the Preact UI, and translating it would be a port. Optionally, a **clean spec** for dedicated visualisations (Q56 "needs the DTO contracts"): Attack matrix grid, Geo map, Attack path graph, Report print view, Assets editor, CSV import. The GeoIP map needs Natural Earth / `world-atlas` (ISC), added as a declared dependency |
| U2 | Event-table triage labels, label filters and free-text search (`bf73560`) | Base events page | Projection part: see H11 (`sources`). UI part: `claude-edit` of HoneyWire's `EventTable.vue` | HoneyWire UI | **Drop the UI.** Optional clean spec, folded into U1's spec |

### 2.5 Deployment, release, docs and wizard

| # | What / where (TS) | Doppel seam | Class and evidence | Depends on excluded code | Decision |
|---|---|---|---|---|---|
| D1 | nginx TLS front end and compose TLS overlay: `Hub/deploy/nginx/truesignal.conf`, `Hub/docker-compose.tls.yml` (`a01bc57`, `4acde62`) | `deploy/compose.yaml`, `docs/operations.md` §1 step 3 (nginx example) | `truesignal.conf`: claude-new, clean, HW 0%. Overlay: 94% Claude, 3 lines from HoneyWire's compose | The overlay targets HoneyWire's compose service names and ports | **Import `truesignal.conf`** as `deploy/nginx/doppel.conf`, adapted to the base's listener (127.0.0.1:8080) and headers. Write a new overlay for `deploy/compose.yaml`. Reconcile it with the inline example in operations §1 so only one example remains |
| D2 | Release process, publish workflows, registry scripts, Hub rollback runbook, wizard release (`07dea28`, `34d6528`, `dde6819` workflows, `a01bc57` docs, `scripts/publish-registry.sh`, `Hub/docker-compose.build.yml`, `.github/workflows/*`, `.gitea/**`) | Base `.github/workflows`, `scripts/release/`, operations §6–§9 | Mixed. Workflows are 19–85% Claude, the rest from HoneyWire | HoneyWire workflow structure | **Drop.** The base's release chain is the authority |
| D3 | Wizard (Go node CLI) changes: argv-safe key handling, MFA client, uninstall, discover tests (`59ef640`, `6592b67`, `b1f7a25`) | Base `cli/` | claude-edit of the HoneyWire wizard (HW 90–99% in the wizard files) | Everything | **Drop.** The base CLI replaces it |
| D4 | Hub hardening, config enum checks, port-conflict rejection, SIEM/liveness fixes (`f889d9c`, `463063d`, `56b9406` + human `589ca05`, `25bd04a`, `a08e57e`) | Base `auth`, `compose` rule 7, `siem`, `liveness` | claude-edit and human edits of HoneyWire code | Everything | **Drop.** The base has the equivalent controls (for example, compose rule 7 `port_conflict`). Where the two disagree, the base's behaviour stays |
| D5 | Project knowledge docs: `CLAUDE.md`, `Docs/PROJECT-KNOWLEDGE.md`, `Docs/KNOWLEDGE-GAPS.md`, `SESSION-HANDOFF.md`, `Docs/LOCAL-VERIFICATION-PROMPT.md`, `CHANGELOG.md`, `NOTICE` | — | claude-new or mixed, but they describe the TS codebase | — | **Drop** |
| D6 | Token-authenticated pulls and the `truesignal-dist` move (`4013e0d`, `370e69c`, both reverted) | — | claude-new, reverted upstream | — | **Drop** |

## 3. Rows most likely to be wrong

1. **All of TrueSignal is AGPL-3.0 as a whole work.** `7679bcf` ("Mark the
   repository legacy; keep it under AGPL") and `NOTICE` say so. The rows marked
   claude-new are new files that the owner commissioned, so the owner can
   relicense them as copyright holder. But they were written inside an AGPL
   work, against its interfaces. HANDOFF §0 already flags this. It is a
   **licensing decision**: counsel should confirm it before the first import
   is merged into `main` (Q67).
2. **S5–S8, the Trapster-concept decoys.** They are line-clean, but their
   origin is a self-declared port "in concept" of an AGPL project. The class
   could be lower (concept only) or higher (structure translated from the
   Python). I chose the restrictive reading: clean spec (Q68).
3. **S1 lure generator and S2 skin engine.** Each was created in the same
   commit that cut its sensor's HoneyWire `main.go`. `-C` finds no moved lines
   and HW similarity is 1–5%. The risk is reworked logic that line matching
   cannot see.
4. **H6 and H10, the hunk-level imports from mixed files.** The boundary
   between the new hunks and the HoneyWire-derived code is my judgement.
5. **H7 and H8, the beacon and honeytoken services.** They are new logic,
   but 7–11% of their lines match HoneyWire idioms, and they were designed
   against HoneyWire's store and event interfaces. Adapting them means
   replacing those interfaces, which is in scope.
6. **Unattributed Claude work.** None found: every non-merge commit without
   a trailer is the owner's (8, all import, licence, CI or Makefile work) or
   the CI bot's registry publishes. The 13 unattributed commits in the
   **base** are Dependabot version bumps (11) and the owner's two mechanical
   commits (`f9d2b51` initial `LICENSE`, `5929e44` deploy key). They are kept,
   as HANDOFF §0 allows.

## 4. Rebrand proposal (§6)

User-facing text (README, doc titles, UI strings, release titles) becomes
**Doppel** without further approval. Wire and operational identifiers need
the owner's decision. Proposed mapping, recorded as Q66:

| Identifier | Now | Proposed | Compatibility plan | Recommendation |
|---|---|---|---|---|
| Go module paths | `github.com/mahmoudahmed3132/TrueSignal-Rewrite/...` (Q2) | `github.com/mahmoudahmed3132/Doppel/...` | Internal only; no runtime effect | Change it, in its own branch |
| CLI binary and paths | `truesignal`, `/opt/truesignal`, `/etc/truesignal/config` | `doppel`, `/opt/doppel`, `/etc/doppel/config` | For one CLI release: `install.sh` installs `doppel` plus a `truesignal` symlink, and the CLI reads the old config path if the new one is absent, then migrates it | Change it |
| Release asset names (Q46) | `truesignal-linux-<arch>` | `doppel-linux-<arch>` | The new CLI release only; old assets stay under the old identity | Change it together with the CLI |
| Images (Q60) | `ghcr.io/<owner>/ts-hub`, `ts-sensor-<name>` | `doppel-hub`, `doppel-sensor-<name>` | The sensor republish at 1.0.1 creates new manifests anyway. For one Hub release the compose rules accept both prefixes, and old manifests pin by digest | Optional. Keeping `ts-*` is zero-risk |
| `TS_*` env vars | Contract v3 reserved keys | Keep | — | **Keep.** Wire contract between the Hub, the CLI and every sensor; renaming means contract v4 |
| `tsk_` key prefix | Node keys | Keep | — | **Keep.** Issued keys must keep working |
| Labels `io.truesignal.*` | CLI container discovery | `io.doppel.*` | The CLI matches both for one release | Keep, unless images are renamed |
| SDK package names | `truesignal-sdk` (Python), Go `sdk/go` | `doppel-sdk`, module under `Doppel` | `truesignal_sdk` stays as a re-export shim for one release | Change, with the shim |
| Syslog app-name / hostname / SD-IDs | `truesignal-hub`, `truesignal`, `truesignal[-audit\|-honeytoken]` | `doppel-hub`, … | Settings switch `siem_legacy_names` (default on) for one release, so SIEM parsers can be updated first | Change, behind the switch |
| ECS namespace (after H9) | `truesignal.*` | `doppel.*` | Same switch as syslog | Same |
| Releases repo | `truesignal-releases` | Keep (HANDOFF §3) | — | **Keep** |
| Copyright holder | `TrueSignal Deception` | The owner's legal entity name | Every header and `scripts/check-headers.sh` change in one mechanical commit | **Owner decision** |
| Image namespace `ghcr.io/<owner>/truesignal-*` | Prohibited | Never used | — | — |

The supply-chain repoint (signer repository → `mahmoudahmed3132/Doppel`) is
not a rebrand choice. It follows from the new repository and is done in its
own branch after approval (task §6, HANDOFF §3).

## 5. Could not classify

None at file level. The residual uncertainty is the depth of the Trapster
derivation (S5–S8) and the AGPL relicensing question (§3 item 1). Raw data
was not committed, because it is regenerable from the commands in §1:
per-file blame tallies, non-Claude line origins, and per-file HW and import
similarity.

## 6. Pre-existing gate failures on the base (§7 baseline)

| Gate | Result on `main` | Fix |
|---|---|---|
| make, make ui, validate-docs, compose-guard, release self-test, Python SDK | passed | — |
| trivy fs | **failed**: `golang.org/x/net` v0.60.0, CVE-2026-78661 (HIGH) | Branch `fix/baseline-cves`: v0.62.0 (19 days old) |
| trivy image | **failed**: Python template image, `zlib1g` CVE-2026-76844 and CVE-2026-85091 (HIGH) | Branch `fix/baseline-cves`: distroless digest from 2026-11-08 (an exception to the 14-day rule, with the reason stated) |
| CodeQL, real-Docker e2e | See the gate report in the hand-over message | — |
