# PORTED module seams (§12)

The modules below are the owner's own work and are imported after review.
This repository provides the integration point for each: a Go interface
(or, for sensors, a package-level seam), the place where it is consumed and
wired, behaviour while it is absent, and a stub used by tests
(`hub/internal/ported/stub`, with a compile-time check that every stub
satisfies its interface). Stubs are not production implementations.

**Installed so far:** step 1 (Sigstore manifest verifier, source-list matcher; input `ported-inbox/step-1`, see `PROVENANCE.md`); merge imports from `TrueSignal` (`MERGE-INVENTORY.md`, one `PROVENANCE.md` row each): TOTP and recovery codes (`hub/internal/totp`); GeoIP (`hub/internal/geoip`); asset inventory (`hub/internal/assets`); ATT&CK mapper, Navigator layer and `attack_matrix` projection (`hub/internal/attack`); honeytoken service (`hub/internal/honeytoken`); beacon service (`hub/internal/beacon`); ECS renderer (`hub/internal/ecs`); Elastic and LogScale transports (`hub/internal/siemhttp`).

**Wiring:** `hub/cmd/truesignal-hub/main.go` constructs the services. An
imported module is passed in the field listed below; nothing else changes.
Every seam fails closed or turns the feature off when the module is absent.

| Module | Interface (`hub/internal/ported/ported.go` unless noted) | Consumed by (field) | Absent → | Stub |
|---|---|---|---|---|
| Sigstore manifest verifier — **installed (step 1)** | `ManifestVerifier.Verify(manifest, bundle, sensorName, version) error`, implemented by `hub/internal/signing` (`Verifier.Verify` adapts the module's `VerifyManifest` argument order). Identity: `https://github.com/<repo>/.github/workflows/publish-sensor.yml@refs/tags/sensor/<name>/v<X.Y.Z>`, issuer `https://token.actions.githubusercontent.com`; SCT, Rekor entry and timestamp required. Config: `TS_MANIFEST_SIGNER_REPO` (default `mahmoudahmed3132/Doppel`; the 1.0.0 fixtures in `hub/internal/signing/testdata` were signed by `mahmoudahmed3132/TrueSignal-Rewrite` and are tested with that repository passed explicitly), `TS_SIGSTORE_TRUSTED_ROOT` (default: embedded public-good root) | `catalogue.Catalogue.Verifier` | n/a (installed). An unreadable trusted root or invalid signer repo stops the Hub (fail closed). `TS_DEV_ALLOW_UNSIGNED_MANIFESTS` still exists for development only | `RejectAllVerifier`, `AcceptAllVerifier` (tests) |
| GeoIP — **installed (`hub/internal/geoip`)** | `GeoLocator.Enabled() bool`, `Locate(source, details) *domain.Location` (`basis` = `source` or `client_subnet`). Config: `TS_GEOIP_DB`, `TS_GEOIP_AUTO_UPDATE` | `enrich.Enricher.Geo` | no `location` in events; UI shows "No location" | `Geo` (fixed table) |
| Asset inventory — **installed (`hub/internal/assets`)** | `AssetInventory.Validate(raw) (normalised, error)`, `Index(normalised) (AssetIndex, error)`; `AssetIndex.Lookup(source) *domain.AssetMatch`. Stored as one settings value | `hubsettings.Service.Assets` (index rebuilt at load and on `PUT /assets`) → `enrich.Enricher.Assets` | inventory read-only, no `source_asset` | `Assets` (exact match, JSON array) |
| ATT&CK mapping — **installed (`hub/internal/attack`)** | `AttackMapper.For(trigger) *domain.AttackMapping`, `NavigatorLayer(events) (json, error)` | `enrich.Enricher.Attack`, `httpapi.Insights.Attack` | no `attack` enrichment; `/analytics/attack/navigator` → 503 `module_unavailable` | `Attack` (fixed table) |
| Source-list matcher — **installed (step 1)** | `SourceListParser.Parse(entries) (SourceMatcher, error)`, implemented by `hub/internal/sourcelist.Parser` (entries joined and parsed as one list: IPs in any notation, CIDR ranges, exact names; a `:port` on the source is ignored; at most 10 000 entries of ≤ 256 bytes). Strict on save; stored lists are re-read leniently (`ParseStored`) so a pre-validation list keeps working | `hubsettings.Service.Parser` | n/a (installed) | `ExactSourceList` (tests) |
| TOTP and recovery codes — **installed (`hub/internal/totp`, `totp.Module`)** | `TOTP.GenerateSecret`, `Verify(secret, code, lastStep, now) (step, ok)`, `GenerateRecoveryCodes`, `ConsumeRecoveryCode`. The Hub enforces replay with a compare-and-swap on the step, independently of the module | `auth.Service` (`Options.TOTP`) | MFA unavailable (`mfa.available: false`); `TS_REQUIRE_MFA` cannot be met | `TOTP` (deterministic codes) |
| Beacon service — **installed (`hub/internal/beacon`)** | `BeaconService` (`Create`, `Artefact`, `Resolve`, `RecordUse`, `Delete`, `List`) over `BeaconStore` (implemented by `store.DB`) and the beacon master key (`secrets.Keys`) | `ingest.Pipeline.Beacons`, `httpapi.System.Beacons` | every beacon unknown; beacon API 503 | `Beacons` |
| Honeytoken service — **installed (`hub/internal/honeytoken`)** | `HoneytokenService` (`Ensure`, `Match`, `RecordUse`, `List`, `Inventory`) over `HoneytokenStore` (`store.DB`) and `CaptureKeyFunc` | `compose.Compiler.Honeytokens` (wrapped by `siem.InventoryHoneytokens`), `ingest.Pipeline.Honeytokens` | File Canary renders refused (except redacted previews); no `honeytoken_used` | `Honeytokens` |
| ECS renderer — **installed (`hub/internal/ecs`)** | `ECSRenderer.Render(domain.Record) (map, error)` for events (with enrichment), audit, honeytoken inventory, Hub heartbeat | `siem.Service.Renderer` | `format: ecs` refused (`capabilities.ecs: false`) | `ECS` |
| HTTP SIEM transports — **installed (`hub/internal/siemhttp`)** | `HTTPSIEMTransport.Send(ctx, protocol, address, token, document) (SendOutcome, error)`; outcome success / transient (retried) / terminal (dropped); https only, no redirects | `siem.Service.HTTP` | `elastic` / `logscale` refused (`capabilities.http_transports: false`) | `HTTPTransport` |
| Analytics projections | `Projection.Name()`, `Build(ctx, events, params) (any, error)`: insights, sources, ATT&CK matrix, attack path, geo map, report (names: QUESTIONS Q56) | `httpapi.Insights.Projections` (map by name), mounted at `GET /api/v3/analytics/projections/{name}?days=` (other query parameters passed through, bounded) | 404; UI page shows "module not installed" | `Projection` |
| Lure-content generator (File Canary) | `sensors/file-canary/lure.go`: `LureGenerator` (`content(path, honeytoken) → (bytes, category)`) | `file-canary` init container | built-in placeholder lures (`stubLures`) | `stubLures` |
| Web skins (Web Router decoy) | `sensors/web-router-decoy/skin.go`: `Skins` / `Skin` (`render(kind, request) → (status, headers, body)`), selection from config | `web-router-decoy` | built-in `generic` skin | `stubSkins` |
| Decoy helper package (SDK add-on) | Go: `sensor.Reporter` (`ReportSeverity`, `Setting`) in `sdk/go/sensor`; Python: `truesignal_sdk.Reporter` (`report_severity`, `setting`) | sensors built on the helper | n/a | `*sensor.Sensor` implements it |
| Decoys (Identity, Database, Remote Access, Network Service, Token Receiver) | none beyond the SDK (§5), manifest schema v3 (`docs/manifest-v3.md`), compose rules (§6.12) and the reserved secrets (`TS_CAPTURE_KEY`, `TS_BEACON_KEY`, `TS_HONEYTOKEN`) | the catalogue | not in the registry | — |
| SIEM detection rules and test harness | the ECS contract (`docs/siem-integration.md`) and `docs/audit-actions.md` | — | — | — |

Tests that exercise each seam *with* a module installed (stubs):
`hub/internal/enrich` (GeoIP, assets, ATT&CK), `hubsettings`
`TestAssetInventoryWithModule`, `httpapi` `TestProjectionsAndNavigatorWithModules`,
`auth`/`httpapi` MFA tests (TOTP), `ingest` pipeline tests (beacons,
honeytokens, source lists), `siem` tests (ECS, HTTP transports), `catalogue`
tests (verifier accept/reject), sensor tests (lures, skins).
