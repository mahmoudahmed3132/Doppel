# PORTED module seams (§12)

All modules below are in-tree and required: each is wired unconditionally in
`hub/cmd/truesignal-hub/main.go`, and the Hub has no "module absent" mode.
The interfaces remain as test seams; `hub/internal/ported/stub` holds the
fakes tests substitute (with a compile-time check that each satisfies its
interface). The stubs are not production implementations. For sensors a seam
is a package-level interface.

**Installed so far:** step 1 (Sigstore manifest verifier, source-list matcher; input `ported-inbox/step-1`, see `PROVENANCE.md`); merge imports from `TrueSignal` (`MERGE-INVENTORY.md`, one `PROVENANCE.md` row each): TOTP and recovery codes (`hub/internal/totp`); GeoIP (`hub/internal/geoip`); asset inventory (`hub/internal/assets`); ATT&CK mapper, Navigator layer and `attack_matrix` projection (`hub/internal/attack`); honeytoken service (`hub/internal/honeytoken`); beacon service (`hub/internal/beacon`); ECS renderer (`hub/internal/ecs`); Elastic and LogScale transports (`hub/internal/siemhttp`); projections `sources`, `geo_map`, `attack_path`, `report` (`hub/internal/projections`).

**Wiring:** `hub/cmd/truesignal-hub/main.go` constructs the services and passes
each one in the field listed below.

| Module | Interface (`hub/internal/ported/ported.go` unless noted) | Consumed by (field) |
|---|---|---|
| Sigstore manifest verifier — **installed (step 1)** | `ManifestVerifier.Verify(manifest, bundle, sensorName, version) error`, implemented by `hub/internal/signing` (`Verifier.Verify` adapts the module's `VerifyManifest` argument order). Identity: `https://github.com/<repo>/.github/workflows/publish-sensor.yml@refs/tags/sensor/<name>/v<X.Y.Z>`, issuer `https://token.actions.githubusercontent.com`; SCT, Rekor entry and timestamp required. Config: `TS_MANIFEST_SIGNER_REPO` (default `mahmoudahmed3132/Doppel`; the 1.0.0 fixtures in `hub/internal/signing/testdata` were signed by `mahmoudahmed3132/TrueSignal-Rewrite` and are tested with that repository passed explicitly), `TS_SIGSTORE_TRUSTED_ROOT` (default: embedded public-good root) | `catalogue.Catalogue.Verifier` |
| GeoIP — **installed (`hub/internal/geoip`)** | `GeoLocator.Enabled() bool`, `Locate(source, details) *domain.Location` (`basis` = `source` or `client_subnet`). Config: `TS_GEOIP_DB`, `TS_GEOIP_AUTO_UPDATE` | `enrich.Enricher.Geo` |
| Asset inventory — **installed (`hub/internal/assets`)** | `AssetInventory.Validate(raw) (normalised, error)`, `Index(normalised) (AssetIndex, error)`; `AssetIndex.Lookup(source) *domain.AssetMatch`. Stored as one settings value | `hubsettings.Service.Assets` (index rebuilt at load and on `PUT /assets`) → `enrich.Enricher.Assets` |
| ATT&CK mapping — **installed (`hub/internal/attack`)** | `AttackMapper.For(trigger) *domain.AttackMapping`, `NavigatorLayer(events) (json, error)` | `enrich.Enricher.Attack`, `httpapi.Insights.Attack` |
| Source-list matcher — **installed (step 1)** | `SourceListParser.Parse(entries) (SourceMatcher, error)`, implemented by `hub/internal/sourcelist.Parser` (entries joined and parsed as one list: IPs in any notation, CIDR ranges, exact names; a `:port` on the source is ignored; at most 10 000 entries of ≤ 256 bytes). Strict on save; stored lists are re-read leniently (`ParseStored`) so a pre-validation list keeps working | `hubsettings.Service.Parser` |
| TOTP and recovery codes — **installed (`hub/internal/totp`, `totp.Module`)** | `TOTP.GenerateSecret`, `Verify(secret, code, lastStep, now) (step, ok)`, `GenerateRecoveryCodes`, `ConsumeRecoveryCode`. The Hub enforces replay with a compare-and-swap on the step, independently of the module | `auth.Service` (`Options.TOTP`) |
| Beacon service — **installed (`hub/internal/beacon`)** | `BeaconService` (`Create`, `Artefact`, `Resolve`, `RecordUse`, `Delete`, `List`) over `BeaconStore` (implemented by `store.DB`) and the beacon master key (`secrets.Keys`) | `ingest.Pipeline.Beacons`, `httpapi.System.Beacons` |
| Honeytoken service — **installed (`hub/internal/honeytoken`)** | `HoneytokenService` (`Ensure`, `Match`, `RecordUse`, `List`, `Inventory`) over `HoneytokenStore` (`store.DB`) and `CaptureKeyFunc` | `compose.Compiler.Honeytokens` (wrapped by `siem.InventoryHoneytokens`), `ingest.Pipeline.Honeytokens` |
| ECS renderer — **installed (`hub/internal/ecs`)** | `ECSRenderer.Render(domain.Record) (map, error)` for events (with enrichment), audit, honeytoken inventory, Hub heartbeat | `siem.Service.Renderer` |
| HTTP SIEM transports — **installed (`hub/internal/siemhttp`)** | `HTTPSIEMTransport.Send(ctx, protocol, address, token, document) (SendOutcome, error)`; outcome success / transient (retried) / terminal (dropped); https only, no redirects | `siem.Service.HTTP` |
| Analytics projections — **installed (`hub/internal/projections`)** | `Projection.Name()`, `Build(ctx, events, params) (any, error)`: insights, sources, ATT&CK matrix, attack path, geo map, report (names: QUESTIONS Q56) | `httpapi.Insights.Projections` (map by name), mounted at `GET /api/v3/analytics/projections/{name}?days=` (other query parameters passed through, bounded) |
| Lure-content generator (File Canary) | `sensors/file-canary/lure.go`: `LureGenerator` (`content(path, honeytoken) → (bytes, category)`) | `file-canary` init container |
| Web skins (Web Router decoy) | `sensors/web-router-decoy/skin.go`: `Skins` / `Skin` (`render(kind, request) → (status, headers, body)`), selection from config | `web-router-decoy` |
| Decoy helper package (SDK add-on) | Go: `sensor.Reporter` (`ReportSeverity`, `Setting`) in `sdk/go/sensor`; Python: `truesignal_sdk.Reporter` (`report_severity`, `setting`) | sensors built on the helper |
| Decoys (Identity, Database, Remote Access, Network Service, Token Receiver) | none beyond the SDK (§5), manifest schema v3 (`docs/manifest-v3.md`), compose rules (§6.12) and the reserved secrets (`TS_CAPTURE_KEY`, `TS_BEACON_KEY`, `TS_HONEYTOKEN`) | the catalogue |
| SIEM detection rules and test harness | the ECS contract (`docs/siem-integration.md`) and `docs/audit-actions.md` | — |

Tests that exercise each seam *with* a module installed (stubs):
`hub/internal/enrich` (GeoIP, assets, ATT&CK), `hubsettings`
`TestAssetInventory`, `httpapi` `TestProjectionsAndNavigatorWithModules`,
`auth`/`httpapi` MFA tests (TOTP), `ingest` pipeline tests (beacons,
honeytokens, source lists), `siem` tests (ECS, HTTP transports), `catalogue`
tests (verifier accept/reject), sensor tests (lures, skins).
