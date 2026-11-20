# Module seams (§12)

All modules are in-tree and required; the interfaces in
`hub/internal/ported/ported.go` remain as test seams (with minimal test
fakes in `hub/internal/ported/stub`). `hub/cmd/truesignal-hub/main.go`
wires every implementation unconditionally.

| Module | Implementation | Interface (`hub/internal/ported/ported.go` unless noted) | Consumed by (field) |
|---|---|---|---|
| Sigstore manifest verifier | `hub/internal/signing` | `ManifestVerifier.Verify(manifest, bundle, sensorName, version) error`. Identity: `https://github.com/<repo>/.github/workflows/publish-sensor.yml@refs/tags/sensor/<name>/v<X.Y.Z>`, issuer `https://token.actions.githubusercontent.com`; SCT, Rekor entry and timestamp required. Config: `TS_MANIFEST_SIGNER_REPO`, `TS_SIGSTORE_TRUSTED_ROOT` | `catalogue.Catalogue.Verifier` |
| GeoIP | `hub/internal/geoip` | `GeoLocator.Enabled() bool`, `Locate(source, details) *domain.Location` (`basis` = `source` or `client_subnet`), `ASNEnabled() bool`, `LookupASN(addr) (uint, string)`. Config: `TS_GEOIP_DB`, `TS_GEOIP_ASN_DB`, `TS_GEOIP_AUTO_UPDATE` | `enrich.Enricher.Geo`, `projections.*.GeoIP` |
| Asset inventory | `hub/internal/assets` | `AssetInventory.Validate(raw) (normalised, error)`, `Index(normalised) (AssetIndex, error)`; `AssetIndex.Lookup(source) *domain.AssetMatch` | `hubsettings.Service.Assets` → `enrich.Enricher.Assets` |
| ATT&CK mapping | `hub/internal/attack` | `AttackMapper.For(trigger) *domain.AttackMapping`, `NavigatorLayer(events) (json, error)` | `enrich.Enricher.Attack`, `httpapi.Insights.Attack` |
| Source-list matcher | `hub/internal/sourcelist` | `SourceListParser.Parse(entries) (SourceMatcher, error)` (strict on save; `ParseStored` lenient on load) | `hubsettings.Service.Parser` |
| TOTP and recovery codes | `hub/internal/totp` | `TOTP.GenerateSecret`, `Verify(secret, code, lastStep, now) (step, ok)`, `GenerateRecoveryCodes`, `ConsumeRecoveryCode` | `auth.Service` (`Options.TOTP`) |
| Beacon service | `hub/internal/beacon` | `BeaconService` (`Create`, `Artefact`, `Resolve`, `RecordUse`, `Delete`, `List`) | `ingest.Pipeline.Beacons`, `httpapi.System.Beacons` |
| Honeytoken service | `hub/internal/honeytoken` | `HoneytokenService` (`Ensure`, `Match`, `RecordUse`, `List`, `Inventory`) | `compose.Compiler.Honeytokens` (wrapped by `siem.InventoryHoneytokens`), `ingest.Pipeline.Honeytokens` |
| ECS renderer | `hub/internal/ecs` | `ECSRenderer.Render(domain.Record) (map, error)` for events, audit, honeytoken inventory, Hub heartbeat | `siem.Service.Renderer` |
| HTTP SIEM transports | `hub/internal/siemhttp` | `HTTPSIEMTransport.Send(ctx, protocol, address, token, document) (SendOutcome, error)` | `siem.Service.HTTP` |
| Analytics projections | `hub/internal/projections`, `hub/internal/attack` | `Projection.Name()`, `Build(ctx, events, params) (any, error)`: `insights`, `sources`, `attack_matrix`, `attack_path`, `geo_map`, `report` (keyed on `source_ip` when set else `source`; drills excluded; optional `group_by=ip\|subnet24\|subnet64\|asn`) | `httpapi.Insights.Projections` |
| Lure-content generator (File Canary) | `sensors/file-canary/lures_generated.go` | `sensors/file-canary/lure.go`: `LureGenerator` | `file-canary` init container |
| Web skins (Web Router decoy) | `sensors/web-router-decoy/skins_builtin.go` | `sensors/web-router-decoy/skin.go`: `Skins` / `Skin` | `web-router-decoy` |
| Decoy helper package (SDK) | `sdk/go/sensor`, `sdk/go/decoy`, `sdk/python` | Go: `sensor.Reporter` (`ReportSeverity`, `Setting`); Python: `doppel_sdk.Reporter` | sensors built on the SDK |
| SIEM detection rules and test harness | `docs/siem/`, `hub/internal/siemrules` | ECS contract (`docs/siem-integration.md`) and `docs/audit-actions.md` | — |

## Schema migration hook seam (`hub/internal/store`)

`store.Migration` supports an optional Go hook `Hook func(ctx context.Context, tx *sql.Tx) error` that runs inside the per-version migration transaction after all DDL statements in `Migration.Stmts` succeed and before `schema_version` is updated.

* **Schema v6 (F-002 — source identity normalisation and correlation):** adds `events.source_ip TEXT`, `events.source_port INTEGER`, `events.source_kind TEXT NOT NULL DEFAULT 'other'`, and `CREATE INDEX events_source_ip ON events(source_ip, received_at)`, then runs `backfillEventSourcesTx` (`SourceBackfillBatchSize = 5000`). The hook pages through existing `events` rows by `seq > lastSeq ORDER BY seq ASC LIMIT 5000`, parses each raw `source` with `domain.ParseSource` (canonical IP, IPv4-mapped IPv6 unmapped to IPv4, IPv6 zone stripped, nullable port, `source_kind` in `ip|local|drill|other`), and updates the batch within the transaction.

Tests that exercise each seam:
`hub/internal/enrich` (GeoIP, assets, ATT&CK), `hubsettings`
`TestAssetInventoryWithModule`, `httpapi` `TestProjectionsAndNavigatorWithModules`,
`auth`/`httpapi` MFA tests (TOTP), `ingest` pipeline tests (beacons,
honeytokens, source lists), `siem` tests (ECS, HTTP transports), `catalogue`
tests (verifier), `store` migration tests (v1→v6 hook backfill), sensor tests (lures, skins).

