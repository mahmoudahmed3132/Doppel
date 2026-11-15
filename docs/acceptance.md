# Acceptance test mapping (§14)

Status legend: **pass** = automated test passing in CI (`make`); **partial** =
some cases automated; **todo** = component not yet implemented.

| # | Test | Status | Implementation |
|---|---|---|---|
| 1 | Setup token, single setup, password ≥ 12 | pass | `hub/internal/auth` `TestSetup`; `hub/internal/httpapi` `TestAdminSetupFlow` |
| 2 | Login lockouts, MFA flow, recovery single use, TOTP replay | pass (stub TOTP and the installed module) | `hub/internal/auth` `TestLoginLockouts`, `TestMFAFlow`, `TestConcurrentRecoveryCodeUse`, `TestHubEnforcesTOTPReplayItself`; `hub/internal/store` `TestAdminCompareAndSwap`; `hub/internal/httpapi` `TestAdminLoginCookieAndLockout`, `TestAdminMFAOverHTTP`; with the real module: `hub/internal/totp` `TestModuleThroughAuthService`, `TestHOTPMatchesRFC6238Vectors`, `TestRecoveryCodesFormatUniqueAndSingleUse` |
| 3 | Require-MFA enrolment-only session | pass (stub TOTP) | `hub/internal/auth` `TestRequireMFAMode`; `hub/internal/httpapi` `TestRequireMFAEnrolOnlySession` |
| 4 | Node key once, hashed, rotation/deletion immediate | pass | `hub/internal/httpapi` `TestFleetNodeKeyLifecycleEndToEnd` (create via admin API → ingest → rotate → old key 401 → delete → 401, no restart; key absent from GET/list/audit); `hub/internal/nodekey`; `hub/internal/fleet` `TestNodeLifecycle` |
| 5 | Ingestion: partial batch, duplicates, reserved 403, other node 404, oversized details, invalid UTF-8, syslog `"]\n` | pass | `hub/internal/httpapi` `TestEventsBatchSemantics`, `TestEventsWholeBatchStatuses`; `hub/internal/ingest` `TestNormalize`; `hub/internal/siem/syslog` `TestHostileValueStaysOneLine` |
| 6 | Whitelist / known beacon / honeytoken interplay | pass (real source-list matcher, PORTED step 1) | `hub/internal/ingest` `TestPipelineWhitelisted`, `TestPipelineBeacon`, `TestPipelineHoneytokenOnWhitelistedSource` (PORTED stubs) |
| 7 | Liveness: timeout, stop + escalation, recovery, restart | pass | `hub/internal/liveness` |
| 8 | Compose rules | pass | `hub/internal/compose`: `TestRuleDigest` (1), `TestPassingRenderHardening` + `TestRuleMounts` init (2), `TestRuleCapabilitiesAndNetwork` (3, incl. `NET_ADMIN`), `TestRuleMounts` (4, incl. `/run/docker.sock`, ancestors), `TestRuleInterpolation` (5, `$` in image, `$$` escaping), `TestRuleConfigDeclaredAndReserved` (6), `TestRulePortConflict` (7, UDP vs TCP same number), `TestRevisionDeterministic` (10), `TestSecretsAndRedaction` (9); `hub/internal/fleet` (11). Mutation-checked: disabling the ancestor check, `$` escaping or `TS_TEST_MODE` pinning fails tests |
| 9 | Migrations: snapshot, newer schema refused, deletion keeps events | pass | `hub/internal/store` `TestMigrationSnapshotAndNewerSchema`, `TestFailedMigrationRollsBack`, `TestEventsSurviveNodeAndSensorDeletion` |
| 10 | SIEM delivery | pass (HTTP parts against a PORTED-transport stand-in) | `hub/internal/siem`: `TestTCPCollectorRestartLosesNothing` (mutation-checked: fails 3/3 without the peer-closed check), `TestHTTPTransientRetriedTerminalDropped` (500→retry, 400→drop, 10-attempt cap), `TestQueueOverflowCounted`, `TestSwitchAuditReachesPreviousDestination`, `TestSwitchInterruptsRetriesAgainstDeadDestination`, `TestHubHeartbeat` (5 min interval), `TestTLSVerifiesCollector`, `TestUDP`, `TestShutdownFlushes`, `TestHoneytokenInventory`. "Redirect not followed" for HTTP outputs is the PORTED transport's duty; webhooks: `hub/internal/webhook` `TestRetriesAndRedirects` |
| 11 | CLI | pass (simulated and real Docker) | `cli/internal/apply`: `TestApplyNoOpWhenUnchanged`, `TestRollbackOnExitedService`, `TestRestartingAndUpFailureRollBack`, `TestFirstDeployFailureTearsDown`, `TestPullFailureChangesNothing`, `TestHostPathChecks`; `cli/internal/app`: `TestApplyAndUninstallKeepsLures`, `TestVersionMismatchMessage`, `TestLinkSavesConfig0600`; Hub side `hub/internal/httpapi` `TestNodeAPI` (426, unredacted compose only for the own node). Real Docker: CI job `real-docker` (`scripts/e2e/real-docker.sh`) links and applies the Hub-rendered compose with the real CLI and `docker compose` (images by digest from a local registry), verifies the containers' hardening, events from host-network and bridge decoys, heartbeats, fire drill, a no-op second apply and uninstall |
| 12 | Sensor test mode / fire drill | pass | each sensor has `TestTestModeAgainstMockHub` (`sensors/{tcp-tarpit,icmp-canary,network-scan-detector,file-canary,web-router-decoy}`); SDK `TestServiceLifecycle` (SIGUSR1 drill); real Hub `hub/internal/httpapi` `TestSDKEndToEnd`; live runs: raw ICMP echo → event, AF_PACKET connect scan → event, real inotify in `file-canary` tests. All manifests validated (`hub/internal/manifest` `TestAllSensorManifests`) and rendered (`hub/internal/compose` `TestRealManifestsRender`) |
| 13 | CI publish guards | pass (GitHub Actions, job `release-tooling`) | `scripts/release/selftest.sh` (CI job `release-tooling`): tag/version mismatch, non-SemVer, unknown sensor, off-default-branch refused; registry first publish, concurrent publishes both land, republish refused, rollback deprecates latest; `:latest` = highest published + signature-verified (SemVer, no pre-release). `hub/internal/registrytool` tests (pinning, index via the Hub decoder, unsigned/unpinned refused). Hub image tag / CLI assets existence checks run only against GHCR/GitHub |
| 14 | Independence check | n/a | run by the specification team |

## Admin UI (§7)

Not a §14 item. `ui/` passes `tsc --noEmit` and the safety lint in `make ui`;
`hub/internal/webui` tests SPA routing, cache headers and that the embedded
`index.html` is CSP-clean. `ui/e2e/smoke.cjs` (Playwright, run manually against
a development Hub) passes all steps with zero CSP violations or page errors.

## Python SDK (§11.6)

`sdk/python/tests` (16 tests, run in CI on the runner's Python and inside the
pinned distroless Python image): configuration rules, UUIDv7 order across
counter exhaustion and clock steps, drop-oldest queue, limiter, test mode
(success, rejection, 401), exit 2 on bad config, batching ≤ 100 with order
kept, heartbeats with `dropped_events`, retries resending the same
`event_id`, 4xx not retried, attempt cap, redirect not followed, real
SIGUSR1/SIGTERM in a child process. Live run against the real Hub: test mode,
TCP connections, fire drill, heartbeat (`sdk_version`), SIGTERM →
`sensor_stopped` and sensor offline.

## PORTED seams (§12, §15)

`docs/ported-seams.md` lists every seam, where it is wired, behaviour when
absent and its stub. `hub/internal/ported/stub` asserts at compile time that
each stub implements its interface. Paths with a module installed are tested:
`enrich` (GeoIP, assets, ATT&CK), `hubsettings` `TestAssetInventoryWithModule`,
`httpapi` `TestProjectionsAndNavigatorWithModules`, plus the MFA, pipeline,
SIEM, catalogue and sensor tests listed there.

## PORTED step 1 (Sigstore verifier, source lists)

* Verifier: `hub/internal/catalogue` `TestProductionHubListsPublishedSensors`
  — production configuration (real verifier, https, no development flags)
  lists the five published `1.0.0` sensors from the registry branch content
  and keeps them after a restart; `TestProductionHubRefusesTamperedManifest`.
  `hub/internal/signing`: the real published bundles verify through the seam;
  a bundle is refused for another sensor, version, repository, manifest or
  swapped arguments; mutation-checked (the module's original workflow name or
  signer repository rejects every real bundle).
* Source lists: acceptance #6 runs on the real matcher (`ingest`
  `TestPipelineWhitelisted`, including a CIDR entry); `hubsettings`
  `TestSourceListsWithRealMatcher` (strict on save, lenient on load).

