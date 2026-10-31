# Acceptance test mapping (§14)

Status legend: **pass** = automated test passing in CI (`make`); **partial** =
some cases automated; **todo** = component not yet implemented.

| # | Test | Status | Implementation |
|---|---|---|---|
| 1 | Setup token, single setup, password ≥ 12 | pass | `hub/internal/auth` `TestSetup`; `hub/internal/httpapi` `TestAdminSetupFlow` |
| 2 | Login lockouts, MFA flow, recovery single use, TOTP replay | pass (stub TOTP) | `hub/internal/auth` `TestLoginLockouts`, `TestMFAFlow`, `TestConcurrentRecoveryCodeUse`, `TestHubEnforcesTOTPReplayItself`; `hub/internal/store` `TestAdminCompareAndSwap`; `hub/internal/httpapi` `TestAdminLoginCookieAndLockout`, `TestAdminMFAOverHTTP`. Re-run with the PORTED TOTP module once imported |
| 3 | Require-MFA enrolment-only session | pass (stub TOTP) | `hub/internal/auth` `TestRequireMFAMode`; `hub/internal/httpapi` `TestRequireMFAEnrolOnlySession` |
| 4 | Node key once, hashed, rotation/deletion immediate | pass | `hub/internal/httpapi` `TestFleetNodeKeyLifecycleEndToEnd` (create via admin API → ingest → rotate → old key 401 → delete → 401, no restart; key absent from GET/list/audit); `hub/internal/nodekey`; `hub/internal/fleet` `TestNodeLifecycle` |
| 5 | Ingestion: partial batch, duplicates, reserved 403, other node 404, oversized details, invalid UTF-8, syslog `"]\n` | pass | `hub/internal/httpapi` `TestEventsBatchSemantics`, `TestEventsWholeBatchStatuses`; `hub/internal/ingest` `TestNormalize`; `hub/internal/siem/syslog` `TestHostileValueStaysOneLine` |
| 6 | Whitelist / known beacon / honeytoken interplay | pass (pipeline level) | `hub/internal/ingest` `TestPipelineWhitelisted`, `TestPipelineBeacon`, `TestPipelineHoneytokenOnWhitelistedSource` (PORTED stubs) |
| 7 | Liveness: timeout, stop + escalation, recovery, restart | pass | `hub/internal/liveness` |
| 8 | Compose rules | todo | compiler not built; render-before-save, refusal without saving, and port-conflict serialisation are tested against a fake compiler in `hub/internal/fleet` |
| 9 | Migrations: snapshot, newer schema refused, deletion keeps events | pass | `hub/internal/store` `TestMigrationSnapshotAndNewerSchema`, `TestFailedMigrationRollsBack`, `TestEventsSurviveNodeAndSensorDeletion` |
| 10 | SIEM delivery | todo | formatter done; transport/queue pending |
| 11 | CLI | todo | — |
| 12 | Sensor test mode / fire drill | partial | SDK: `sdk/go/sensor` `TestTestModeSuccessAndFailure`, `TestServiceLifecycle`; real Hub: `hub/internal/httpapi` `TestSDKEndToEnd`; per-sensor tests pending (§11 sensors not started) |
| 13 | CI publish guards | todo | — |
| 14 | Independence check | n/a | run by the specification team |
