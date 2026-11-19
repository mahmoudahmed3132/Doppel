# Doppel Enterprise Specification

**Author role:** CISO review (payments / fintech, EMEA).
**Date:** 2026-11-20.
**Baseline:** `main` @ `e204a10` (includes PR #39). Hub `3.0.0-rc.1`, schema v4.
**Audience:** Claude Code sessions that implement these features, one feature or work package per session.
**Status:** proposal; the owner approves scope per phase.

This document lists every change and new feature I would need before buying Doppel for a regulated enterprise, or before selling it to one in Europe, the Middle East and Africa. It extends, and does not replace, `docs/plan/ROADMAP.md` and `docs/plan/EXECUTION-PLAN.md`. Where those plans already specify a work package (U1, S1, H1, B1, WP-4A..C), this document references it and adds only the extra requirements.

---

## Table of contents

0. [Instructions for the implementing session](#0-instructions-for-the-implementing-session)
1. [Assessment summary](#1-assessment-summary)
2. [Market research: EMEA needs and gaps](#2-market-research-emea-needs-and-gaps)
3. [Product positioning and editions](#3-product-positioning-and-editions)
4. [Non-functional requirements](#4-non-functional-requirements)
5. [Feature specifications](#5-feature-specifications)
   - [E0 Correctness and release foundations](#e0-correctness-and-release-foundations)
   - [E1 Identity, access and administration](#e1-identity-access-and-administration)
   - [E2 SOC workflow and incident management](#e2-soc-workflow-and-incident-management)
   - [E3 Integrations: SIEM, notification, ticketing, response, intel](#e3-integrations)
   - [E4 Deception content](#e4-deception-content)
   - [E5 Fleet, deployment and network placement](#e5-fleet-deployment-and-network-placement)
   - [E6 Platform: scale, availability, observability, sovereignty](#e6-platform-scale-availability-observability-sovereignty)
   - [E7 Multi-tenancy and MSSP](#e7-multi-tenancy-and-mssp)
   - [E8 Analytics, assurance and compliance reporting](#e8-analytics-assurance-and-compliance-reporting)
   - [E9 UX, localisation and accessibility](#e9-ux-localisation-and-accessibility)
   - [E10 Privacy and employee-monitoring safeguards](#e10-privacy-and-employee-monitoring-safeguards)
   - [E11 Product security assurance](#e11-product-security-assurance)
   - [E12 Licensing, editions and commercial plumbing](#e12-licensing-editions-and-commercial-plumbing)
   - [E13 API and extensibility](#e13-api-and-extensibility)
6. [Sequencing, dependencies and schema reservations](#6-sequencing-dependencies-and-schema-reservations)
7. [Definition of done (global)](#7-definition-of-done-global)
8. [Sources](#8-sources)

---

## 0. Instructions for the implementing session

Read this section before writing any code. It applies to every feature below.

### 0.1 Read first

1. `docs/plan/ROADMAP.md` §0 (ground rules) and `docs/plan/EXECUTION-PLAN.md` §0 (mandatory execution rules). Those rules stay in force: licence headers, clean-room rules for decoys, pinned Dockerfiles, UI CSP rules, verification gates.
2. `THREATMODEL.md`, `QUESTIONS.md`, `docs/contract-v3.md`, `docs/manifest-v3.md`, `docs/audit-actions.md`, `docs/openapi.yaml`, `docs/siem-integration.md`.
3. The feature's own section in this file, plus every feature it lists under **Depends on**.

### 0.2 Repository map (as of `e204a10`)

| Area | Path | Notes |
|---|---|---|
| Hub entrypoint | `hub/cmd/truesignal-hub/main.go` | subcommands `serve`, `mfa-reset`, `kek-generate`, `secrets-reset`, `kek-rotate`, `version` |
| HTTP API | `hub/internal/httpapi/*.go` | admin API `/api/v3/*`, node API `/v3/*`; every route needs an explicit role (U1 test) |
| Storage | `hub/internal/store/` | SQLite (`modernc.org/sqlite`), linear `migrations` in `schema.go`; **never edit a released migration, append** |
| Ingest | `hub/internal/ingest/` (`normalize.go`, `pipeline.go`) | event normalisation and fan-out |
| Liveness | `hub/internal/liveness/` | already raises sensor offline/online Hub events (§6.6) |
| Analytics | `hub/internal/analytics/`, `hub/internal/projections/` | attack path, insights, report, geomap, sources |
| ATT&CK | `hub/internal/attack/` | trigger to technique mapping |
| ECS/SIEM | `hub/internal/ecs/`, `hub/internal/siem/`, `hub/internal/siemhttp/`, `hub/internal/siemrules/` | ECS document builder, syslog and HTTPS outputs, shipped detection rules |
| Notifications | `hub/internal/webhook/` | Slack, Discord, ntfy, Gotify |
| Secrets | `hub/internal/seal/`, `hub/internal/secrets/` | KEK-sealed secrets at rest |
| Auth | `hub/internal/auth/`, `hub/internal/totp/` | sessions, roles, TOTP; `NewUserSession` exists for SSO |
| Audit | `hub/internal/audit/` | audit records to log and SIEM |
| UI | `ui/src/` (Preact + TS, `pages/*.tsx`, `api.ts`, `router.tsx`) | strict CSP, no inline styles; `npm run check` |
| CLI | `cli/internal/app/app.go` | `link`, `apply`, `discover`, `firedrill`, `status`, `uninstall` |
| SDK | `sdk/go/{sensor,decoy,ber}`, `sdk/python/` | fire drill = `sensor.DrillSource` string today |
| Sensors | `sensors/*` (11) | database-decoy, file-canary, icmp-canary, identity-decoy, network-scan-detector, network-service-decoy, remote-access-decoy, tcp-tarpit, template, token-receiver, web-router-decoy |
| e2e | `scripts/e2e/real-docker.sh`, `scripts/demo/run-demo.sh` | real Docker e2e and kill-chain demo |

### 0.3 Rules for every feature

- **One feature per branch** named `feat/<feature-id-lowercase>-<slug>` (e.g. `feat/f001-drill-flag`). No tags, publishes or merges. End at a pushed branch.
- **Schema:** migrations are a gap-free linear list (`SchemaVersion() = len(migrations)`), so a migration always takes the **next free version after rebasing on the latest `origin/main`**. §6.3 shows the intended order only. State the version used in the PR. New `QUESTIONS.md` ids start at **Q82** (take the next free one).
- **Contract changes** (`docs/contract-v3.md`) must stay backward compatible. A Hub must accept events from SDKs one minor version older, and a new SDK must not break against an old Hub (feature-detect through `/v3/version` capabilities). Add a capability string per contract addition.
- **Every admin action** writes an audit record with an action name added to `docs/audit-actions.md`.
- **Every new outbound destination** (IdP, ticketing, EDR, firewall, cloud API) must:
  - go into `THREATMODEL.md` boundary B4;
  - have an SSRF guard (https only unless a dev flag is set, no cross-host redirects, bounded body and timeout, private ranges denied unless explicitly allowed per destination);
  - store its credentials sealed through `hub/internal/seal`.
- **Every new route** updates `docs/openapi.yaml` (validate-docs checks route drift) and declares its role.
- **Every new trigger** gets an ATT&CK mapping row, ECS mapping, and Elastic and LogScale rule updates in `hub/internal/siemrules` / `docs/siem/`.
- **Never weaken** an existing security check, test or assertion to make something pass. If a requirement here conflicts with an existing invariant, stop and write a `QUESTIONS.md` entry.
- **Test data:** use only payment-network test PANs and test BINs, dummy keys, and RFC 5737 / RFC 3849 documentation addresses.
- **Gates** (report each as passed / failed with output / not run with reason):
  - `make`
  - `make ui`
  - `python3 scripts/validate-docs.py`
  - `./scripts/compose-guard.sh`
  - `./scripts/release/selftest.sh`
  - `./scripts/e2e/real-docker.sh`
  - fuzz new parsers for at least 15 s each.

### 0.4 Priority and size legend

- **P0:** blocks an internal production pilot.
- **P1:** required to sell to a regulated enterprise.
- **P2:** competitive differentiator for EMEA.
- **P3:** later or optional.
- **Effort:** S < 1 week, M 1–3 weeks, L > 3 weeks, XL = multiple sessions or a team. Estimates assume one engineer who knows the codebase.

---

## 1. Assessment summary

Hands-on findings from 2026-11-19/20 on a Mac (arm64, Docker Desktop 4.97.0): the kill-chain demo natively and in Docker, a real Docker e2e, a live POC, and a walk through all 13 UI pages and 7 Settings tabs.

**Verdict:** the security engineering underneath is strong. The product around it, which a SOC, IT operations and auditors need, is immature.

**Strengths to keep and market:**

- Signed (Sigstore) and digest-pinned sensor supply chain. Unsigned manifests are visibly flagged.
- Sensor containers verified at runtime: read-only, `cap_drop: ALL`, no-new-privileges, non-root, no docker.sock.
- KEK-sealed secrets at rest, `kek-rotate`, MFA break-glass.
- Strict CSP and security headers. Cross-origin login rejected.
- 11 sensors, including DC-protocol emulation (`identity-decoy`: LDAP/LDAPS/RDP with NTLM capture), database login emulation (MySQL/PostgreSQL/MSSQL), SNMP/DNS, ICMP, scan detection, file canaries and beacons.
- Per-event ATT&CK mapping, Navigator export, attack path, executive report.
- Native Elastic and Falcon LogScale outputs, plus syslog-TLS.
- Serious test culture: `-race`, real-Docker CI, Playwright smoke, fuzzing.

**Defects and gaps found (each becomes a feature below):**

| # | Finding | Feature |
|---|---|---|
| 1 | Fire drills are counted as real attacks. The drill shows as CRITICAL, Scans classifies it "external · multi-decoy · repeat", and it's the top source in the executive report. A drill is identified only by the free-text source `"Fire drill"`. | F-001 |
| 2 | Sources are correlated on the raw `IP:port` string, so one scanner becomes N sources. This breaks Scans, Attack path, top sources and "distinct sources". | F-002 |
| 3 | Only the bootstrap admin can sign in. OIDC is planned (S1) but not built, so roles are unusable. | F-101 (S1+) |
| 4 | Triage is read/archive only. No incidents, assignee, notes, disposition or SLA. | F-201..F-206 |
| 5 | One notification channel (Slack/Discord/ntfy/Gotify) and one SIEM output, with no routing. | F-301, F-302 |
| 6 | Single SQLite file, single process, binds all interfaces. No `/healthz`, `/readyz` or `/metrics`. No backup tooling. | F-003 (H1/B1+), F-601.. |
| 7 | No scoped API tokens. Audit log can't be viewed in-product. Destructive actions need only one admin. | F-104, F-105, F-106 |
| 8 | Decoys share the node's IP (host networking), so one host shows many unrelated services. Easy to fingerprint, and it can't represent "a server in VLAN 20". | F-501 |
| 9 | Fleet is managed by hand: no node groups, policies or bulk enrolment. Production images are amd64 only. | F-502..F-506 |
| 10 | e2e script portability bug on macOS (fixed locally), and the KEEP POC builds without the UI. | F-004 |

---

## 2. Market research: EMEA needs and gaps

### 2.1 Market

- Sizing estimates disagree widely (roughly USD 2.5–3.4 bn for 2025–26, 12–18 % CAGR). Every source agrees that Europe is the #2 region (about 26–30 % share) and attributes this to **NIS2 and DORA**. MEA is the smallest region (about 5–10 %) but growing, driven by national critical-infrastructure and reporting mandates (UAE, KSA) rather than EU law.
- Gartner frames 2026 security architecture around **preemptive cybersecurity**, with deception as a core technique. ITDR is maturing quickly. Non-human and AI-agent identities are a fast-growing attack surface.
- Adoption barriers cited repeatedly: deployment and integration complexity, cost for mid-market, a skills gap (managed services preferred), privacy and compliance concerns (GDPR), and the fear that decoys can be fingerprinted.

### 2.2 Competitors (public information; vendor claims not independently verified)

| Vendor | Positioning | Delivery | What EMEA buyers say is missing (my assessment) |
|---|---|---|---|
| Thinkst Canary | Simplest tripwires, Canarytokens | HW/VM/cloud birds + SaaS console; roughly USD 5–7.5k/yr for a few birds (unofficial) | Few native SIEM integrations, no incident workflow, console is SaaS-hosted |
| Acalvio ShadowPlex | Enterprise, AI-placed, identity and OT, deep CrowdStrike integration (honeytokens surfaced in Falcon Identity) | SaaS-led | SaaS dependency is a problem for sovereignty-sensitive buyers. Expensive. |
| Zscaler Deception (ex-Smokescreen) | Add-on to Zero Trust Exchange. GenAI decoys (fake LLM chatbots and APIs, honeytokens in RAG/vector stores) | Cloud | Requires the Zscaler platform. Lock-in. |
| SentinelOne (ex-Attivo) | Identity / AD deception | Platform module | Tied to the S1 stack. Standalone position diluted. |
| CounterCraft | Intelligence-grade digital twins | Enterprise | Heavy, specialist |
| Lupovis | Lightweight SaaS. Internet-facing "Prowl" separates scanners from real threats | SaaS | SaaS only |
| Tracebit | Cloud canaries deployed as IaC across AWS/Azure/GCP, K8s, CI/CD, IdP. AI-regenerated | SaaS | Cloud-centric, little on-prem network deception |

**Known weakness of third-party canary keys:** an AWS access key ID encodes the account ID offline, so canary keys from well-known issuer accounts can be fingerprinted without triggering. TruffleHog now flags them natively, and Horizon3 documents the evasion. Canaries must be minted in **customer-owned accounts**.

### 2.3 Regulatory drivers

| Regulation | What it demands that deception can serve | Product implication |
|---|---|---|
| **DORA** (EU financial entities, applies since Jan 2025) | ICT detection capability. Major-incident reporting: initial notification within **4 h of classification and ≤ 24 h of awareness**, intermediate within **72 h** of the initial notification, final report (adopted text; draft said 1 month). TLPT for significant entities. | Regulatory incident clocks (F-205), detection-assurance evidence (F-802), TLPT support mode (F-806) |
| **NIS2** (Art. 21 measures, Art. 23 reporting) | Incident handling, effectiveness assessment of measures. Early warning **≤ 24 h**, notification **≤ 72 h**, final report in 1 month. National transpositions vary. | Same clocks (configurable per regime), effectiveness metrics (F-802), evidence packs (F-803) |
| **PCI DSS v4.0.1** | 10.2 audit logging, 10.4.1 automated log review, 10.5.1 retention (12 months, 3 immediately available), **10.7.2 detect and alert on failures of critical security controls**, 11.5.1 intrusion detection, 12.10 incident response, 8.2.1 unique IDs, 8.4.2 MFA | SSO + unique IDs (F-101), audit (F-105), liveness alerting (F-005), retention (F-604), decoys inside the CDE segment (F-501) |
| **CBE Egyptian Financial Cybersecurity Framework** (EG-FinCSF; v2.0 reported in 2026) and PSP licensing rules (in force 17 June 2025) | Mandatory for CBE-regulated banks, FIs and PSPs. Cyber-defence domain. Breach reporting reported as **within 2 working days** (verify against the primary CBE text). | Regime profile "CBE" for clocks and report templates (F-205, F-803), on-prem by default |
| **SAMA CSF / NCA ECC-2:2024** (KSA) | Maturity model (SAMA expects ≥ level 3). ECC-2 moved data localisation to NDMO/SDAIA. Cloud use abroad needs SAMA approval (per secondary sources). | On-prem / in-Kingdom deployment, air-gapped mode (F-607), Arabic UI (F-901) |
| **UAE IA Standard v2.1** (Nov 2025, UAE Cyber Security Council) | National baseline for critical-service entities | Control mapping in evidence packs (F-803) |
| **GDPR / UAE PDPL / KSA PDPL** | Lawful basis, minimisation, retention, data subject rights. EU works councils for employee monitoring. | Privacy mode, pseudonymisation, capture minimisation (E10) |

### 2.4 Gaps Doppel can win in EMEA

1. **Sovereign by design.** Full feature parity on-prem and **air-gapped**, with BYOK/HSM, in-country data, and no SaaS dependency. Most rivals are SaaS-first. *(F-605, F-606, F-607)*
2. **Regulatory clocks and evidence** for DORA, NIS2, CBE, SAMA, NCA and UAE IA in one place. *(F-205, F-803)*
3. **Detection-pipeline assurance.** Prove continuously that a decoy hit reaches the SIEM and fires the rule, which auditors and DORA/NIS2 "effectiveness" checks need. *(F-802)*
4. **Fintech and payments decoys** that no generalist ships: merchant portal, payment API, ISO 8583 listener, HSM command port, honey card records using test PANs. *(F-410..F-413)*
5. **Fingerprint-resistant tokens:** cloud canaries minted in customer-owned accounts, per-install personas, IP-per-decoy. *(F-406, F-501, F-415)*
6. **Privacy mode for EU works councils:** pseudonymised internal identities with four-eyes de-pseudonymisation. *(F-1001)*
7. **Arabic / RTL UI and reports.** No major deception vendor offers this credibly. *(F-901)*
8. **MSSP-ready multi-tenancy** for regional MSSPs, the dominant buying channel in MEA. *(E7)*
9. **AI and agent deception:** decoy LLM API, MCP server and RAG honey-documents, matching Zscaler without needing its platform. *(F-414)*
10. **Mid-market price point**, with an open SDK for custom sensors. *(E12, E13)*

---

## 3. Product positioning and editions

| Edition | For | Includes |
|---|---|---|
| **Core** | Mid-market, single site | Hub, all network decoys, beacons, 1 SIEM output, 2 notification routes, local users + OIDC |
| **Enterprise** | Regulated enterprise | Core + SAML/SCIM, incidents, regulatory clocks, multi-SIEM, response actions, IP-per-decoy, node groups, HA, evidence packs, privacy mode, Arabic |
| **Sovereign** | Government, CNI, banks in KSA/UAE/Egypt | Enterprise + air-gapped bundles, HSM/BYOK, FIPS build, offline licence |
| **MSSP** | Service providers | Enterprise + tenants, MSSP console, white-label, usage metering |

Enforce editions with feature flags evaluated from a signed licence (F-1201). Every feature below names its minimum edition.

---

## 4. Non-functional requirements

These are acceptance targets for the platform as a whole. F-608 builds the load harness that measures them.

| ID | Requirement | Target |
|---|---|---|
| NFR-1 | Ingest throughput (single Hub, 4 vCPU / 8 GB, PostgreSQL) | ≥ 2,000 events/s sustained, ≥ 10,000 events/s burst for 60 s with zero loss (backpressure, no drop) |
| NFR-2 | Fleet scale per Hub cluster | 5,000 nodes, 50,000 sensors, heartbeat every 30 s |
| NFR-3 | Event-to-SIEM latency | p95 ≤ 5 s, p99 ≤ 15 s |
| NFR-4 | Event-to-notification latency (critical) | p95 ≤ 10 s |
| NFR-5 | UI performance | Events page ≤ 1.5 s for 1 M events in the window (server-side pagination and indexed filters) |
| NFR-6 | Availability (HA mode) | 99.9 % monthly. RPO ≤ 5 min, RTO ≤ 15 min (F-602) |
| NFR-7 | Data durability | No acknowledged event lost on Hub crash (WAL / fsync before 200 OK) |
| NFR-8 | Security | No high/critical findings from external pentest. All OWASP ASVS L2 controls (L3 for auth) |
| NFR-9 | Upgrades | Zero-downtime rolling upgrade in HA mode. One-minor-version skew between Hub, CLI and SDK |
| NFR-10 | Accessibility | WCAG 2.2 AA |
| NFR-11 | Localisation | en, ar (RTL), fr (North Africa, EU). All strings externalised |
| NFR-12 | Supportability | Every error shown in the UI or CLI has a stable code documented in `docs/errors.md` |

---

## 5. Feature specifications

Template: **Why** (need) → **Requirements** (MUST/SHOULD) → **Data model** → **API** → **UI** → **CLI / sensor / SDK** → **SIEM & audit** → **Security** → **Tests** → **Acceptance**. Fields that don't apply are omitted.

---

### E0 Correctness and release foundations

#### F-001 Fire drill as a first-class flag
- **Priority:** P0 · **Edition:** all · **Effort:** S · **Schema:** v6 · **Depends on:** none.
- **Why:** drills currently pollute every analytic and the executive report, and page on-call as CRITICAL. Drills prove the pipeline works, so they must reach the SIEM, but clearly labelled.
- **Requirements:**
  1. Contract: add an optional boolean `drill` to the event object in `docs/contract-v3.md`. The SDKs (`sdk/go/sensor`, `sdk/python`) set `drill: true` on every event produced by the drill path (SIGUSR1 and `TS_TEST_MODE`). Keep `source: "Fire drill"` for backward compatibility. Advertise capability `event.drill`.
  2. Hub ingest MUST also treat `source == sensor.DrillSource` from SDKs that don't send the flag as a drill (compatibility shim). Log a deprecation counter.
  3. Hub-side drills MUST come only from authenticated sensors (node key). Drill events can't be created through the admin API.
  4. Drill events MUST:
     - be stored with `is_drill = 1`;
     - have severity forced to `info` (keep the sensor's original severity in `details.original_severity`);
     - never trigger notifications, except to a route that explicitly opts in with `include_drills` (F-301);
     - be excluded by default from every projection: dashboard, scans, attack path, ATT&CK, geo, report, insights, "touched decoys", "distinct sources";
     - be kept for the drill-success metric (F-802).
  5. Events page: a "Drills" view filter (Active / Archived / Drills / All). Drill rows show a `DRILL` pill in FLAGS.
  6. Analytics endpoints accept `include_drills=true` (admin/analyst only). The report gets a toggle, off by default.
  7. ECS: `event.kind = "pipeline_test"`, `labels.drill = true`, `tags: ["drill"]`. Syslog: structured-data param `drill="1"`. Update the shipped Elastic and LogScale rules to exclude drills from alerting rules, and add a separate "drill received" rule used by F-802.
- **Data model:** `ALTER TABLE events ADD COLUMN is_drill INTEGER NOT NULL DEFAULT 0;` plus a partial index `events_nondrill ON events(received_at) WHERE is_drill = 0`. Backfill: `UPDATE events SET is_drill = 1 WHERE source = 'Fire drill'`.
- **Tests:**
  - Unit: normalise sets the flag (new SDK and legacy shim); severity is clamped; projections exclude drills.
  - e2e: extend `real-docker.sh`. After `firedrill`, `/api/v3/analytics/summary` counts are unchanged and `/api/v3/events?view=drills` returns 3.
  - Playwright: the drill pill renders.
- **Acceptance:** a fire drill leaves all dashboard, report, scans, ATT&CK and attack-path numbers unchanged. The SIEM document carries `labels.drill=true`. No webhook fires.

#### F-002 Source identity normalisation and correlation
- **Priority:** P0 · **Edition:** all · **Effort:** M · **Schema:** v7 · **Depends on:** none.
- **Why:** ephemeral source ports split one attacker into many "sources". Lateral-movement detection, which is the product's core value, depends on per-IP correlation.
- **Requirements:**
  1. At ingest, parse `source` into `source_ip` (canonical text form; IPv4-mapped IPv6 → IPv4; zone stripped), `source_port` (nullable), and `source_kind` (`ip` | `local` | `drill` | `other`). The existing `source` string stays as the raw display value.
  2. All projections in `hub/internal/projections` (`sources.go`, `path.go`, `insights.go`, `report.go`, `geomap.go`) MUST key on `source_ip` when it's set, and on `source` otherwise.
  3. Optional rollups, behind a projection parameter `group_by=ip|subnet24|subnet64|asn`. ASN comes from the GeoIP ASN DB when one is loaded.
  4. Loopback and Docker Desktop NAT (`192.168.65.0/24`, `[::1]`) sources get a `labels: ["host_local"]` tag. When the node reports `docker_desktop=true` in host facts (F-505), the node page shows a banner: "source IPs on this node are not real client addresses".
  5. ECS: always set `source.ip` and `source.port` separately (already partly done in `hub/internal/ecs/ecs.go`).
  6. Scans labels (`multi-decoy`, `repeat`) are recomputed on `source_ip`.
- **Data model:** `ALTER TABLE events ADD COLUMN source_ip TEXT; ADD COLUMN source_port INTEGER; ADD COLUMN source_kind TEXT NOT NULL DEFAULT 'other';` plus `CREATE INDEX events_source_ip ON events(source_ip, received_at)`. Backfill in the migration with a Go migration hook (parse existing rows in batches of 5,000). If the migration framework is SQL-only, add a post-migration Go step and document it in `docs/ported-seams.md`.
- **Tests:**
  - Table-driven parser tests: IPv4:port, `[v6]:port`, bare IPs, hostnames, `Fire drill`, `local`, garbage.
  - A projection test where one IP hits 3 decoys from 3 ports gives 1 source labelled `multi-decoy`.
  - e2e: run `nc` against two decoys and assert 1 source in `/api/v3/analytics/projections/sources`.
- **Acceptance:** "Distinct sources" in the walk-through scenario drops from 5 to 2 (192.168.65.1 and ::1), with drills excluded.

#### F-003 Hub listen address, TLS, health, metrics, backup (extends H1, B1, WP-4A, WP-4C)
- **Priority:** P0 · **Edition:** all · **Effort:** M · **Schema:** none · **Depends on:** existing plans H1/B1.
- **Additional requirements beyond H1/B1:**
  1. `TS_LISTEN_ADDR` (default `127.0.0.1`). The binary currently binds `net.JoinHostPort("", port)`, which exposes a bare-binary Hub on every interface. Production with a non-loopback address requires native TLS or `TS_TRUSTED_PROXIES`.
  2. `/metrics` (Prometheus text). Listener on `TS_METRICS_ADDR`, default `127.0.0.1:9090`, never on the public port. Metrics:
     - `doppel_events_ingested_total{node,sensor,severity,drill}`
     - `doppel_ingest_rejected_total{code}`
     - `doppel_siem_queue_depth{output}`
     - `doppel_siem_sent_total{output}`
     - `doppel_siem_dropped_total{output}`
     - `doppel_notify_sent_total{route}`
     - `doppel_notify_failed_total{route}`
     - `doppel_nodes{state}`
     - `doppel_sensors{state}`
     - `doppel_heartbeat_lag_seconds` (histogram)
     - `doppel_http_requests_total{route,code}`
     - `doppel_http_request_seconds` (histogram)
     - `doppel_db_query_seconds` (histogram)
     - `doppel_build_info{version,schema}`
  3. Backup: in addition to B1, add `backup --schedule` documentation (systemd timer and Kubernetes CronJob examples), `--encrypt-to <age-recipient>` (age, permissive licence) so the snapshot is encrypted at rest, and a `verify --from <dir>` subcommand that checks integrity without restoring.
  4. Ship a Grafana dashboard JSON in `deploy/observability/`, plus Elastic and LogScale dashboards for Hub self-health.
- **Acceptance:** Prometheus scrape works. A restore drill runs in CI. A Hub started without `TS_LISTEN_ADDR` isn't reachable from another host.

#### F-004 Build and release hygiene
- **Priority:** P0 · **Edition:** n/a · **Effort:** S · **Depends on:** none.
- **Requirements:**
  1. Commit the macOS e2e fix (CLI at `$W/bin/doppel`, KEEP-mode Try/Stop lines carry the `TS_*` env). With `KEEP=1`, the e2e builds the UI (`make ui`) before `go build`, or fails with a clear message if Node 22+ is missing.
  2. CI asserts the local Go version against `go.mod` with `GOTOOLCHAIN=local` and doesn't rely on silent toolchain download.
  3. Finish the rebrand. Binaries: `doppel-hub` with a `truesignal-hub` symlink for one major version. Env vars: accept `DOPPEL_*` and `TS_*`, with `DOPPEL_*` winning and a warning on `TS_*`. Images: `ghcr.io/<org>/doppel-sensor-<name>`, with aliases. Move the signing identity to an organisation (ROADMAP §6 item 2).
  4. Cut a signed `3.0.0` GA and run one registry rollback drill (ROADMAP §6 item 3).
  5. Publish an SBOM (CycloneDX) per image and binary, and SLSA v1 provenance (`slsa-github-generator`). Gate releases on Trivy with no unwaived critical vulnerabilities.
- **Acceptance:** `real-docker.sh` passes on macOS and Linux. `KEEP=1` shows the real UI. Release artifacts verify with cosign and carry SBOM and provenance.

#### F-005 Liveness alerting to PCI 10.7.2 grade
- **Priority:** P0 · **Edition:** all · **Effort:** S · **Depends on:** F-301 for routing (can ship before it using the existing webhook).
- **Why:** `hub/internal/liveness` already raises sensor offline/online events. PCI DSS 10.7.2 requires that failures of critical security controls are detected, alerted on and responded to. A silenced or killed decoy is also a tampering signal.
- **Requirements:**
  1. Node-level liveness: emit `node_offline` when no heartbeat arrives from any sensor on the node for `3 × interval`, and `node_online` on recovery.
  2. `config_drift`: emit when a node's applied revision ≠ desired revision for longer than a configurable period (default 15 min).
  3. `sensor_tamper_suspected`: emit when a sensor stops without a stop notice while its node keeps heartbeating, or when a container restarts more than N times in M minutes (from the CLI agent's status report, F-505).
  4. Silence windows: sensor silence (exists) gains a mandatory reason and expiry (max 30 days). An expired silence auto-unsilences, with an audit record.
  5. Default severities: node_offline = high, sensor offline = medium, tamper = high.
- **Acceptance:** `docker stop` on a sensor produces `sensor_tamper_suspected` within 2 intervals. Unplugging a node produces `node_offline`.

---

### E1 Identity, access and administration

#### F-101 SSO: OIDC (S1 / WP-4B) + SAML 2.0 + SCIM
- **Priority:** P0 (OIDC), P1 (SAML, SCIM) · **Edition:** Core (OIDC), Enterprise (SAML, SCIM) · **Effort:** M + M + M · **Schema:** v5 (S1, reserved), v8 (SAML/SCIM).
- **OIDC:** implement exactly as S1 / WP-4B. Additional requirements:
  1. Test against Entra ID, Okta, Keycloak and Google Workspace. Document each in `docs/operations.md`.
  2. Map an `amr`/`acr` claim requirement (require MFA at the IdP; reject logins without an MFA `amr` value when the setting is on).
  3. Back-channel logout and session revocation on IdP logout (OIDC Back-Channel Logout 1.0) when supported.
- **SAML 2.0 (SP-initiated and IdP-initiated off by default):**
  1. Signed assertions required. Encrypted assertions supported. Allowed signature algs: RSA-SHA256+ and ECDSA.
  2. Metadata import (URL with SSRF guard, or file upload). SP metadata export at `/api/v3/sso/saml/metadata`.
  3. Attribute → role mapping identical to OIDC group mapping.
  4. Replay protection (assertion ID cache until `NotOnOrAfter`), clock skew ≤ 2 min.
  5. Library: a maintained permissive Go SAML library. Record it in `THIRD_PARTY.md`, and fuzz the XML parsing path. Never use an XML parser without a size limit.
- **SCIM 2.0** (`/scim/v2/Users`, `/scim/v2/Groups`, bearer token per IdP):
  1. Create, update and deactivate users. Deactivation revokes all sessions within 60 s.
  2. Group membership drives roles and scopes (F-102).
- **Data model (v8):** `sso_providers(id, kind, name, config_sealed, enabled, created_at)`, `scim_tokens(id, provider_id, token_hash, created_at, last_used_at, expires_at)`, and `users.external_id`, `users.provider_id`.
- **UI:** Settings → "Single sign-on" tab: providers list, test login button, mapping table, "Restrict break-glass login to CIDRs".
- **Audit:** `sso.provider.create|update|delete`, `sso.login.success|failure`, `scim.user.provision|deprovision`, `user.role.change`.
- **Acceptance:**
  - An Entra ID user in group `doppel-analysts` signs in as analyst.
  - Removing them from the group demotes or denies them at the next login, or within 60 s via SCIM.
  - Every audit record names the person.

#### F-102 RBAC v2: custom roles and scopes
- **Priority:** P1 · **Edition:** Enterprise · **Effort:** M · **Schema:** v9 · **Depends on:** F-101, F-502 (node groups).
- **Why:** large organisations separate duties: SOC tier 1 vs tier 2, the network team owning fleet, auditors read-only, prod vs DR vs office sites.
- **Requirements:**
  1. Permissions are fine-grained verbs: `events.read`, `events.triage`, `incidents.manage`, `fleet.read`, `fleet.write`, `sensors.silence`, `beacons.manage`, `honeytokens.read_secret`, `settings.read`, `settings.write`, `integrations.manage`, `users.manage`, `audit.read`, `danger.execute`, `privacy.depseudonymise` (E10), `response.execute` (F-305).
  2. Built-in roles: Admin, SOC Lead, Analyst, Fleet Operator, Auditor (read-only plus audit), Viewer. Custom roles are composed from permissions.
  3. Scope: a role binding can be limited to one or more node groups / sites. Events, incidents, nodes and sensors outside the scope are invisible (filtered in SQL, not in the UI).
  4. The U1 route test is extended: every route declares a permission, and a test fails if any route lacks one.
- **Data model:** `roles(id, name, builtin, permissions JSON)`, `role_bindings(user_id|group_name, role_id, scope_group_ids JSON)`.
- **Tests:** matrix test of every route × every built-in role. Scope leakage tests on list endpoints, exports, the WebSocket live feed and analytics.
- **Acceptance:** an analyst scoped to "office" can't see DR events through the UI, API, export or the live feed.

#### F-103 Local user management and password policy
- **Priority:** P1 · **Edition:** Core · **Effort:** S.
- **Requirements:**
  1. Admins can create local users (for organisations without an IdP).
  2. Policy: minimum length 14, breached-password check against a bundled k-anonymity-free offline list (top 100k), no forced periodic rotation (NIST SP 800-63B), lockout with exponential backoff per account and per IP.
  3. Local users MUST enrol TOTP or WebAuthn at first login when `require_mfa` is set (production default).
  4. **WebAuthn / passkeys** for local and break-glass accounts (FIDO2, platform and roaming authenticators). Keep TOTP as a fallback.
- **Acceptance:** a local analyst can be created, is forced to enrol MFA, and is locked out after repeated failures. Passkey login works in Chrome and Safari.

#### F-104 API tokens and service accounts
- **Priority:** P1 · **Edition:** Core (read-only tokens), Enterprise (write) · **Effort:** M · **Schema:** v10.
- **Requirements:**
  1. Service accounts are principals without interactive login. Tokens are bound to a service account, carry a subset of permissions plus an optional scope (F-102), have a mandatory expiry (max 1 year) and an optional CIDR allow-list.
  2. Token format `dpl_<id>_<secret>`. Store a hash only (argon2id or SHA-256 with a server pepper sealed under the KEK). Show the token once.
  3. `Authorization: Bearer` on `/api/v3/*`. CSRF/Origin checks are skipped for bearer auth only.
  4. Last-used timestamp and IP. Automatic disable after 90 days unused (configurable).
  5. Secret-scanning friendliness: publish the token prefix regex for GitHub secret scanning partner registration later.
- **UI:** Settings → API tokens.
- **Audit:** `token.create|revoke|use_denied`.
- **Acceptance:** a token with `events.read` can export events and gets 403 on `nodes.write`. An expired token is rejected.

#### F-105 In-product audit log
- **Priority:** P1 · **Edition:** Core (view), Enterprise (export, hash chain) · **Effort:** M · **Schema:** v11.
- **Why:** PCI 10.2/10.4.1/10.5.1 and SOC 2 CC7: auditors need to query admin actions without SIEM access.
- **Requirements:**
  1. Persist every audit record (today they go to log/SIEM only) in an append-only `audit_log` table.
  2. Hash-chain each row: `hash = SHA-256(prev_hash || canonical_json(row))`. Store the chain head in `settings`, and emit the head to the SIEM every hour as an anchor.
  3. A `verify-audit` Hub subcommand checks the chain.
  4. View: filter by actor, action, outcome, time and target. CSV/JSON export.
  5. Retention is independent from events and defaults to 400 days. Deletion is forbidden through the API. Only the retention job deletes, and it writes a `audit.retention.purge` record.
- **Data model:** `audit_log(seq, at, actor_id, actor_name, actor_ip, action, method, route, target, outcome, details JSON, prev_hash, hash)`.
- **Acceptance:** tampering with any row makes `verify-audit` fail and point at the first bad row.

#### F-106 Dual control and step-up authentication
- **Priority:** P1 · **Edition:** Enterprise · **Effort:** S · **Schema:** v12.
- **Requirements:**
  1. Step-up: a fresh MFA (≤ 5 min) is required for `danger.*`, `settings.write` on security/SIEM/SSO tabs, `users.manage`, `response.execute`, `privacy.depseudonymise`, and honeytoken secret reveal.
  2. Dual control (four-eyes), optional per action class: the action is created as a `pending_approval` request. A second user with the same permission approves it within a TTL (default 30 min). The executor ≠ the approver. Approval is audited with both identities.
  3. Default dual-control actions in production: factory reset, delete all events, SIEM output change, SSO provider change, de-pseudonymisation.
- **Acceptance:** factory reset can't run with one admin. Approving your own request is rejected.

#### F-107 Session management and admin access restrictions
- **Priority:** P1 · **Edition:** Core · **Effort:** S.
- **Requirements:**
  1. Users can list and revoke their own sessions. Admins can do this for anyone.
  2. Optional admin-UI CIDR allow-list (outside the IdP).
  3. Configurable idle and absolute TTL in the UI (env vars exist).
  4. Show "last sign-in from IP/time" at login.

---

### E2 SOC workflow and incident management

#### F-201 Incidents (correlation engine)
- **Priority:** P1 · **Edition:** Enterprise (basic grouping in Core) · **Effort:** L · **Schema:** v13 · **Depends on:** F-001, F-002.
- **Why:** analysts work incidents, not single events. Deception's strength is that one intruder touching several decoys is one high-confidence incident.
- **Requirements:**
  1. Correlation rules (configurable, with defaults):
     - same `source_ip` within a sliding window (default 30 min, max 24 h) → same incident;
     - same honeytoken or beacon used from any source → same incident keyed on the token id;
     - optional subnet or ASN grouping (F-002 rollups).
  2. Incident fields: id (`INC-YYYY-NNNNN`), title (auto: "<source> touched N decoys on M nodes"), severity (max of members, escalated: ≥ 3 decoys or any honeytoken/credential use → critical), status, assignee, created/updated/closed, first_seen/last_seen, sources, nodes, sensors, techniques, member event count, disposition, regulatory classification (F-205), tags, external ticket refs.
  3. Late events matching an open incident attach to it. Events matching a closed incident within a reopen window (default 24 h) reopen it with a `reopened` timeline entry. Outside the window they open a new incident linked as `related_to`.
  4. Incident notifications replace per-event notifications for members after the first, to avoid alert storms. Configurable.
  5. Manual operations: merge, split (move events), link.
- **API:** `GET/POST /api/v3/incidents`, `GET/PATCH /api/v3/incidents/{id}`, `POST /api/v3/incidents/{id}/merge|split|link|comments`, `GET /api/v3/incidents/{id}/timeline`.
- **UI:** a new Incidents page (list + detail), which becomes the default landing page for analysts. Incident detail shows: kill-chain graph (reuse the attack-path component), timeline, member events, enrichment (asset, geo, AD user if known), notes, actions.
- **SIEM:** emit incident create/update/close records as `event.kind=alert`, `doppel.incident.*` fields.
- **Tests:** correlation unit tests (window edges, honeytoken key, late events, reopen). Load test with 100k events/hour.
- **Acceptance:** an nmap sweep plus an SSH attempt plus a honeytoken use from one IP produces exactly 1 critical incident with 3+ member events.

#### F-202 Triage lifecycle, assignment and disposition
- **Priority:** P1 · **Edition:** Core · **Effort:** M · **Depends on:** F-201.
- **Requirements:**
  1. Status: `new → acknowledged → investigating → contained → closed`.
  2. Disposition on close, required: `true_positive_malicious`, `true_positive_authorised` (pentest/red team), `benign_misconfiguration` (e.g. a monitoring tool scanning), `false_positive`, `duplicate`.
  3. Assignee (user), watchers.
  4. Markdown notes, rendered safely: CSP-compatible, no raw HTML, links `rel="noopener noreferrer"`.
  5. Bulk actions on the list.
  6. Saved views per user and shared views per team.
  7. Metrics per incident: time to acknowledge (TTA), time to contain, time to close.
- **Acceptance:** analysts can work an incident end to end. Closing requires a disposition. MTTA and MTTR appear in reports (F-801).

#### F-203 Suppressions with reason and expiry
- **Priority:** P1 · **Edition:** Core · **Effort:** S · **Schema:** v14.
- **Why:** the current whitelist is permanent and global. Auditors flag permanent suppression of security alerts.
- **Requirements:**
  1. A suppression has a match (source IP/CIDR, sensor, trigger, node group, honeytoken id, any combination), a required reason, an owner, an expiry (max 180 days; "permanent" needs a dual-control approval, F-106), and a mode: `tag_only` (events kept, marked) or `drop_notifications` (events kept, no notify).
  2. Events are **never** dropped from storage or SIEM by a suppression.
  3. A weekly digest of suppressions expiring within 14 days goes to owners.
  4. Migrate existing `sourcelist` whitelist entries into suppressions with reason "migrated", owner = admin, expiry = 90 days, and a banner telling admins to review them.
- **Acceptance:** an expired suppression stops matching automatically, and every change is audited.

#### F-204 Evidence export with chain of custody
- **Priority:** P1 · **Edition:** Enterprise · **Effort:** S.
- **Requirements:**
  1. Export an incident as a signed bundle (`.zip`): `incident.json`, `events.ndjson`, `timeline.csv`, an HTML summary, sealed captures that the requester is allowed to unseal (`TS_CAPTURE_KEY` material decrypted only with permission `honeytokens.read_secret`), `manifest.json` with SHA-256 of each file, a Hub Ed25519 signature (key sealed under the KEK), exporter identity and time.
  2. A `doppel-hub verify-bundle` subcommand verifies the signature and hashes offline.
- **Acceptance:** a bundle modified after export fails verification.

#### F-205 Regulatory incident clocks (DORA, NIS2, CBE, SAMA, NCA, UAE, custom)
- **Priority:** P2 · **Edition:** Enterprise · **Effort:** M · **Schema:** v15 · **Depends on:** F-201.
- **Why:** EMEA regulators impose hard reporting clocks. SOCs track them in spreadsheets today. No deception vendor helps with this.
- **Requirements:**
  1. Regime profiles, shipped as versioned JSON in `hub/internal/regimes/`, are editable by admins and each carries a `source` URL and `verified_on` date. Shipped defaults:

     | Regime | Clock starts | Deadlines |
     |---|---|---|
     | DORA | classification as major | initial: min(classification + 4 h, awareness + 24 h); intermediate: initial + 72 h; final: per adopted RTS (configurable, default 1 month) |
     | NIS2 | awareness of a significant incident | early warning + 24 h; notification + 72 h; final + 1 month (national variants editable) |
     | CBE PSP | awareness | breach report within 2 **working** days, with an Egyptian working-week calendar. Flag "verify against the primary CBE text". |
     | SAMA / NCA / UAE IA | — | placeholders with editable deadlines and a "not verified" banner until the owner confirms |
     | Custom | — | — |

  2. Incidents get an `awareness_at` timestamp (defaults to the first member event's `received_at`, editable with an audit record) and a `classification` (none / significant / major) with `classified_at` and `classified_by`.
  3. When classified, every applicable regime's deadlines appear as countdowns on the incident, in the incidents list and on the dashboard. Alerts go out at T-50 % and T-1 h and on breach (F-301 routes).
  4. A "Prepare notification" action produces a pre-filled draft (Markdown and PDF via F-801) with the fields regulators ask for: timeline, affected services and assets, indicators, actions taken, classification rationale. The draft is labelled "draft — not submitted". Doppel never submits to a regulator.
  5. Working-day calendars per regime, with public holidays loaded from an admin-uploaded ICS or JSON. No calendar → calendar days with a warning.
- **Tests:** deadline arithmetic (DORA's dual rule, working days across a weekend and a holiday, DST transitions in Europe/Cairo/Riyadh time zones).
- **Acceptance:** classifying an incident as DORA-major at 10:00, with awareness at 08:00 the previous day, shows "initial notification overdue". Classifying at awareness + 2 h shows "due in 4 h".

#### F-206 Ticketing and case-management integrations
- **Priority:** P1 · **Edition:** Enterprise · **Effort:** M · **Depends on:** F-201, F-301.
- **Requirements:**
  1. Connectors: Jira Cloud/DC (REST v2/v3), ServiceNow (Table API, SecOps SIR if available), TheHive 5, generic webhook.
  2. Create a ticket on incident creation (rule-based: severity ≥ X, node group Y).
  3. Two-way sync of status, assignee and comments, with conflict policy "last writer wins, both audited".
  4. Store the external reference on the incident and link to it in the UI.
  5. Credentials sealed. SSRF guard. Per-connector rate limit and retry queue.
- **Acceptance:** a critical incident opens a Jira issue. Closing it in Jira moves the Doppel incident to `closed` with disposition required. If the disposition is missing, the incident moves to `contained` and an "awaiting disposition" flag is set.

---

### E3 Integrations

#### F-301 Notification router (multi-destination, rule-based)
- **Priority:** P1 · **Edition:** Core (2 routes), Enterprise (unlimited) · **Effort:** M · **Schema:** v16.
- **Requirements:**
  1. Destinations:
     - Slack, Discord, ntfy, Gotify (existing);
     - **Microsoft Teams** (Workflows webhook);
     - **PagerDuty** (Events API v2, dedup key = incident id);
     - **Opsgenie**;
     - **SMTP email** (STARTTLS required, DKIM-friendly, HTML + text);
     - **generic HTTPS webhook with HMAC-SHA256 signature** (`X-Doppel-Signature: t=<unix>,v1=<hex>` over `t.body`; 5-min replay window documented);
     - **Telegram Bot API** (common in MEA SOCs).
  2. Rules: match on severity, incident vs event, node group, sensor type, trigger, honeytoken, drill (`include_drills`, default false). Actions: send to destination(s), throttle (N per window), quiet hours with override for critical.
  3. A durable outbound queue (DB-backed) with exponential backoff, max age 24 h, a dead-letter view, and a manual retry.
  4. Message templates per destination, with variables, and safe rendering (escape per channel format).
  5. Keep the "armed/disarmed" switch, but give it a required reason and an auto-re-arm time (max 24 h).
- **Acceptance:** critical incidents page PagerDuty and post to Teams, mediums go to email digest only, and no notification is lost during a 30-minute destination outage.

#### F-302 SIEM fan-out, schemas and durable delivery
- **Priority:** P1 · **Edition:** Core (1), Enterprise (N) · **Effort:** M · **Schema:** v17.
- **Requirements:**
  1. N outputs, each with its own filter (e.g. incidents only, or exclude drills).
  2. Output types:
     - existing syslog (TLS/TCP/UDP), Elastic and LogScale;
     - **Splunk HEC**;
     - **Microsoft Sentinel** (Azure Monitor Logs Ingestion API with DCR, OAuth client credentials);
     - **Google SecOps / Chronicle** (ingestion API);
     - **IBM QRadar** (LEEF over syslog-TLS);
     - **CEF** over syslog;
     - **Kafka** (TLS + SASL/SCRAM) for data lakes.
  3. Schemas: ECS (default, existing), **OCSF 1.x** (Detection Finding / Network Activity classes), CEF and LEEF mappings. Document the mapping tables in `docs/siem/`.
  4. Per-output durable queue: disk-backed (DB table or segment files), size-bounded (default 2 GB), drop-oldest **only** after the bound, with a `siem_dropped` counter and a high-severity Hub event on the first drop.
  5. At-least-once delivery with `event.id` for de-duplication on the receiving side. Batch and compress (gzip) for HTTPS outputs.
  6. "Send test record" per output (exists for one). A "replay range" admin action to re-send events from time A to B to one output (dual control in production).
  7. Ship content packs: Elastic detection rules + dashboards, LogScale parser + alerts + dashboard, Sentinel analytics rules + workbook, Splunk app (props/transforms + saved searches), QRadar DSM notes.
- **Acceptance:** Elastic and LogScale both receive identical records during a migration. Killing one output doesn't affect the other. Queue metrics are exported.

#### F-303 Asset and identity enrichment sources
- **Priority:** P1 · **Edition:** Enterprise · **Effort:** M · **Depends on:** F-002.
- **Requirements:**
  1. Connectors that sync assets (`hub/internal/assets`) on a schedule:
     - **Active Directory / LDAP** (computers, OUs, owners; read-only bind, LDAPS required);
     - **CrowdStrike Falcon host inventory** (Hosts API: hostname, IP, OS, last seen, tags);
     - **Microsoft Defender for Endpoint / Intune**;
     - **VMware vCenter / vCloud Director** (VM name, network, vApp, org);
     - **ServiceNow CMDB**;
     - **NetBox**;
     - CSV (existing).
  2. Precedence rules when sources disagree. Field-level provenance is shown in the UI.
  3. Raise the 5,000-asset limit to 500,000 with indexed CIDR matching (interval tree or sorted ranges).
  4. Identity enrichment: map a captured username (LDAP bind, NTLM, SSH) to a real directory user when one exists. That's high-signal: "a real account's credentials are being tried on a decoy" means credential compromise. Privacy mode (F-1001) applies.
- **Acceptance:** an event from 10.20.30.40 shows hostname, owner, OS, criticality and source system without any CSV upkeep.

#### F-304 Threat-intel sharing (STIX/TAXII, MISP)
- **Priority:** P2 · **Edition:** Enterprise · **Effort:** M.
- **Requirements:**
  1. Built-in **TAXII 2.1 server** (read-only collection) publishing STIX 2.1 `indicator` (attacker IPs, honeytoken-use IPs, beacon-hit IPs), `observed-data` and `sighting` objects.
  2. TLP marking per object (default TLP:AMBER). Confidence derived from the trigger (honeytoken use = high).
  3. Expiry on indicators, default 30 days.
  4. MISP push connector (events + attributes) with sharing-group configuration.
  5. Exclude drills, internal-allow-listed and pentest-disposition sources.
  6. Feeds for firewalls: plain-text EDL/IP list endpoint (PAN-OS External Dynamic List, FortiGate external threat feed), token-protected, TLS only.
- **Acceptance:** a PAN-OS EDL and a FortiGate external connector can both consume the attacker-IP list. The list updates within 60 s of a new incident.

#### F-305 Response actions (approval-gated)
- **Priority:** P2 · **Edition:** Enterprise · **Effort:** L · **Schema:** v18 · **Depends on:** F-201, F-106.
- **Why:** deception produces near-zero-false-positive signals. Automated or one-click containment shortens dwell time.
- **Requirements:**
  1. Action providers:
     - **CrowdStrike Falcon:** network-contain host by AID/hostname, lift containment, add custom IOC (IP, expiring);
     - **Microsoft Defender for Endpoint:** isolate / unisolate;
     - **Palo Alto PAN-OS:** register an IP to a Dynamic Address Group tag through the XML API User-ID, with a timeout;
     - **Fortinet FortiGate:** add to an address group via REST, or quarantine;
     - **F5 BIG-IP AFM / Advanced WAF:** add to an IP-intelligence blocklist / shun;
     - **Generic webhook** (SOAR: XSOAR, Tines, Shuffle).
  2. Every action has a dry-run, an expiry (auto-revert, default 24 h), a reason, and an audit trail. Approval is required unless a **playbook** explicitly allows automatic execution for a rule (e.g. "honeytoken used from an internal host → contain host, automatic").
  3. Safety rails:
     - never act on IPs in a protected list (DCs, core routers, payment switches, Hub, nodes);
     - global "response kill-switch";
     - rate limit (max N automatic actions per hour);
     - every automatic action notifies.
  4. Results (success, failure, provider response) are recorded on the incident timeline.
- **Acceptance:** honeytoken use from 10.0.5.12 creates an incident, automatically contains the Falcon host whose IP is 10.0.5.12 (if the playbook allows), and auto-lifts containment after the expiry unless an analyst extends it. A protected IP is never acted on.

---

### E4 Deception content

General rules for every new sensor:

- Follow EXECUTION-PLAN §0 (clean-room, pinned Dockerfile, SDK reuse, fuzzing).
- Add a clean spec under `docs/clean-specs/<name>.md` **before** implementation.
- Every login fails. Never proxy to a real system. Strict input limits and per-source rate limits.
- No outbound connections except to the Hub, unless the spec says otherwise.

#### F-401 SMB/CIFS file-share decoy
- **Priority:** P1 · **Edition:** Core · **Effort:** L.
- **Requirements:**
  1. SMB 2.1/3.x negotiate, NTLMSSP and Kerberos AP-REQ capture (attempted principal, domain, workstation; NTLMv2 response captured per `TS_PASSWORD_CAPTURE` policy, sealed).
  2. Share enumeration (`srvsvc NetShareEnum`), plus tree connect to configured share names (`Finance$`, `Backups`, `IT`).
  3. Directory listing with persona-generated file names and sizes. File reads return lure documents (planted honeytokens, F-404).
  4. Triggers: `smb_login`, `smb_share_enum`, `smb_file_read`, `smb_file_write_attempt`.
  5. ATT&CK: T1021.002, T1135, T1039, T1110.
  6. No SMBv1 (log `smb1_negotiate` and refuse).
- **Acceptance:** `smbclient -L`, `crackmapexec smb --shares` and Explorer browsing each produce events with the attempted identity.

#### F-402 AD-integrated deception objects (honey users, SPNs, AS-REP)
- **Priority:** P1 · **Edition:** Enterprise · **Effort:** L · **Depends on:** F-303 (AD connector), F-302.
- **Why:** the existing `identity-decoy` emulates a DC. Real attackers query the **real** DCs, so honey objects must live in the real directory. Competitors such as Acalvio and SentinelOne lead here.
- **Requirements:**
  1. A connector with a delegated, least-privilege service account (only create/manage objects in one designated OU, documented delegation script) creates:
     - honey users with realistic attributes (cloned naming convention, `description`, `lastLogon` aged by a scheduled benign bind from the node, group memberships in honey groups only);
     - **Kerberoastable** honey service accounts (SPN set, strong random password, AES disabled to look attractive: configurable);
     - **AS-REP roastable** honey users (`DONT_REQ_PREAUTH`);
     - honey computer objects pointing at decoy IPs (F-501);
     - honey groups (`SQL-Admins-Legacy`).
  2. Detection paths, at least one required:
     - (a) DC event forwarding: the Hub correlates Windows Security events 4768/4769/4771/4625/4624 and 4662 (read of a honey object with auditing SACL) received from the customer SIEM via a pull connector (Elastic/LogScale/Sentinel query API) or WEF/syslog;
     - (b) tagging honey objects in **Microsoft Defender for Identity** (honeytoken tag) and **CrowdStrike Falcon Identity Protection** (honeytoken accounts), and ingesting their alerts via API.
  3. Any authentication or ticket request for a honey object raises a critical `ad_honey_object_used` event, with the source host and the real account that requested it (when present).
  4. Lifecycle: creation, rotation (yearly password change), removal on uninstall (with dual control), and drift detection (attributes changed by someone else → alert).
  5. Never grant honey objects real privileges. Add them to "Protected Users" where it doesn't break the lure. Document the risk analysis in `THREATMODEL.md`.
- **Acceptance:** `GetUserSPNs.py` (Kerberoast) and `GetNPUsers.py` (AS-REP) run against the real domain produce a critical event naming the requesting host within 60 s (with path (a) or (b) configured).

#### F-403 Entra ID / Microsoft 365 deception
- **Priority:** P2 · **Edition:** Enterprise · **Effort:** M.
- **Requirements:**
  1. Honey users (no licence, sign-in blocked or conditional-access-denied), a honey app registration with a client secret planted as a lure, and a honey service principal.
  2. Detection via Microsoft Graph sign-in logs and audit logs (polling with delta queries, or Event Hub stream).
  3. Triggers: `entra_honey_signin_attempt`, `entra_honey_secret_used`, `entra_honey_object_read` (where audit data allows).
- **Acceptance:** a sign-in attempt for a honey user or use of the honey app secret raises a critical event within the Graph log latency (documented, usually minutes).

#### F-404 Lure and breadcrumb engine
- **Priority:** P1 · **Edition:** Core (files), Enterprise (endpoint distribution) · **Effort:** L · **Schema:** v19.
- **Why:** decoys are found only if attackers are led to them. Breadcrumbs on real endpoints are the highest-yield placement.
- **Requirements:**
  1. Lure types:
     - `.rdp` files pointing at decoy hosts;
     - saved SSH config + key (key accepted only by the SSH decoy);
     - PuTTY/WinSCP session registry entries;
     - browser bookmarks to decoy web apps;
     - `hosts` file entries;
     - mapped drive pointing at the SMB decoy;
     - AWS/Azure credential files (F-406);
     - `.env` and `kubeconfig` files;
     - database connection strings;
     - Office documents with beacons (existing web bug);
     - password-manager-style export files.
  2. Distribution channels:
     - **CrowdStrike RTR** (put-file / runscript to target host groups);
     - **Microsoft Intune** (remediation scripts);
     - **GPO** (generated script + instructions);
     - **Ansible** (generated playbook);
     - manual download bundle.
     Each channel's credentials are sealed, and actions are audited and reversible (an "uninstall breadcrumbs" job).
  3. Inventory: every planted lure is tracked (host, path, type, token id, planted_at, channel). Unique tokens per host let a hit identify the **compromised source endpoint**.
  4. Rotation: re-generate lures on a schedule (default 90 days) without breaking the decoys they point to.
  5. Realism: names and contents come from persona templates (F-415), never generic "honeypot" strings.
- **Acceptance:** RTR deploys a `.rdp` lure to a Falcon host group. Opening the lure and connecting raises an event naming the endpoint the lure came from.

#### F-405 Additional network service decoys (wave 1)
- **Priority:** P1 · **Edition:** Core · **Effort:** L (several sessions) · one clean spec per item.
- **Decoys:**
  - `kubernetes-api-decoy`: HTTPS `/api`, `/apis`, `/version`; token and cert auth attempts; `kubectl` user-agent capture. T1613, T1552.007.
  - `docker-api-decoy`: TCP 2375/2376 Engine API (version, info, containers/json); container-create attempts logged and refused. T1610.
  - `redis-decoy`: RESP2/3, AUTH capture, `CONFIG SET dir` / `SLAVEOF` / `MODULE LOAD` attempts flagged critical. T1190, T1210.
  - `elasticsearch-decoy`: `/_cat/indices`, `/_search` with persona indices; auth capture. T1213.
  - `mongodb-decoy`: OP_MSG hello and SCRAM capture.
  - `vnc-decoy`: RFB 3.8, VNC auth challenge capture.
  - `smtp-decoy`: EHLO/AUTH capture, open-relay probe detection, never relays.
  - `http-app-decoy`: a configurable generic web-app login (persona templates: "VPN portal", "Jenkins-like CI", "HR portal", "Grafana-like dashboard"). Customer-supplied HTML templates are sandboxed: static assets only, form fields mapped to capture. **Never ship real vendors' logos or trademarks.** Templates are generic and the customer brands them.
- **Acceptance per decoy:** clean spec, fuzzed parsers, e2e test with a standard client tool, ATT&CK mapping, SIEM rule.

#### F-406 Cloud canaries minted in customer-owned accounts
- **Priority:** P2 · **Edition:** Enterprise · **Effort:** L · **Schema:** v20.
- **Why:** third-party canary keys can be fingerprinted offline from the account ID embedded in the key (TruffleHog detects them, Horizon3 documents evasion). Keys must come from the customer's own accounts and look like the customer's real keys.
- **Requirements:**
  1. AWS: in a customer-designated account (ideally one that also holds real resources), create IAM users or roles with **no permissions** (or a deny-all boundary) and access keys. Detect through CloudTrail via EventBridge → a lightweight forwarder (Lambda template shipped as CloudFormation/Terraform) that calls the Hub's ingest with a node key, or by polling CloudTrail Lake / S3. Cover the "safety net" case where `GetCallerIdentity`-style or error-only calls must still alert.
  2. Azure: service principal client secrets plus storage-account SAS tokens. Detection via Entra sign-in logs and Activity Log (Event Hub).
  3. GCP: service account keys. Detection via Cloud Audit Logs → Pub/Sub.
  4. Decoy resources: S3 buckets / storage containers with persona names and honey objects (read → alert via data-event logging).
  5. Distribution through the lure engine (F-404) and IaC repos (planting in CI variables is opt-in).
  6. Inventory: which key was planted where. A hit names the placement.
- **Acceptance:** using a planted AWS key (any call, including one that fails with AccessDenied) raises a critical event within 5 min. The key's account ID is the customer's own.

#### F-407 Beacon types (extends token-receiver)
- **Priority:** P2 · **Edition:** Core · **Effort:** M.
- **Add:**
  - Office document beacons (Word/Excel remote template or external image);
  - PDF beacons (where viewers fetch);
  - QR-code URL beacons;
  - email-address honeytokens (an inbox on a delegated domain via the token-receiver's SMTP listener, for phishing-list and data-leak detection);
  - SQL-dump beacons (fake rows containing beacon hostnames);
  - Git repo canaries (a fake private repo URL in config).
- **Requirement:** the beacon zone is customer-owned (delegated sub-zone). No shared vendor domain, for the same fingerprinting reason as F-406.

#### F-408 OT/ICS decoys (GCC energy and utilities)
- **Priority:** P2 · **Edition:** Enterprise · **Effort:** L.
- **Decoys:**
  - Modbus/TCP: read holding registers return persona values; write attempts are critical;
  - Siemens S7comm (S7-300/400 SZL reads);
  - DNP3 (outstation);
  - BACnet/IP;
  - EtherNet/IP (CIP identity).
- **Requirements:**
  1. Read-only emulation. No physical process is ever touched.
  2. Strict rate limits.
  3. ATT&CK for ICS technique mappings (separate matrix in the ATT&CK view).
- **Acceptance:** a Modbus scanner and an S7 info query each produce events mapped to ICS techniques.

#### F-409 Internet-facing sensor mode (scanner intelligence)
- **Priority:** P3 · **Edition:** Enterprise · **Effort:** M.
- **Requirements:**
  1. Run selected decoys on public IPs with an "external" profile: aggressive rate limits, no credential capture by default (privacy), and classification into mass scanner (known research scanners list), opportunistic exploit, or **targeted** (matches the organisation's domains, SNI, Host header or brand strings).
  2. Only "targeted" raises incidents. The rest feeds TI (F-304).

#### F-410 Fake merchant portal and payment API decoy (fintech)
- **Priority:** P2 · **Edition:** Enterprise · **Effort:** L.
- **Why:** merchant-portal abuse and API-key theft are top fintech threats. No generalist vendor ships this.
- **Requirements:**
  1. `merchant-portal-decoy`: a configurable merchant dashboard login (customer-branded template via F-405 `http-app-decoy`), a password-reset flow (captures the targeted email), an API-key page behind login (never reachable), and 2FA prompt emulation.
  2. `payment-api-decoy`: a REST API mimicking a generic PSP shape: `/v1/payments`, `/v1/refunds`, `/v1/merchants/{id}`, `/v1/cards/bin/{bin}`. Responses come from persona fixtures. **Honey API keys** (format configurable to match the customer's real key format) planted via lures (F-404). Any call with a honey key → critical `payment_api_honey_key_used`.
  3. **BIN-enumeration and card-testing detection:** many `/cards/bin` lookups or many small authorisations with distinct PANs from one source → `card_testing_suspected` (T1110-like behaviour; also a custom fintech technique tag `FIN-CARDTEST`).
  4. PAN handling: the decoy MUST NOT store PANs. It records only BIN (first 6/8), last 4, Luhn validity, and a keyed hash (HMAC with a key sealed per node) for repeat detection. That keeps the decoy out of PCI DSS scope (document the rationale in `docs/clean-specs/payment-api-decoy.md`, to be confirmed with the QSA).
  5. Fixture data uses **only** card-network test PANs and test BIN ranges.
- **Acceptance:** a card-testing script with 50 distinct test PANs from one IP raises one incident with `card_testing_suspected`. No PAN is stored in clear anywhere (DB, logs, SIEM, captures), verified by a test that greps all outputs.

#### F-411 ISO 8583 listener decoy
- **Priority:** P3 · **Edition:** Sovereign/Enterprise · **Effort:** L.
- **Requirements:**
  1. A TCP listener that parses ISO 8583 (1987/1993 bitmaps, configurable length-header variants).
  2. Logs MTI, processing code, STAN and terminal ID. Same PAN rules as F-410.
  3. Responds with a declined `0110`/`0210`, or not at all (configurable).
  4. Detects attackers who reached the payment network segment and are probing switches.
- **Acceptance:** a jPOS-style client sending an `0100` gets an event with MTI and BIN only.

#### F-412 HSM command-port decoy
- **Priority:** P3 · **Edition:** Sovereign · **Effort:** M.
- **Requirements:**
  1. A TCP listener emulating a **generic** payment HSM host-command framing (length prefix + header + 2-char command code).
  2. Logs command codes. Returns a generic error code to everything. Never implements cryptography.
  3. Any connection from a non-allow-listed host is critical.
  4. Vendor-specific command sets only from public documentation, and only where licensing allows. Otherwise stay generic.
- **Acceptance:** a connection plus a diagnostic command to the decoy raises a critical event.

#### F-413 Honey records for data-exfiltration detection
- **Priority:** P2 · **Edition:** Enterprise · **Effort:** M.
- **Requirements:**
  1. Generate honey records for insertion into real customer databases or data warehouses (by the customer's DBA, from generated SQL/CSV): fake customers with beacon emails (F-407), honey phone numbers (optional provider), and Luhn-valid **test-range** card numbers.
  2. Detection: a beacon email or domain receives mail; a honey value appears in DLP (Falcon Data Protection custom pattern export), WAF logs (F5 ASM data-guard custom pattern), or SIEM (shipped search).
  3. Export DLP/WAF patterns: RE2-compatible regex plus exact-match hashes.
- **Acceptance:** emailing a honey customer's address raises `honey_record_used`. The exported Falcon Data Protection pattern matches the honey values and nothing else in a test corpus.

#### F-414 AI and agent deception
- **Priority:** P2 · **Edition:** Enterprise · **Effort:** M.
- **Requirements:**
  1. `llm-api-decoy`: an OpenAI-compatible endpoint (`/v1/models`, `/v1/chat/completions`, `/v1/embeddings`) with honey API keys. Returns canned or declined responses. **Never forwards to a real model.** Logs prompts (truncated to 4 KiB, sealed). Detects prompt-injection markers and jailbreak patterns as tags.
  2. `mcp-server-decoy`: a Model Context Protocol server (streamable HTTP + stdio wrapper for planting) advertising attractive tools (`get_customer_record`, `run_sql`, `read_secrets`). Any tool call → critical event with the calling client info.
  3. RAG honey documents: generate documents with unique canary strings and beacon URLs for vector stores and knowledge bases. Detection when the canary appears in outbound traffic (WAF/DLP patterns), when a beacon is hit, or when it's queried through a monitored API.
  4. Honey **non-human identities**: agent API keys and OAuth client credentials planted in agent configs (`.cursor/mcp.json`-style, `.env`), detected via F-406/F-410 mechanisms.
- **Acceptance:** an agent using a planted MCP config that calls a decoy tool raises an event. The honey LLM key used against the decoy endpoint raises an event.

#### F-415 Persona and realism engine (extends WP-2C / Q81)
- **Priority:** P1 · **Edition:** Core · **Effort:** M.
- **Requirements:**
  1. Per-installation and per-node persona seed. Banner, hostname, certificate subject, OS fingerprint hints (TCP options where feasible), file names and directory contents are derived from the seed and from customer naming conventions learned by `discover` and the AD connector (e.g. `HQ-SRV-FIN-03`).
  2. Stable certificates per decoy (generate once, seal, reuse; rotate yearly). The ROADMAP §6 item 7 notes that regenerating per restart is a tell.
  3. "Fingerprint self-test": a CI job and an admin action that run common honeypot-detection heuristics against each decoy and report tells.
  4. No string in any decoy response may contain `doppel`, `truesignal`, `honeypot`, `decoy` or `canary`. Enforce with a test that scans responses in e2e.
- **Acceptance:** two installations produce different banners and certificates for the same decoy type. The self-test reports no known tells for shipped decoys.

---

### E5 Fleet, deployment and network placement

#### F-501 IP-per-decoy and VLAN projection
- **Priority:** P1 · **Edition:** Enterprise · **Effort:** L · **Schema:** v21 · **Depends on:** manifest v3 extension.
- **Why:** today every decoy uses `network_mode: host`, so all decoys on a node share one IP. An attacker sees one host with SSH, PostgreSQL, LDAP, SNMP and a router login together, which is both implausible and easy to fingerprint. Enterprises need "a fake DB server in VLAN 30 and a fake DC in VLAN 10" from one appliance.
- **Requirements:**
  1. Manifest v3: add an optional `runtime.network` block: `mode: host | macvlan | ipvlan_l2`, `parent_interface` (may be an 802.1Q sub-interface the CLI creates, e.g. `eth1.30`), `address: dhcp | static`, `ip`, `prefix`, `gateway`, `mac: random_oui(<vendor OUI list>) | fixed`.
  2. The compose compiler (`hub/internal/compose`) emits a per-sensor macvlan/ipvlan network. `compose-guard.sh` is updated so hardening rules still hold: no privileged containers, and only `NET_BIND_SERVICE` where needed.
  3. CLI: `doppel net plan|apply` creates and removes VLAN sub-interfaces with idempotent, reversible changes. It needs root only for interface creation, and shows a dry-run first.
  4. DHCP: a lease client per decoy MAC (a sidecar or the CLI agent), with a hostname option set from the persona, so decoys show up in IPAM and DNS like real hosts.
  5. Multiple sensors can share one decoy "host" (one IP) to build coherent personas, e.g. a fake DB server = SSH + PostgreSQL + SMB.
  6. UI: a "Decoy hosts" concept on the node page (IP, MAC, VLAN, persona, sensors).
  7. Docker Desktop / macOS: unsupported. The CLI refuses with a clear message.
- **Security:** document in `THREATMODEL.md` that the node is multi-homed into sensitive VLANs. The node itself MUST NOT route between VLANs (`ip_forward=0` asserted by the CLI). Host firewall rules are shipped.
- **Acceptance:** one node projects 3 decoy hosts in 3 VLANs with distinct IPs and MACs obtained by DHCP. An nmap from each VLAN sees only that VLAN's decoy host.

#### F-502 Node groups, sites and policies
- **Priority:** P1 · **Edition:** Enterprise · **Effort:** M · **Schema:** v22.
- **Requirements:**
  1. Node groups (hierarchical: site → zone, e.g. `HQ-DC/Prod/CDE`). Each node belongs to exactly one leaf group.
  2. **Deployment policies:** a named set of sensor configurations, persona settings and lure settings applied to a group. Nodes inherit them, and per-node overrides are explicit and visible.
  3. Policy versioning, with a diff view before apply and staged rollout (F-504).
  4. Groups are the scope unit for RBAC (F-102), notifications (F-301) and reports.
- **Acceptance:** assigning policy "CDE-standard" to group CDE deploys the same decoys to its 10 nodes. Changing the policy shows a diff and rolls out.

#### F-503 Bulk enrolment and node bootstrap
- **Priority:** P1 · **Edition:** Core · **Effort:** M.
- **Requirements:**
  1. Enrolment tokens with target group, max uses, expiry (≤ 7 days) and an optional source CIDR. A node exchanges the token for a unique node key on first contact. Token values are never logged.
  2. One-line install: `curl … | sh` is **not** acceptable. Provide a signed installer (cosign-verified tarball and deb/rpm packages), with the token passed via a file or env.
  3. Cloud-init and Ansible role examples. vCD/vSphere OVA (F-506).
  4. Node-key rotation per group, and a revoke-all for an incident.
- **Acceptance:** 50 VMs enrol with one token into group `Office`, and the token stops working after its uses run out.

#### F-504 Upgrade orchestration
- **Priority:** P1 · **Edition:** Enterprise · **Effort:** M.
- **Requirements:**
  1. Sensor and CLI upgrades are rolled out by group with a canary percentage, a health gate (sensors heartbeating and fire drill passing, F-802), and automatic rollback to the previous digest on gate failure.
  2. A maintenance window per group.
  3. The Hub-version compatibility matrix is enforced (refuse sensor versions needing a newer Hub contract).
- **Acceptance:** a deliberately broken sensor image fails the canary gate on 10 % of nodes and is rolled back automatically. The rest never receive it.

#### F-505 Node host facts and health
- **Priority:** P1 · **Edition:** Core · **Effort:** S · **Schema:** v23.
- **Requirements:**
  1. The CLI agent reports OS, kernel, arch, CLI version, Docker/containerd version, `docker_desktop` flag, CPU/memory/disk, clock skew vs Hub, container restart counts, and interface list (for F-501).
  2. Facts are shown on the node page.
  3. Alerts on disk > 90 %, clock skew > 30 s, and Docker version below the minimum.
- **Acceptance:** the node page shows facts, and a clock skew injected in a test raises a warning.

#### F-506 Platforms: arm64, Kubernetes, appliances, Windows
- **Priority:** P1 (arm64, K8s), P2 (OVA), P3 (Windows) · **Edition:** Core/Enterprise · **Effort:** M each.
- **Requirements:**
  1. **arm64:** multi-arch images (`linux/amd64,linux/arm64`) for the Hub and every sensor. Remove the `TS_ALLOW_NON_AMD64` requirement once signed multi-arch digests are published.
  2. **Kubernetes:**
     - a Helm chart for the Hub (PostgreSQL mode, F-601);
     - a node mode as a DaemonSet or per-decoy Deployments with Multus macvlan for IP-per-decoy, PodSecurity `restricted` except where the decoy needs `NET_BIND_SERVICE`, NetworkPolicies shipped;
     - an operator (CRD `DecoyPolicy`) as P2.
  3. **Appliance:** a hardened OVA (Ubuntu LTS minimal or Flatcar) with the CLI preinstalled and a first-boot wizard (console TUI) for IP and enrolment token. Built for vSphere and **vCloud Director** (common with MEA hosting providers). Signed images and a documented hardening baseline (CIS level 1).
  4. **Windows:** a Windows service running the SMB/RDP decoys natively for maximum realism (P3). This needs a separate threat-model section.
- **Acceptance:** the Helm install passes `helm test`. The OVA boots to an enrolled node in under 10 minutes with only IP and token entered.

#### F-507 Fleet-wide discovery and placement recommendations
- **Priority:** P2 · **Edition:** Enterprise · **Effort:** M · **Depends on:** F-303, F-501, F-502.
- **Requirements:**
  1. Extend `doppel discover` from a single-host planner to a group-level recommender using asset inventory and segment data.
  2. Per segment, propose decoys that blend in: dominant OS and services, naming convention, and gaps such as "VLAN 30 has 40 DB servers and no DB decoy".
  3. Read-only. Apply goes through policies (F-502) with approval.
- **Acceptance:** with inventory loaded, the recommender proposes at least one decoy per segment that has none, with reasons.

---

### E6 Platform: scale, availability, observability, sovereignty

#### F-601 PostgreSQL backend
- **Priority:** P1 · **Edition:** Enterprise · **Effort:** L · **Depends on:** all schema features use portable SQL from now on.
- **Requirements:**
  1. Introduce a store dialect abstraction in `hub/internal/store`. SQLite stays the default for Core.
  2. PostgreSQL 15+ support, with migrations kept in parallel dialect files under one version number.
  3. `events` partitioned by month (declarative partitioning). Retention drops partitions.
  4. A connection pool, statement timeouts, and TLS to the database (`sslmode=verify-full`).
  5. A migration tool: `doppel-hub migrate-store --from sqlite:<path> --to postgres://…` (offline, verified row counts and checksums).
  6. CI runs the full test suite against both dialects.
- **Acceptance:** all tests pass on both. NFR-1 is met on PostgreSQL.

#### F-602 High availability
- **Priority:** P1 · **Edition:** Enterprise · **Effort:** L · **Depends on:** F-601.
- **Requirements:**
  1. Stateless Hub replicas behind a load balancer. Sessions live in the DB (already the case).
  2. The live WebSocket feed fans out across replicas via PostgreSQL `LISTEN/NOTIFY`.
  3. Leader election (PostgreSQL advisory lock) for singleton jobs: catalogue refresh, retention, liveness evaluation, scheduled reports, connector syncs.
  4. Outbound queues use `SELECT … FOR UPDATE SKIP LOCKED`.
  5. Reference architectures:
     - two replicas + PostgreSQL primary/standby (Patroni or managed) in one site;
     - an active/passive pair across prod and DR with streaming replication and a documented failover runbook (RPO ≤ 5 min).
  6. Chaos test in CI: kill the leader mid-ingest; no event loss (NFR-7), and singleton jobs resume on the new leader within 30 s.
- **Acceptance:** NFR-6 and NFR-7 are demonstrated by the chaos test.

#### F-603 Ingest durability and backpressure
- **Priority:** P0 · **Edition:** all · **Effort:** S.
- **Requirements:**
  1. Confirm and document that the Hub fsyncs before acknowledging an event batch (SQLite WAL with `synchronous=FULL` for ingest, or an equivalent PostgreSQL commit).
  2. Under overload, return `429` with `Retry-After`. The SDK already buffers and retries; verify bounded memory and expose `dropped_events` (exists in heartbeat) on the node page and in metrics.
- **Acceptance:** `kill -9` of the Hub during a burst loses no acknowledged event (test counts SDK-acknowledged vs stored).

#### F-604 Retention, archive and legal hold
- **Priority:** P1 · **Edition:** Core (retention), Enterprise (archive, hold) · **Effort:** M.
- **Requirements:**
  1. Retention per data class (events, incidents, audit, captures, status history), with PCI defaults: events ≥ 12 months, of which 3 months are immediately available.
  2. Archive tier: export closed partitions to **S3-compatible object storage** (on-prem MinIO, Ceph, or cloud), as Parquet or NDJSON plus a manifest, with optional object lock (WORM). Searchable on demand by re-hydrating a range.
  3. **Legal hold** on an incident or time range suspends deletion, is audited, and requires dual control to lift.
- **Acceptance:** a held incident survives a retention run. Archived months can be re-hydrated and searched.

#### F-605 Key management: BYOK and HSM
- **Priority:** P1 · **Edition:** Enterprise (cloud KMS / Vault), Sovereign (PKCS#11 HSM) · **Effort:** M.
- **Requirements:**
  1. A KEK provider interface in `hub/internal/seal`. Providers:
     - file (exists);
     - **HashiCorp Vault Transit**;
     - **AWS KMS**;
     - **Azure Key Vault / Managed HSM**;
     - **GCP KMS**;
     - **PKCS#11** (Thales Luna, Entrust nShield, Utimaco): wrap and unwrap of the DEK only. The KEK never leaves the HSM.
  2. Rotation without downtime (exists for file; extend). Provider health is shown in Settings → System and in metrics.
  3. Envelope encryption for archives (F-604) and evidence bundles (F-204).
- **Acceptance:** with PKCS#11 (SoftHSM2 in CI), the Hub starts, seals and unseals, and refuses to start when the HSM is unreachable (fail closed), with a clear error.

#### F-606 Data residency controls
- **Priority:** P1 · **Edition:** Enterprise · **Effort:** S.
- **Requirements:**
  1. A "Residency mode" setting that disables every feature which sends data out of the deployment by default: update check, catalogue from the public registry (use a mirror), GeoIP auto-update, and cloud connectors unless explicitly enabled.
  2. A per-destination egress allow-list (hostnames/CIDRs) enforced centrally in the HTTP client used by all connectors.
  3. An egress report page listing every configured outbound destination, its data class and its region.
- **Acceptance:** in residency mode with an empty allow-list, the Hub makes zero outbound connections (verified in e2e with a network namespace that logs egress attempts).

#### F-607 Air-gapped / offline operation
- **Priority:** P1 · **Edition:** Sovereign · **Effort:** M · **Depends on:** F-606.
- **Requirements:**
  1. An offline bundle: one signed archive with Hub image, CLI, all sensor images (multi-arch), catalogue manifests, Sigstore trusted root and signatures (verifiable offline with a bundled `cosign verify --offline` flow), GeoIP DB, and docs.
  2. `doppel-hub registry import <bundle>` loads it into a local registry (the `ts-registry` tool exists) and verifies every signature before import.
  3. Offline licence (F-1201).
  4. An update procedure documented as "import newer bundle → staged rollout (F-504)".
- **Acceptance:** a full install and upgrade in a network namespace without internet, with every signature verified.

#### F-608 Load, soak and chaos testing harness
- **Priority:** P1 · **Edition:** n/a · **Effort:** M.
- **Requirements:**
  1. `scripts/load/`: a synthetic node simulator (thousands of fake nodes and sensors over the real node API) that measures NFR-1..5.
  2. A 24-hour soak in nightly CI (reduced scale), with results published as artifacts.
  3. Chaos scenarios: DB failover, SIEM endpoint down, notification endpoint slow, disk full.
- **Acceptance:** a report showing every NFR target met, or the measured gap.

#### F-609 Observability for operators
- **Priority:** P1 · **Edition:** Core · **Effort:** S · **Depends on:** F-003.
- **Requirements:**
  1. OpenTelemetry traces (OTLP exporter, off by default) for HTTP, ingest pipeline, SIEM and notification sends.
  2. Structured logs with `trace_id`.
  3. A Settings → System "Health" page aggregating component status: DB, KEK provider, queues, connectors, licence, certificate expiry (TLS, SAML signing).
  4. Alert 30 days and again 7 days before any certificate or token in use expires.

---

### E7 Multi-tenancy and MSSP

#### F-701 Tenants
- **Priority:** P2 · **Edition:** MSSP · **Effort:** XL · **Depends on:** F-601, F-102.
- **Requirements:**
  1. A `tenant_id` on every tenant-owned table, enforced in the store layer: queries are built through a tenant-scoped repository and raw table access is forbidden by a lint test. On PostgreSQL also use row-level security as defence in depth.
  2. A per-tenant DEK under the KEK provider (F-605). Optionally a per-tenant KEK for "bring your own key" tenants.
  3. Per-tenant settings: SSO, SIEM outputs, notifications, retention, residency, branding, regimes.
  4. Node keys are tenant-bound. The node API rejects cross-tenant sensor ids.
  5. Isolation test suite: every API route × two tenants, asserting zero leakage, including exports, the live feed, analytics, TAXII and the audit log.
- **Acceptance:** the isolation suite passes, and a tenant admin can't enumerate other tenants by any route.

#### F-702 MSSP console
- **Priority:** P2 · **Edition:** MSSP · **Effort:** L · **Depends on:** F-701.
- **Requirements:**
  1. Cross-tenant views for MSSP analysts (an explicit MSSP role): incident queue across tenants, fleet health, SLA board.
  2. Tenant onboarding wizard.
  3. Delegated access with customer approval: tenants can see and revoke MSSP access, which is audited in both tenants.
- **Acceptance:** an MSSP analyst triages incidents for 3 tenants from one queue. Tenant A sees MSSP actions in its audit log.

#### F-703 White-labelling
- **Priority:** P3 · **Edition:** MSSP · **Effort:** S.
- **Requirements:** logo, product name, colours (theme tokens), login page text, report templates and email sender per tenant or MSSP. CSP-compatible (no inline styles: generated CSS file per tenant).

#### F-704 Usage metering
- **Priority:** P2 · **Edition:** MSSP · **Effort:** S.
- **Requirements:** daily counters per tenant (nodes, active decoys, events, storage). Export CSV/API for billing. Feeds licence checks (F-1201).

---

### E8 Analytics, assurance and compliance reporting

#### F-801 Reporting engine (scheduled, server-rendered, localised)
- **Priority:** P1 · **Edition:** Core (basic), Enterprise (scheduled + templates) · **Effort:** M.
- **Requirements:**
  1. Server-side PDF rendering (headless engine bundled in a separate container, or a Go PDF library), because the UI's "Print / Save PDF" depends on the browser.
  2. Templates: Executive (monthly), SOC operations (weekly: MTTA/MTTR, incidents by disposition, top sources excluding drills), Coverage (F-804), Compliance evidence (F-803), Incident report (F-204/F-205).
  3. Scheduled delivery by email (F-301) or to an S3 bucket. Arabic, English and French templates with RTL layout (F-901).
  4. Every number in a report is reproducible: the report appendix lists the API query parameters used.
- **Acceptance:** a monthly executive PDF in Arabic and English is delivered by email, and its numbers match the UI for the same window with drills excluded.

#### F-802 Detection-pipeline assurance (continuous control validation)
- **Priority:** P2 · **Edition:** Enterprise · **Effort:** M · **Depends on:** F-001, F-302.
- **Why:** DORA and NIS2 ask for effectiveness testing, and PCI 10.7.2 asks for detection of control failures. A drill that reaches the Hub proves only half the path. Assurance proves that **the SIEM rule fired**.
- **Requirements:**
  1. Scheduled drills per group (default daily, randomised minute).
  2. For each drill, the Hub verifies:
     - (a) the event was stored;
     - (b) each SIEM output acknowledged it;
     - (c) optionally, **the downstream detection fired**, by querying the SIEM API for the drill's unique id: Elastic `_search` on the alerts index, LogScale query job, Sentinel KQL via the Log Analytics API, Splunk REST search. This uses read-only, sealed credentials.
  3. Results: a per-sensor, per-output, per-rule pass/fail matrix, trends, and an alert on failure (F-301). This produces the "drill success rate" KPI.
  4. Evidence export for auditors (F-803).
- **Acceptance:** disabling the Elastic drill rule makes the next assurance run fail with "SIEM detection missing" for Elastic only.

#### F-803 Compliance evidence packs
- **Priority:** P2 · **Edition:** Enterprise · **Effort:** M · **Depends on:** F-105, F-802, F-604.
- **Requirements:**
  1. Control mappings shipped as versioned YAML in `docs/compliance/`, each with a source reference and a `verified_on` date:
     - PCI DSS v4.0.1: 8.2.1, 8.4.2, 10.2.1.x, 10.4.1, 10.5.1, 10.7.2, 11.5.1, 12.10.x;
     - DORA: ICT risk management detection, Art. 17–19 incident management and reporting, TLPT support;
     - NIS2 Art. 21(2)(b) incident handling and (f) effectiveness assessment;
     - SOC 2 CC6.1, CC7.2, CC7.3, CC7.4;
     - ISO/IEC 27001:2022 A.8.16 monitoring activities, A.5.24–A.5.28 incident management;
     - CBE EG-FinCSF (cyber-defence domain);
     - SAMA CSF;
     - NCA ECC-2:2024;
     - UAE IA Standard v2.1.
     Regional framework mappings are marked "to be verified against the primary text" until the owner confirms them.
  2. A monthly evidence pack: per control, the Doppel evidence (drill success matrix, sensor uptime, liveness alerts and response times, MFA/SSO enforcement state, audit chain verification result, retention configuration, incident statistics). Signed like F-204.
- **Acceptance:** a PCI evidence pack for a month is generated, signed and verifiable, and every claim links to an artifact.

#### F-804 Deception coverage map
- **Priority:** P2 · **Edition:** Enterprise · **Effort:** M · **Depends on:** F-303, F-502, F-501.
- **Requirements:**
  1. Per segment / node group: decoy count, decoy-to-real-host ratio, services represented vs real services present, lure density on endpoints (F-404), and identity coverage (AD honey objects per OU).
  2. ATT&CK coverage: techniques detectable by deployed content vs a target technique set (a customer-selected threat profile, e.g. "ransomware affiliate", "carding crew", "insider").
  3. A blind-spot list with recommended actions (link to F-507).
- **Acceptance:** the map shows each segment with a coverage score and at least one actionable gap where coverage is missing.

#### F-805 Analytics correctness and performance
- **Priority:** P1 · **Edition:** all · **Effort:** M · **Depends on:** F-001, F-002.
- **Requirements:**
  1. Analytics computed from incremental aggregates (rollup tables per hour/day per source_ip, sensor, technique), not full scans.
  2. Time zones: user-selectable display zone, with server timestamps in UTC. The report shows its zone.
  3. Trend comparisons (vs previous period) on dashboard tiles.
  4. MTTD (first event → incident ack), MTTA and MTTR.
  5. A golden-dataset regression test: a fixture event stream with known expected outputs for every projection.
- **Acceptance:** the golden test passes, and dashboard p95 ≤ 1 s at 10 M events.

#### F-806 Red-team / TLPT engagement mode
- **Priority:** P2 · **Edition:** Enterprise · **Effort:** S.
- **Requirements:**
  1. Declare an engagement with: name, start/end, tester source IPs/CIDRs and identities, and white-team contacts.
  2. During the engagement, matching events still raise incidents (deception must be tested), but they're tagged `engagement:<name>`, routed to the white-team notification route only, and auto-dispositioned `true_positive_authorised` when closed.
  3. An end-of-engagement report: what the testers touched, time to first detection, and decoys not discovered.
  4. Doppel itself MUST NOT disclose decoy locations to the engagement view before the engagement ends (control-team only).
- **Acceptance:** a TLPT run produces a detection report without paging the SOC on-call.

---

### E9 UX, localisation and accessibility

#### F-901 Internationalisation: Arabic (RTL), French, English
- **Priority:** P1 · **Edition:** Core · **Effort:** M.
- **Requirements:**
  1. Externalise all UI strings (`ui/src/i18n/<locale>.json`) with an ICU message format library (permissive licence, small).
  2. RTL layout via CSS logical properties (`margin-inline-start`, etc.) throughout `ui/src/styles.css`, and `dir="rtl"` on the root for `ar`.
  3. Charts and the ATT&CK matrix mirror correctly or stay LTR where semantics require (time axes stay LTR; document the choice).
  4. Number, date and time-zone formatting via `Intl` with the user's locale and time zone. Arabic-Indic digits are optional (user setting).
  5. Reports (F-801) and notification templates (F-301) are localised.
  6. A CI check fails if any UI string isn't in the catalogue.
  7. Professional translation required for `ar` and `fr`. Machine translation is not acceptable for release.
- **Acceptance:** the full UI and reports in Arabic, with no layout breakage in the Playwright suite run under `ar`.

#### F-902 Onboarding and guided deployment
- **Priority:** P1 · **Edition:** Core · **Effort:** M.
- **Requirements:**
  1. A first-run wizard: secure the admin (MFA), configure SSO, connect SIEM (send test), configure a notification route (send test), create a node group, generate an enrolment token, deploy a starter policy, run the first drill, and confirm the event in the SIEM.
  2. A checklist widget on the dashboard until all steps are done.
  3. An empty state on every page that says what will appear there and how to get it.
- **Acceptance:** a new admin reaches "first drill confirmed in SIEM" without reading docs, in a usability test with 3 people.

#### F-903 Accessibility (WCAG 2.2 AA)
- **Priority:** P1 · **Edition:** all · **Effort:** M.
- **Requirements:**
  1. Keyboard navigation for all pages and dialogs (focus trap and restore).
  2. Visible focus. Colour contrast ≥ 4.5:1 in both themes.
  3. Severity conveyed by text plus colour.
  4. Charts have data tables.
  5. axe-core run in the Playwright suite with zero serious violations.

#### F-904 Global search and investigation pivots
- **Priority:** P2 · **Edition:** Core · **Effort:** M.
- **Requirements:**
  1. A search bar across events, incidents, nodes, sensors, honeytokens, beacons and assets (IP, CIDR, hostname, username, token id).
  2. One-click pivots from any IP, user or host to "everything about this" across Doppel, plus deep links into the configured SIEM (Elastic Discover / LogScale search URL templates) and EDR console (Falcon host page) for the same entity.

---

### E10 Privacy and employee-monitoring safeguards

#### F-1001 Privacy mode (pseudonymisation with four-eyes reveal)
- **Priority:** P2 · **Edition:** Enterprise · **Effort:** M · **Depends on:** F-106, F-102.
- **Why:** in several EU states (e.g. Germany, Austria, the Netherlands), detecting **employee** activity is subject to works-council agreements and GDPR proportionality. Pseudonymisation by default plus controlled re-identification is often the condition for approval. This also helps under the UAE and KSA PDPLs.
- **Requirements:**
  1. When enabled, internal identities are pseudonymised at storage and display time: usernames, internal hostnames resolved from assets, and internal source IPs (optional). The pseudonym is `HMAC(tenant key, value)` rendered as e.g. `user-7f3a`. External IPs are not pseudonymised.
  2. SIEM output follows the same mode (configurable per output: some SIEMs are themselves governed).
  3. Re-identification needs the permission `privacy.depseudonymise` + step-up MFA + dual control (F-106) + a justification text. It's scoped to one incident, audited and time-limited (e.g. 72 h).
  4. A data-protection officer (DPO) role can read the re-identification log.
  5. Capture minimisation: the default password capture policy is "hash only" (keyed hash for reuse detection), with clear-text capture an explicit per-sensor opt-in that needs justification.
- **Acceptance:** with privacy mode on, an analyst sees `user-7f3a` on an incident. Reveal requires a second approver. The DPO sees the reveal log.

#### F-1002 Data subject and retention tooling
- **Priority:** P2 · **Edition:** Enterprise · **Effort:** S.
- **Requirements:**
  1. Search all stored data for an identifier, export it, and delete it (excluding data under legal hold, F-604). Every step is audited.
  2. A Record of Processing Activities (ROPA) template and DPIA template in `docs/privacy/`.

#### F-1003 Lawful-deception guidance pack
- **Priority:** P3 · **Edition:** all · **Effort:** S (docs).
- **Requirements:** document templates covering deception policy, works-council briefing, acceptable-use notice wording, legal review checklist for internet-facing decoys, and data minimisation defaults. Docs only, reviewed by counsel before publication.

---

### E11 Product security assurance

#### F-1101 Secure development lifecycle evidence
- **Priority:** P1 · **Effort:** M.
- **Requirements:**
  1. Keep CodeQL, add Semgrep with custom rules (SQL built with string concatenation; routes without permissions; outbound HTTP not using the guarded client).
  2. govulncheck and npm audit as gates.
  3. A dependency review policy.
  4. A signed-commit requirement on `main`.
  5. Branch protection documented.
  6. `SECURITY.md` with a vulnerability disclosure policy (VDP) and PGP key / security contact.
  7. CVE issuance process (GitHub Security Advisories).

#### F-1102 Independent penetration test and fuzzing programme
- **Priority:** P1 · **Effort:** M (vendor).
- **Requirements:**
  1. An annual third-party pentest of the Hub (web, API, node API), CLI and sensors, with a summary letter for customers.
  2. Continuous fuzzing of all protocol parsers (OSS-Fuzz-style in CI nightly with corpus persistence).
  3. A decoy escape review: a container breakout attempt per sensor, documented.

#### F-1103 Hardening guides and benchmarks
- **Priority:** P1 · **Effort:** S.
- **Requirements:** a Hub hardening guide (CIS-style checklist), a node hardening guide, an F5/nginx front-door guide (in H1), and `doppel-hub doctor`, which checks the running configuration against the guide and prints findings.

#### F-1104 FIPS 140-3 build
- **Priority:** P3 · **Edition:** Sovereign · **Effort:** M.
- **Requirements:** a build variant using Go's FIPS 140-3 module mode, with algorithms restricted accordingly (no X25519 where FIPS disallows; argon2id → PBKDF2-HMAC-SHA-256 for FIPS mode, with documented trade-offs). Separate images tagged `-fips`.

---

### E12 Licensing, editions and commercial plumbing

#### F-1201 Signed licences and edition gating
- **Priority:** P1 · **Effort:** M.
- **Requirements:**
  1. The licence is a signed JSON (Ed25519, vendor public key embedded) with customer, edition, limits (nodes, decoys, tenants), features and expiry.
  2. Works offline. No phone-home is required.
  3. Grace behaviour: when the licence expires or limits are exceeded, the Hub **never stops detecting**. It shows banners, blocks only config growth (adding nodes or decoys), and keeps ingest, SIEM and notifications working. A security product must fail safe.
  4. Licence status appears on Settings → System and in metrics.
- **Acceptance:** an expired licence keeps all detection running and blocks adding a node with a clear message.

#### F-1202 Trial and demo mode
- **Priority:** P2 · **Effort:** S.
- **Requirements:** a 30-day trial licence with all features at small limits. The existing demo simulator (WP-2C) is reachable from the UI in trial mode only, and its data is clearly labelled and isolated (a demo tenant or a `demo` flag excluded from reports).

#### F-1203 Opt-in product telemetry
- **Priority:** P3 · **Effort:** S.
- **Requirements:** anonymous, opt-in, aggregate-only (version, counts, feature usage). Disabled in residency mode (F-606). The full payload is viewable before sending.

---

### E13 API and extensibility

#### F-1301 Public API contract and versioning
- **Priority:** P1 · **Effort:** M.
- **Requirements:**
  1. `docs/openapi.yaml` is complete and validated in CI against the routes (exists for drift) **and** against responses (contract tests).
  2. API versioning policy: `/api/v3` stable, deprecations announced in two minor releases, `Deprecation` and `Sunset` headers.
  3. Pagination, filtering and sorting conventions are consistent across list endpoints.
  4. Idempotency keys on POSTs that create objects.
  5. Generated clients for Python and Go published with releases.

#### F-1302 Terraform provider and configuration as code
- **Priority:** P2 · **Effort:** M · **Depends on:** F-104.
- **Requirements:**
  1. A Terraform provider (`doppel_node_group`, `doppel_policy`, `doppel_notification_route`, `doppel_siem_output`, `doppel_suppression`, `doppel_beacon`, `doppel_service_account`).
  2. Alternatively or additionally, a `doppel-hub config export|apply` YAML format for GitOps, with dry-run diff.
- **Acceptance:** a full environment is reproducible from code. Applying it twice produces no change.

#### F-1303 Third-party sensor ecosystem
- **Priority:** P3 · **Effort:** M.
- **Requirements:**
  1. Customers can sign their **own** sensors with their own Sigstore identity or a cosign key. The Hub trusts multiple signer identities, configured per catalogue source.
  2. An SDK guide and template (`sensors/template`, `sdk/python/template` exist).
  3. A catalogue UI shows the signer identity per manifest.
  4. Unsigned stays dev-only (no weakening of the current rule).
- **Acceptance:** a customer-built sensor signed with the customer's identity deploys in production mode. An unsigned one is refused.

---

## 6. Sequencing, dependencies and schema reservations

### 6.1 Phases

| Phase | Goal | Features |
|---|---|---|
| **P0: Pilot-ready** (≈ 4–6 weeks) | One internal site in production, SIEM as the system of record | F-001, F-002, F-003 (+H1, B1), F-004, F-005, F-101 OIDC (S1), F-603 |
| **P1: Sellable enterprise** (≈ 3–4 months) | First regulated customer | F-102, F-103, F-104, F-105, F-106, F-107, F-201, F-202, F-203, F-204, F-206, F-301, F-302, F-303, F-401, F-402, F-404, F-405, F-415, F-501, F-502, F-503, F-504, F-505, F-506 (arm64, K8s), F-601, F-602, F-604, F-605, F-606, F-607, F-608, F-609, F-801, F-805, F-901, F-902, F-903, F-1101, F-1102, F-1103, F-1201, F-1301 |
| **P2: EMEA differentiation** (≈ 2 quarters) | Win against SaaS incumbents on sovereignty, regulation and fintech | F-101 SAML/SCIM, F-205, F-304, F-305, F-403, F-406, F-407, F-408, F-410, F-413, F-414, F-506 (OVA), F-507, F-701, F-702, F-704, F-802, F-803, F-804, F-806, F-904, F-1001, F-1002, F-1202, F-1302 |
| **P3: Later** | | F-409, F-411, F-412, F-506 (Windows), F-703, F-1003, F-1104, F-1203, F-1303 |

### 6.2 Dependency graph (main edges)

```
F-001 ─┬─► F-201 ─► F-202 ─► F-205 ─► F-803
F-002 ─┘     │        └─► F-206
             ├─► F-305 (needs F-106)
             └─► F-802 (needs F-302) ─► F-803
S1/F-101 ─► F-102 ─► F-701 ─► F-702
F-104 ─► F-1302
F-303 ─► F-402, F-507, F-804
F-501 ─► F-507, F-804 ;  F-502 ─► F-504, F-102 scopes
F-601 ─► F-602, F-701
F-605 ─► F-607 ;  F-606 ─► F-607
F-404 ─► F-406, F-410, F-413, F-414 (distribution)
```

### 6.3 Schema version reservations

**Intended order, not fixed numbers.** Migrations are a gap-free linear list, so versions are assigned in merge order: each branch takes the next free version after rebasing on `origin/main` and renumbers on conflict. v5 is the intended slot for S1 (OIDC) per `docs/plan/ROADMAP.md`.

| v | Feature | v | Feature |
|---|---|---|---|
| 5 | S1 OIDC (existing plan) | 15 | F-205 regulatory clocks |
| 6 | F-001 drill flag | 16 | F-301 notification router |
| 7 | F-002 source normalisation | 17 | F-302 SIEM fan-out queues |
| 8 | F-101 SAML / SCIM | 18 | F-305 response actions |
| 9 | F-102 roles and scopes | 19 | F-404 lure inventory |
| 10 | F-104 API tokens | 20 | F-406 cloud canaries |
| 11 | F-105 audit log | 21 | F-501 decoy hosts / networks |
| 12 | F-106 approvals | 22 | F-502 node groups / policies |
| 13 | F-201 incidents | 23 | F-505 host facts |
| 14 | F-203 suppressions | 24+ | allocate in merge order |

Once F-601 lands, every migration needs a PostgreSQL twin under the same version.

### 6.4 Open questions to log before implementation (start at Q82)

- **Q82:** F-002, whether to backfill `source_ip` inside migration v7 or in a post-migration job. Default: a Go post-migration step, batched.
- **Q83:** F-205, the authoritative deadline texts for CBE, SAMA, NCA and UAE IA. Default: ship editable placeholders marked "not verified".
- **Q84:** F-410, QSA confirmation that storing BIN + last4 + HMAC keeps the decoy out of PCI scope. Default: no PAN storage at all until confirmed.
- **Q85:** F-501, macvlan vs ipvlan default per environment (VMware port groups often block multiple MACs per vNIC without promiscuous / forged-transmits). Default: ipvlan L2 on VMware, macvlan elsewhere, with a preflight check.
- **Q86:** F-1201, licence enforcement behaviour on expiry. Default: never stop detection (as specified).
- **Q87:** F-402, the minimum AD delegation needed for honey objects. Default: create/delete child user, computer and group objects in one OU, plus write SPN on objects in that OU only.

---

## 7. Definition of done (global)

A feature is done only when **all** of these are true:

1. The requirements in its section are implemented, and every MUST is tested.
2. All gates from §0.3 pass. Their output is in the branch description.
3. `docs/openapi.yaml`, `docs/audit-actions.md`, `docs/contract-v3.md` / `docs/manifest-v3.md` (if touched), `THREATMODEL.md` (new boundaries, egress, privileges), `QUESTIONS.md` (decisions) and `docs/operations.md` (operator steps) are updated.
4. The SIEM content packs (Elastic, LogScale, and others once F-302 lands) are updated for new triggers and fields.
5. The UI passes `npm run check`, Playwright, axe (F-903), and works in `ar` RTL once F-901 lands.
6. e2e (`scripts/e2e/real-docker.sh`) is extended with at least one assertion for the feature where it touches the runtime path.
7. No existing security check, test or assertion was weakened.
8. The PR body lists the schema version used, the acceptance checklist and gate results. The owner adds the §9 status-log line at merge time.

---

## 8. Sources

Market and vendor research (web, 2026-11-20). The numbers disagree between publishers. Vendor claims are unverified.

- Deception market size and regional split: [Future Market Insights](https://www.futuremarketinsights.com/reports/deception-technology-market), [Mordor Intelligence](https://www.mordorintelligence.com/industry-reports/deception-technology-market), [DataM Intelligence](https://www.datamintelligence.com/research-report/deception-technology-market), [Fact.MR](https://www.factmr.com/report/deception-technology-market), [Coherent Market Insights](https://www.coherentmarketinsights.com/industry-reports/deception-technology-market), [SNS Insider](https://www.snsinsider.com/reports/deception-technology-market-2866), [Credence Research](https://www.credenceresearch.com/report/deception-technology-market)
- Vendor landscape: [Expert Insights](https://expertinsights.com/network-security/best-deception-technology-companies), [Cybersecurity News](https://cybersecuritynews.com/best-deception-technology/), [CyberPress review](https://cyberpress.org/deception-technology-review/), [Tracebit vendor list](https://ai.tracebit.com/best-deception-vendors-2026), [East Bay Cyber](https://eastbaycyber.com/content/compare-best-deception-technology-platforms-2026/)
- Thinkst Canary pricing and integrations (unofficial): [G2](https://www.g2.com/products/canary/pricing), [Trapster comparison](https://trapster.cloud/en/blog/thinkst-canary-alternatives), [Grafana Labs on Canarytokens](https://grafana.com/blog/canary-tokens-learn-all-about-the-unsung-heroes-of-security-at-grafana-labs/), [XSOAR integration](https://xsoar.pan.dev/docs/reference/integrations/thinkst-canary)
- Zscaler GenAI deception: [Zscaler Deception product](https://www.zscaler.com/products-and-solutions/deception-technology), [Zscaler blog](https://www.zscaler.com/blogs/product-insights/prevent-ai-powered-cyberattacks-deception-technology), [HyperFRAME Research](https://hyperframeresearch.com/2025/11/17/zscaler-deception-ready-to-break-the-kill-chain-for-ai-orchestrated-attacks/)
- Acalvio identity deception and CrowdStrike integration: [CrowdStrike Store listing](https://store.crowdstrike.com/apps/acalvio-shadowplex-identity-security), [Acalvio honeytokens for CrowdStrike](https://acalvio.com/solutions/honeytokens-for-crowdstrike), [Acalvio ITDR launch](https://www.businesswire.com/news/home/20230209005130/en/Acalvio-Launches-Identity-Threat-Detection-and-Response-ITDR-Solution-Built-on-Active-Defense), [HackRead review](https://hackread.com/acalvio-shadowplex-review-preemptive-cybersecurity)
- Gartner trends (secondary): [Quartz on Gartner 2026 trends](https://qz.com/gartner-top-technology-trends-2026), [Silverfort on Hype Cycle for Digital Identity 2026](https://www.silverfort.com/blog/3-takeaways-from-the-2026-gartner-hype-cycle-for-digital-identity/), [Gartner AI agents prediction](https://www.gartner.com/en/newsroom/press-releases/2025-08-26-gartner-predicts-40-percent-of-enterprise-apps-will-feature-task-specific-ai-agents-by-2026-up-from-less-than-5-percent-in-2025)
- Canary key fingerprinting: [Thinkst safety net](https://blog.thinkst.com/2022/02/a-safety-net-for-aws-canarytokens.html), [Truffle Security canaries](https://trufflesecurity.com/canaries), [Horizon3 H3-2024-0035](https://docs.horizon3.ai/knowledge_base/weaknesses/H3-2024-0035/), [Tracebit on canary AWS credentials](https://tracebit.com/blog/deploying-effective-canary-aws-credentials), [Rhino Security Labs](https://rhinosecuritylabs.com/aws/aws-iam-enumeration-2-0-bypassing-cloudtrail-logging/)
- Other vendors: [Tracebit](https://ai.tracebit.com/), [Labyrinth vs Tracebit](https://sourceforge.net/software/compare/Labyrinth-Deception-Platform-vs-Tracebit/), [Guideflow list](https://www.guideflow.com/blog/deception-technology-software)
- DORA incident reporting: [EBA joint technical standards](https://www.eba.europa.eu/activities/single-rulebook/regulatory-activities/operational-resilience/joint-technical-standards-major-incident-reporting), [JC 2024 33 final report](https://www.esma.europa.eu/sites/default/files/2024-07/JC_2024-33_-_Final_report_on_the_draft_RTS_and_ITS_on_incident_reporting.pdf), [Morgan Lewis](https://morganlewis.com/blogs/sourcingatmorganlewis/2024/08/preparing-for-dora-esas-publish-incident-reporting-requirements), [Austrian FMA](https://www.fma.gv.at/en/dora-ict-related-incidents/)
- NIS2: [ENISA incident reporting infographic](https://enisa.europa.eu/topics/cybersecurity-education/awareness-campaigns/network-and-information-systems-directive-2-nis2/files/enisa_nis2_infogr05_incident-reporting.pdf), [Article 21 text (Prighter)](https://prighter.com/resources/laws/nis2/articles/article-21), [6clicks Article 21 measures](https://www.6clicks.com/resources/blog/the-ten-nis2-article-21-measures-and-who-owns-the-evidence-for-each)
- KSA: [ECC-2:2024 summary (Sandbox Security)](https://sandboxsecurity.ai/saudi-arabia-nca-updated-ecc-2-2024/), [Cre8 IT on ECC-2 evidence](https://createit.sa/insights/nca-essential-cybersecurity-controls-ecc-2024/), [Saudi compliance guide (SAMA)](https://agmadev.com/en/blogs/saudi-cyber-compliance-nca-ecc-pdpl-sama-guide), [Morgan Lewis on Saudi cloud residency](https://www.morganlewis.com/de/blogs/sourcingatmorganlewis/2026/03/saudi-arabia-cloud-compliance-part-1-data-residency-and-contractual-expectations)
- UAE / GCC data: [UAE IA Standard summary](https://massivegrid.com/blog/uae-ia-standard/), [Clyde & Co ME privacy landscape](https://www.clydeco.com/en/insights/2025/02/data-protection-privacy-landscape-in-me), [CMS ME TMT 2025 review](https://cms.law/en/int/legal-updates/middle-east-tmt-2025-in-review)
- Egypt: [CBE Financial Cybersecurity Framework (OSA)](https://opensecurityarchitecture.org/frameworks/cbe-csf), [Andersen on the instant payment network](https://eg.andersen.com/instant-payment-network-egypt/), [Chambers Fintech 2026 Egypt](https://chambers.com/practice-guides/guides/fintech-2026/egypt/law-and-practice), [Egypt Today on CBE PSP licensing](https://www.egypttoday.com/Article/3/140779/CBE-announces-new-rules-for-licensing-and-registration-of-payment)

Primary texts to confirm before shipping regime profiles (F-205) and control mappings (F-803): EUR-Lex Regulation (EU) 2022/2554 (DORA) and its RTS/ITS; Directive (EU) 2022/2555 (NIS2) and national transpositions; PCI DSS v4.0.1; CBE EG-FinCSF v2.0; SAMA Cyber Security Framework; NCA ECC-2:2024; UAE IA Standard v2.1.

---

## 9. Status log

Maintained by the owner when a feature PR is merged (feature branches don't edit it, to avoid conflicts). One line per merged feature: `YYYY-MM-DD | feature | branch | schema vN or none | gates`.

- 2026-11-20 | spec | docs/enterprise-spec | none | headers + validate-docs passed
