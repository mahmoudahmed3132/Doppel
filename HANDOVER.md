# TrueSignal Core — implementation handover

**To:** the author of *TrueSignal-CleanRoom-Spec-v1.md*
**From:** the implementing AI agent (Claude Code, session `session_01TGdGKDp6wnhogyaRQY1eEm`)
**Repository:** `mahmoudahmed3132/TrueSignal-Rewrite`, branch `main` at `c4e6600` (58 commits; PRs #1–#14 merged)
**Date:** 2026-10-31

## 1. Status

Every requirement of the specification that is in scope for the implementer
is implemented, tested and merged. Modules marked **PORTED** (§12) were not
written, as instructed; each has a seam, a stub and interface documentation.
The remaining items need the owner or the specification team (§6 below).

## 2. Clean-room statement (§0)

**Attested for the whole of this work:**

- **No prohibited sources accessed.** I did not open, clone, fetch, search,
  download, pull or inspect:
  - `andreicscs/HoneyWire` (any branch, tag, fork, mirror or package);
  - `mahmoudahmed3132/TrueSignal`;
  - any `ghcr.io/mahmoudahmed3132/truesignal-*` image or any HoneyWire image;
  - any project named HoneyWire.

  No tool, search result or dependency surfaced such content, so
  `PROVENANCE.md` records no incidents in any of its 21 entries.
- **Inputs.** The only inputs were the specification and public,
  permissively licensed references: RFCs, language and library
  documentation, Docker, Compose, GitHub Actions and Sigstore docs. Each
  `PROVENANCE.md` entry lists the sources used for its component.
- **External network access was limited to:**
  - package registries for declared dependencies (Go module proxy, npm);
  - `git ls-remote` and reading `action.yml` at the pinned commits of the
    public GitHub Actions used in CI;
  - digest lookups (manifest HEAD requests only) for the pinned base images:
    `golang`, `distroless`, `registry`;
  - this repository and its own CI logs and releases.
- **Dependencies** are permissive only (MIT, BSD, Apache-2.0), each recorded
  with its justification in `THIRD_PARTY.md`. There are no GPL, AGPL or LGPL
  dependencies.
- **No reproduction from memory.** I did not knowingly reproduce code, file
  layouts, identifiers or comments from the prohibited projects. Designs were
  written from the specification.
- **The §14.14 similarity check is the objective control.** I cannot prove the
  absence of influence from model training data, and I make no claim beyond the
  statements above. I did not attempt to influence the check (§14.14).
- **One recorded near-miss (Q60).** Early sensor manifests used image names
  under `ghcr.io/mahmoudahmed3132/truesignal-sensor-*`, which fall inside the
  prohibited namespace. Nothing under that namespace was ever pulled,
  inspected or pushed. The names were changed to `ts-hub` and
  `ts-sensor-<name>` before any publish, and a test pins the new prefix.

## 3. What was delivered (§15)

| Path | Contents |
|---|---|
| `sdk/go` | Go sensor SDK (§5), zero third-party dependencies; reporter seam for the PORTED decoy helper |
| `sdk/python` | Python SDK (§11.6), standard library only; template sensor, manifest, distroless Dockerfile |
| `hub/` | Hub (§6): storage with snapshot-before-migrate; ingest; liveness; admin auth (argon2id, lockouts, MFA flows, sessions, CSRF); nodes and sensors; compose compiler (§6.12); signed catalogue; SIEM, webhooks and audit; events, analytics, retention, factory reset, update check, live feed; embedded admin UI |
| `cli/`, `install.sh` | Node agent (§8): link, apply with rollback, discover, firedrill, status, uninstall; verified installer (SHA-256 and Sigstore) |
| `sensors/` | tcp-tarpit, icmp-canary, network-scan-detector, file-canary, web-router-decoy, template (§11) |
| `ui/` | Admin web UI (§7): Preact + TypeScript; strict CSP with no inline script or style; dark and light themes; every listed page |
| `.github/workflows/` | CI, CodeQL, publish-hub, publish-cli, publish-sensor, registry-rollback (§10); actions pinned by commit SHA |
| `docs/` | contract v3, OpenAPI, manifest v3 + JSON Schema, registry, SIEM (ECS placeholder), audit actions, CLI, sensors, operations guide, PORTED seams, acceptance mapping |
| Governance | `THREATMODEL.md` (including a §6.12 per-rule table), `THIRD_PARTY.md`, `PROVENANCE.md`, `QUESTIONS.md` (Q1–Q62), `LICENSE` (left as the owner's file, Q1) |

## 4. Verification

- **Acceptance (§14):** items 1–13 pass; 14 belongs to the specification team.
  The mapping to tests is in `docs/acceptance.md`.
- **Automated tests:**
  - 199 Go test functions, run with `-race` on every module;
  - 16 Python tests, run on two interpreters;
  - UI type-check, a safety lint and a CSP check of the embedded build;
  - manifest validation against the JSON Schema and the Hub decoder;
  - an OpenAPI-versus-routes drift check;
  - the compose guard;
  - CodeQL (Go, JavaScript/TypeScript);
  - Trivy, failing on fixable HIGH or CRITICAL findings in dependencies and
    every image;
  - a self-test of the release guards.
- **Real Docker end to end (CI job `real-docker`):** a real Hub and the real
  CLI deploy three sensors with `docker compose`. The job verifies the §6.12
  hardening on the running containers, events, heartbeats, fire drill,
  idempotent re-apply and uninstall.
- **Live checks during development:**
  - the Hub with SIEM and webhook collectors, and the catalogue;
  - the CLI against a simulated Docker;
  - raw ICMP, AF_PACKET and inotify sensors on a real kernel;
  - a 14-step Playwright smoke test of the UI against a real Hub, with zero
    CSP violations.
- **First real releases (published from this repository):**
  - Hub `3.0.0-rc.1`: GHCR image by digest, signed keyless and verified,
    GitHub pre-release;
  - CLI `3.0.0`: static amd64 and arm64 binaries, `SHA256SUMS`, a Sigstore
    bundle per binary;
  - five sensors at `1.0.0`: images, plus signed manifests on the `registry`
    branch. All five were published concurrently and all landed.

  An anonymous client pulled every image, and each digest matches its
  manifest or release notes. The real installer installed the released CLI.
- **Security issues found and fixed during the work:**
  - Go stdlib CVEs: the toolchain moved from 1.26.2 to 1.26.10;
  - a preact CVE;
  - a stale CPython/OpenSSL base image;
  - a factory-reset cookie without `Secure`;
  - a HTTP socket leak in the Python SDK;
  - a `:latest` job that could pass silently during a registry outage.

  The remaining CodeQL alerts were traced, found not reachable, and dismissed
  by the owner.

## 5. Decisions taken under "ask, don't guess"

Q1–Q62 in `QUESTIONS.md` record each ambiguity and the conservative default
taken. The owner explicitly answered Q1 (interim only), Q21, Q43 and Q56–Q62.
The others stand as documented defaults pending review. The ones most worth a
look:

- **Q27:** the node key is injected by the CLI, not written into the rendered
  compose.
- **Q46:** release asset names and the signing identity.
- **Q47:** UID 0 plus a single capability for privileged sensors.
- **Q52:** factory reset is refused if its audit record cannot be delivered.
- **Q56:** projection names (no PORTED contract was available).
- **Q60:** image names.
- **Q61:** extra publish guards.

## 6. Not done by the implementer (by design or out of reach)

1. **PORTED modules (§12)** were not written, as instructed:
   - verifier, TOTP, GeoIP, assets, ATT&CK, source lists;
   - beacons, honeytokens, ECS, HTTP SIEM transports, projections;
   - lures, web skins, the decoy helper and the additional decoys.

   `docs/ported-seams.md` gives each module's interface, wiring field,
   behaviour while absent, and stub. Until the verifier is installed, a
   production Hub's catalogue is empty: it fails closed.
2. **§14.14 independence check:** run by the specification team.
3. **Licence (Q1):** the Apache-2.0 `LICENSE` conflicts with the §0.8 "All
   rights reserved" headers. This needs a legal decision.
4. **Stable `3.0.0` Hub release:** follows owner testing of `3.0.0-rc.1`.
5. **Not yet exercised by a run:** the deploy-key path for `registry` pushes.
   It was added in #14 by the owner, with the branch ruleset, after the five
   sensors were published. The first sensor release or rollback after #14
   will exercise it.

## 7. Residual risks (see `THREATMODEL.md`)

- **R1:** Hub secrets are stored in plaintext in SQLite. These are the master
  keys, the SIEM token, the webhook URL and the TOTP seed. Protect the host,
  volume and backups; at-rest encryption is recommended as follow-up work.
- **R2:** an `http://` Hub endpoint is accepted; the CLI only warns.
- **Development flags:** `TS_DEV_ALLOW_UNSIGNED_MANIFESTS` and
  `TS_DEV_ALLOW_UNPINNED_IMAGES` disable supply-chain controls. They are
  logged at every start and must never be set in production.
