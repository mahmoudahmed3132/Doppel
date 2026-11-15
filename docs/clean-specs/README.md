# Clean specifications

Features that Doppel wants but may not import, because the only existing
implementation is derived from third-party or HoneyWire code, or reworks it
(`MERGE-INVENTORY.md`, QUESTIONS Q68 and Q69). Each file describes **what** to
build, in prose: behaviour, inputs and outputs, limits, error cases, and the
Doppel seam it plugs into.

Rules for whoever implements a spec:

- Work in a copy of Doppel only. Do not open, search, clone or recall
  `mahmoudahmed3132/TrueSignal`, `andreicscs/HoneyWire`, Trapster Community or
  any project derived from them.
- Design from the spec, Doppel's own code and contracts, and public
  standards (RFCs, vendor protocol documentation).
- Deliver through the named seam with tests, including one through the seam;
  add a `PROVENANCE.md` row ("clean implementation from spec; implementer
  had no access to TrueSignal or HoneyWire").
- Pass every gate (`make`, `make ui`, `scripts/validate-docs.py`,
  `scripts/compose-guard.sh`, `scripts/release/selftest.sh`, Trivy, CodeQL,
  `scripts/e2e/real-docker.sh`).

| Spec | Seam |
|---|---|
| `identity-decoy.md` | new sensor `sensors/identity-decoy` on `sdk/go/sensor` + `sdk/go/decoy` |
| `database-decoy.md` | new sensor `sensors/database-decoy` |
| `remote-access-decoy.md` | new sensor `sensors/remote-access-decoy` |
| `network-service-decoy.md` | new sensor `sensors/network-service-decoy` |
| `insights-projection.md` | `ported.Projection` named `insights` |
| `analytics-ui.md` | `ui/` pages for the installed projections |

## Prompt for a clean implementation session

Start a new Claude Code session whose workspace holds **only a copy of
Doppel** (a fresh clone of `mahmoudahmed3132/Doppel`, no `sources/` folder,
and no GitHub access to `TrueSignal`, `TrueSignal-Rewrite` or HoneyWire).
Replace `<SPEC>` and send:

> You are implementing one feature of Doppel, a deception platform, from a
> written specification. Clean-room rules: do not open, search, clone, fetch
> or recall `mahmoudahmed3132/TrueSignal`, `andreicscs/HoneyWire`, Trapster
> Community or anything derived from them; use only this repository, the
> specification, and public standards and library documentation. Read
> `docs/clean-specs/README.md`, `docs/clean-specs/common-decoy.md` (for
> sensors) and `docs/clean-specs/<SPEC>.md`, then `docs/ported-seams.md`,
> `docs/sensors.md`, `docs/manifest-v3.md` and `QUESTIONS.md`. Implement
> `<SPEC>` through the seam it names, on a new branch `clean/<SPEC>` from
> `main`: code with the repository's licence header, tests including one that
> exercises the module through its seam, `THIRD_PARTY.md` rows for any new
> dependency (permissive licences only), docs updates, and one
> `PROVENANCE.md` row reading "clean implementation from spec
> docs/clean-specs/<SPEC>.md; implementer had no access to TrueSignal or
> HoneyWire". Anything ambiguous goes to `QUESTIONS.md` with the conservative
> default. Run every gate (`make`, `make ui`, `python3
> scripts/validate-docs.py`, `scripts/compose-guard.sh`,
> `scripts/release/selftest.sh`, Trivy, the CodeQL gate,
> `scripts/e2e/real-docker.sh`) and report each as passed, failed (with
> output) or not run (with the reason). Commit with explanatory messages,
> push the branch, and stop for the owner's review; do not merge, tag or
> release.

Run one session per spec. The four sensor specs are independent; the
`analytics-ui` page for the insights tiles depends on `insights-projection`.
