# Provenance log

Rule source: Clean-Room Implementation Specification v1, §0.6.

Every entry records date, implementer, component, sources used, and incidents
under §0.1. Entries are append-only.

## Implementer disclosure (applies to every entry by "AI agent")

The AI agent is a large language model. Its training data is a broad crawl of
public text and code and **may** include public repositories named in §0.1.
The agent cannot inspect or exclude specific items of its training data. To
comply with §0.2 the agent:

- uses only the specification, public RFCs/standards and public library
  documentation as design inputs;
- did not open, search, clone or fetch any repository, image or package named
  in §0.1 during the session (GitHub access for the session was scoped to
  `mahmoudahmed3132/TrueSignal-Rewrite` only);
- designs package layout, identifiers and algorithms from the specification
  text, not from recollection of any existing implementation.

Counsel should weigh this disclosure when assessing §0.2; the similarity
analysis of §14.14 is the objective control.

## Entries

| Date | Implementer | Component | Sources used | Incidents |
|---|---|---|---|---|
| 2026-10-31 | AI agent, session `session_01TGdGKDp6wnhogyaRQY1eEm` | Repository scaffolding, `PROVENANCE.md`, `QUESTIONS.md`, `THIRD_PARTY.md`, `Makefile`, `go.work` | Spec §0, §2, §10, §15 | None |
| 2026-10-31 | AI agent, session `session_01TGdGKDp6wnhogyaRQY1eEm` | `sdk/go` (Go Sensor SDK), `sensors/template` | Spec §4, §5; RFC 9562 (UUIDv7); Go standard library docs | None |
| 2026-10-31 | AI agent, session `session_01TGdGKDp6wnhogyaRQY1eEm` | `docs/contract-v3.md` | Spec §4 | None |
