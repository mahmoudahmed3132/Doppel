# Prompt for the merge session (Claude Fable)

Run this in a local Claude Code session (CLI or desktop app) on **Claude Fable
5.2** (`claude-fable-5-2`) at effort `high`. The new repository is built in a
local folder and uploaded to GitHub later by the owner.

**Before starting, on your machine:**

```bash
mkdir -p ~/truesignal-merge/sources && cd ~/truesignal-merge
```

```bash
git clone https://github.com/mahmoudahmed3132/TrueSignal-Rewrite.git sources/TrueSignal-Rewrite
```

```bash
git clone https://github.com/mahmoudahmed3132/TrueSignal.git sources/TrueSignal
```

```bash
git clone https://github.com/andreicscs/HoneyWire.git sources/HoneyWire
```

Use full clones, not shallow ones: the authorship test needs all of the
history. Then start Claude Code in `~/truesignal-merge` (not inside a source
clone) and send the prompt.

**Local tools the gates need:**
- Go 1.26.10, Node 22, Python 3 with `pyyaml` and `jsonschema`;
- Docker with the compose plugin, `jq`;
- Trivy v0.70.0;
- the CodeQL CLI.

A gate whose tool is missing is reported as not run, never as passed.

Fill in `<NEW_REPO>` (the final GitHub name, which the signing identities depend
on) and the sensor republish version before sending. Everything below the line
is the prompt.

---

You are building a new private repository, `mahmoudahmed3132/<NEW_REPO>`, that
combines two codebases written for the same product, TrueSignal, a deception
platform with a Hub, node agents and decoy sensors:

- **`mahmoudahmed3132/TrueSignal-Rewrite`, the base.** It is a clean-room
  rewrite with a full test suite, CI, signed releases and governance files.
  Read `docs/merge/HANDOFF.md` in it before anything else. It explains the
  architecture, the quality gates, the PORTED integration seams, the decisions
  in force (`QUESTIONS.md`) and the supply-chain consequences of a new
  repository name.
- **`mahmoudahmed3132/TrueSignal`, the source of extra features.** It is the
  owner's earlier implementation. It mixes:
  - code written by people;
  - code derived from `andreicscs/HoneyWire`, a third party's project;
  - code written by Claude sessions.

  It has features the rewrite lacks (the rewrite's `docs/ported-seams.md`
  lists the modules expected from it).

**The rule (owner's decision):** the new repository contains **only code that
Claude wrote new**, from both repositories. HANDOFF §0 defines "Claude-new"
precisely; read it.

**Goal:** the rewrite's architecture and quality bar, plus every Claude-new
feature from `TrueSignal`, in one repository that builds, passes every gate
and can ship. Every feature that is wanted but excluded by the rule is written
up as a clean spec.

## Owner decisions (filled in by the owner)

- **Import rule:** Claude-new code only (HANDOFF §0). Nothing written by
  people, nothing derived from HoneyWire, and nothing Claude only edited.
- **Sensor republish version:** `1.0.1`. This is the version the five
  published sensors are re-signed under from the new repository.

## Layout (local, no GitHub)

- `sources/TrueSignal-Rewrite`, `sources/TrueSignal`, `sources/HoneyWire`:
  read-only clones. Never commit, push or change anything in them.
- `<NEW_REPO>/`: the new repository, which you create. It lives outside
  `sources/`.
  - Nothing from `sources/` enters it except through the imports this prompt
    allows.
  - No submodules, symlinks or `file://` remotes pointing into `sources/`.
  - Do not add a GitHub remote; the owner uploads it later.

## How to work

1. **Start from the base, with its history.**
   - Run `git clone sources/TrueSignal-Rewrite <NEW_REPO>`, then remove its
     `origin` remote.
   - Each coherent step goes on its own local branch, with commit messages
     that explain it.
   - Merge a step into `main` only after the owner has reviewed that branch.
     The owner reviews locally, with `git log` and `git diff main...<branch>`.
   - Do not rewrite history.
2. **Inventory first, code second.**
   - Survey `TrueSignal`.
   - Write `MERGE-INVENTORY.md`. It has one row for each feature, module,
     sensor, script or document there that the base lacks, or does
     differently.
   - Give each row:
     - what it does;
     - where it lives;
     - which base seam or contract it maps to;
     - its provenance class;
     - the evidence;
     - the proposed decision.
   - Show the owner the inventory, and wait for approval before importing
     anything.
3. **Authorship classes.** Decide each one per file, and per hunk where a file
   mixes authors, from evidence. The class is the most restrictive one the
   evidence supports.
   - **What counts as evidence:**
     - `git log --follow -M -C` and `git blame -w -M -C` across the full history;
     - commit trailers (`Co-Authored-By: Claude …`, `Claude-Session:`);
     - `claude/*` branch names, and PRs opened by a Claude integration;
     - commit messages and PR descriptions;
     - similarity against the earlier tree and against HoneyWire.
   - **Classes:**
     - **claude-new:** created by a Claude-attributed commit, and not a port,
       translation, move, rename or refactor of earlier code. Importable.
     - **claude-edit:** Claude-attributed changes to code that existed before.
       Not importable, unless the hunk is self-contained new logic that passes
       the claude-new test on its own.
     - **human:** no Claude attribution. Not importable.
     - **HoneyWire-derived:** includes a translation, a port, or code with the
       same structure, whoever committed it. Not importable.
     - **third-party (permissive):** a vendored dependency under MIT, BSD,
       Apache-2.0, ISC or MPL-2.0. Re-add it as a declared dependency, not as
       copied code, and record it in `THIRD_PARTY.md`.
     - **unknown:** treat it as not importable, and add a `QUESTIONS.md` entry
       for the owner.
   - **GPL, AGPL or LGPL code:** never import it.
   - **The base gets the same test.** Apply it to `TrueSignal-Rewrite` as
     well. Most of it is claude-new, but PORTED step 1
     (`hub/internal/signing`, `hub/internal/sourcelist`) came from the owner's
     earlier project at commit `2884102`. Trace it in `TrueSignal`. If it is
     not claude-new, remove it, put the stub seam back (see the history of
     `hub/cmd/truesignal-hub/main.go` before step 1), and specify it as below.
     The owner's mechanical commits in the base (`LICENSE`, headers, the
     deploy-key workflow) stay.
   - **Excluded but wanted:**
     - Do not write a replacement yourself: you have read the excluded code.
     - Write a prose spec in `docs/clean-specs/<feature>.md`: behaviour, inputs
       and outputs, limits, error cases, and how it plugs into the base's seam.
     - The spec must contain no code, identifiers, file layout or comments from
       either source.
     - A separate session that never sees `TrueSignal` or HoneyWire implements it.
   - **Dependencies on excluded code.** For each import, record which
     interfaces in excluded code it depends on. Adapt it to the base's seams;
     if it cannot be separated from excluded code, specify it instead.
4. **Import through seams.**
   - Where `docs/ported-seams.md` defines an interface, implement that
     interface. Add an adapter rather than change the seam.
   - Where a feature needs a new seam or a contract change (node API v3,
     manifest v3, OpenAPI, audit actions, the §6.12 compose rules), add a
     `QUESTIONS.md` entry with the conservative default. Change the contract,
     its docs and its tests together.
   - The base is the authority on architecture, security controls and naming.
     Where the two disagree, keep the base's behaviour, and record the
     difference in the inventory.
5. **Per import, on the same branch:**
   - the licence header;
   - tests, including one that exercises the real module through its seam;
   - `THIRD_PARTY.md` rows for new dependencies (permissive only, with the
     reason);
   - a `PROVENANCE.md` row naming the source commit and path in `TrueSignal`,
     the Claude-attributed commits that created it, its class, the evidence,
     and every change made.
   - `docs/ported-seams.md`, `README.md` and `THREATMODEL.md` updates where
     they apply.
6. **Repoint the supply chain** (HANDOFF §3):
   - set the signer repository default to `<NEW_REPO>`, and `SIGNER_REPO` in
     `install.sh`;
   - update the identity strings in the docs;
   - keep the old signed fixtures as historical tests, with the old repository
     passed explicitly;
   - write the owner's republish plan into `docs/operations.md`: new App
     installation, sensors at the republish version, a new CLI release, and
     Hub `3.0.0-rc.2` or stable.

   Do not push tags or create releases; the owner does that.
7. **Keep every gate green on every branch**, run locally (GitHub CI runs
   them again after the upload):
   - `make`;
   - `make ui`;
   - `python3 scripts/validate-docs.py`;
   - `scripts/compose-guard.sh`;
   - `scripts/release/selftest.sh`;
   - `trivy fs` on each module, and `trivy image` on the Hub and sensor images,
     with the flags in `.github/workflows/ci.yml`;
   - CodeQL through the CLI with the `security-extended` suite, then
     `scripts/codeql-gate.py` on the resulting SARIF;
   - `scripts/e2e/real-docker.sh`.

   Never disable, skip or weaken a test or gate to get green. A new CodeQL
   finding is fixed, or accepted in `.github/codeql/accepted-findings.json`
   only after you have traced it and written down why it is not exploitable.

## Constraints

- Never use or recreate image names under `ghcr.io/mahmoudahmed3132/truesignal-*`.
  The images are `ts-hub` and `ts-sensor-<name>`.
- No secrets in the repository or in commits.
- Pin GitHub Actions by commit SHA. Take no dependency version younger than
  14 days without a stated reason.
- Do not merge a branch into `main` before the owner has reviewed it.
- If something is ambiguous, write it in `QUESTIONS.md` with the conservative
  default and carry on. Stop and ask only when you are blocked, or when a
  decision changes provenance or licensing.

## Deliverables

1. The local `<NEW_REPO>` on `main`, passing every gate that could run
   locally, with the approved imports.
2. `MERGE-INVENTORY.md`, with every row resolved.
3. `docs/clean-specs/` for every feature not imported, ready to hand to a
   clean session.
4. A final report, `docs/merge/REPORT.md`, covering:
   - what was imported, specified or dropped, and why;
   - the test evidence;
   - open questions;
   - the owner's release and republish checklist.
5. `docs/merge/UPLOAD.md` for the owner: the steps to publish the repository to
   GitHub (below), and anything that could only be checked after the upload.

## Upload (done by the owner; record these steps in `docs/merge/UPLOAD.md`)

1. Create an empty **private** repository `mahmoudahmed3132/<NEW_REPO>`, with
   no README or licence.
2. In the local repository: `git remote add origin
   https://github.com/mahmoudahmed3132/<NEW_REPO>.git`, then push `main`, and
   push other branches only if wanted.
3. **Before the first tag:**
   - the tag ruleset;
   - the `truesignal-releases` App installation;
   - the `RELEASES_APP_CLIENT_ID` variable and the `RELEASES_APP_PRIVATE_KEY`
     secret;
   - Dependabot.

   Details are in `docs/operations.md` §9 and §9.1.
4. Confirm that CI is green on GitHub, then follow the republish plan.

