#!/usr/bin/env python3
# Copyright (c) 2026 TrueSignal Deception. All rights reserved.
#
# Generates one Claude Code prompt per feature (docs/plan/prompts/*.txt) and
# the run order (docs/plan/prompts/00-INDEX.md) from docs/plan/ENTERPRISE-SPEC.md.
# Re-run after editing the spec:  python3 scripts/plan/gen-prompts.py
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "docs/plan/ENTERPRISE-SPEC.md"
OUT = ROOT / "docs/plan/prompts"

# Features too big or mixed-priority for one session are split.
# id -> list of (suffix, title, scope note)
SPLITS = {
    "F-003": [
        ("a", "Native TLS, listen address, health and metrics (H1 / WP-4A + F-003 items 1, 2, 4)",
         "Implement H1 from docs/plan/ROADMAP.md and WP-4A from docs/plan/EXECUTION-PLAN.md, plus F-003 requirements 1 (TS_LISTEN_ADDR), 2 (/metrics on a separate loopback listener) and 4 (dashboards). Do NOT implement backup here."),
        ("b", "Backup, restore and verify (B1 / WP-4C + F-003 item 3)",
         "Implement B1 from docs/plan/ROADMAP.md and WP-4C from docs/plan/EXECUTION-PLAN.md, plus F-003 requirement 3 (scheduling docs, --encrypt-to age recipient, verify subcommand). Do NOT touch TLS/health/metrics here."),
    ],
    "F-101": [
        ("a", "OIDC single sign-on (S1 / WP-4B + extra OIDC requirements)",
         "Implement only the OIDC part: S1 in docs/plan/ROADMAP.md, WP-4B in docs/plan/EXECUTION-PLAN.md, plus the three extra OIDC requirements in this section and the SSO settings UI. Do NOT implement SAML or SCIM."),
        ("b", "SAML 2.0 and SCIM 2.0",
         "Implement only the SAML 2.0 and SCIM 2.0 parts of this section. OIDC (F-101a) must already be merged; reuse its provider/mapping model."),
    ],
    "F-405": [
        ("a", "kubernetes-api-decoy", "Implement only `kubernetes-api-decoy`. Write docs/clean-specs/kubernetes-api-decoy.md first."),
        ("b", "docker-api-decoy", "Implement only `docker-api-decoy`. Write docs/clean-specs/docker-api-decoy.md first."),
        ("c", "redis-decoy", "Implement only `redis-decoy`. Write docs/clean-specs/redis-decoy.md first."),
        ("d", "elasticsearch-decoy", "Implement only `elasticsearch-decoy`. Write docs/clean-specs/elasticsearch-decoy.md first."),
        ("e", "mongodb-decoy", "Implement only `mongodb-decoy`. Write docs/clean-specs/mongodb-decoy.md first."),
        ("f", "vnc-decoy", "Implement only `vnc-decoy`. Write docs/clean-specs/vnc-decoy.md first."),
        ("g", "smtp-decoy", "Implement only `smtp-decoy`. Write docs/clean-specs/smtp-decoy.md first."),
        ("h", "http-app-decoy", "Implement only `http-app-decoy`. Write docs/clean-specs/http-app-decoy.md first."),
    ],
    "F-506": [
        ("a", "Multi-arch (arm64) images", "Implement only requirement 1 (arm64 / multi-arch)."),
        ("b", "Kubernetes: Helm chart and node mode", "Implement only requirement 2 (Helm chart for the Hub, Kubernetes node mode; the operator is out of scope for this session)."),
        ("c", "Hardened OVA appliance", "Implement only requirement 3 (OVA appliance and first-boot wizard)."),
        ("d", "Windows native decoy service", "Implement only requirement 4 (Windows service). Start with the THREATMODEL.md section and a design note; ask before large platform-specific code."),
    ],
    "F-1102": [
        ("", "Continuous fuzzing and decoy escape review",
         "The third-party pentest is vendor work and is out of scope. Implement requirements 2 (nightly fuzzing with corpus persistence) and 3 (per-sensor container escape review, documented)."),
    ],
}

# Run order. Features in one wave are independent enough to run in parallel
# sessions; schema-touching branches still merge one at a time (rebase, take
# the next free migration version).
WAVES = [
    ("Wave 1: pilot blockers (P0)", ["F-004", "F-603", "F-001", "F-002", "F-005", "F-003a", "F-003b", "F-101a"]),
    ("Wave 2: identity, security and platform basics (P1)", ["F-103", "F-104", "F-105", "F-106", "F-107", "F-502", "F-505", "F-503", "F-609", "F-608", "F-1101", "F-1103", "F-1301"]),
    ("Wave 3: SOC core and scale (P1)", ["F-201", "F-102", "F-203", "F-301", "F-302", "F-805", "F-504", "F-601"]),
    ("Wave 4: workflow, sovereignty, UX (P1)", ["F-202", "F-204", "F-206", "F-303", "F-602", "F-604", "F-605", "F-606", "F-607", "F-801", "F-901", "F-902", "F-903", "F-415", "F-501", "F-506a", "F-506b", "F-1102", "F-1201"]),
    ("Wave 5: deception content (P1)", ["F-401", "F-405a", "F-405b", "F-405c", "F-405d", "F-405e", "F-405f", "F-405g", "F-405h", "F-404", "F-402"]),
    ("Wave 6: EMEA differentiation (P2)", ["F-101b", "F-205", "F-802", "F-803", "F-806", "F-1001", "F-1002", "F-304", "F-305", "F-403", "F-406", "F-407", "F-408", "F-410", "F-413", "F-414", "F-506c", "F-507", "F-804", "F-904", "F-701", "F-702", "F-704", "F-1202", "F-1302"]),
    ("Wave 7: later (P3)", ["F-409", "F-411", "F-412", "F-506d", "F-703", "F-1003", "F-1104", "F-1203", "F-1303"]),
]

TEMPLATE = """You are implementing feature {fid} "{title}" of the Doppel deception platform
(repo: mahmoudahmed3132/Doppel). Work from the repository root.

=== 1. SET UP THE BRANCH ===
git fetch origin
git switch -c {branch} origin/main
(If the branch already exists, continue on it instead: git switch {branch} && git rebase origin/main)

=== 2. READ BEFORE CODING (in this order) ===
- docs/plan/ENTERPRISE-SPEC.md sections 0 (rules) and 7 (definition of done)
- docs/plan/ROADMAP.md section 0 and docs/plan/EXECUTION-PLAN.md section 0 (still binding)
- the feature section below, then THREATMODEL.md and every file the section names
{extra_reading}
=== 3. DEPENDENCIES ===
{meta}
Check that every dependency named above is already merged into origin/main:
  gh pr list --state merged --search "<dependency id> in:title"   (and confirm in the code).
If one is missing, STOP and tell me which one. Do not build a dependency yourself unless I say so.

=== 4. SCOPE ===
{scope}- Implement only this feature. No unrelated refactors.
- Schema: if you add a migration, it takes the next free version after rebasing on the latest
  origin/main (migrations are a gap-free list). Say which version you used in the PR.
- Ambiguity: add an entry to QUESTIONS.md (next free id, Q82 or later) with the conservative
  default, then continue.
- STOP and ask me if: a requirement conflicts with an existing security invariant; you need a
  real credential, cloud account or external service; you need sudo or changes outside the repo.
- Never weaken an existing test, assertion or security check to make something pass.
- Test data: card-network test PANs/BINs only, dummy keys, documentation IP ranges.

=== 5. FEATURE SPECIFICATION (copied from docs/plan/ENTERPRISE-SPEC.md; the repo file wins if they differ) ===
{section}
=== 6. VERIFY (report each: passed / failed with output / not run with reason) ===
make
make ui                              (if ui/ changed)
python3 scripts/validate-docs.py
./scripts/compose-guard.sh
./scripts/release/selftest.sh
./scripts/e2e/real-docker.sh         (needs Docker; extend it if the feature touches the runtime path)
go test -fuzz=. -fuzztime=15s        (each new protocol parser)

=== 7. FINISH ===
1. Do not edit the section 9 status log (the owner updates it at merge time; parallel PRs would
   conflict there).
2. Commit in logical steps (Conventional Commits), push the branch, and open a DRAFT pull request
   to main titled "{fid}: {title}". The PR body must contain: what changed, schema version used,
   the Acceptance criteria as a checklist (each ticked or explained), gate results, and any
   QUESTIONS.md entries added.
3. Do not merge, tag or publish anything. End with the PR link and a one-paragraph summary.
"""


def slug(text: str) -> str:
    s = re.sub(r"\(.*?\)", "", text.lower())
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return "-".join(s.split("-")[:6])


def parse(spec: str):
    lines = spec.splitlines()
    feats, i, decoy_rules = {}, 0, ""
    # General decoy rules sit between "### E4" and the first "#### F-4".
    m = re.search(r"### E4 Deception content\n(.*?)\n#### F-401", spec, re.S)
    if m:
        decoy_rules = m.group(1).strip()
    while i < len(lines):
        h = re.match(r"^#### (F-\d+) (.+)$", lines[i])
        if not h:
            i += 1
            continue
        fid, title = h.group(1), h.group(2).strip()
        j = i + 1
        while j < len(lines) and not re.match(r"^(#{2,4} |---\s*$)", lines[j]):
            j += 1
        body = "\n".join(lines[i:j]).strip() + "\n"
        meta = next((l for l in lines[i:j] if l.startswith("- **Priority:**")), "")
        feats[fid] = {"title": title, "body": body, "meta": meta}
        i = j
    return feats, decoy_rules


def main() -> int:
    feats, decoy_rules = parse(SPEC.read_text())
    if not feats:
        print("no features found in spec", file=sys.stderr)
        return 1
    OUT.mkdir(parents=True, exist_ok=True)
    for old in OUT.glob("F-*.txt"):
        old.unlink()
    written = {}
    for fid, f in feats.items():
        parts = SPLITS.get(fid, [("", f["title"], "")])
        for suffix, title, note in parts:
            pid = fid + suffix
            branch = f"feat/{pid.lower()}-{slug(title)}"
            extra = ""
            if fid.startswith("F-4"):
                extra = ("- docs/clean-specs/README.md and docs/clean-specs/common-decoy.md (clean-room decoy rules)\n"
                         "- General rules for every new sensor (spec section E4):\n  "
                         + decoy_rules.replace("\n", "\n  ") + "\n")
            if fid in ("F-003", "F-101"):
                extra += "- docs/plan/ROADMAP.md section 4 (U1, S1, H1, B1) and docs/plan/EXECUTION-PLAN.md section 5 (WP-4A..C)\n"
            scope = f"- THIS SESSION: {note}\n" if note else ""
            text = TEMPLATE.format(fid=pid, title=title, branch=branch, extra_reading=extra,
                                   meta=f["meta"] or "(see section)", scope=scope, section=f["body"])
            name = f"{pid}-{slug(title)}.txt"
            (OUT / name).write_text(text)
            written[pid] = (name, title, f["meta"])
    # Index
    listed = [p for _, ids in WAVES for p in ids]
    missing = sorted(set(written) - set(listed))
    unknown = sorted(set(listed) - set(written))
    if missing or unknown:
        print(f"wave table out of sync: missing={missing} unknown={unknown}", file=sys.stderr)
        return 1
    idx = ["# Feature prompts: run order", "",
           "Generated by `scripts/plan/gen-prompts.py` from `docs/plan/ENTERPRISE-SPEC.md`. Do not edit by hand; edit the spec and re-run.", "",
           "## How to run one", "",
           "- **Local, one feature:** `scripts/plan/run-feature.sh F-001`. This opens Claude Code in its own git worktree with the prompt.",
           "- **Copy for Claude Code on the web / desktop:** `scripts/plan/run-feature.sh F-001 --copy` copies the prompt to the clipboard.",
           "- **List:** `scripts/plan/run-feature.sh --list`.", "",
           "Features in the same wave can run in parallel sessions. Merge schema-touching PRs one at a time: the next PR rebases and takes the next free migration version.",
           "Start a wave only after the previous wave's PRs that it depends on are merged (each prompt checks its dependencies and stops if one is missing).", ""]
    for wave, ids in WAVES:
        idx += [f"## {wave}", "", "| Prompt | Feature | Priority / effort / depends on |", "|---|---|---|"]
        for pid in ids:
            name, title, meta = written[pid]
            m = re.sub(r"^- \*\*Priority:\*\*\s*", "", meta).replace("**", "").replace("|", "/")
            idx.append(f"| [{pid}]({name}) | {title} | {m} |")
        idx.append("")
    (OUT / "00-INDEX.md").write_text("\n".join(idx))
    print(f"wrote {len(written)} prompts + 00-INDEX.md to {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
