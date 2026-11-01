#!/usr/bin/env python3
# Copyright (c) 2026 TrueSignal Deception. All rights reserved.
#
# CodeQL gate for a repository without GitHub code scanning (Q65). Reads the
# post-processed SARIF written by github/codeql-action/analyze and fails on
# every result that is not accepted in .github/codeql/accepted-findings.json.
# An accepted entry matches one rule, one file and CodeQL's fingerprint of the
# flagged line (partialFingerprints.primaryLocationLineHash), so editing that
# line, or any new finding, fails the gate again until it is re-reviewed.
#   codeql-gate.py <sarif-dir> <accepted-findings.json>
import json
import pathlib
import sys

FP = "primaryLocationLineHash"


def results(sarif_dir):
    files = sorted(pathlib.Path(sarif_dir).glob("*.sarif"))
    if not files:
        sys.exit(f"codeql-gate: no SARIF file in {sarif_dir}")
    for f in files:
        for run in json.loads(f.read_text())["runs"]:
            for r in run.get("results", []):
                if r.get("suppressions"):
                    continue
                loc = r["locations"][0]["physicalLocation"]
                yield {
                    "rule": r.get("ruleId", "?"),
                    "file": loc["artifactLocation"]["uri"],
                    "line": loc.get("region", {}).get("startLine", 0),
                    "fingerprint": r.get("partialFingerprints", {}).get(FP, ""),
                    "message": r.get("message", {}).get("text", "").splitlines()[0][:200],
                }


def main():
    sarif_dir, accepted_path = sys.argv[1], sys.argv[2]
    accepted = json.loads(pathlib.Path(accepted_path).read_text())
    for a in accepted:
        for k in ("rule", "file", "fingerprint", "reason"):
            if not str(a.get(k, "")).strip():
                sys.exit(f"codeql-gate: accepted entry without {k}: {a}")
    keys = {(a["rule"], a["file"], a["fingerprint"]) for a in accepted}
    found = list(results(sarif_dir))
    used, bad = set(), []
    for r in found:
        k = (r["rule"], r["file"], r["fingerprint"])
        if r["fingerprint"] and k in keys:
            used.add(k)
            print(f"accepted  {r['rule']} {r['file']}:{r['line']}")
        else:
            bad.append(r)
    for r in bad:
        print(f"::error file={r['file']},line={r['line']}::{r['rule']}: {r['message']}")
        print(f"  to accept after review: {json.dumps({'rule': r['rule'], 'file': r['file'], 'fingerprint': r['fingerprint'], 'reason': '...'})}")
    print(f"codeql-gate: {len(found)} result(s), {len(found) - len(bad)} accepted, {len(bad)} failing")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
