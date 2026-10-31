#!/usr/bin/env python3
# Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.
#
# CI checks (§10): sensor manifests against docs/manifest-v3.schema.json
# (JSON Schema 2020-12), docs/openapi.yaml well-formed, and every HTTP route
# registered by the Hub documented in the OpenAPI file (and vice versa).
# Needs python3-yaml and python3-jsonschema (Ubuntu packages in CI).
import glob, json, re, sys

import jsonschema
import yaml

ok = True
def fail(msg):
    global ok
    ok = False
    print("validate-docs:", msg, file=sys.stderr)

schema = json.load(open("docs/manifest-v3.schema.json"))
jsonschema.Draft202012Validator.check_schema(schema)
validator = jsonschema.Draft202012Validator(schema)
manifests = sorted(glob.glob("sensors/*/manifest.json")) + ["sdk/python/template/manifest.json"]
if not manifests:
    fail("no sensor manifests found")
for p in manifests:
    for err in validator.iter_errors(json.load(open(p))):
        fail(f"{p}: {'/'.join(map(str, err.path))}: {err.message}")

spec = yaml.safe_load(open("docs/openapi.yaml"))
if not isinstance(spec, dict) or not str(spec.get("openapi", "")).startswith("3."):
    fail("docs/openapi.yaml: not an OpenAPI 3 document")
documented = set()
for path, item in (spec.get("paths") or {}).items():
    if not isinstance(item, dict):
        fail(f"openapi: {path}: malformed path item")
        continue
    for method in item:
        if method in ("get", "post", "put", "patch", "delete"):
            documented.add((method.upper(), path))

consts = {}
registered = set()
for src in glob.glob("hub/internal/httpapi/*.go"):
    if src.endswith("_test.go"):
        continue
    text = open(src).read()
    for name, val in re.findall(r'\b(route\w+)\s*=\s*"([^"]+)"', text):
        consts[name] = val
    for m in re.finditer(r'(?:Route|RouteFull|HandleFunc|Handle)\(\s*"(GET|POST|PUT|PATCH|DELETE) ([^"]+)"', text):
        registered.add((m.group(1), m.group(2)))
    for m in re.finditer(r'RouteFull\(\s*"(GET|POST|PUT|PATCH|DELETE) "\s*\+\s*(route\w+)(?:\s*\+\s*"([^"]*)")?', text):
        registered.add((m.group(1), (m.group(2), m.group(3) or "")))
resolved = set()
for method, p in registered:
    if isinstance(p, tuple):
        if p[0] not in consts:
            fail(f"unresolved route constant {p[0]}")
            continue
        p = consts[p[0]] + p[1]
    resolved.add((method, p))
if len(resolved) < 50:
    fail(f"only {len(resolved)} routes found in hub/internal/httpapi; the route scan is broken")
for r in sorted(resolved - documented):
    fail(f"route not in docs/openapi.yaml: {r[0]} {r[1]}")
for r in sorted(documented - resolved):
    fail(f"documented route not registered by the Hub: {r[0]} {r[1]}")

print(f"validate-docs: {len(manifests)} manifests, {len(resolved)} routes checked")
sys.exit(0 if ok else 1)
