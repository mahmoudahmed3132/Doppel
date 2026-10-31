# Sensor registry (§6.7)

A static HTTPS location. Default:
`https://raw.githubusercontent.com/mahmoudahmed3132/TrueSignal-Rewrite/registry/`
(the `registry` branch written by the sensor publish workflow, §10).
Override with `TS_REGISTRY_URL` (operator default) or the `registry_url`
setting (admin). Plain `http://` is accepted only with `TS_ENV=development`.

## Layout

```
index.json
sensors/<name>/<version>/manifest.json
sensors/<name>/<version>/manifest.json.sigstore.json   # detached Sigstore bundle
```

## index.json

```json
{
  "schema_version": 1,
  "generated_at": "2026-10-31T00:00:00Z",
  "sensors": {
    "tcp-tarpit": {
      "latest": "1.1.0",
      "versions": {
        "1.0.0": {"manifest": "sensors/tcp-tarpit/1.0.0/manifest.json", "deprecated": false},
        "1.1.0": {"manifest": "sensors/tcp-tarpit/1.1.0/manifest.json", "deprecated": false}
      }
    }
  }
}
```

Decoded strictly (unknown fields refused). Manifest paths must be relative,
plain segments (`[A-Za-z0-9._-]`), no `.`/`..`, no scheme, query or leading
`/`; they always resolve under the registry base. Limits: index ≤ 1 MiB,
manifest ≤ 256 KiB, bundle ≤ 256 KiB, ≤ 500 sensors, ≤ 200 versions each.
Redirects are never followed; requests time out after 30 s.

## Hub behaviour

1. Fetch `index.json` at start and every `catalogue_refresh_hours` (default 24, 1–168).
2. For each listed version **not already verified**, fetch the manifest and its
   bundle, then call the signing module's `verify(manifest, bundle, name, version)`
   **before parsing**. Versions are immutable (§10), so verified versions are
   never refetched; only their `deprecated` flag follows the index.
3. Decode strictly against schema v3 and require `name`/`version` to equal the
   index entry.
4. Cache verified manifest + bundle bytes in the database; re-verify them on
   every Hub start (a revoked identity or a missing verifier unloads them).

Unavailable versions are listed with a reason: `unsigned`, `signature_invalid`,
`fetch_failed`, `invalid_manifest`, `manifest_mismatch`.

**Latest** is computed by the Hub: the highest available (verified), listed,
non-deprecated version. The index's own `latest` is advisory and ignored, so a
tampered index cannot steer upgrades to an unverified version.

**Deprecated or removed versions stay renderable** for sensors already
deployed on them (decoys are never silently dropped), but are not offered as
"latest" and are reported as deprecated.

If the index cannot be fetched, the current catalogue is kept and the error is
shown in the catalogue status.

`TS_DEV_ALLOW_UNSIGNED_MANIFESTS=true` accepts manifests that fail verification,
marked `verified: false`, with a warning per manifest. Strict decoding and the
identity check still apply. Never use in production.
