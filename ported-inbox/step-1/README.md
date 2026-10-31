# PORTED import, step 1: Sigstore manifest verifier and source-list matcher

Released by the specification team (owner side), 2026-10-31. This folder is an **input** for the implementation team, the same way the specification is. Do not merge it as-is. Integrate it (below), then delete the folder in the same PR.

## What is here

| File (`.go.txt` = Go source; renamed so CI header and build checks skip it) | sha256 |
|---|---|
| `signing/signing.go.txt` | `e01e58bf9cf5baefe7676e4c43c7d97922164c16da83f75db05f2eb64f95593c` |
| `signing/signing_test.go.txt` | `3136a31ad2ee4818b9cc0c5278d0274cccafa903c4a15f787d40c1cc7863f643` |
| `signing/trusted_root.json` (Sigstore public-good trusted root) | `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66` |
| `signing/testdata/publicgood-provenance.sigstore.json` (public Sigstore bundle, test fixture) | `e88fe678350e86bce3275c6ecdfb27731dbe01756b42604ee8b0f4500932ff38` |
| `sourcelist/sourcelist.go.txt` | `fd3e499d0db6e66d1b392c173f0d2342e2b30616ecd4526121d8cf7b7bfc547e` |
| `sourcelist/sourcelist_test.go.txt` | `d3b3569f2ca4d6c113750f22ff57ddff369b00988c2a03992cf9dc9ff1d3c06d` |

## Provenance and rights

- **Origin.** These files are the owner's own work, written after the fork for the owner's earlier AGPL project. Origin commit: `2884102`.
  - `Hub/internal/signing/`
  - `Hub/internal/services/sourcelist/`
- **Never part of HoneyWire.** The specification team checked them against HoneyWire v2.1.0 and HEAD with the §14.14 tool:

  | File | line% | fp% | fpN% | shared literals |
  |---|---|---|---|---|
  | `signing.go` | 0.0 | 0.0 | 0.4 | none |
  | `signing_test.go` | 0.0 | 0.0 | 0.3 | none |
  | `sourcelist.go` | 6.4 | 0.0 | 0.0 | none |
  | `sourcelist_test.go` | 0.0 | 0.0 | 0.6 | none |

  All results are at or below the noise floor.
- **Licence.** As copyright holder, the owner licenses them to this repository under its proprietary licence. Replace their headers with this repository's header when integrating.
- **Third-party dependency (verifier):** `github.com/sigstore/sigstore-go` (Apache-2.0). Add it to `THIRD_PARTY.md` with its justification. It is the official Sigstore verification library, and no standard-library alternative exists.

## Integration notes (decisions are yours, within `docs/ported-seams.md`)

1. **Seam shape.**
   - `ported.ManifestVerifier.Verify(manifest, bundle, sensorName, version)` maps to `Verifier.VerifyManifest(sensorName, version, manifest, bundle)` (argument order differs).
   - `ported.SourceListParser.Parse(entries []string)` maps to `sourcelist.Parse(raw string)`, which takes newline- or comma-separated text; `Split` / `Normalize` exist.
   - Write thin adapters, or change the module's signatures. Either is fine.
2. **Signing identity.** The module hard-codes:
   - the workflow path `.github/workflows/publish-sensor-registry.yml`, where this repository uses `.github/workflows/publish-sensor.yml`;
   - `DefaultSignerRepo = "mahmoudahmed3132/TrueSignal"`, which must point to this repository and come from `TS_MANIFEST_SIGNER_REPO`.

   Make both match `publish-sensor.yml` (identity `https://github.com/<repo>/.github/workflows/publish-sensor.yml@refs/tags/sensor/<name>/v<version>`). Add a test that a bundle signed for one sensor or version is refused for another.
3. **Versions.** The verifier accepts only plain `X.Y.Z` sensor versions. Keep that, or extend it deliberately if sensor pre-releases are ever published (Q62 applies to the Hub only today).
4. **Trusted root.** `TS_SIGSTORE_TRUSTED_ROOT` overrides the embedded root. Keep the embedded file's sha256 in a comment and the refresh procedure in `docs/operations.md`.
5. **Source lists.** Keep the entry cap and the exact-name semantics. Remove `services/` from the package path to fit this repository's layout.
6. **Acceptance.**
   - The verifier: after integration, a production Hub (no development flags) lists the five published `1.0.0` sensors from the `registry` branch.
   - The source lists: acceptance #6 passes with the real matcher.
   - Add a `PROVENANCE.md` entry naming this folder as the input.
7. **Delete `ported-inbox/step-1/`** in the integration PR.
