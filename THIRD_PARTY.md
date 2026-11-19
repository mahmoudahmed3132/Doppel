# Third-party dependencies

Policy (spec §0.5, §13): permissive licences only (MIT, BSD, Apache-2.0, ISC,
MPL-2.0 file-level). No GPL/AGPL/LGPL. Standard library preferred; every entry
must state why it is needed.

| Module / package | Component | Version | Licence | Justification |
|---|---|---|---|---|
| Go standard library | all | go1.26.10 | BSD-3-Clause | Baseline |
| `modernc.org/sqlite` | hub | v1.61.0 | BSD-3-Clause | Pure-Go SQLite driver (§2: SQLite, `CGO_ENABLED=0`) |
| `golang.org/x/crypto` (`argon2`) | hub | v0.58.0 | BSD-3-Clause | argon2id password hashing (§6.3); not in the standard library |
| `modernc.org/libc` | hub (via sqlite) | v1.79.0 | BSD-3-Clause | Transitive: C runtime for the transpiled SQLite |
| `modernc.org/mathutil` | hub (via sqlite) | v1.7.1 | BSD-3-Clause | Transitive |
| `modernc.org/memory` | hub (via sqlite) | v1.12.1 | BSD-3-Clause | Transitive |
| `github.com/remyoudompheng/bigfft` | hub (via sqlite) | v0.0.0-20230129092748 | BSD-3-Clause | Transitive |
| `github.com/dustin/go-humanize` | hub (via sqlite) | v1.1.0 | MIT | Transitive |
| `github.com/google/uuid` | hub (via sqlite) | v1.6.0 | BSD-3-Clause | Transitive (not used directly; Hub UUIDv7 is in `internal/ids`) |
| `golang.org/x/sys` | hub (via sqlite) | v0.49.0 | BSD-3-Clause | Transitive |
| `golang.org/x/term` | cli | v0.47.0 | BSD-3-Clause | No-echo password prompt for `discover`; TTY detection for colour |
| `golang.org/x/sys` | cli (via term) | v0.49.0 | BSD-3-Clause | Transitive |
| `golang.org/x/crypto` (`ssh`) | `sensors/remote-access-decoy` | v0.58.0 | BSD-3-Clause | SSH 2.0 server transport (RFC 4251–4254); not in the standard library |
| `golang.org/x/sys` | `sensors/remote-access-decoy` (via crypto) | v0.49.0 | BSD-3-Clause | Transitive |

### Sigstore manifest verifier (hub, PORTED step 1)

| Module | Component | Version | Licence | Justification |
|---|---|---|---|---|
| `github.com/sigstore/sigstore-go` | hub (`internal/signing`) | v1.3.0 | Apache-2.0 | Official Sigstore verification library: verifies the keyless signature on every sensor manifest (Fulcio certificate identity, Rekor transparency-log entry, SCT, timestamp) before parsing (§6.7, §12). No standard-library alternative exists. |

Its transitive modules linked into the Hub binary (`go list -deps ./cmd/truesignal-hub`), all
permissive; none is used directly by TrueSignal code. They take the Hub from 9
to 77 linked third-party modules: CI's Trivy scan and Dependabot cover them.

`github.com/go-jose/go-jose/v4` is required in `hub/go.mod` (via sigstore's
OIDC signing flow) but not linked into the binary; it is held at v4.1.6, the
first release without CVE-2026-116587. `google.golang.org/grpc` is held at
v1.83.2 for CVE-2026-84304 and CVE-2026-84445.

| Module | Version | Licence |
|---|---|---|
| `github.com/asaskevich/govalidator` | v0.0.0-20230301143203-a9d515a09cc2 | MIT |
| `github.com/blang/semver` | v3.5.1+incompatible | MIT |
| `github.com/cenkalti/backoff/v5` | v5.0.3 | MIT |
| `github.com/cespare/xxhash/v2` | v2.3.0 | MIT |
| `github.com/cyberphone/json-canonicalization` | v0.0.0-20241213102144-19d51d7fe467 | Apache-2.0 |
| `github.com/digitorus/pkcs7` | v0.0.0-20230818184609-3a137a874352 | MIT |
| `github.com/digitorus/timestamp` | v0.0.0-20231217203849-220c5c2851b7 | BSD-2-Clause |
| `github.com/go-logr/logr` | v1.4.4 | Apache-2.0 |
| `github.com/go-logr/stdr` | v1.2.2 | Apache-2.0 |
| `github.com/go-openapi/analysis` | v0.25.5 | Apache-2.0 |
| `github.com/go-openapi/errors` | v0.22.8 | Apache-2.0 |
| `github.com/go-openapi/jsonpointer` | v1.0.0 | Apache-2.0 |
| `github.com/go-openapi/jsonreference` | v1.0.0 | Apache-2.0 |
| `github.com/go-openapi/loads` | v0.25.0 | Apache-2.0 |
| `github.com/go-openapi/runtime` | v0.33.0 | Apache-2.0 |
| `github.com/go-openapi/runtime/server-middleware` | v0.30.0 | Apache-2.0 |
| `github.com/go-openapi/spec` | v0.22.9 | Apache-2.0 |
| `github.com/go-openapi/strfmt` | v0.27.0 | Apache-2.0 |
| `github.com/go-openapi/swag` | v0.26.1 | Apache-2.0 |
| `github.com/go-openapi/swag/cmdutils` | v0.27.0 | Apache-2.0 |
| `github.com/go-openapi/swag/conv` | v0.27.3 | Apache-2.0 |
| `github.com/go-openapi/swag/fileutils` | v0.27.3 | Apache-2.0 |
| `github.com/go-openapi/swag/jsonname` | v0.26.1 | Apache-2.0 |
| `github.com/go-openapi/swag/jsonutils` | v0.27.3 | Apache-2.0 |
| `github.com/go-openapi/swag/loading` | v0.27.3 | Apache-2.0 |
| `github.com/go-openapi/swag/mangling` | v0.27.3 | Apache-2.0 |
| `github.com/go-openapi/swag/netutils` | v0.27.0 | Apache-2.0 |
| `github.com/go-openapi/swag/pools` | v0.27.3 | Apache-2.0 |
| `github.com/go-openapi/swag/stringutils` | v0.27.3 | Apache-2.0 |
| `github.com/go-openapi/swag/typeutils` | v0.27.3 | Apache-2.0 |
| `github.com/go-openapi/swag/yamlutils` | v0.27.3 | Apache-2.0 |
| `github.com/go-openapi/validate` | v0.26.1 | Apache-2.0 |
| `github.com/go-viper/mapstructure/v2` | v2.5.0 | MIT |
| `github.com/google/certificate-transparency-go` | v1.3.3 | Apache-2.0 |
| `github.com/google/go-containerregistry` | v0.21.7 | Apache-2.0 |
| `github.com/grpc-ecosystem/grpc-gateway/v2` | v2.29.0 | BSD-3-Clause |
| `github.com/in-toto/attestation` | v1.2.0 | Apache-2.0 |
| `github.com/in-toto/in-toto-golang` | v0.11.0 | Apache-2.0 |
| `github.com/oklog/ulid/v2` | v2.1.1 | Apache-2.0 |
| `github.com/opencontainers/go-digest` | v1.0.0 | Apache-2.0 |
| `github.com/pkg/errors` | v0.9.1 | BSD-2-Clause |
| `github.com/secure-systems-lab/go-securesystemslib` | v0.11.0 | MIT |
| `github.com/shibumi/go-pathspec` | v1.3.0 | Apache-2.0 |
| `github.com/sigstore/protobuf-specs` | v0.5.1 | Apache-2.0 |
| `github.com/sigstore/rekor` | v1.5.3 | Apache-2.0 |
| `github.com/sigstore/rekor-tiles/v2` | v2.3.0 | Apache-2.0 |
| `github.com/sigstore/sigstore` | v1.10.8 | Apache-2.0 |
| `github.com/sigstore/timestamp-authority/v2` | v2.1.3 | Apache-2.0 |
| `github.com/theupdateframework/go-tuf/v2` | v2.4.2 | Apache-2.0 |
| `github.com/transparency-dev/formats` | v0.1.1 | Apache-2.0 |
| `github.com/transparency-dev/merkle` | v0.0.2 | Apache-2.0 |
| `github.com/youmark/pkcs8` | v0.0.0-20240726163527-a2c0da244d78 | MIT |
| `go.opentelemetry.io/auto/sdk` | v1.2.1 | Apache-2.0 |
| `go.opentelemetry.io/otel` | v1.44.0 | Apache-2.0 |
| `go.opentelemetry.io/otel/metric` | v1.44.0 | Apache-2.0 |
| `go.opentelemetry.io/otel/trace` | v1.44.0 | Apache-2.0 |
| `go.yaml.in/yaml/v3` | v3.0.5 | Apache-2.0 |
| `golang.org/x/mod` | v0.42.0 | BSD-3-Clause |
| `golang.org/x/net` | v0.60.0 | BSD-3-Clause |
| `golang.org/x/sync` | v0.24.0 | BSD-3-Clause |
| `golang.org/x/term` | v0.47.0 | BSD-3-Clause |
| `golang.org/x/text` | v0.43.0 | BSD-3-Clause |
| `google.golang.org/genproto/googleapis/api` | v0.0.0-20260526163538-3dc84a4a5aaa | Apache-2.0 |
| `google.golang.org/genproto/googleapis/rpc` | v0.0.0-20260526163538-3dc84a4a5aaa | Apache-2.0 |
| `google.golang.org/grpc` | v1.83.2 | Apache-2.0 |
| `google.golang.org/protobuf` | v1.36.11 | BSD-3-Clause |
| `k8s.io/klog/v2` | v2.140.0 | Apache-2.0 |

### Admin UI (`ui/`, npm, exact versions pinned in `package-lock.json`)

| Package | Shipped? | Version | Licence | Justification |
|---|---|---|---|---|
| `preact` | yes (bundled into the Hub binary) | 11.1.0 | MIT | 4 kB component/rendering library; escapes text by default (no HTML injection path) |
| `esbuild` (+ its `@esbuild/<platform>` binary) | no, build time only | 0.28.2 | MIT | Bundles and minifies the UI into one script + one stylesheet (CSP-compatible output) |
| `typescript` | no, build time only | 7.0.2 | Apache-2.0 | Type-checking (`tsc --noEmit`) in CI |
| `world-atlas` | no, build time only | 2.0.2 | ISC | Natural Earth 1:110m country outlines (`countries-110m.json`) compiled by `ui/build.mjs` into static SVG paths (`ui/src/generated/world-paths.ts`) for the offline Geo map |

No runtime CDN, font or analytics dependency: everything is embedded and served
by the Hub (§7). Charts are hand-written SVG. `npm ci --ignore-scripts` is used
in CI and release builds.

`sdk/python` has zero runtime dependencies (standard library only, §11.6).
`setuptools` (MIT) is needed only to `pip install` it (`pyproject.toml` build
backend); sensors may vendor `doppel_sdk/` instead. The Python template
image uses `gcr.io/distroless/python3-debian13:nonroot` (Apache-2.0; CPython
under the PSF licence), pinned by digest.

`sdk/go` has zero third-party dependencies by requirement (§5.9).

Only modules linked into a build are listed (`go list -deps`). Modules that
appear in `go.sum` solely through dependencies' tests or tooling are not
linked; at the time of writing that includes `github.com/hashicorp/golang-lru/v2`
(MPL-2.0, file-level — permitted) and `golang.org/x/tools`.

### CI and release tooling (not shipped)

Pinned by commit SHA in `.github/workflows/` (Dependabot proposes bumps):
`actions/checkout` v7.0.1, `actions/setup-go` v7.0.0, `actions/setup-node`
v7.1.0 (MIT); `actions/upload-artifact` v7.0.2 (MIT; keeps the CodeQL SARIF);
`actions/create-github-app-token` v3.3.0 (MIT; mints the
short-lived token that publishes to the public releases repository);
`github/codeql-action` v4.39.1 (MIT); `docker/login-action`
v4.7.0, `docker/setup-buildx-action` v4.4.1, `docker/build-push-action`
v7.4.0 (Apache-2.0); `sigstore/cosign-installer` v4.1.2 (Apache-2.0) installing
cosign v3.0.6 (Apache-2.0); `aquasecurity/trivy-action` v0.36.0 (Apache-2.0)
running Trivy v0.70.0 (Apache-2.0). `crane` v0.22.1
(`github.com/google/go-containerregistry`, Apache-2.0) via `go install`
(checksum-verified by sum.golang.org). `python3-yaml` (MIT) and
`python3-jsonschema` (MIT) from the Ubuntu archive.
Base images (pinned by digest): `golang:1.26.10-bookworm` (BSD-3-Clause Go;
Debian packages under their own licences, build stage only) and
`gcr.io/distroless/static-debian12:nonroot` (Apache-2.0; shipped runtime base).


### GeoIP module (hub, merge import H1)

| Module | Component | Version | Licence | Justification |
|---|---|---|---|---|
| `github.com/oschwald/maxminddb-golang/v2` | hub (`internal/geoip`) | v2.9.0 (2026-10-31) | ISC | Reads the MMDB format of the DB-IP City Lite database. The standard library has no MMDB reader. Its v2.9.0 also raises `go.yaml.in/yaml/v3` to v3.0.5 (transitive, Apache-2.0) |
| `github.com/maxmind/mmdbwriter` | test fixture generator only (`hub/internal/geoip/testdata/gen`, not in any `go.mod`) | v1.2.0 | Apache-2.0 | Regenerates the two test databases. It is never built into the Hub |

**Data, not code:** the operator supplies DB-IP IP to City Lite
(<https://db-ip.com>, CC BY 4.0). It is not distributed with Doppel. The UI
credits DB-IP wherever it shows a location, as the licence requires
(`ui/src/pages/events.tsx`, `ui/src/pages/analytics/geo-map.tsx`).
