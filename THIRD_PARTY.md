# Third-party dependencies

Policy (spec §0.5, §13): permissive licences only (MIT, BSD, Apache-2.0, ISC,
MPL-2.0 file-level). No GPL/AGPL/LGPL. Standard library preferred; every entry
must state why it is needed.

| Module / package | Component | Version | Licence | Justification |
|---|---|---|---|---|
| Go standard library | all | go1.26 | BSD-3-Clause | Baseline |
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

### Admin UI (`ui/`, npm, exact versions pinned in `package-lock.json`)

| Package | Shipped? | Version | Licence | Justification |
|---|---|---|---|---|
| `preact` | yes (bundled into the Hub binary) | 10.27.2 | MIT | 4 kB component/rendering library; escapes text by default (no HTML injection path) |
| `esbuild` (+ its `@esbuild/<platform>` binary) | no, build time only | 0.25.12 | MIT | Bundles and minifies the UI into one script + one stylesheet (CSP-compatible output) |
| `typescript` | no, build time only | 5.9.3 | Apache-2.0 | Type-checking (`tsc --noEmit`) in CI |

No runtime CDN, font or analytics dependency: everything is embedded and served
by the Hub (§7). Charts are hand-written SVG. `npm ci --ignore-scripts` is used
in CI and release builds.

`sdk/go` has zero third-party dependencies by requirement (§5.9).

Only modules linked into a build are listed (`go list -deps`). Modules that
appear in `go.sum` solely through dependencies' tests or tooling are not
linked; at the time of writing that includes `github.com/hashicorp/golang-lru/v2`
(MPL-2.0, file-level — permitted) and `golang.org/x/tools`.

### CI and release tooling (not shipped)

Pinned by commit SHA in `.github/workflows/` (Dependabot proposes bumps):
`actions/checkout` v7.0.1, `actions/setup-go` v7.0.0, `actions/setup-node`
v7.1.0 (MIT); `github/codeql-action` v4.39.1 (MIT); `docker/login-action`
v4.7.0, `docker/setup-buildx-action` v4.4.1, `docker/build-push-action`
v7.4.0 (Apache-2.0); `sigstore/cosign-installer` v4.1.2 (Apache-2.0) installing
cosign v3.0.6 (Apache-2.0); `aquasecurity/trivy-action` v0.36.0 (Apache-2.0)
running Trivy v0.70.0 (Apache-2.0). `crane` v0.22.1
(`github.com/google/go-containerregistry`, Apache-2.0) via `go install`
(checksum-verified by sum.golang.org). `python3-yaml` (MIT) and
`python3-jsonschema` (MIT) from the Ubuntu archive.
Base images (pinned by digest): `golang:1.26.2-bookworm` (BSD-3-Clause Go;
Debian packages under their own licences, build stage only) and
`gcr.io/distroless/static-debian12:nonroot` (Apache-2.0; shipped runtime base).

