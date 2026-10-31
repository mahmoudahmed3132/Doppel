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

`sdk/go` has zero third-party dependencies by requirement (§5.9).

Only modules linked into a build are listed (`go list -deps`). Modules that
appear in `go.sum` solely through dependencies' tests or tooling are not
linked; at the time of writing that includes `github.com/hashicorp/golang-lru/v2`
(MPL-2.0, file-level — permitted) and `golang.org/x/tools`.
