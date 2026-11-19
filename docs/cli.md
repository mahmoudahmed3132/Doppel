# Node agent CLI (`doppel`)

The command is `doppel`. For one release the installer also creates a
`truesignal` link to it, and a node linked under the old paths
(`/etc/truesignal/config.json`, `/opt/truesignal`) keeps using them; new
links use `/etc/doppel/config.json` and `/opt/doppel`. `TS_CONFIG_FILE` and
`TS_WORK_DIR` override both (QUESTIONS Q66).

Spec §8. Runs on each node as root, on demand (not a daemon). Linux and macOS
(darwin) amd64 and arm64 builds; sensors are deployed only on amd64 unless
`TS_ALLOW_NON_AMD64=true` (needed on Apple Silicon, where Docker Desktop runs
the `linux/amd64` sensor images under Rosetta).

On macOS the sensors run inside Docker Desktop's Linux VM: enable host
networking (Docker Desktop 4.34+, *Settings → Resources → Network*) so decoy
ports are reachable from the Mac's interfaces. `doppel discover` reads `/proc`
on Linux and falls back to `lsof` and `ps` where `/proc` is absent; run it
with `sudo` so `lsof` sees every process's sockets.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/mahmoudahmed3132/truesignal-releases/main/install.sh \
  | sudo TS_NODE_KEY='tsk_…' sh -s -- --hub https://hub.example.com
```

`install.sh` downloads `doppel-<os>-<arch>` (`os` is `linux` or `darwin`) from the `cli/vX.Y.Z` release,
verifies it against `SHA256SUMS`, optionally against `--sha256 <hex>`, and —
when `cosign` is installed — against `doppel-<os>-<arch>.sigstore.json`
(identity: `https://github.com/mahmoudahmed3132/Doppel/.github/workflows/publish-cli.yml@refs/tags/cli/vX.Y.Z`;
releases before the move to Doppel name `mahmoudahmed3132/TrueSignal-Rewrite`, operations §9.2). Only
`https://` (or `file://` for mirrors) is fetched. The script body runs from
`main()` on its last line, so a truncated download executes nothing.

## Files

| Path | Mode | Contents |
|---|---|---|
| `/etc/doppel/config.json` | 0600 (dir 0700) | `hub_endpoint`, `node_id`, `node_key`. Refused if group/other-readable. |
| `/opt/doppel/compose.json` | 0600 | active compose file (contains the node key and sensor secrets) |
| `/opt/doppel/compose.json.bak` | 0600 | previous compose file (rollback) |
| `/opt/doppel/.apply.lock` | 0600 | prevents concurrent applies |

`TS_CONFIG_FILE` and `TS_WORK_DIR` override the locations.

## Commands

| Command | Behaviour |
|---|---|
| `link <hub-url>` | Key from `TS_NODE_KEY` (`--key` exists but warns: visible in `ps`). Verifies the key, writes the config, prints the node identity. Plain `http://` is accepted for labs with a warning. |
| `apply` | Fetch → inject `TS_NODE_KEY` into every service → re-check host paths → semantic comparison (no-op if identical) → back up → `docker compose -p truesignal pull` → `up -d --remove-orphans` → after 3 s every service must be running (init services must have exited 0). On failure: restore the backup and bring it up (first deploy: `down`). Reports `applied` / `unchanged` / `rolled_back` / `failed` to the Hub. |
| `discover [--plan] [--json] [--apply] [--yes] [--no-apply]` | Reads `/proc` (listening TCP/UDP sockets, process names) and checks files — no network probing; a local bind test checks candidate ports. Scores catalogue manifests against the host and proposes a conflict-free decoy mix (`--plan` / `--json` preview without modifying the Hub; `--apply` asks per proposal, registers via the admin API, then runs `apply`). Admin password/MFA from `TS_ADMIN_PASSWORD` / `TS_ADMIN_MFA_CODE` or no-echo prompts; never stored. |
| `firedrill` | Sends SIGUSR1 to every container labelled `io.truesignal.role=sensor`. |
| `status [--json]` | Node identity, Hub reachability and version, desired vs local revision, container states. Exit 1 if the Hub is unreachable. |
| `uninstall [--yes]` | `docker compose down --remove-orphans`, removes `/opt/doppel`, the config and the binary. **Lure files are left in place** and listed; reminds you to delete the node in the Hub. |
| `version` | |

Every Hub request sends `X-TrueSignal-CLI-Version`; on `426` the CLI states the
required major version.

## Host-path re-check (why `apply` may refuse)

The Hub cannot see this host's filesystem. Before deploying, every bind-mount
source must exist, must be reached **without symbolic links**, and must not
resolve into `/`, `/etc`, `/run`, `/var/run`, `/proc`, `/sys`, `/dev`, `/boot`,
`/root`, `/usr`, `/bin`, `/sbin`, `/lib*`, `/var/lib/{docker,containerd,kubelet}`
or an ancestor of them. A lure file that already exists as a symlink is
reported (it is never replaced).

## Node API (Hub side, node-key authenticated)

| Method | Path | Purpose |
|---|---|---|
| GET | `/v3/node/identity` | node id, alias, tags, desired/applied revision, Hub version |
| GET | `/v3/node/compose` | the node's **unredacted** compose (JSON) and revision |
| POST | `/v3/node/applied` | `{"revision","result","message"}`; `applied`/`unchanged` update the applied revision |

All require `X-TrueSignal-CLI-Version` with the Hub's major version; otherwise
`426 version_mismatch` with `required_major`.
