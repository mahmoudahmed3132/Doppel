# Sensor manifest v3

Spec §9. Machine-readable schema: [`manifest-v3.schema.json`](manifest-v3.schema.json)
(JSON Schema 2020-12). The Hub additionally enforces the cross-field rules
below (`hub/internal/manifest`), so **the Go validator is authoritative**; CI
runs both. Example: [`sensors/template/manifest.json`](../sensors/template/manifest.json).

Manifests are untrusted. The Hub parses a manifest only after the PORTED
signing module has verified its detached Sigstore bundle, decodes it strictly
(unknown fields rejected, ≤ 256 KiB), and re-validates it on every render.

## Fields

| Field | Notes |
|---|---|
| `schema_version` | `3` |
| `name`, `version` | kebab-case name; SemVer. Must equal the registry index entry. |
| `display_name`, `description`, `category`, `author`, `documentation` | UI text; `documentation` is Markdown (≤ 64 KiB), rendered escaped |
| `image` | `repository`, `tag`, `digest` (`sha256:<64 hex>`, filled by CI), `platforms` |
| `runtime.network_mode` | `host`, `bridge` or `none` |
| `runtime.cap_add` | subset of `NET_RAW`, `NET_BIND_SERVICE`, `DAC_OVERRIDE` |
| `runtime.user` | `uid[:gid]`; default `65532:65532` |
| `runtime.memory_mb` | container memory limit; default 256 |
| `runtime.listen_ports[]` | `config_key` (type `port` or list of `port`) + `protocol`; used for port-conflict checks and, with `bridge`, for publishing |
| `runtime.host_paths[]` | `config_key` (type `path` or list of `path`), `mount` `self`\|`parent`, `read_only`. Container path = host path. |
| `init` | optional init container: pinned `image`, `command` (list, no `$`/`{{`), `cap_add`, `writable_host_paths` (config keys from `runtime.host_paths`), `user` |
| `config[]` | `name` (`TS_…`), `type` (`string int bool enum list port path`), `item_type` for lists, `default`, `required`, `secret`, `hub_reserved`, `description`, `validation` (`pattern` full-match RE2, `min`, `max`, `enum`, `max_items`, `max_length`) |
| `discovery` | `process_names`, `listening_ports`, `files`, `defaults` (templates: `free_port(N)`, `random_choice(a,b,…)`, `hostname()` only) |
| `triggers[]` | `name` (snake_case), `default_severity`, `description` |
| `compatibility.hub_major` | must be `3` |
| `status` | set by the registry index (`active`/`deprecated`); ignored if present in the file |

## Hub-reserved variables

Always set by the Hub; user values are dropped with a warning:
`TS_HUB_ENDPOINT`, `TS_SENSOR_ID`, `TS_CONFIG_REVISION`, `TS_TEST_MODE`,
`TS_NODE_KEY` (added by the CLI on the node, see below).

Set only when the manifest declares them with `"hub_reserved": true`:

| Variable | Value |
|---|---|
| `TS_CAPTURE_KEY` | hex HMAC-SHA256(capture master key, node id) |
| `TS_BEACON_KEY` | hex HMAC-SHA256(beacon master key, `truesignal/beacon-receiver/v1`) |
| `TS_HONEYTOKEN` | JSON `{"id","username","secret"}` from the honeytoken module, created on the first deploy render |

Master keys are generated once, stored in settings and never leave the Hub.

## Values

List values are comma-separated, items trimmed. Control characters are
refused in every value. A `default` that is a discovery template is not
evaluated by the Hub: such a key needs an explicit value (normally filled by
`truesignal discover`).

## Rendered compose (contract with the CLI)

The Hub renders JSON (valid YAML) with deterministic key order:

```json
{
  "name": "truesignal",
  "x-truesignal": {"node_id": "node-…", "revision": "rev_…", "node_key_env": "TS_NODE_KEY"},
  "services": { "<sensor id>": { … }, "<sensor id>-init": { … } }
}
```

Every service: digest-pinned `image`, `container_name` = service name,
`read_only: true`, `cap_drop: [ALL]`, allow-listed `cap_add`,
`security_opt: [no-new-privileges:true]`, `pids_limit: 256`, `mem_limit`,
bounded `json-file` logging, a 16 MiB `/tmp` tmpfs, long-syntax bind mounts
with `bind.create_host_path: false`. Init services: `network_mode: none`,
`restart: "no"`; the main service waits for `service_completed_successfully`.
All `$` in environment values are escaped as `$$`.

**Node key:** the Hub stores only the key's SHA-256, so it cannot render it.
The CLI must add `TS_NODE_KEY=<key from /etc/truesignal/config.json>` to the
`environment` of every service (the variable named by
`x-truesignal.node_key_env`) before writing the file.

## Rule codes (§6.12)

| Code | HTTP | Rule |
|---|---|---|
| `image_not_pinned` | 422 | 1 |
| `capability_not_allowed`, `network_mode_not_allowed` | 422 | 3 |
| `mount_not_allowed` | 422 | 4 |
| `interpolation` | 422 | 5 |
| `missing_config`, `invalid_config` | 422 | 6 |
| `port_conflict` | 409 | 7 |
| `manifest_unavailable`, `manifest_mismatch`, `incompatible_manifest`, `invalid_manifest` | 422 | catalogue / schema |
| `honeytoken_unavailable`, `hub_endpoint_unset` | 422 | rule 9 prerequisites |
