# SIEM integration

Spec §6.9. One destination at a time, configured in Settings → SIEM output
(`PUT /api/v3/settings/siem`). The token is write-only.

| Protocol | Address | Payload | Available |
|---|---|---|---|
| `tcp` | `host:port` | one record per line (`\n`) | now |
| `tls` | `host:port` | as `tcp`, TLS ≥ 1.2, verified against system roots + `TS_SIEM_CA_BUNDLE` | now |
| `udp` | `host:port` | one record per datagram (records > 65 000 bytes are dropped) | now |
| `elastic` | `https://<cluster>/<data stream>` | ECS via bulk `create`, `Authorization: ApiKey` | installed (`hub/internal/siemhttp`) |
| `logscale` | HEC URL | ECS in HEC `event`, `sourcetype: truesignal`, `Authorization: Bearer` | installed (`hub/internal/siemhttp`) |

Stream formats: `rfc5424` (default) or `ecs` (ECS JSON per line; the ECS
renderer is installed, `hub/internal/ecs`).

## ECS field contract

Rendered by `hub/internal/ecs` (merge import H9, `PROVENANCE.md`). ECS 8.11.
SIEM detection rules (`docs/siem/detection-rules.md`) depend on these fields:
change them only deliberately, with a QUESTIONS entry.

| Record | `event.kind` / `event.dataset` | Main fields |
|---|---|---|
| Event | `alert` (`event` when the source is whitelisted or a known scanner, and for Hub liveness `sensor_*`; `pipeline_test` for a fire drill) / `truesignal.alert` | `event.action` (trigger), `event.severity` (critical 99, high 73, medium 47, low 21, info 1), `event.category` (`intrusion_detection` plus `authentication`, `file`, `web` or `network`; `host` for liveness), `event.outcome: failure` for logins, `event.id` (event UUID), `source.ip` (canonical IP when parseable, including `ip:port` and `[v6]:port`; otherwise `source.address`), `source.port` (when an ephemeral source port is present), `source.geo.*` (GeoIP, basis `source` only), `destination.port`, `user.name` / `user.domain` (`DOMAIN\user` split), `file.path` or `url.path`, `user_agent.original`, `http.request.method`, `host.{name,id}`, `observer.{type: honeypot, vendor, product}`, `threat.*` (ATT&CK, `docs/siem/attack-mapping.md`), `tags` (`whitelisted`, `known_scanner`, `drill`), `labels.drill: true` on fire drills only (no `threat.*` on drills) |
| Audit | `event` / `truesignal.audit` | `event.action`, `event.outcome`, `event.category` (`authentication` for login, logout and setup; otherwise `configuration`), `url.path`, `http.response.status_code`, `source.ip`, `source.port` (when present) |
| Honeytoken inventory | `enrichment` / `truesignal.honeytoken` | `user.name`, `threat.indicator.type: user-account` (watchlist for real authentication logs; never the secret) |
| Hub heartbeat | `metric` / `truesignal.heartbeat` | `service.version`, `truesignal.heartbeat.*` (node, sensor and SIEM queue counters) |

Every document also carries the full Hub record under `truesignal.*`
(`truesignal.details` is free-form per sensor: map it as `flattened` in
Elastic). Captured secrets (password HMACs, NTLM responses) stay under
`truesignal.details` and never reach `user.*`. The `truesignal` namespace,
dataset prefix and vendor strings are wire identifiers (Q66).

## Elastic setup

`truesignal.details` differs per sensor, so map it as `flattened` to avoid mapping conflicts. The template below assumes Elastic 8.13+ (for the `ecs@mappings` component). Create it once:

```json
PUT _index_template/logs-truesignal
{
  "index_patterns": ["logs-truesignal-*"],
  "data_stream": {},
  "priority": 200,
  "composed_of": ["logs@mappings", "logs@settings", "ecs@mappings"],
  "template": {
    "mappings": {
      "properties": {
        "truesignal": { "properties": { "details": { "type": "flattened" } } }
      }
    }
  }
}
```

API key for the Hub, limited to writing its own data stream:

```json
POST /_security/api_key
{
  "name": "truesignal-hub",
  "role_descriptors": {
    "truesignal_writer": {
      "indices": [{ "names": ["logs-truesignal-*"], "privileges": ["create_doc", "auto_configure"] }]
    }
  }
}
```

In the Hub's SIEM settings choose `elastic`, put the response's `encoded` value in the token field and set the address to `https://<es-host>:9200/logs-truesignal-default`. To check ingest, search `event.module:truesignal` in Discover.

## LogScale setup

1. Create (or choose) a repository and an **ingest token** for it. Assign a parser that parses JSON (for example the built-in `json` parser) so the ECS fields are extracted.
2. In the Hub's SIEM settings choose `logscale`, set the address to `https://<your-logscale>/api/v1/ingest/hec` and the token to the ingest token.
3. To check ingest, search the repository for `event.module = "truesignal"`.

As an alternative, `tcp`/`tls` with format `ecs` works with the LogScale Collector or Elastic Agent's TCP input.

## RFC 5424 contract (this repository)

```
<PRI>1 <timestamp> truesignal truesignal-hub - <MSGID> [<SD-ID> k="v" …] <record JSON>
```

* Facility local0. PRI severity: events critical 2, high 3, medium 4, low 5,
  info 6; AUDIT 5; HONEYTOKEN 6; HEARTBEAT 6.
* Timestamp RFC 3339 UTC with microseconds. MSG is the full record as
  single-line JSON (no BOM).
* PARAM-VALUE escaping per RFC 5424 §6.3.3 (`"`, `\`, `]`), control
  characters → space, invalid UTF-8 replaced, values ≤ 1024 bytes. No
  attacker-controlled value can break line framing (tested with `"]\n`).

| MSGID | SD-ID | Parameters (in order; new ones only appended) |
|---|---|---|
| `EVENT` | `truesignal@<PEN>` | `event_id, trigger, severity, source, target, node, node_id, sensor, whitelisted, known_scanner, mitre_technique, mitre_tactic, source_asset, source_asset_criticality, source_country, source_geo_basis`, then `drill="1"` on fire drills only |
| `AUDIT` | `truesignal-audit@<PEN>` | `action, route, path, status, actor_ip` (`route` = `METHOD template`) |
| `HONEYTOKEN` | `truesignal-honeytoken@<PEN>` | `honeytoken_id, username, planted_node_id, planted_sensor_id, status` |
| `HEARTBEAT` | `truesignal-hub@<PEN>` | `version, uptime_seconds, nodes_total, nodes_online, sensors_total, sensors_online, siem_queue_depth, siem_dropped` |

PEN defaults to 32473 (`TS_SYSLOG_PEN`). Audit action names: [`audit-actions.md`](audit-actions.md).

## What is sent

* Every stored event, **including** whitelisted and known-scanner events
  (flagged `whitelisted` / `known_scanner`); Hub-raised events:
  `honeytoken_used`, `sensor_stopped`, `sensor_heartbeat_lost`,
  `sensor_recovered`, and `node_apply_failed` (a node could not apply its
  configuration and rolled back or failed — its decoys may not be running as
  configured; `sensor` is empty, `target` is the node id; once per node and
  revision).
* Fire drills (`doppel firedrill`, sensor test mode), labelled so they never
  page anyone: ECS `event.kind: pipeline_test`, `labels.drill: true`, tag
  `drill`, severity `info` (the sensor's severity in
  `truesignal.details.original_severity`), no ATT&CK mapping; syslog
  `drill="1"`. The shipped rules exclude them and `truesignal-drill-received`
  records each one (F-001).
* Every audit record (state-changing admin requests, logins, setup attempts,
  `mfa.reset_cli`).
* Honeytoken inventory (username and planting location, never the secret):
  on creation, at Hub start and every 24 h.
* Hub heartbeat every 5 minutes (SIEM-only): version, uptime, node/sensor
  totals and online counts, queue depth, dropped count. Alert on its absence
  to detect a dead or blinded Hub.

## Delivery guarantees and limits

* Queue of 5 000 records in memory; when full, **new** records are dropped and
  counted (`siem_dropped` in the heartbeat and in `GET /api/v3/settings/siem`).
  The queue does not survive a Hub restart; shutdown flushes for up to 5 s.
* Transient failures (network, 5xx, 429) are retried with exponential backoff
  and jitter (0.5 s doubling, cap 30 s), up to 10 attempts per record;
  terminal failures (other 4xx, Elastic per-item errors) drop the record with
  a log line.
* Stream outputs check before every write whether the collector closed the
  connection (1 ms read; EOF/reset ⇒ reconnect, at most every 2 s), so a
  collector restart loses no record. **Limit:** a collector that disappears
  without closing the connection (host crash, network partition) cannot be
  detected this way; records written into that dead connection can be lost.
  Use `tls`/`tcp` to a local relay or monitor the heartbeat.
* Changing the output applies immediately: retries against the old
  destination are abandoned, the `siem.update` audit record is delivered to
  the previous destination (bounded to 10 s), then the switch happens; queued
  records and the post-change audit go to the new destination.
