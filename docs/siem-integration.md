# SIEM integration

Spec §6.9. One destination at a time, configured in Settings → SIEM output
(`PUT /api/v3/settings/siem`). The token is write-only.

| Protocol | Address | Payload | Available |
|---|---|---|---|
| `tcp` | `host:port` | one record per line (`\n`) | now |
| `tls` | `host:port` | as `tcp`, TLS ≥ 1.2, verified against system roots + `TS_SIEM_CA_BUNDLE` | now |
| `udp` | `host:port` | one record per datagram (records > 65 000 bytes are dropped) | now |
| `elastic` | `https://<cluster>/<data stream>` | ECS via bulk `create`, `Authorization: ApiKey` | when the PORTED transport + ECS renderer are imported |
| `logscale` | HEC URL | ECS in HEC `event`, `sourcetype: truesignal`, `Authorization: Bearer` | as above |

Stream formats: `rfc5424` (default) or `ecs` (ECS JSON per line; requires the
PORTED renderer).

## ECS field contract

**Owned by the PORTED ECS renderer (§12).** That module's documentation is
inserted here when it is imported; SIEM detection rules depend on it and it
must not be changed by this repository.

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
| `EVENT` | `truesignal@<PEN>` | `event_id, trigger, severity, source, target, node, node_id, sensor, whitelisted, known_scanner, mitre_technique, mitre_tactic, source_asset, source_asset_criticality, source_country, source_geo_basis` |
| `AUDIT` | `truesignal-audit@<PEN>` | `action, route, path, status, actor_ip` (`route` = `METHOD template`) |
| `HONEYTOKEN` | `truesignal-honeytoken@<PEN>` | `honeytoken_id, username, planted_node_id, planted_sensor_id, status` |
| `HEARTBEAT` | `truesignal-hub@<PEN>` | `version, uptime_seconds, nodes_total, nodes_online, sensors_total, sensors_online, siem_queue_depth, siem_dropped` |

PEN defaults to 32473 (`TS_SYSLOG_PEN`). Audit action names: [`audit-actions.md`](audit-actions.md).

## What is sent

* Every stored event, **including** whitelisted and known-scanner events
  (flagged `whitelisted` / `known_scanner`); Hub-raised liveness and
  `honeytoken_used` events.
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
