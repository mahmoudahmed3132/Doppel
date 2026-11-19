# Sensor ↔ Hub contract v3

Normative source: specification §4. This page records the wire details the
specification leaves open (see `QUESTIONS.md` for the open items).

## Transport

- `POST` JSON (UTF-8), `Content-Type: application/json`, body ≤ 256 KiB.
- `Authorization: Bearer <node key>` (`tsk_` + 64 lowercase hex).
- Unknown top-level fields → `400 unknown_field`.
- Envelope: `{"ok": true, ...}` or `{"ok": false, "error": "<code>", "message": "<text>"}`.
- Per-node-key token bucket, 50 req/s, burst 200 → `429 rate_limited` with `Retry-After` (seconds).
- Hub-wide ingest admission (event batches only): at most 8 batches are processed
  at once; a batch that cannot start within 1 s → `429 overloaded` with
  `Retry-After` (seconds). Heartbeats and stop notices are not gated. SDKs already
  retry every `429`, so no capability check is needed (Q87).
- Redirects are never issued on ingest paths; the SDK refuses to follow them.

## Endpoints

| Method | Path | Body | Success reply |
|---|---|---|---|
| GET | `/v3/version` | — | `{"product":"truesignal-hub","version":"3.0.0","contract":3}` |
| POST | `/v3/ingest/events` | `{"events":[<event>…]}` (1..100) | `{"ok":true,"accepted":n,"duplicates":m,"rejected":[{"index":i,"error":"<code>"}]}` |
| POST | `/v3/ingest/heartbeats` | `{"sensor_id","config_revision","sdk_version","dropped_events"?}` | `{"ok":true}` |
| POST | `/v3/ingest/stopping` | `{"sensor_id","reason"}` (reason ≤ 128 chars) | `{"ok":true}` |

`dropped_events` (optional, integer ≥ 0): events the SDK lost since the last
acknowledged heartbeat (queue overflow or undeliverable batches). See Q3. The
Hub adds it to the sensor's cumulative `dropped_events` (saturating), shown on
the node page and in the sensor view (F-603).

### Durability (F-603, NFR-7)

A `200` from `/v3/ingest/events` is sent only after every accepted event of the
batch has been committed to the database with an fsync (SQLite WAL,
`synchronous=FULL`). An acknowledged event therefore survives a Hub process
kill, an OS crash or a power loss. Any other reply (including a dropped
connection) acknowledges nothing: the SDK resends the whole batch, and events
the Hub had already stored come back as `duplicates` (idempotency by
`event_id` per node).

### Event object

| Field | Type | Notes |
|---|---|---|
| `event_id` | string | UUIDv7 (RFC 9562), sensor-generated; idempotency key per node |
| `sensor_id` | string | `ts-sensor-<kebab-name>`, must belong to the authenticated node |
| `trigger` | string | snake_case; Hub-reserved triggers are refused (`403 reserved_trigger`) |
| `severity` | string | `info`, `low`, `medium`, `high`, `critical` |
| `occurred_at` | string | RFC 3339 with offset |
| `source` | string | IP, IP:port, or short name |
| `target` | string | what was touched |
| `details` | object | sensor-specific, ≤ 64 KiB |

### Error codes

| HTTP | Code | When |
|---|---|---|
| 400 | `invalid_json`, `unknown_field`, `invalid_batch` | malformed body / batch size outside 1..100 |
| 401 | `unauthorized` | missing or unknown node key |
| 403 | `reserved_trigger` | per-event (in `rejected`) or whole request for a single-event batch |
| 404 | `sensor_not_registered` | sensor id not on the authenticated node |
| 413 | `body_too_large` | body > 256 KiB |
| 426 | `version_mismatch` | CLI major ≠ Hub major (CLI only) |
| 429 | `rate_limited` | token bucket exhausted |
| 429 | `overloaded` | Hub-wide ingest admission full (event batches only) |

## Sensor environment (set by the Hub's compose compiler; reserved)

| Variable | Meaning |
|---|---|
| `TS_HUB_ENDPOINT` | Hub base URL (`https://…`; `http://` for lab only) |
| `TS_NODE_KEY` | node key |
| `TS_SENSOR_ID` | sensor instance id |
| `TS_DEFAULT_SEVERITY` | default event severity (default `medium`) |
| `TS_CONFIG_REVISION` | `rev_xxxxxxxx` of the rendered compose |
| `TS_TEST_MODE` | `true` → send the synthetic event once and exit |
| `TS_CA_BUNDLE` | optional PEM file appended to system roots |
| `TS_CAPTURE_KEY` | per-node capture hash key (HMAC key) |
| `TS_HONEYTOKEN` | File Canary honeytoken credential |
| `TS_BEACON_KEY` | Token Receiver beacon key |

## SDK delivery semantics

- Queue: 1000 events, drop-oldest, drops counted.
- Per-event limits applied before queueing (F-603): `details` over 64 KiB are
  replaced with `{"details_dropped":true}` (as the Hub would), `source` and
  `target` are truncated to 256 bytes. Queue memory is therefore bounded by
  queue size × about 65 KiB.
- Batching: up to 100 events or 1 s.
- Retry: network errors, `408`, `429`, `5xx`; up to 7 attempts per batch;
  delay = min(60 s, 1 s·2^(n-1)) with jitter in [d/2, d]; `Retry-After`
  honoured up to 60 s. Other `4xx`: batch dropped and counted.
- Heartbeat: immediately at start, then every 30 s.
- SIGTERM/SIGINT: stop the sensor body, flush ≤ 5 s, send stop notice, exit 0.
- SIGUSR1: queue the sensor's synthetic event with `source = "Fire drill"`.
- Test mode: send the synthetic event once; exit 0 when the Hub counts it as
  accepted or duplicate within 10 s, else 1.

## Node agent endpoints

See [`cli.md`](cli.md#node-api-hub-side-node-key-authenticated): `GET /v3/node/identity`,
`GET /v3/node/compose`, `POST /v3/node/applied`. Same bearer node key; additionally
`X-TrueSignal-CLI-Version` must carry the Hub's major version (`426 version_mismatch`,
body includes `required_major`).
