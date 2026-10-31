# TrueSignal Python sensor SDK

Contract v3 (`docs/contract-v3.md`), the same behaviour as the Go SDK (§5),
standard library only (Python ≥ 3.11). For community sensors (§11.6).

```python
from truesignal_sdk import Drill, Spec, Severity, main

def run(sensor, stop):            # runs in a worker thread
    while not stop.wait(1):
        ...
        sensor.report("my_trigger", source_ip, "My decoy (port 2222)", {"user": name})
        sensor.report_severity(Severity.CRITICAL, "my_login", source_ip, "My decoy", [("user", name)])

main(Spec(drill=Drill("my_trigger", "My decoy (fire drill)"), run=run))
```

| Requirement (§5) | Implementation |
|---|---|
| Config from env; missing endpoint/key/id → exit 2 (test mode needs only the endpoint) | `config.py` (`TS_HUB_ENDPOINT`, `TS_NODE_KEY`, `TS_SENSOR_ID`, `TS_DEFAULT_SEVERITY`, `TS_CONFIG_REVISION`, `TS_TEST_MODE`, `TS_CA_BUNDLE`); `sensor.setting("TS_…")` never exposes reserved keys |
| Event API, UUIDv7 ids, `occurred_at` | `report` / `report_severity`; details as a dict or ordered `(key, value)` pairs; `uuid7.py` (monotonic within a millisecond) |
| Bounded queue (1000, drop oldest, counted → `dropped_events`) | `eventqueue.py`, reported in the next heartbeat |
| Batches ≤ 100 / 1 s; 7 attempts, exponential backoff with jitter, cap 60 s; 4xx except 408/429 not retried; `Retry-After` honoured | `Sensor._sender`, `_deliver`; retries resend the same `event_id` |
| Heartbeat every 30 s with the config revision | `Sensor._heartbeats` |
| SIGTERM/SIGINT: flush ≤ 5 s, stop notice, exit 0 | `Sensor._service` (signals handled on the main thread) |
| SIGUSR1 fire drill (`source` = `Fire drill`) | `Spec.drill` |
| Test mode (`TS_TEST_MODE=true`): send the drill, wait ≤ 10 s, exit 0/1 | `Sensor._test_mode` |
| TLS: system roots + optional CA bundle; never disabled; redirects not followed | `client.py` |
| Decoy-helper seam (PORTED) | `Reporter` protocol: `report_severity`, `setting` |

Exit codes: 0 success, 1 failure (test mode not acknowledged, sensor body
raised), 2 invalid configuration. Helpers: `SourceLimiter` (per-source
cooldown with `suppressed_since_last`), `printable` (escape raw payloads),
`clean` (sanitise short strings).

`template/` is a minimal sensor (TCP connection reporter) with a distroless,
non-root Dockerfile and a manifest. Tests: `python3 -m unittest discover -s tests`.
