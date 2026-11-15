# Copyright (c) 2026 TrueSignal Deception. All rights reserved.
"""Sensor runtime (§5): event queue and batched sender with retries,
heartbeats, graceful shutdown with stop notice, fire drill (SIGUSR1) and
test mode.

Threads: the sensor body, the sender and the heartbeat loop run in worker
threads; the main thread owns signal handling (Python delivers signals only
to the main thread) and the shutdown sequence."""

from __future__ import annotations

import json
import logging
import random
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional, Protocol

from .client import PATH_EVENTS, PATH_HEARTBEATS, PATH_STOPPING, REQUEST_TIMEOUT, HubClient, HubError, ingest_response, retryable
from .config import Config, ConfigError
from .events import DRILL_SOURCE, Details, Severity, encode_details, now_rfc3339
from .eventqueue import EventQueue
from .uuid7 import UUID7

SDK_VERSION = "3.0.0"


@dataclass(frozen=True)
class Drill:
    """The synthetic event sent on SIGUSR1 and in test mode (source is
    always "Fire drill")."""

    trigger: str
    target: str
    severity: Optional[Severity] = None  # None: the sensor's default severity
    details: Details = None


@dataclass(frozen=True)
class Spec:
    drill: Drill
    # run(sensor, stop) is the sensor body. It must return soon after
    # stop.is_set(); returning ends the sensor ("sensor finished"); raising
    # ends it with exit code 1.
    run: Optional[Callable[["Sensor", threading.Event], None]] = None


class Reporter(Protocol):
    """The seam for the PORTED decoy helper package (§5): report an event with
    a severity, and read a sensor setting."""

    def report_severity(self, severity: Severity, trigger: str, source: str, target: str, details: Details = None) -> None: ...

    def setting(self, name: str) -> Optional[str]: ...


@dataclass
class Options:
    env: Optional[Mapping[str, str]] = None
    logger: Optional[logging.Logger] = None
    install_signals: bool = True
    queue_size: int = 1000
    batch_size: int = 100
    batch_delay: float = 1.0
    heartbeat_interval: float = 30.0
    max_attempts: int = 7
    backoff_base: float = 1.0
    backoff_cap: float = 60.0
    flush_timeout: float = 5.0
    test_mode_timeout: float = 10.0
    # Tests only: replaces signal delivery. Put "TERM"/"INT"/"USR1" here.
    signal_queue: Any = field(default=None, repr=False)


class _JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out = {"time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"), "level": record.levelname, "msg": record.getMessage()}
        out.update(getattr(record, "fields", {}))
        return json.dumps(out, ensure_ascii=False, default=str)


def _default_logger() -> logging.Logger:
    log = logging.getLogger("doppel_sdk")
    if not log.handlers:
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(_JSONFormatter())
        log.addHandler(h)
        log.setLevel(logging.INFO)
        log.propagate = False
    return log


class Sensor:
    """Handed to the sensor body. Thread-safe."""

    def __init__(self, cfg: Config, client: HubClient, opts: Options, log: logging.Logger):
        self.config = cfg
        self._client = client
        self._opts = opts
        self._log = log
        self._q = EventQueue(opts.queue_size)
        self._ids = UUID7()

    # ---- public API -------------------------------------------------------

    def log(self, level: int, msg: str, **fields: Any) -> None:
        self._log.log(level, msg, extra={"fields": {"sensor_id": self.config.sensor_id, **fields}})

    def setting(self, name: str) -> Optional[str]:
        return self.config.setting(name)

    def report(self, trigger: str, source: str, target: str, details: Details = None) -> None:
        """Queues an event with the sensor's default severity. Never blocks;
        on overflow the oldest queued event is dropped and counted."""
        self.report_severity(self.config.default_severity, trigger, source, target, details)

    def report_severity(self, severity: Severity, trigger: str, source: str, target: str, details: Details = None) -> None:
        self._q.push(self._build(severity, trigger, source, target, details))

    # ---- internals --------------------------------------------------------

    def _build(self, severity: Any, trigger: str, source: str, target: str, details: Details) -> dict:
        try:
            sev = Severity(severity)
        except ValueError:
            self.log(logging.WARNING, "invalid severity, using default", severity=str(severity))
            sev = self.config.default_severity
        try:
            det = encode_details(details)
        except Exception as e:  # a sensor bug must not kill the sender
            self.log(logging.WARNING, "event details not encodable, sending marker", trigger=trigger, error=str(e))
            det = {"details_encode_error": True}
        return {
            "event_id": self._ids.next(),
            "sensor_id": self.config.sensor_id,
            "trigger": trigger,
            "severity": sev.value,
            "occurred_at": now_rfc3339(),
            "source": source,
            "target": target,
            "details": det,
        }

    def _drill_event(self, d: Drill) -> dict:
        return self._build(d.severity or self.config.default_severity, d.trigger, DRILL_SOURCE, d.target, d.details)

    def _backoff(self, attempt: int) -> float:
        d = min(self._opts.backoff_base * (2 ** (attempt - 1)), self._opts.backoff_cap)
        return d / 2 + random.uniform(0, d / 2)

    def _deliver(self, batch: list, abort: threading.Event) -> None:
        attempt = 0
        while True:
            attempt += 1
            try:
                out = self._client.post(PATH_EVENTS, {"events": batch})
            except Exception as err:  # HubError or network/TLS error
                if not retryable(err):
                    self.log(logging.ERROR, "event batch refused, dropping", events=len(batch), error=str(err))
                    self._q.add_dropped(len(batch))
                    return
                if attempt >= self._opts.max_attempts or abort.is_set():
                    self.log(logging.ERROR, "event batch undeliverable, dropping", events=len(batch), attempts=attempt, error=str(err))
                    self._q.add_dropped(len(batch))
                    return
                wait = self._backoff(attempt)
                if isinstance(err, HubError) and err.retry_after > wait:
                    wait = min(err.retry_after, self._opts.backoff_cap)
                self.log(logging.WARNING, "event delivery failed, retrying", attempt=attempt, wait=round(wait, 2), error=str(err))
                if abort.wait(wait):
                    self._q.add_dropped(len(batch))
                    return
                continue
            _, _, rejected = ingest_response(out)
            for r in rejected:
                i = r.get("index", -1) if isinstance(r, dict) else -1
                trig = batch[i]["trigger"] if isinstance(i, int) and 0 <= i < len(batch) else ""
                self.log(logging.WARNING, "hub rejected event", index=i, trigger=trig, error=r.get("error") if isinstance(r, dict) else r)
            return

    def _sender(self, flushing: threading.Event, abort: threading.Event) -> None:
        o = self._opts
        while not abort.is_set():
            if not flushing.is_set():
                if self._q.wait(0.2) == 0:
                    continue
                deadline = time.monotonic() + o.batch_delay
                while not flushing.is_set() and not abort.is_set():
                    left = deadline - time.monotonic()
                    if left <= 0 or self._q.wait(left, o.batch_size) >= o.batch_size:
                        break
            batch = self._q.pop(o.batch_size)
            if not batch:
                if flushing.is_set():
                    return
                continue
            self._deliver(batch, abort)

    def _heartbeat(self) -> None:
        dropped = self._q.take_dropped()
        body: dict = {"sensor_id": self.config.sensor_id, "config_revision": self.config.config_revision, "sdk_version": SDK_VERSION}
        if dropped:
            body["dropped_events"] = dropped
        try:
            self._client.post(PATH_HEARTBEATS, body, timeout=REQUEST_TIMEOUT)
        except Exception as e:
            self._q.add_dropped(dropped)  # report again next time
            self.log(logging.WARNING, "heartbeat failed", error=str(e))

    def _heartbeats(self, stop: threading.Event) -> None:
        while True:
            self._heartbeat()
            if stop.wait(self._opts.heartbeat_interval):
                return

    def _test_mode(self, drill: Drill) -> int:
        ev = self._drill_event(drill)
        try:
            out = self._client.post(PATH_EVENTS, {"events": [ev]}, timeout=self._opts.test_mode_timeout)
        except Exception as e:
            self.log(logging.ERROR, "test mode: delivery failed", error=str(e))
            return 1
        accepted, duplicates, rejected = ingest_response(out)
        if accepted + duplicates != 1:
            code = rejected[0].get("error", "") if rejected and isinstance(rejected[0], dict) else ""
            self.log(logging.ERROR, "test mode: hub rejected the synthetic event", error=code)
            return 1
        self.log(logging.INFO, "test mode: synthetic event acknowledged", event_id=ev["event_id"], trigger=ev["trigger"])
        return 0

    def _service(self, spec: Spec) -> int:
        o = self._opts
        pending: "list[str]" = []
        wake = threading.Event()

        def on_signal(signum, _frame):
            pending.append({signal.SIGUSR1: "USR1", signal.SIGINT: "INT"}.get(signum, "TERM"))
            wake.set()

        previous = {}
        if o.install_signals and o.signal_queue is None:
            for s in (signal.SIGTERM, signal.SIGINT, signal.SIGUSR1):
                previous[s] = signal.signal(s, on_signal)

        flushing, abort, stop_body, stop_hb = (threading.Event() for _ in range(4))
        sender = threading.Thread(target=self._sender, args=(flushing, abort), name="ts-sender", daemon=True)
        heart = threading.Thread(target=self._heartbeats, args=(stop_hb,), name="ts-heartbeat", daemon=True)
        result: dict = {}

        def body():
            try:
                spec.run(self, stop_body)  # type: ignore[misc]
            except BaseException as e:  # noqa: BLE001 - reported as the stop reason
                result["error"] = e
            finally:
                result["done"] = True
                wake.set()

        worker = threading.Thread(target=body, name="ts-sensor", daemon=True)
        sender.start()
        heart.start()
        worker.start()
        self.log(logging.INFO, "sensor started", sdk_version=SDK_VERSION, config_revision=self.config.config_revision)

        exit_code, reason = 0, ""
        try:
            while not reason:
                if o.signal_queue is not None:
                    try:
                        pending.append(o.signal_queue.get(timeout=0.1))
                    except Exception:
                        pass
                else:
                    wake.wait(0.2)
                    wake.clear()
                while pending and not reason:
                    sig = pending.pop(0)
                    if sig == "USR1":
                        self._q.push(self._drill_event(spec.drill))
                        self.log(logging.INFO, "fire drill triggered", trigger=spec.drill.trigger)
                    else:
                        reason = f"received SIG{sig}"
                if not reason and result.get("done"):
                    err = result.get("error")
                    if err is not None:
                        reason, exit_code = f"sensor failed: {err}", 1
                    else:
                        reason = "sensor finished"
        finally:
            for s, h in previous.items():
                signal.signal(s, h)

        self.log(logging.INFO, "sensor stopping", reason=reason)
        deadline = time.monotonic() + o.flush_timeout
        stop_body.set()
        if not result.get("done"):
            worker.join(max(0.0, (deadline - time.monotonic()) / 2))
            if worker.is_alive():
                self.log(logging.WARNING, "sensor body did not stop in time")
        stop_hb.set()
        heart.join(REQUEST_TIMEOUT)
        flushing.set()
        self._q.wake()
        sender.join(max(0.0, deadline - time.monotonic()))
        if sender.is_alive():
            abort.set()
            self._q.wake()
            sender.join(REQUEST_TIMEOUT)
        lost = len(self._q)
        if lost:
            self.log(logging.WARNING, "events lost at shutdown", count=lost)
        try:
            r = reason.encode("utf-8")[:128].decode("utf-8", "ignore")
            self._client.post(PATH_STOPPING, {"sensor_id": self.config.sensor_id, "reason": r}, timeout=2.0)
        except Exception as e:
            self.log(logging.WARNING, "stop notice not delivered", error=str(e))
        return exit_code


def run(spec: Spec, options: Optional[Options] = None) -> int:
    """Runs a sensor and returns its exit code: 0 success, 1 failure,
    2 invalid configuration or spec."""
    o = options or Options()
    log = o.logger or _default_logger()
    if not spec.drill or not spec.drill.trigger:
        log.error("sensor spec has no fire-drill trigger")
        return 2
    try:
        cfg = Config.load(o.env)
    except ConfigError as e:
        log.error("invalid sensor configuration: %s", e)
        return 2
    try:
        client = HubClient(cfg.hub_endpoint, cfg.node_key, cfg.ca_bundle, SDK_VERSION)
    except ValueError as e:
        log.error("invalid TLS configuration: %s", e)
        return 2
    o.batch_size = min(max(1, o.batch_size), 100)  # contract: 1..100 events per batch
    s = Sensor(cfg, client, o, log)
    if cfg.test_mode:
        return s._test_mode(spec.drill)
    if spec.run is None:
        log.error("sensor spec has no run function")
        return 2
    return s._service(spec)


def main(spec: Spec) -> None:
    sys.exit(run(spec))
