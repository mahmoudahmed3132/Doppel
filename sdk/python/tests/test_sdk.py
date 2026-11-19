# Copyright (c) 2026 TrueSignal Deception. All rights reserved.
"""Tests for the Python SDK against a mock Hub over real HTTP."""

from __future__ import annotations

import json
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from doppel_sdk import Drill, Options, Severity, SourceLimiter, Spec, printable, clean, run  # noqa: E402
from doppel_sdk.config import Config, ConfigError  # noqa: E402
from doppel_sdk.eventqueue import EventQueue  # noqa: E402
from doppel_sdk.events import encode_details  # noqa: E402
from doppel_sdk.uuid7 import UUID7  # noqa: E402

UUID7_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
KEY = "tsk_" + "a" * 64


class MockHub:
    """Records requests; per-path response scripts (status, body, headers)."""

    def __init__(self):
        self.requests: list = []
        self.scripts: dict = {}
        self.lock = threading.Lock()
        hub = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(n) or b"{}")
                with hub.lock:
                    hub.requests.append((self.path, dict(self.headers), body))
                    script = hub.scripts.get(self.path) or []
                    status, resp, hdrs = script.pop(0) if script else (200, None, {})
                if resp is None and self.path == "/v3/ingest/events":
                    resp = {"ok": True, "accepted": len(body.get("events", [])), "duplicates": 0, "rejected": []}
                data = json.dumps(resp if resp is not None else {"ok": True}).encode()
                self.send_response(status)
                for k, v in hdrs.items():
                    self.send_header(k, v)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()

    def bodies(self, path):
        with self.lock:
            return [b for p, _, b in self.requests if p == path]

    def events(self):
        return [e for b in self.bodies("/v3/ingest/events") for e in b["events"]]

    def wait(self, pred, timeout=5.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if pred():
                return True
            time.sleep(0.02)
        return False


def env(hub, **extra):
    e = {"TS_HUB_ENDPOINT": hub.url + "/", "TS_NODE_KEY": KEY, "TS_SENSOR_ID": "ts-sensor-x", "TS_CONFIG_REVISION": "rev_12345678"}
    e.update(extra)
    return e


DRILL = Drill("x_trigger", "X (fire drill)", details=[("port", 0), ("phase", "drill")])


def fast(hub, **kw):
    o = Options(env=env(hub, **kw.pop("env", {})), install_signals=False, signal_queue=queue.Queue(),
                batch_delay=0.05, heartbeat_interval=0.2, backoff_base=0.01, backoff_cap=0.05, flush_timeout=2.0)
    for k, v in kw.items():
        setattr(o, k, v)
    return o


class ConfigTests(unittest.TestCase):
    def test_required_and_validation(self):
        with self.assertRaises(ConfigError) as cm:
            Config.load({})
        msg = str(cm.exception)
        for k in ("TS_HUB_ENDPOINT", "TS_NODE_KEY", "TS_SENSOR_ID"):
            self.assertIn(k, msg)
        for bad in ("ftp://hub", "https://user:pw@hub", "https://", "https://hub:99999"):
            with self.assertRaises(ConfigError, msg=bad):
                Config.load({"TS_HUB_ENDPOINT": bad, "TS_NODE_KEY": "k", "TS_SENSOR_ID": "s"})
        with self.assertRaises(ConfigError):
            Config.load({"TS_HUB_ENDPOINT": "https://hub", "TS_TEST_MODE": "yes"})
        with self.assertRaises(ConfigError):
            Config.load({"TS_HUB_ENDPOINT": "https://hub", "TS_NODE_KEY": "k", "TS_SENSOR_ID": "s", "TS_DEFAULT_SEVERITY": "urgent"})

    def test_test_mode_needs_only_endpoint_and_settings_hide_reserved(self):
        c = Config.load({"TS_HUB_ENDPOINT": "https://hub.example/base/?q#f", "TS_TEST_MODE": "TRUE",
                         "TS_DEFAULT_SEVERITY": "High", "TS_PORT": "22", "TS_NODE_KEY": ""})
        self.assertTrue(c.test_mode)
        self.assertEqual(c.hub_endpoint, "https://hub.example/base")
        self.assertEqual(c.sensor_id, "ts-sensor-test")
        self.assertEqual(c.default_severity, Severity.HIGH)
        self.assertEqual(c.setting("TS_PORT"), "22")
        for k in ("TS_NODE_KEY", "TS_HUB_ENDPOINT", "TS_SENSOR_ID", "TS_CA_BUNDLE", "PATH", "TS_MISSING"):
            self.assertIsNone(c.setting(k), k)


class UnitTests(unittest.TestCase):
    def test_uuid7_format_and_order(self):
        ms = [1_700_000_000_000]
        g = UUID7(lambda: ms[0])
        ids = [g.next() for _ in range(5000)]  # exhausts the 12-bit counter
        ms[0] -= 10  # clock steps back
        ids += [g.next() for _ in range(10)]
        self.assertTrue(all(UUID7_RE.match(i) for i in ids))
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(len(set(ids)), len(ids))
        self.assertEqual(int(UUID7().next().replace("-", "")[:12], 16) // 1000, int(time.time()) // 1)

    def test_queue_drops_oldest_and_counts(self):
        q = EventQueue(3)
        for i in range(5):
            q.push(i)
        self.assertEqual(q.pop(10), [2, 3, 4])
        self.assertEqual(q.take_dropped(), 2)
        self.assertEqual(q.take_dropped(), 0)

    def test_event_size_bounded(self):
        # F-603: per-event limits make the bounded queue bounded in bytes too.
        import logging
        from doppel_sdk.events import MAX_DETAILS_BYTES, MAX_FIELD_BYTES, dumps
        from doppel_sdk.sensor import Options as Opts, Sensor
        cfg = Config.load({"TS_HUB_ENDPOINT": "https://hub", "TS_NODE_KEY": "k", "TS_SENSOR_ID": "ts-sensor-demo"})
        quiet = logging.getLogger("test-quiet")
        quiet.addHandler(logging.NullHandler())
        quiet.propagate = False
        s = Sensor(cfg, None, Opts(queue_size=5), quiet)
        huge = "A" * (1 << 20)
        ev = s._build(Severity.HIGH, "x", "\u00e9" * 400, huge, {"blob": huge})
        self.assertEqual(ev["details"], {"details_dropped": True})
        self.assertEqual(len(ev["source"].encode()), MAX_FIELD_BYTES)
        self.assertEqual(len(ev["target"].encode()), MAX_FIELD_BYTES)
        edge = {"b": "B" * (MAX_DETAILS_BYTES - len('{"b":""}'))}
        self.assertEqual(len(dumps(s._build(Severity.HIGH, "x", "s", "t", edge)["details"])), MAX_DETAILS_BYTES)
        for _ in range(50):
            s.report("x", huge, huge, {"blob": huge})
        self.assertLessEqual(len(s._q), 5)
        self.assertEqual(s._q.take_dropped(), 45)
        held = s._q.pop(10)
        self.assertTrue(all(len(dumps(e["details"])) <= MAX_DETAILS_BYTES and len(e["source"].encode()) <= MAX_FIELD_BYTES for e in held))

    def test_limiter(self):
        t = [0.0]
        lim = SourceLimiter(10, max_sources=2, clock=lambda: t[0])
        self.assertEqual(lim.allow("a"), (True, 0))
        self.assertEqual(lim.allow("a"), (False, 0))
        self.assertEqual(lim.allow("a"), (False, 0))
        t[0] = 11
        self.assertEqual(lim.allow("a"), (True, 2))
        lim.allow("b"), lim.allow("c")  # evicts "a" (LRU)
        self.assertEqual(lim.allow("a"), (True, 0))

    def test_details_encoding(self):
        d = encode_details([("b", 1), ("a", float("nan")), ("raw", b"\xff"), ("b", 2)])
        self.assertEqual(list(d), ["b", "a", "raw"])
        self.assertEqual(d, {"b": 2, "a": "nan", "raw": "�"})
        json.dumps(d, allow_nan=False)
        self.assertEqual(encode_details(None), {})

    def test_printable_and_clean(self):
        self.assertEqual(printable(b"GET \\\r\n\x00"), "GET \\\\\\x0d\\x0a\\x00")
        self.assertEqual(printable(b"abc", 2), "ab")
        self.assertEqual(clean("a\x1bb\nc", 3), "a?b")


class SensorTests(unittest.TestCase):
    def setUp(self):
        self.hub = MockHub()

    def tearDown(self):
        self.hub.close()

    def test_test_mode_success_and_failure(self):
        o = fast(self.hub, env={"TS_TEST_MODE": "true", "TS_SENSOR_ID": ""})
        self.assertEqual(run(Spec(DRILL), o), 0)
        (path, headers, body), = self.hub.requests
        ev = body["events"][0]
        self.assertEqual(headers["Authorization"], "Bearer " + KEY)
        self.assertTrue(headers["User-Agent"].startswith("truesignal-sdk-python/3."))
        self.assertEqual((ev["source"], ev["trigger"], ev["sensor_id"], ev["severity"]), ("Fire drill", "x_trigger", "ts-sensor-test", "medium"))
        self.assertEqual(ev["details"], {"port": 0, "phase": "drill"})
        self.assertRegex(ev["event_id"], UUID7_RE)
        self.assertTrue(ev["occurred_at"].endswith("Z"))
        self.hub.scripts["/v3/ingest/events"] = [(200, {"ok": True, "accepted": 0, "duplicates": 0, "rejected": [{"index": 0, "error": "invalid_trigger"}]}, {})]
        self.assertEqual(run(Spec(DRILL), fast(self.hub, env={"TS_TEST_MODE": "true"})), 1)
        self.hub.scripts["/v3/ingest/events"] = [(401, {"ok": False, "error": "unauthorized"}, {})]
        self.assertEqual(run(Spec(DRILL), fast(self.hub, env={"TS_TEST_MODE": "true"})), 1)

    def test_invalid_config_exits_2(self):
        self.assertEqual(run(Spec(DRILL), Options(env={}, install_signals=False)), 2)
        self.assertEqual(run(Spec(Drill("", "x")), fast(self.hub)), 2)
        self.assertEqual(run(Spec(DRILL), fast(self.hub, env={"TS_CA_BUNDLE": "/nonexistent.pem"})), 2)

    def test_service_batches_heartbeats_drill_and_stop(self):
        o = fast(self.hub)

        def body(s, stop):
            for i in range(250):
                s.report("x_trigger", f"10.0.0.{i % 250}", "X", {"i": i})
            s.report_severity(Severity.CRITICAL, "x_login", "10.0.0.9", "X", {"user": "root"})
            stop.wait()

        t = threading.Thread(target=lambda: setattr(self, "rc", run(Spec(DRILL, body), o)))
        t.start()
        self.assertTrue(self.hub.wait(lambda: len(self.hub.events()) == 251))
        o.signal_queue.put("USR1")
        self.assertTrue(self.hub.wait(lambda: any(e["source"] == "Fire drill" for e in self.hub.events())))
        self.assertTrue(self.hub.wait(lambda: len(self.hub.bodies("/v3/ingest/heartbeats")) >= 2))
        o.signal_queue.put("TERM")
        t.join(10)
        self.assertEqual(self.rc, 0)
        sizes = [len(b["events"]) for b in self.hub.bodies("/v3/ingest/events")]
        self.assertTrue(all(1 <= n <= 100 for n in sizes), sizes)
        self.assertEqual([e["details"]["i"] for e in self.hub.events()[:250]], list(range(250)))  # order kept
        self.assertEqual(self.hub.events()[250]["severity"], "critical")
        hb = self.hub.bodies("/v3/ingest/heartbeats")[0]
        self.assertEqual(hb, {"sensor_id": "ts-sensor-x", "config_revision": "rev_12345678", "sdk_version": "3.0.0"})
        self.assertEqual(self.hub.bodies("/v3/ingest/stopping"), [{"sensor_id": "ts-sensor-x", "reason": "received SIGTERM"}])

    def test_retry_then_success_and_retry_after(self):
        self.hub.scripts["/v3/ingest/events"] = [(503, None, {}), (429, {"ok": False, "error": "rate_limited"}, {"Retry-After": "0"}), (500, None, {})]
        o = fast(self.hub)

        def body(s, stop):
            s.report("x_trigger", "1.2.3.4", "X")
            stop.wait()

        t = threading.Thread(target=lambda: run(Spec(DRILL, body), o))
        t.start()
        self.assertTrue(self.hub.wait(lambda: len(self.hub.bodies("/v3/ingest/events")) == 4))
        o.signal_queue.put("TERM")
        t.join(10)
        ids = {b["events"][0]["event_id"] for b in self.hub.bodies("/v3/ingest/events")}
        self.assertEqual(len(ids), 1, "retries must resend the same event_id (idempotency)")

    def test_4xx_not_retried_counted_as_dropped(self):
        self.hub.scripts["/v3/ingest/events"] = [(400, {"ok": False, "error": "invalid_batch"}, {})]
        o = fast(self.hub)
        sent = threading.Event()

        def body(s, stop):
            s.report("x_trigger", "1.2.3.4", "X")
            stop.wait()

        t = threading.Thread(target=lambda: run(Spec(DRILL, body), o))
        t.start()
        self.assertTrue(self.hub.wait(lambda: any(b.get("dropped_events") == 1 for b in self.hub.bodies("/v3/ingest/heartbeats"))))
        self.assertEqual(len(self.hub.bodies("/v3/ingest/events")), 1)
        o.signal_queue.put("TERM")
        t.join(10)
        del sent

    def test_gives_up_after_max_attempts(self):
        self.hub.scripts["/v3/ingest/events"] = [(500, None, {})] * 20
        o = fast(self.hub, max_attempts=3)

        def body(s, stop):
            s.report("x_trigger", "1.2.3.4", "X")
            stop.wait()

        t = threading.Thread(target=lambda: run(Spec(DRILL, body), o))
        t.start()
        self.assertTrue(self.hub.wait(lambda: any(b.get("dropped_events") == 1 for b in self.hub.bodies("/v3/ingest/heartbeats"))))
        self.assertEqual(len(self.hub.bodies("/v3/ingest/events")), 3)
        o.signal_queue.put("TERM")
        t.join(10)

    def test_redirect_not_followed(self):
        self.hub.scripts["/v3/ingest/events"] = [(307, None, {"Location": "http://127.0.0.1:1/steal"})]
        self.assertEqual(run(Spec(DRILL), fast(self.hub, env={"TS_TEST_MODE": "true"})), 1)
        self.assertEqual(len(self.hub.requests), 1)

    def test_body_failure_exit_1_and_finish_exit_0(self):
        def boom(s, stop):
            raise RuntimeError("port in use")

        self.assertEqual(run(Spec(DRILL, boom), fast(self.hub)), 1)
        self.assertEqual(self.hub.bodies("/v3/ingest/stopping")[-1]["reason"], "sensor failed: port in use")

        def done(s, stop):
            s.report("x_trigger", "1.2.3.4", "X")

        self.assertEqual(run(Spec(DRILL, done), fast(self.hub)), 0)
        self.assertTrue(any(e["source"] == "1.2.3.4" for e in self.hub.events()), "queue flushed before exit")

    def test_real_signals_in_a_process(self):
        script = f"""
import sys, threading
sys.path.insert(0, {os.path.dirname(HERE)!r})
from doppel_sdk import Drill, Spec, Options, run
def body(s, stop):
    print("ready", flush=True)
    stop.wait()
sys.exit(run(Spec(Drill("x_trigger", "X"), body), Options(batch_delay=0.05)))
"""
        p = subprocess.Popen([sys.executable, "-c", script], env={**os.environ, **env(self.hub)}, stdout=subprocess.PIPE, text=True)
        self.assertEqual(p.stdout.readline().strip(), "ready")
        p.send_signal(signal.SIGUSR1)
        self.assertTrue(self.hub.wait(lambda: any(e["source"] == "Fire drill" for e in self.hub.events())))
        p.send_signal(signal.SIGTERM)
        self.assertEqual(p.wait(10), 0)
        p.stdout.close()
        self.assertEqual(self.hub.bodies("/v3/ingest/stopping")[-1]["reason"], "received SIGTERM")


if __name__ == "__main__":
    unittest.main()


class CompatibilityAliasTest(unittest.TestCase):
    """The old package name works for one release and warns (Q66)."""

    def test_truesignal_sdk_alias(self):
        import importlib
        import warnings
        sys.modules.pop("truesignal_sdk", None)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            old = importlib.import_module("truesignal_sdk")
        self.assertTrue(any(issubclass(x.category, DeprecationWarning) for x in w))
        import doppel_sdk
        from truesignal_sdk.config import Config as OldConfig
        from doppel_sdk.config import Config
        self.assertIs(old.Spec, doppel_sdk.Spec)
        self.assertIs(OldConfig, Config)
