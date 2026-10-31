# Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.
"""Template sensor (Python): reports every TCP connection to one port and
closes it. Copy this directory to start a community sensor.

Settings (declared in manifest.json): TS_TEMPLATE_PORT, TS_TEMPLATE_COOLDOWN_SEC.
"""

from __future__ import annotations

import logging
import selectors
import socket
import sys
import threading

from truesignal_sdk import Drill, Spec, SourceLimiter, main

TRIGGER = "template_connection"


def settings(sensor) -> tuple[int, float]:
    port, cooldown = 9099, 60.0
    raw = sensor.setting("TS_TEMPLATE_PORT")
    if raw is not None:
        if not raw.isdigit() or not 1 <= int(raw) <= 65535:
            raise ValueError(f"TS_TEMPLATE_PORT: invalid port {raw!r}")
        port = int(raw)
    raw = sensor.setting("TS_TEMPLATE_COOLDOWN_SEC")
    if raw is not None:
        if not raw.isdigit() or int(raw) > 86400:
            raise ValueError(f"TS_TEMPLATE_COOLDOWN_SEC: invalid value {raw!r}")
        cooldown = float(raw)
    return port, cooldown


def serve(sensor, stop: threading.Event, listener: socket.socket, limiter: SourceLimiter) -> None:
    port = listener.getsockname()[1]
    target = f"Template (port {port})"
    sel = selectors.DefaultSelector()
    sel.register(listener, selectors.EVENT_READ)
    try:
        while not stop.is_set():
            if not sel.select(timeout=0.5):
                continue
            try:
                conn, (ip, src_port, *_) = listener.accept()
            except OSError:
                continue  # transient (e.g. EMFILE); keep serving
            conn.close()  # the template only records the connection
            ok, suppressed = limiter.allow(ip)
            if not ok:
                continue
            details = [("src_port", src_port), ("dst_port", port)]
            if suppressed:
                details.append(("suppressed_since_last", suppressed))
            sensor.report(TRIGGER, ip, target, details)
    finally:
        sel.close()


def run(sensor, stop: threading.Event) -> None:
    port, cooldown = settings(sensor)
    listener = socket.create_server(("", port), family=socket.AF_INET6, dualstack_ipv6=True) if socket.has_dualstack_ipv6() \
        else socket.create_server(("", port))
    sensor.log(logging.INFO, "listening", port=port)
    try:
        serve(sensor, stop, listener, SourceLimiter(cooldown))
    finally:
        listener.close()


SPEC = Spec(
    drill=Drill(TRIGGER, "Template (fire drill)", details=[("dst_port", 0), ("phase", "connect")]),
    run=run,
)

if __name__ == "__main__":
    sys.exit(main(SPEC))
