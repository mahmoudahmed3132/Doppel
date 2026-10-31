# Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.
"""HTTPS client for the sensor endpoints (contract v3 §4). TLS uses the system
roots plus an optional CA bundle; verification is never disabled. Redirects
are not followed (a redirect would carry the node key elsewhere)."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any, Optional

PATH_EVENTS = "/v3/ingest/events"
PATH_HEARTBEATS = "/v3/ingest/heartbeats"
PATH_STOPPING = "/v3/ingest/stopping"
MAX_RESPONSE = 64 << 10
REQUEST_TIMEOUT = 15.0


class HubError(Exception):
    """A non-2xx answer from the Hub."""

    def __init__(self, status: int, code: str = "", message: str = "", retry_after: float = 0.0):
        super().__init__(f"hub answered {status} {code}: {message}".rstrip(": "))
        self.status, self.code, self.message, self.retry_after = status, code, message, retry_after

    @property
    def retryable(self) -> bool:
        # 4xx other than 408/429 are the sensor's fault and never retried (§5.3).
        return self.status in (408, 429) or self.status >= 500


def retryable(err: BaseException) -> bool:
    return err.retryable if isinstance(err, HubError) else True  # network errors are retried


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None  # surfaces the 3xx as an HTTPError


class HubClient:
    def __init__(self, base: str, node_key: str, ca_bundle: str = "", sdk_version: str = "3.0.0"):
        ctx = ssl.create_default_context()  # system roots, hostname checks, CERT_REQUIRED
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if ca_bundle:
            try:
                ctx.load_verify_locations(cafile=ca_bundle)
            except (OSError, ssl.SSLError) as e:
                raise ValueError(f"TS_CA_BUNDLE: cannot load {ca_bundle}: {e}") from None
        self._base = base
        self._key = node_key
        self._ua = f"truesignal-sdk-python/{sdk_version}"
        self._opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirect())

    def post(self, path: str, body: Any, timeout: float = REQUEST_TIMEOUT) -> dict:
        data = json.dumps(body, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
        req = urllib.request.Request(self._base + path, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", self._ua)
        if self._key:
            req.add_header("Authorization", "Bearer " + self._key)
        try:
            with self._opener.open(req, timeout=timeout) as resp:
                raw = resp.read(MAX_RESPONSE)
        except urllib.error.HTTPError as e:
            try:
                raw = e.read(MAX_RESPONSE) if e.fp else b""
            finally:
                e.close()  # long-running sensors must not leak a socket per retry
            code = msg = ""
            try:
                env = json.loads(raw)
                code, msg = str(env.get("error", "")), str(env.get("message", ""))
            except (ValueError, AttributeError):
                pass
            ra = 0.0
            try:
                ra = max(0.0, float(int(e.headers.get("Retry-After", "0"))))
            except (TypeError, ValueError):
                pass
            raise HubError(e.code, code, msg, ra) from None
        if not raw:
            return {}
        try:
            out = json.loads(raw)
        except ValueError as e:
            raise ValueError(f"decoding hub response: {e}") from None
        return out if isinstance(out, dict) else {}


def ingest_response(out: Optional[dict]) -> tuple[int, int, list]:
    out = out or {}
    return int(out.get("accepted", 0)), int(out.get("duplicates", 0)), list(out.get("rejected") or [])
