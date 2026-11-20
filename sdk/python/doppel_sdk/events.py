# Copyright (c) 2026 TrueSignal Deception. All rights reserved.
"""Event model and JSON encoding (contract v3 §4.2)."""

from __future__ import annotations

import enum
import json
import math
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Tuple, Union

DRILL_SOURCE = "Fire drill"

Details = Union[Mapping[str, Any], Iterable[Tuple[str, Any]], None]


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls(value.strip().lower())
        except ValueError:
            raise ValueError(f"unknown severity {value!r}") from None


def _jsonable(v: Any) -> Any:
    """Plain JSON values only; NaN/Inf and unknown types become strings so a
    sensor bug never produces invalid JSON."""
    if v is None or isinstance(v, (bool, int, str)):
        return v
    if isinstance(v, float):
        return v if math.isfinite(v) else str(v)
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace")
    if isinstance(v, Mapping):
        return {str(k): _jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple, set, frozenset)):
        return [_jsonable(x) for x in v]
    if isinstance(v, datetime):
        return v.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(v, enum.Enum):
        return _jsonable(v.value)
    return str(v)


def encode_details(details: Details) -> dict:
    """Details as a JSON object. A mapping or an ordered list of (key, value)
    pairs is accepted; order is preserved; a later duplicate key wins."""
    if details is None:
        return {}
    items = details.items() if isinstance(details, Mapping) else details
    out: dict = {}
    for k, v in items:
        out[str(k)] = _jsonable(v)
    return out


# Per-event limits of contract v3 (§4.2), applied before an event is queued.
# The Hub enforces the same limits; applying them in the SDK also bounds the
# queue's memory (at most queue capacity x about 64 KiB).
MAX_FIELD_BYTES = 256  # source and target, in UTF-8 bytes
MAX_DETAILS_BYTES = 64 << 10  # encoded details object


def clamp_field(s: str) -> str:
    """Truncates s to MAX_FIELD_BYTES of UTF-8 on a character boundary."""
    b = str(s).encode("utf-8", "replace")
    if len(b) <= MAX_FIELD_BYTES:
        return str(s)
    return b[:MAX_FIELD_BYTES].decode("utf-8", "ignore")


def bound_details(det: dict) -> dict:
    """Returns det, or the Hub's {"details_dropped": true} marker when its
    encoding exceeds MAX_DETAILS_BYTES."""
    if len(dumps(det)) > MAX_DETAILS_BYTES:
        return {"details_dropped": True}
    return det


def now_rfc3339() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def dumps(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
