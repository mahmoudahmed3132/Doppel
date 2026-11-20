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
    return bound_details_sized(det)[0]


_DROPPED = {"details_dropped": True}


def bound_details_sized(det: dict) -> "tuple[dict, int]":
    """bound_details, plus the encoded size of the returned object."""
    n = len(dumps(det))
    if n > MAX_DETAILS_BYTES:
        return dict(_DROPPED), len(dumps(_DROPPED))
    return det, n


# The Hub refuses request bodies over 256 KiB with 413 body_too_large, which
# is not retried. A batch is capped at this many bytes of wire_size; the
# 16 KiB margin covers the {"events":[...]} envelope.
MAX_BATCH_BYTES = 240 << 10

# Upper bound on an event's fixed parts: key names and punctuation (about
# 110 bytes), event_id (36), severity (at most 8), occurred_at (at most 35)
# and the comma separating it from the next event.
EVENT_OVERHEAD = 256


def wire_size(ev: dict, details_size: int) -> int:
    """Upper bound on the encoded size of ev inside a batch, given the exact
    encoded size of its details. json.dumps(ensure_ascii=False) writes each
    character of a string as at most 6 bytes (\\uXXXX for control characters;
    otherwise its UTF-8 form, at most 4), so string fields count at 6 bytes
    per character. Source and target often carry attacker-supplied text; a
    plain length estimate could be pushed past the Hub limit on purpose."""
    chars = sum(len(str(ev[k])) for k in ("sensor_id", "trigger", "source", "target"))
    return EVENT_OVERHEAD + details_size + 6 * chars


def now_rfc3339() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def dumps(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
