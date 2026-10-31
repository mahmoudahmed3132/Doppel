# Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.
"""Per-source cooldown limiter (same semantics as the Go SDK): at most one
event per source per cooldown; suppressed events are counted and returned
with the next allowed one as ``suppressed_since_last``. Bounded LRU."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Callable, Tuple


class SourceLimiter:
    def __init__(self, cooldown_s: float, max_sources: int = 4096, clock: Callable[[], float] = time.monotonic):
        self._cooldown = cooldown_s
        self._max = max_sources if max_sources > 0 else 4096
        self._clock = clock
        self._lock = threading.Lock()
        self._seen: "OrderedDict[str, list]" = OrderedDict()  # source -> [last_emit, suppressed]

    def allow(self, source: str) -> Tuple[bool, int]:
        now = self._clock()
        with self._lock:
            e = self._seen.get(source)
            if e is not None:
                self._seen.move_to_end(source)
                if now - e[0] < self._cooldown:
                    e[1] += 1
                    return False, 0
                suppressed, e[0], e[1] = e[1], now, 0
                return True, suppressed
            if len(self._seen) >= self._max:
                self._seen.popitem(last=False)
            self._seen[source] = [now, 0]
            return True, 0
