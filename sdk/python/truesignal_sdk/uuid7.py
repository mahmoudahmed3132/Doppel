# Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.
"""UUIDv7 (RFC 9562 §5.7) with a monotonic sequence inside one millisecond
(method 1: 12-bit counter in rand_a), so ids from one process sort in
generation order."""

from __future__ import annotations

import os
import threading
import time
from typing import Callable


class UUID7:
    def __init__(self, clock_ms: Callable[[], int] = lambda: time.time_ns() // 1_000_000):
        self._clock = clock_ms
        self._lock = threading.Lock()
        self._last_ms = -1
        self._seq = 0

    def next(self) -> str:
        with self._lock:
            ms = self._clock()
            if ms > self._last_ms:
                self._last_ms = ms
                self._seq = int.from_bytes(os.urandom(2), "big") & 0x7FF  # leave headroom
            else:
                ms = self._last_ms  # clock went back or same ms: keep order
                self._seq += 1
                if self._seq > 0xFFF:  # counter exhausted: borrow the next millisecond
                    self._last_ms += 1
                    ms = self._last_ms
                    self._seq = 0
            rand_b = int.from_bytes(os.urandom(8), "big") & ((1 << 62) - 1)
            v = (ms & ((1 << 48) - 1)) << 80 | 0x7 << 76 | self._seq << 64 | 0b10 << 62 | rand_b
        h = f"{v:032x}"
        return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
