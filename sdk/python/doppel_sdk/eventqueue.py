# Copyright (c) 2026 TrueSignal Deception. All rights reserved.
"""Bounded event queue: on overflow the oldest event is dropped and counted
(§5.3); the count is reported in the next heartbeat. Each item carries a
size so the sender can cap a batch in bytes as well as in events."""

from __future__ import annotations

import threading
from collections import deque
from typing import Any, List, Optional


class EventQueue:
    def __init__(self, capacity: int = 1000):
        self._items: deque = deque()  # (item, size)
        self._bytes = 0
        self._cap = max(1, capacity)
        self._dropped = 0
        self._cond = threading.Condition()

    def push(self, item: Any, size: int = 0) -> None:
        with self._cond:
            if len(self._items) >= self._cap:
                self._bytes -= self._items.popleft()[1]
                self._dropped += 1
            self._items.append((item, size))
            self._bytes += size
            self._cond.notify_all()

    def pop(self, n: int, max_bytes: Optional[int] = None) -> List[Any]:
        """Removes and returns the oldest items: at most n, and no more than
        max_bytes of size in total. At least one item is taken from a
        non-empty queue, so an item larger than max_bytes is still sent."""
        with self._cond:
            out: List[Any] = []
            used = 0
            while self._items and len(out) < n:
                size = self._items[0][1]
                if out and max_bytes is not None and used + size > max_bytes:
                    break
                out.append(self._items.popleft()[0])
                used += size
            self._bytes -= used
            return out

    def full(self, n: int, max_bytes: Optional[int] = None) -> bool:
        """Whether a complete batch is queued: n items or max_bytes of size."""
        with self._cond:
            return self._full(n, max_bytes)

    def _full(self, n: int, max_bytes: Optional[int]) -> bool:
        return len(self._items) >= n or (max_bytes is not None and self._bytes >= max_bytes)

    def __len__(self) -> int:
        with self._cond:
            return len(self._items)

    def wait(self, timeout: float, min_items: int = 1, min_bytes: Optional[int] = None) -> int:
        """Waits until at least min_items (or min_bytes of size) are queued
        or timeout; returns len."""
        with self._cond:
            self._cond.wait_for(lambda: self._full(min_items, min_bytes), timeout)
            return len(self._items)

    def wake(self) -> None:
        with self._cond:
            self._cond.notify_all()

    def take_dropped(self) -> int:
        with self._cond:
            d, self._dropped = self._dropped, 0
            return d

    def add_dropped(self, n: int) -> None:
        with self._cond:
            self._dropped += n
