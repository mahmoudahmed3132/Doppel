# Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.
"""Bounded event queue: on overflow the oldest event is dropped and counted
(§5.3); the count is reported in the next heartbeat."""

from __future__ import annotations

import threading
from collections import deque
from typing import Any, List


class EventQueue:
    def __init__(self, capacity: int = 1000):
        self._items: deque = deque()
        self._cap = max(1, capacity)
        self._dropped = 0
        self._cond = threading.Condition()

    def push(self, item: Any) -> None:
        with self._cond:
            if len(self._items) >= self._cap:
                self._items.popleft()
                self._dropped += 1
            self._items.append(item)
            self._cond.notify_all()

    def pop(self, n: int) -> List[Any]:
        with self._cond:
            out = [self._items.popleft() for _ in range(min(n, len(self._items)))]
            return out

    def __len__(self) -> int:
        with self._cond:
            return len(self._items)

    def wait(self, timeout: float, min_items: int = 1) -> int:
        """Waits until at least min_items are queued or timeout; returns len."""
        with self._cond:
            self._cond.wait_for(lambda: len(self._items) >= min_items, timeout)
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
