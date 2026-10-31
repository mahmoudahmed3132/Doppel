# Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.
"""Helpers for putting attacker-controlled bytes into event fields."""

from __future__ import annotations


def printable(data: bytes, max_len: int = 2048) -> str:
    """Escapes non-printable bytes as \\xNN (and backslash as \\\\) so raw
    payloads are safe and unambiguous in details; truncates to max_len input
    bytes."""
    out = []
    for b in data[:max_len]:
        if b == 0x5C:
            out.append("\\\\")
        elif 0x20 <= b < 0x7F:
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


def clean(s: str, max_len: int = 256) -> str:
    """Valid text without control characters, at most max_len characters."""
    s = s.encode("utf-8", "replace").decode("utf-8", "replace")
    return "".join(c if c.isprintable() else "?" for c in s)[:max_len]
