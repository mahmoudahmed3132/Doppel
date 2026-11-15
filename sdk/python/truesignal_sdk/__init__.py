# Copyright (c) 2026 TrueSignal Deception. All rights reserved.
"""Compatibility alias for one release (QUESTIONS Q66): the SDK is now
``doppel_sdk``. ``import truesignal_sdk`` (and its submodules) keeps working
and warns; switch imports to ``doppel_sdk``."""

import importlib
import sys
import warnings

import doppel_sdk
from doppel_sdk import *  # noqa: F401,F403

warnings.warn("truesignal_sdk is renamed doppel_sdk; this alias is removed in the next release",
              DeprecationWarning, stacklevel=2)

for _name in ("client", "config", "eventqueue", "events", "limiter", "sensor", "util", "uuid7"):
    sys.modules[__name__ + "." + _name] = importlib.import_module("doppel_sdk." + _name)

__all__ = getattr(doppel_sdk, "__all__", [])
