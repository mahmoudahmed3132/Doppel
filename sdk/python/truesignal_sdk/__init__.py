# Copyright (c) 2026 TrueSignal Deception. All rights reserved.
"""TrueSignal Python sensor SDK (contract v3, spec §5 / §11.6).

Standard library only. A sensor defines a :class:`Spec` (fire-drill event and
a ``run(sensor, stop)`` function) and calls :func:`main`::

    from truesignal_sdk import Spec, Drill, main

    def run(sensor, stop):
        while not stop.wait(1):
            ...
            sensor.report("my_trigger", source, target, {"key": "value"})

    main(Spec(drill=Drill("my_trigger", "My decoy"), run=run))
"""

from .config import Config, ConfigError
from .events import Severity, DRILL_SOURCE
from .limiter import SourceLimiter
from .sensor import SDK_VERSION, Drill, Options, Reporter, Sensor, Spec, main, run
from .util import clean, printable

__all__ = [
    "Config", "ConfigError", "Drill", "Options", "DRILL_SOURCE", "Reporter", "SDK_VERSION", "Sensor",
    "Severity", "SourceLimiter", "Spec", "clean", "main", "printable", "run",
]
