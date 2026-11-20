# Copyright (c) 2026 TrueSignal Deception. All rights reserved.
"""Runtime configuration from the environment (§5.1). The variables are set by
the Hub's compose compiler and cannot be overridden by user configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Callable, Mapping, Optional
from urllib.parse import urlsplit, urlunsplit

from .events import Severity

ENV_HUB_ENDPOINT = "TS_HUB_ENDPOINT"
ENV_NODE_KEY = "TS_NODE_KEY"
ENV_SENSOR_ID = "TS_SENSOR_ID"
ENV_DEFAULT_SEVERITY = "TS_DEFAULT_SEVERITY"
ENV_CONFIG_REVISION = "TS_CONFIG_REVISION"
ENV_TEST_MODE = "TS_TEST_MODE"
ENV_CA_BUNDLE = "TS_CA_BUNDLE"
ENV_DEV_ALLOW_HTTP = "TS_DEV_ALLOW_HTTP"

RESERVED = frozenset({
    ENV_HUB_ENDPOINT,
    ENV_NODE_KEY,
    ENV_SENSOR_ID,
    ENV_CONFIG_REVISION,
    ENV_TEST_MODE,
    ENV_CA_BUNDLE,
    ENV_DEV_ALLOW_HTTP,
})
TEST_MODE_SENSOR_ID = "ts-sensor-test"


class ConfigError(ValueError):
    """Invalid or missing configuration; the sensor must exit non-zero."""


@dataclass(frozen=True)
class Config:
    hub_endpoint: str
    node_key: str
    sensor_id: str
    default_severity: Severity
    config_revision: str
    test_mode: bool
    ca_bundle: str
    _env: Mapping[str, str] = field(repr=False, compare=False, default_factory=dict)
    dev_allow_http: bool = False

    @classmethod
    def load(cls, env: Optional[Mapping[str, str]] = None) -> "Config":
        env = dict(os.environ if env is None else env)
        get: Callable[[str], str] = lambda k: env.get(k, "").strip()
        errors: list[str] = []

        tm = get(ENV_TEST_MODE).lower()
        if tm in ("", "false", "0"):
            test_mode = False
        elif tm == "true":
            test_mode = True
        else:
            raise ConfigError(f"{ENV_TEST_MODE} must be true or false, got {tm!r}")

        ah = (env.get("DOPPEL_DEV_ALLOW_HTTP") or env.get(ENV_DEV_ALLOW_HTTP) or "").strip().lower()
        if ah in ("", "false", "0", "no"):
            dev_allow_http = False
        elif ah in ("true", "1", "yes"):
            dev_allow_http = True
        else:
            raise ConfigError(f"{ENV_DEV_ALLOW_HTTP} must be true or false, got {ah!r}")

        endpoint = ""
        raw = get(ENV_HUB_ENDPOINT)
        if not raw:
            errors.append(f"{ENV_HUB_ENDPOINT} is required")
        else:
            try:
                u = urlsplit(raw)
                if u.scheme not in ("https", "http"):
                    errors.append(f"{ENV_HUB_ENDPOINT} must use https://")
                elif u.scheme == "http" and not dev_allow_http:
                    errors.append(
                        f"{ENV_HUB_ENDPOINT} must use https:// (set {ENV_DEV_ALLOW_HTTP}=true for local development)"
                    )
                elif not u.hostname:
                    errors.append(f"{ENV_HUB_ENDPOINT} has no host")
                elif u.username is not None or u.password is not None:
                    errors.append(f"{ENV_HUB_ENDPOINT} must not contain credentials")
                else:
                    u.port  # raises ValueError on an invalid port
                    endpoint = urlunsplit((u.scheme, u.netloc, u.path.rstrip("/"), "", ""))
            except ValueError as e:
                errors.append(f"{ENV_HUB_ENDPOINT}: {e}")

        node_key, sensor_id = get(ENV_NODE_KEY), get(ENV_SENSOR_ID)
        if not test_mode:
            if not node_key:
                errors.append(f"{ENV_NODE_KEY} is required")
            if not sensor_id:
                errors.append(f"{ENV_SENSOR_ID} is required")
        sensor_id = sensor_id or TEST_MODE_SENSOR_ID

        sev = Severity.MEDIUM
        if get(ENV_DEFAULT_SEVERITY):
            try:
                sev = Severity.parse(get(ENV_DEFAULT_SEVERITY))
            except ValueError as e:
                errors.append(f"{ENV_DEFAULT_SEVERITY}: {e}")
        if errors:
            raise ConfigError("; ".join(errors))
        return cls(
            endpoint,
            node_key,
            sensor_id,
            sev,
            get(ENV_CONFIG_REVISION),
            test_mode,
            get(ENV_CA_BUNDLE),
            env,
            dev_allow_http=dev_allow_http,
        )

    def setting(self, name: str) -> Optional[str]:
        """A sensor setting declared in the manifest (a TS_ variable). Reserved
        SDK keys are never exposed. Returns None when unset or empty."""
        if not name.startswith("TS_") or name in RESERVED:
            return None
        return self._env.get(name) or None
