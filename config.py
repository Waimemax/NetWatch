"""Central, validated configuration (spec 10.11, FR-22, NFR-11).

All safety limits live here so every module shares one source of truth.
Values are validated when a Settings object is created, so an unsafe or
nonsensical configuration fails at startup rather than mid-scan.

These limits are guard rails, not permission to scan any network.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

# Hard ceilings: even a custom Settings object may not exceed these.
ABSOLUTE_MAX_WORKERS = 500
ABSOLUTE_MAX_TARGETS = 65_536
ABSOLUTE_MAX_PORTS = 65_535

# Small, conservative default port list used when the user supplies none.
DEFAULT_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080,
)


class ConfigError(ValueError):
    """Raised when configuration values are invalid or unsafe."""


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


@dataclass(frozen=True)
class Settings:
    """Safe defaults and limits. Immutable once created."""

    default_timeout: float = 1.0       # seconds per connection attempt
    min_timeout: float = 0.05
    max_timeout: float = 30.0
    default_workers: int = 20          # concurrent connection attempts
    max_workers: int = 100
    max_targets: int = 1024            # hard cap on hosts in one range
    confirm_above_targets: int = 256   # FR-03: ask before larger ranges
    max_ports: int = 1024              # hard cap on ports per scan
    allow_public: bool = False         # public ranges refused by default
    default_ports: tuple[int, ...] = DEFAULT_PORTS

    def __post_init__(self) -> None:
        for name in ("default_timeout", "min_timeout", "max_timeout"):
            value = getattr(self, name)
            if not _is_number(value) or not math.isfinite(value) or value <= 0:
                raise ConfigError(f"{name} must be a positive, finite number of seconds.")
        if not self.min_timeout <= self.default_timeout <= self.max_timeout:
            raise ConfigError("Timeouts must satisfy min_timeout <= default_timeout <= max_timeout.")

        for name in ("default_workers", "max_workers", "max_targets",
                     "confirm_above_targets", "max_ports"):
            if not _is_int(getattr(self, name)) or getattr(self, name) < 1:
                raise ConfigError(f"{name} must be a whole number of at least 1.")
        if self.max_workers > ABSOLUTE_MAX_WORKERS:
            raise ConfigError(f"max_workers may not exceed {ABSOLUTE_MAX_WORKERS}.")
        if self.default_workers > self.max_workers:
            raise ConfigError("default_workers may not exceed max_workers.")
        if self.max_targets > ABSOLUTE_MAX_TARGETS:
            raise ConfigError(f"max_targets may not exceed {ABSOLUTE_MAX_TARGETS}.")
        if self.confirm_above_targets > self.max_targets:
            raise ConfigError("confirm_above_targets may not exceed max_targets.")
        if self.max_ports > ABSOLUTE_MAX_PORTS:
            raise ConfigError(f"max_ports may not exceed {ABSOLUTE_MAX_PORTS}.")

        if not isinstance(self.allow_public, bool):
            raise ConfigError("allow_public must be True or False.")

        ports = self.default_ports
        if not isinstance(ports, tuple) or not ports:
            raise ConfigError("default_ports must be a non-empty tuple of ports.")
        if not all(_is_int(p) and 1 <= p <= 65_535 for p in ports):
            raise ConfigError("default_ports must contain only ports from 1 to 65535.")
        if len(set(ports)) != len(ports) or len(ports) > self.max_ports:
            raise ConfigError("default_ports must be unique and within max_ports.")


DEFAULT_SETTINGS = Settings()