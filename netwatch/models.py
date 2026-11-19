"""Domain models (spec 9.2, 11.2).

Plain, immutable dataclasses with no network or file I/O. They enforce basic
invariants (valid ports, timezone-aware timestamps, honest MAC handling) so
bad data cannot silently flow into reports or comparisons.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from ipaddress import IPv4Address, IPv4Network
from typing import Any, Mapping, Optional

SCHEMA_VERSION = "1.0"

_MAC_RE = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}")


class PortState(str, Enum):
    """TCP port states, defined by the evidence behind them (spec 13.3).

    There is deliberately no "filtered": a timeout alone cannot prove a
    firewall dropped the packet.
    """

    OPEN = "open"                # connection accepted
    CLOSED = "closed"            # connection actively refused
    NO_RESPONSE = "no_response"  # attempt timed out; inconclusive
    UNREACHABLE = "unreachable"  # local stack reported no route/host
    ERROR = "error"              # unexpected per-port socket error
    UNKNOWN = "unknown"          # ambiguous evidence; infer nothing


def normalize_mac(value: Optional[str]) -> Optional[str]:
    """Return a lowercase colon-separated MAC, or None if not provided.

    Accepts aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff. Raises ValueError for
    malformed values rather than guessing; MACs are never fabricated.
    """
    if value is None:
        return None
    candidate = value.strip().lower().replace("-", ":")
    if not _MAC_RE.fullmatch(candidate):
        raise ValueError(f"invalid MAC address: {value!r}")
    return candidate


def _require_aware(name: str, value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime (use UTC).")


@dataclass(frozen=True)
class NetworkTarget:
    """A validated discovery target (output of validator.parse_network)."""

    network: IPv4Network
    host_count: int
    needs_confirmation: bool  # FR-03: above the small-network threshold

    @property
    def is_single_host(self) -> bool:
        return self.network.prefixlen == 32


@dataclass(frozen=True)
class HostObservation:
    """One host seen by one discovery method (FR-05)."""

    ip_address: IPv4Address
    method: str
    observed_at: datetime
    status: str = "observed"
    mac_address: Optional[str] = None  # None = unknown, never guessed
    evidence: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.ip_address, IPv4Address):
            raise ValueError("ip_address must be an IPv4Address.")
        if not self.method:
            raise ValueError("method must not be empty.")
        _require_aware("observed_at", self.observed_at)
        object.__setattr__(self, "mac_address", normalize_mac(self.mac_address))


@dataclass(frozen=True)
class PortResult:
    """Outcome of one TCP connection attempt (FR-09 to FR-11)."""

    target_ip: IPv4Address
    port: int
    state: PortState
    checked_at: datetime
    protocol: str = "TCP"
    service_hint: str = "unknown"  # conventional hint, not verified identity
    latency_ms: Optional[float] = None

    def __post_init__(self) -> None:
        if not isinstance(self.target_ip, IPv4Address):
            raise ValueError("target_ip must be an IPv4Address.")
        if isinstance(self.port, bool) or not isinstance(self.port, int) \
                or not 1 <= self.port <= 65_535:
            raise ValueError("port must be an integer from 1 to 65535.")
        if not isinstance(self.state, PortState):
            raise ValueError("state must be a PortState.")
        if self.latency_ms is not None and self.latency_ms < 0:
            raise ValueError("latency_ms must not be negative.")
        _require_aware("checked_at", self.checked_at)


@dataclass(frozen=True)
class ScanMetadata:
    """Describes one execution so a report is reproducible (FR-13)."""

    scan_id: str
    timestamp_utc: datetime
    target: str
    scan_type: str  # "discovery" or "port_scan"
    method: tuple[str, ...]
    tool_version: str
    duration_seconds: float = 0.0
    options: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.scan_id:
            raise ValueError("scan_id must not be empty.")
        _require_aware("timestamp_utc", self.timestamp_utc)
        if self.duration_seconds < 0:
            raise ValueError("duration_seconds must not be negative.")


@dataclass(frozen=True)
class DiscoverySnapshot:
    """A saved set of host observations (FR-16)."""

    metadata: ScanMetadata
    hosts: tuple[HostObservation, ...]
    schema_version: str = SCHEMA_VERSION


@dataclass(frozen=True)
class ComparisonResult:
    """Neutral difference between two snapshots (FR-17).

    "not_observed" means absent from the current scan, not proven offline.
    """

    baseline_scan_id: str
    current_scan_id: str
    new_hosts: tuple[IPv4Address, ...]
    continuing_hosts: tuple[IPv4Address, ...]
    not_observed_hosts: tuple[IPv4Address, ...]
    warnings: tuple[str, ...] = ()