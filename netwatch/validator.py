"""Input validation (spec 10.3; FR-01, FR-02, FR-03, FR-07, FR-08, NFR-11).

Pure functions: no network or file access, so they are fully unit-testable.
Every function either returns a typed, normalized value or raises
ValidationError with a message that is safe to show directly to the user.

Strictness is deliberate. These functions decide what NetWatch is allowed to
touch, so ambiguous input (leading zeros, netmasks, host bits, hostnames,
unbounded ranges) is rejected rather than interpreted.
"""

from __future__ import annotations

import math
import re
from ipaddress import IPv4Address, IPv4Network
from typing import Union

from .models import NetworkTarget
from config import DEFAULT_SETTINGS, Settings

MAX_TARGET_LENGTH = 32
MAX_PORT_SPEC_LENGTH = 1024

# ASCII-only patterns: Unicode digits and lookalikes never pass.
_IPV4_RE = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}")
_PREFIX_RE = re.compile(r"0|[1-9][0-9]?")
_PORT_RE = re.compile(r"[0-9]{1,5}")
_NUMBER_RE = re.compile(r"[0-9]+(?:\.[0-9]+)?|\.[0-9]+")
_INT_RE = re.compile(r"[0-9]{1,6}")
_HOSTNAME_RE = re.compile(r"(?=.*[A-Za-z])[A-Za-z0-9.-]+")

# Never valid scan targets, regardless of settings.
_BLOCKED = (
    (IPv4Network("0.0.0.0/8"), "the 'this network' range (0.0.0.0/8)"),
    (IPv4Network("224.0.0.0/4"), "a multicast range (224.0.0.0/4)"),
    (IPv4Network("240.0.0.0/4"), "a reserved/broadcast range (240.0.0.0/4)"),
)


class ValidationError(ValueError):
    """Invalid user input. str(error) is a clear, user-facing message."""


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _show(text: str, limit: int = 40) -> str:
    text = text if len(text) <= limit else text[:limit] + "..."
    return repr(text)


def _clean(value: object, name: str, max_length: int) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{name} must be given as text.")
    value = value.strip()
    if not value:
        raise ValidationError(f"{name} must not be empty.")
    if len(value) > max_length:
        raise ValidationError(f"{name} is too long (maximum {max_length} characters).")
    if not value.isprintable():
        raise ValidationError(f"{name} contains unprintable or control characters.")
    return value


def _parse_address(text: str) -> IPv4Address:
    if not _IPV4_RE.fullmatch(text):
        if ":" in text:
            raise ValidationError(
                "IPv6 is not supported in this version; use an IPv4 address."
            )
        if _HOSTNAME_RE.fullmatch(text):
            raise ValidationError(
                f"{_show(text)} looks like a hostname. Hostnames are not supported yet; "
                "supply an IPv4 address such as 192.168.10.20."
            )
        raise ValidationError(
            f"{_show(text)} is not a valid IPv4 address "
            "(expected four numbers from 0 to 255, like 192.168.10.20)."
        )
    try:
        return IPv4Address(text)
    except ValueError:
        raise ValidationError(
            f"{_show(text)} is not a valid IPv4 address: each part must be "
            "0-255 with no leading zeros."
        ) from None


def _usable_hosts(network: IPv4Network) -> int:
    """Host addresses in a network, computed arithmetically (never enumerated)."""
    prefix = network.prefixlen
    if prefix == 32:
        return 1
    if prefix == 31:
        return 2  # point-to-point link, RFC 3021
    return network.num_addresses - 2  # exclude network and broadcast


def _longest_allowed_hint(max_hosts: int) -> int:
    """Shortest prefix length whose range still fits within max_hosts."""
    for prefix in range(0, 33):
        net = IPv4Network((0, prefix))
        if _usable_hosts(net) <= max_hosts:
            return prefix
    return 32


# --------------------------------------------------------------------------
# targets (FR-01, FR-02, FR-03)
# --------------------------------------------------------------------------

def parse_network(text: str, settings: Settings = DEFAULT_SETTINGS) -> NetworkTarget:
    """Validate an IPv4 address or CIDR range for discovery.

    A bare address is treated as a /32 (single host). Returns a NetworkTarget
    carrying the host count and whether the range is large enough to need
    explicit user confirmation (FR-03).
    """
    text = _clean(text, "Target", MAX_TARGET_LENGTH)
    address_part, slash, prefix_part = text.partition("/")
    address = _parse_address(address_part)

    if slash:
        if not _PREFIX_RE.fullmatch(prefix_part):
            raise ValidationError(
                f"{_show(prefix_part)} is not a valid prefix length. Use a whole number "
                "from 0 to 32 such as /24; netmasks like 255.255.255.0 are not accepted."
            )
        prefix = int(prefix_part)
        if prefix > 32:
            raise ValidationError(f"Prefix /{prefix} is invalid; IPv4 prefixes are 0 to 32.")
    else:
        prefix = 32

    try:
        network = IPv4Network((address, prefix), strict=True)
    except ValueError:
        suggestion = IPv4Network((address, prefix), strict=False)
        raise ValidationError(
            f"{text} has host bits set. Did you mean {suggestion}?"
        ) from None

    for blocked, reason in _BLOCKED:
        if network.overlaps(blocked):
            raise ValidationError(f"{network} is not a valid scan target: it overlaps {reason}.")

    if not settings.allow_public and not network.is_private:
        raise ValidationError(
            f"{network} is not a private/lab range. NetWatch only accepts private, "
            "loopback and link-local ranges by default. Only enable allow_public in "
            "settings if you have explicit authorization to assess that range."
        )

    host_count = _usable_hosts(network)
    if host_count > settings.max_targets:
        raise ValidationError(
            f"{network} contains {host_count:,} hosts; the maximum is "
            f"{settings.max_targets:,}. Use /{_longest_allowed_hint(settings.max_targets)} "
            "or a longer prefix."
        )

    return NetworkTarget(
        network=network,
        host_count=host_count,
        needs_confirmation=host_count > settings.confirm_above_targets,
    )


def parse_host(text: str, settings: Settings = DEFAULT_SETTINGS) -> IPv4Address:
    """Validate a single IPv4 address (used for TCP port scans)."""
    cleaned = _clean(text, "Target", MAX_TARGET_LENGTH)
    if "/" in cleaned:
        raise ValidationError(
            "Port scans need a single IPv4 address, not a range. "
            "Remove the /prefix, or use the discover command for ranges."
        )
    return parse_network(cleaned, settings).network.network_address


# --------------------------------------------------------------------------
# ports (FR-07, FR-08)
# --------------------------------------------------------------------------

def _parse_port(number: str, entry: str) -> int:
    if not _PORT_RE.fullmatch(number):
        raise ValidationError(
            f"{_show(entry)} is not a valid port or range. Use numbers from 1 to 65535, "
            "for example 22,80,443 or 8000-8010."
        )
    port = int(number)
    if not 1 <= port <= 65_535:
        raise ValidationError(f"Port {port} is out of range; ports must be 1 to 65535.")
    return port


def parse_ports(text: str, settings: Settings = DEFAULT_SETTINGS) -> tuple[int, ...]:
    """Parse "22", "22,80,443", "1-100" or a mix into sorted unique ports.

    Ranges are size-checked before expansion and the running total is capped,
    so input like 1-65535 is refused without building a huge list.
    """
    text = _clean(text, "Ports", MAX_PORT_SPEC_LENGTH)
    limit = settings.max_ports
    ports: set[int] = set()

    for raw in text.split(","):
        entry = raw.strip()
        if not entry:
            raise ValidationError(
                "The port list has an empty entry (check for doubled or trailing commas)."
            )
        if "-" in entry:
            low_text, _, high_text = entry.partition("-")
            low = _parse_port(low_text.strip(), entry)
            high = _parse_port(high_text.strip(), entry)
            if low > high:
                raise ValidationError(
                    f"Range {entry} is backwards; write it as {high}-{low}."
                )
            if high - low + 1 > limit:
                raise ValidationError(
                    f"Range {entry} covers {high - low + 1:,} ports; the maximum per scan is {limit:,}."
                )
            ports.update(range(low, high + 1))
        else:
            ports.add(_parse_port(entry, entry))

        if len(ports) > limit:
            raise ValidationError(f"Too many ports; the maximum per scan is {limit:,}.")

    return tuple(sorted(ports))


# --------------------------------------------------------------------------
# timeout and workers (NFR-02, NFR-11)
# --------------------------------------------------------------------------

def parse_timeout(value: Union[str, int, float], settings: Settings = DEFAULT_SETTINGS) -> float:
    """Validate a per-connection timeout in seconds."""
    if isinstance(value, bool):
        raise ValidationError("Timeout must be a number of seconds.")
    if isinstance(value, (int, float)):
        seconds = float(value)
    elif isinstance(value, str):
        cleaned = value.strip()
        if not _NUMBER_RE.fullmatch(cleaned):
            raise ValidationError(
                f"{_show(cleaned)} is not a valid timeout. Use a positive number of "
                "seconds such as 0.5 or 2."
            )
        seconds = float(cleaned)
    else:
        raise ValidationError("Timeout must be a number of seconds.")

    if not math.isfinite(seconds):
        raise ValidationError("Timeout must be a finite number of seconds.")
    if not settings.min_timeout <= seconds <= settings.max_timeout:
        raise ValidationError(
            f"Timeout must be between {settings.min_timeout:g} and "
            f"{settings.max_timeout:g} seconds."
        )
    return seconds


def parse_workers(value: Union[str, int], settings: Settings = DEFAULT_SETTINGS) -> int:
    """Validate the number of concurrent workers."""
    if isinstance(value, bool):
        raise ValidationError("Worker count must be a whole number.")
    if isinstance(value, int):
        workers = value
    elif isinstance(value, str):
        cleaned = value.strip()
        if not _INT_RE.fullmatch(cleaned):
            raise ValidationError(
                f"{_show(cleaned)} is not a valid worker count. Use a whole number such as 20."
            )
        workers = int(cleaned)
    else:
        raise ValidationError("Worker count must be a whole number.")

    if not 1 <= workers <= settings.max_workers:
        raise ValidationError(
            f"Worker count must be between 1 and {settings.max_workers}."
        )
    return workers