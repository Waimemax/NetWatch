"""TCP connect scanner (spec 10.6, 13.2, 13.3; FR-09 to FR-12, NFR-02, NFR-03).

Each port is tested with an ordinary TCP connection attempt, so no raw-socket
privileges are needed. Results are classified only by the evidence the
operating system gives us:

    connection succeeds           -> open
    connection actively refused   -> closed
    attempt times out             -> no_response   (NOT "filtered")
    no route / host unreachable   -> unreachable
    reset or other ambiguity      -> unknown
    anything else                 -> error

A timeout cannot prove a firewall dropped the packet, so it is never reported
as anything stronger than "no_response".

The scanner re-validates its inputs (scope, timeout, workers, port limits)
instead of trusting the caller, so it stays safe even if used without the CLI.
"""

from __future__ import annotations

import errno
import itertools
import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from ipaddress import IPv4Address
from typing import Callable, Iterable, Optional, Union

from config import DEFAULT_SETTINGS, Settings
from .models import PortResult, PortState
from .validator import ValidationError, parse_host, parse_timeout, parse_workers

logger = logging.getLogger(__name__)

Connector = Callable[[str, int, float], None]
ServiceLookup = Callable[[int], str]


class ScanInterrupted(Exception):
    """The scan was stopped early (Ctrl+C or stop_event).

    `partial_results` holds every port that finished before stopping, sorted
    by port, so the caller can still show or save what was observed.
    """

    def __init__(self, partial_results: list[PortResult]) -> None:
        super().__init__(f"Scan interrupted after {len(partial_results)} completed port checks.")
        self.partial_results = partial_results


# --------------------------------------------------------------------------
# single connection attempt and classification
# --------------------------------------------------------------------------

def _errno_set(*names: str) -> frozenset[int]:
    """Collect errno values by name, skipping any this platform lacks."""
    return frozenset(getattr(errno, n) for n in names if hasattr(errno, n))


_UNREACHABLE = _errno_set("ENETUNREACH", "EHOSTUNREACH", "ENETDOWN", "EHOSTDOWN")
_AMBIGUOUS = _errno_set("ECONNRESET", "ECONNABORTED")
_TIMED_OUT = _errno_set("ETIMEDOUT")


def tcp_connect(host: str, port: int, timeout: float) -> None:
    """Open and immediately close a TCP connection. Raises OSError on failure.

    The socket is always closed, including when connect() raises.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((host, port))


def classify_connect_error(error: BaseException) -> PortState:
    """Map a connection failure to the most conservative honest state."""
    if isinstance(error, ConnectionRefusedError):
        return PortState.CLOSED
    if isinstance(error, TimeoutError):  # socket.timeout is an alias on 3.10+
        return PortState.NO_RESPONSE
    if isinstance(error, (ConnectionResetError, ConnectionAbortedError)):
        return PortState.UNKNOWN  # something answered, but not conclusively
    if isinstance(error, OSError):
        if error.errno in _TIMED_OUT:
            return PortState.NO_RESPONSE
        if error.errno in _UNREACHABLE:
            return PortState.UNREACHABLE
        if error.errno in _AMBIGUOUS:
            return PortState.UNKNOWN
    return PortState.ERROR


def check_port(
    ip: IPv4Address,
    port: int,
    timeout: float,
    *,
    connector: Connector = tcp_connect,
    service_lookup: Optional[ServiceLookup] = None,
    clock: Callable[[], float] = time.perf_counter,
) -> PortResult:
    """Test one port and return its PortResult. Never raises for network errors."""
    checked_at = datetime.now(timezone.utc)
    started = clock()
    try:
        connector(str(ip), port, timeout)
        state = PortState.OPEN
    except Exception as error:  # per-port failures must not stop the scan (NFR-03)
        state = classify_connect_error(error)
        if state is PortState.ERROR:
            logger.debug("Unclassified error on port %s: %s", port, type(error).__name__)
    elapsed_ms = (clock() - started) * 1000

    # Latency is only meaningful when the host actually answered.
    latency = elapsed_ms if state in (PortState.OPEN, PortState.CLOSED) else None
    hint = service_lookup(port) if service_lookup else "unknown"
    return PortResult(
        target_ip=ip,
        port=port,
        state=state,
        checked_at=checked_at,
        service_hint=hint,
        latency_ms=latency,
    )


# --------------------------------------------------------------------------
# scanning many ports
# --------------------------------------------------------------------------

def _validate_port_list(ports: Iterable[int], settings: Settings) -> tuple[int, ...]:
    unique: set[int] = set()
    for port in ports:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
            raise ValidationError(f"Invalid port {port!r}; ports must be whole numbers 1 to 65535.")
        unique.add(port)
        if len(unique) > settings.max_ports:
            raise ValidationError(f"Too many ports; the maximum per scan is {settings.max_ports:,}.")
    if not unique:
        raise ValidationError("No ports to scan.")
    return tuple(sorted(unique))


_scan_counter = itertools.count(1)


def _join_stragglers(prefix: str, wait_seconds: float) -> None:
    """Wait for any worker thread of this scan that the executor lost track of.

    If Ctrl+C arrives while a worker is still starting, the executor never
    records that thread, so shutdown() does not wait for it. It exits promptly
    on its own, but we join it so no socket is left open after we return.
    """
    for thread in threading.enumerate():
        if thread.name.startswith(prefix) and thread is not threading.current_thread():
            thread.join(wait_seconds)


def scan_ports(
    target: Union[str, IPv4Address],
    ports: Iterable[int],
    timeout: Union[str, int, float, None] = None,
    workers: Union[str, int, None] = None,
    settings: Settings = DEFAULT_SETTINGS,
    *,
    service_lookup: Optional[ServiceLookup] = None,
    stop_event: Optional[threading.Event] = None,
    connector: Connector = tcp_connect,
    on_result: Optional[Callable[[PortResult], None]] = None,
) -> list[PortResult]:
    """Scan selected TCP ports on one authorized host.

    Returns results sorted by port. Raises ValidationError for unsafe input and
    ScanInterrupted (carrying partial results) if stopped early.

    At most `workers` connection attempts run at once. On Ctrl+C or when
    `stop_event` is set, no new ports are started, running attempts finish
    (bounded by the timeout) and every socket is closed before returning.
    """
    ip = parse_host(str(target), settings)
    timeout_s = settings.default_timeout if timeout is None else parse_timeout(timeout, settings)
    worker_count = settings.default_workers if workers is None else parse_workers(workers, settings)
    port_list = _validate_port_list(ports, settings)

    stop = stop_event if stop_event is not None else threading.Event()

    def task(port: int) -> Optional[PortResult]:
        if stop.is_set():
            return None  # skipped: scan was stopped before this port started
        return check_port(ip, port, timeout_s, connector=connector, service_lookup=service_lookup)

    logger.info("TCP scan started: %s, %d port(s), timeout=%gs, workers=%d",
                ip, len(port_list), timeout_s, worker_count)

    # Unique per scan, so cleanup only ever waits on this scan's own threads.
    thread_prefix = f"netwatch-scan-{next(_scan_counter)}"
    executor = ThreadPoolExecutor(
        max_workers=min(worker_count, len(port_list)),
        thread_name_prefix=thread_prefix,
    )
    futures = []
    interrupted = False
    try:
        # Submission is inside the try so Ctrl+C during startup is also clean.
        for port in port_list:
            futures.append(executor.submit(task, port))
        for future in as_completed(futures):
            result = future.result()
            if result is not None and on_result is not None:
                on_result(result)
    except KeyboardInterrupt:
        stop.set()
        interrupted = True
    finally:
        # Cancel anything not yet started and wait for running attempts to
        # finish (each is bounded by the timeout) so every socket is closed.
        executor.shutdown(wait=True, cancel_futures=True)
        _join_stragglers(thread_prefix, timeout_s + 1.0)

    results = sorted(
        (f.result() for f in futures if f.done() and not f.cancelled() and f.result() is not None),
        key=lambda r: r.port,
    )
    if interrupted or len(results) < len(port_list):
        logger.warning("TCP scan interrupted: %d of %d port(s) completed", len(results), len(port_list))
        raise ScanInterrupted(results)

    logger.info("TCP scan finished: %s, %d port(s) checked", ip, len(results))
    return results