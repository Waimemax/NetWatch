"""Port scanner tests. TC-xx ids map to spec section 16.2.

Real-socket tests only ever touch 127.0.0.1. Timeout, unreachable and
interrupt behaviour is tested with injected fake connectors, so no test
depends on external network conditions.
"""

import errno
import socket
import threading
import time
import _thread
from ipaddress import IPv4Address

import pytest

from config import Settings
from netwatch.models import PortResult, PortState
from netwatch.port_scanner import (
    ScanInterrupted,
    check_port,
    classify_connect_error,
    scan_ports,
    tcp_connect,
)
from netwatch.validator import ValidationError

LOOPBACK = IPv4Address("127.0.0.1")


@pytest.fixture
def listener():
    """A local TCP server on a free loopback port."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(16)
    yield server.getsockname()[1]
    server.close()


@pytest.fixture
def closed_port():
    """A loopback port that was free a moment ago, so nothing listens on it."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


# ---- classification (pure) -----------------------------------------------

@pytest.mark.parametrize("error,state", [
    (ConnectionRefusedError(), PortState.CLOSED),
    (TimeoutError(), PortState.NO_RESPONSE),
    (socket.timeout(), PortState.NO_RESPONSE),
    (OSError(errno.ETIMEDOUT, "timed out"), PortState.NO_RESPONSE),
    (OSError(errno.ENETUNREACH, "net unreachable"), PortState.UNREACHABLE),
    (OSError(errno.EHOSTUNREACH, "host unreachable"), PortState.UNREACHABLE),
    (ConnectionResetError(), PortState.UNKNOWN),
    (ConnectionAbortedError(), PortState.UNKNOWN),
    (OSError(errno.EPERM, "operation not permitted"), PortState.ERROR),
    (OSError(), PortState.ERROR),
    (RuntimeError("boom"), PortState.ERROR),
])
def test_classify_connect_error(error, state):
    assert classify_connect_error(error) is state


def test_timeout_is_never_reported_as_filtered():
    assert "filtered" not in {s.value for s in PortState}


# ---- TC-08 / TC-09: real loopback sockets --------------------------------

def test_tc08_open_port_reported_open(listener):
    [result] = scan_ports("127.0.0.1", [listener], timeout=1)
    assert result.state is PortState.OPEN
    assert result.port == listener
    assert result.target_ip == LOOPBACK
    assert result.protocol == "TCP"
    assert result.latency_ms is not None and result.latency_ms >= 0


def test_tc09_closed_port_reported_closed(closed_port):
    [result] = scan_ports("127.0.0.1", [closed_port], timeout=1)
    assert result.state is PortState.CLOSED
    assert result.latency_ms is not None


def test_open_and_closed_in_one_scan_sorted_by_port(listener, closed_port):
    results = scan_ports("127.0.0.1", [max(listener, closed_port), min(listener, closed_port)], timeout=1)
    assert [r.port for r in results] == sorted([listener, closed_port])
    states = {r.port: r.state for r in results}
    assert states[listener] is PortState.OPEN
    assert states[closed_port] is PortState.CLOSED


def test_tcp_connect_closes_socket_on_failure(closed_port):
    with pytest.raises(ConnectionRefusedError):
        tcp_connect("127.0.0.1", closed_port, 1.0)


# ---- TC-10: timeouts, with fakes -----------------------------------------

def _raising(error):
    def connector(host, port, timeout):
        raise error
    return connector


def test_tc10_timeout_is_conservative_and_does_not_crash():
    result = check_port(LOOPBACK, 81, 0.1, connector=_raising(socket.timeout("timed out")))
    assert result.state is PortState.NO_RESPONSE
    assert result.latency_ms is None


def test_unreachable_and_unexpected_errors_are_per_port_results():
    assert check_port(LOOPBACK, 22, 1, connector=_raising(OSError(errno.ENETUNREACH, "x"))).state is PortState.UNREACHABLE
    assert check_port(LOOPBACK, 22, 1, connector=_raising(ValueError("bug"))).state is PortState.ERROR


def test_one_failing_port_does_not_stop_the_scan():
    def connector(host, port, timeout):
        if port == 22:
            raise RuntimeError("unexpected")
        if port == 80:
            raise TimeoutError()
        # 443 succeeds
    results = scan_ports("127.0.0.1", [22, 80, 443], timeout=1, connector=connector)
    assert {r.port: r.state for r in results} == {
        22: PortState.ERROR, 80: PortState.NO_RESPONSE, 443: PortState.OPEN,
    }


def test_service_lookup_is_applied_and_defaults_to_unknown():
    results = scan_ports("127.0.0.1", [22], connector=lambda h, p, t: None)
    assert results[0].service_hint == "unknown"
    results = scan_ports("127.0.0.1", [22], connector=lambda h, p, t: None,
                         service_lookup=lambda p: "ssh" if p == 22 else "unknown")
    assert results[0].service_hint == "ssh"


def test_results_are_valid_models_with_aware_timestamps():
    [result] = scan_ports("127.0.0.1", [22], connector=lambda h, p, t: None)
    assert isinstance(result, PortResult)
    assert result.checked_at.tzinfo is not None


# ---- input validation inside the scanner ---------------------------------

@pytest.mark.parametrize("target", ["8.8.8.8", "192.168.10.0/24", "not-an-ip", "224.0.0.1"])
def test_scanner_refuses_out_of_scope_targets(target):
    with pytest.raises(ValidationError):
        scan_ports(target, [80], connector=lambda h, p, t: None)


@pytest.mark.parametrize("ports", [[], [0], [65536], [-1], ["80"], [True], [1.5]])
def test_scanner_refuses_bad_ports(ports):
    with pytest.raises(ValidationError):
        scan_ports("127.0.0.1", ports, connector=lambda h, p, t: None)


def test_scanner_enforces_port_cap_and_deduplicates():
    strict = Settings(max_ports=5, default_ports=(80,))
    with pytest.raises(ValidationError):
        scan_ports("127.0.0.1", range(1, 7), settings=strict, connector=lambda h, p, t: None)
    results = scan_ports("127.0.0.1", [80, 80, 80], settings=strict, connector=lambda h, p, t: None)
    assert [r.port for r in results] == [80]


@pytest.mark.parametrize("kwargs", [
    {"timeout": 0}, {"timeout": 999}, {"timeout": "abc"},
    {"workers": 0}, {"workers": 101}, {"workers": "many"},
])
def test_scanner_enforces_timeout_and_worker_limits(kwargs):
    with pytest.raises(ValidationError):
        scan_ports("127.0.0.1", [80], connector=lambda h, p, t: None, **kwargs)


# ---- bounded concurrency (FR-12) -----------------------------------------

def test_concurrency_never_exceeds_worker_limit():
    lock = threading.Lock()
    active = peak = 0

    def connector(host, port, timeout):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.01)
        with lock:
            active -= 1

    results = scan_ports("127.0.0.1", range(1, 41), workers=4, connector=connector)
    assert len(results) == 40
    assert 1 < peak <= 4


def test_single_worker_runs_serially():
    lock = threading.Lock()
    active = peak = 0

    def connector(host, port, timeout):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.002)
        with lock:
            active -= 1

    scan_ports("127.0.0.1", range(1, 11), workers=1, connector=connector)
    assert peak == 1


# ---- TC-16: interruption --------------------------------------------------

def test_tc16_stop_event_skips_remaining_ports_and_returns_partial():
    stop = threading.Event()
    seen = []

    def connector(host, port, timeout):
        seen.append(port)
        if len(seen) == 3:
            stop.set()

    with pytest.raises(ScanInterrupted) as info:
        scan_ports("127.0.0.1", range(1, 51), workers=1, connector=connector, stop_event=stop)
    partial = info.value.partial_results
    assert 3 <= len(partial) < 50
    assert [r.port for r in partial] == sorted(r.port for r in partial)
    assert len(seen) < 50  # later ports were never attempted


def test_tc16_keyboard_interrupt_stops_cleanly_with_partial_results():
    fired = threading.Event()

    def connector(host, port, timeout):
        if port == 2 and not fired.is_set():
            fired.set()  # fire exactly once, even if workers race
            _thread.interrupt_main()  # simulates Ctrl+C in the main thread
        time.sleep(0.05)

    with pytest.raises(ScanInterrupted) as info:
        scan_ports("127.0.0.1", range(1, 200), workers=2, connector=connector)
    assert len(info.value.partial_results) < 199
    # nothing is left running after the call returns
    assert not [t for t in threading.enumerate() if t.name.startswith("netwatch-scan")]


def test_on_result_callback_receives_each_result():
    seen = []
    scan_ports("127.0.0.1", [1, 2, 3], connector=lambda h, p, t: None, on_result=seen.append)
    assert sorted(r.port for r in seen) == [1, 2, 3]