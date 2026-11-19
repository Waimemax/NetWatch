"""Validator tests. TC-xx ids map to spec section 16.2."""

from ipaddress import IPv4Address, IPv4Network

import pytest

from config import DEFAULT_SETTINGS, Settings
from netwatch.validator import (
    ValidationError,
    parse_host,
    parse_network,
    parse_ports,
    parse_timeout,
    parse_workers,
)


# ---- TC-01 / TC-02: single IPv4 address ----------------------------------

def test_tc01_valid_ipv4_is_accepted_and_normalized():
    target = parse_network("  192.168.10.20 ")
    assert target.network == IPv4Network("192.168.10.20/32")
    assert target.is_single_host
    assert target.host_count == 1
    assert parse_host("192.168.10.20") == IPv4Address("192.168.10.20")


@pytest.mark.parametrize("bad", [
    "192.168.10.256",      # octet too large
    "192.168.10",          # too few octets
    "192.168.10.1.5",      # too many octets
    "192.168.010.1",       # leading zero (ambiguous octal)
    "192.168.-1.1",
    "192.168.10.1 5",
    "１９２.168.10.1",     # unicode digits
    "3232235521",          # integer form
    "0x7f.0.0.1",
    "",
    "   ",
    "192.168.10.1\n10.0.0.1",
])
def test_tc02_malformed_ipv4_rejected(bad):
    with pytest.raises(ValidationError):
        parse_network(bad)


def test_hostnames_and_ipv6_give_specific_messages():
    with pytest.raises(ValidationError, match="hostname"):
        parse_network("router.local")
    with pytest.raises(ValidationError, match="IPv6"):
        parse_network("fe80::1")


def test_non_string_input_rejected():
    with pytest.raises(ValidationError):
        parse_network(None)  # type: ignore[arg-type]


# ---- TC-03 / TC-04: CIDR --------------------------------------------------

def test_tc03_valid_cidr_accepted():
    target = parse_network("192.168.10.0/24")
    assert target.network == IPv4Network("192.168.10.0/24")
    assert target.network.prefixlen == 24
    assert target.host_count == 254
    assert not target.needs_confirmation


@pytest.mark.parametrize("text,hosts", [
    ("10.0.0.4/30", 2), ("10.0.0.0/31", 2), ("10.0.0.1/32", 1), ("10.0.0.0/29", 6),
])
def test_host_counts_for_small_prefixes(text, hosts):
    assert parse_network(text).host_count == hosts


@pytest.mark.parametrize("bad", [
    "192.168.10.0/33",
    "192.168.10.0/",
    "192.168.10.0/-1",
    "192.168.10.0/024",
    "192.168.10.0/abc",
    "192.168.10.0/24/24",
    "192.168.10.0/255.255.255.0",   # netmask form not accepted
    "192.168.10.0/0.0.0.255",       # hostmask form not accepted
])
def test_tc04_invalid_cidr_rejected(bad):
    with pytest.raises(ValidationError):
        parse_network(bad)


def test_host_bits_set_suggests_correction():
    with pytest.raises(ValidationError, match=r"Did you mean 192\.168\.10\.0/24"):
        parse_network("192.168.10.5/24")


# ---- TC-05: oversized range ----------------------------------------------

def test_tc05_oversized_range_refused():
    with pytest.raises(ValidationError, match="maximum"):
        parse_network("10.0.0.0/8")
    with pytest.raises(ValidationError):
        parse_network("10.0.0.0/21")  # 2046 hosts > default 1024


def test_range_at_hard_limit_accepted():
    assert parse_network("10.0.0.0/22").host_count == 1022


def test_confirmation_required_above_threshold():
    big = parse_network("10.0.0.0/23")  # 510 hosts > 256
    assert big.needs_confirmation
    assert not parse_network("10.0.0.0/24").needs_confirmation


def test_custom_limits_respected():
    strict = Settings(max_targets=16, confirm_above_targets=8)
    assert parse_network("10.0.0.0/28", strict).needs_confirmation  # 14 hosts
    with pytest.raises(ValidationError):
        parse_network("10.0.0.0/27", strict)  # 30 hosts


# ---- scope safety ---------------------------------------------------------

@pytest.mark.parametrize("bad", [
    "8.8.8.8", "1.1.1.1", "93.184.216.0/24", "0.0.0.0", "0.0.0.0/0",
    "224.0.0.1", "239.255.255.250", "255.255.255.255", "240.0.0.1",
    "100.64.0.1",  # shared/CGNAT space is not private
])
def test_non_lab_and_special_addresses_rejected(bad):
    with pytest.raises(ValidationError):
        parse_network(bad)


@pytest.mark.parametrize("ok", [
    "10.1.2.3", "172.16.0.1", "172.31.255.254", "192.168.1.1",
    "127.0.0.1", "169.254.1.1", "192.0.2.10",
])
def test_private_loopback_linklocal_and_doc_ranges_accepted(ok):
    parse_network(ok)


def test_range_straddling_public_space_rejected():
    with pytest.raises(ValidationError):
        parse_network("172.0.0.0/8")  # 172.16/12 is private, the rest is not


def test_public_allowed_only_when_explicitly_enabled():
    permissive = Settings(allow_public=True)
    assert parse_network("8.8.8.8", permissive).is_single_host
    with pytest.raises(ValidationError):  # still never multicast
        parse_network("224.0.0.1", permissive)


def test_parse_host_rejects_ranges():
    with pytest.raises(ValidationError, match="single IPv4"):
        parse_host("192.168.10.0/24")
    with pytest.raises(ValidationError, match="single IPv4"):
        parse_host("192.168.10.1/32")


# ---- TC-06 / TC-07: ports -------------------------------------------------

def test_tc06_valid_ports_parsed_as_unique_sorted_ints():
    assert parse_ports("22,80,443") == (22, 80, 443)
    assert parse_ports("443, 80 ,22,80") == (22, 80, 443)
    assert parse_ports("1-5") == (1, 2, 3, 4, 5)
    assert parse_ports("22,20-23,8080") == (20, 21, 22, 23, 8080)
    assert parse_ports("65535") == (65535,)
    assert parse_ports("1") == (1,)


@pytest.mark.parametrize("bad", [
    "0", "65536", "-1", "99999", "100000",   # TC-07 range checks
    "abc", "22;80", "22 80", "1e3", "+22", "0x50", "２２",
    "", " ", "22,", ",22", "22,,80",
    "100-1",       # backwards range
    "1-2-3", "-", "5-", "-5", "0-10", "1-70000",
    "22\n80",
])
def test_tc07_invalid_ports_rejected(bad):
    with pytest.raises(ValidationError):
        parse_ports(bad)


def test_port_count_limit_enforced_without_expanding_huge_ranges():
    with pytest.raises(ValidationError, match="maximum"):
        parse_ports("1-65535")
    assert len(parse_ports("1-1024")) == 1024
    with pytest.raises(ValidationError):
        parse_ports("1-1025")
    # Overlapping ranges are counted as unique ports, not summed.
    assert len(parse_ports("1-1000,1-1000,500-1000")) == 1000
    with pytest.raises(ValidationError):
        parse_ports("1-1000,2000-2100")  # 1101 unique


def test_overlong_port_input_rejected():
    with pytest.raises(ValidationError, match="too long"):
        parse_ports(",".join(["1"] * 600))


# ---- timeout / workers ----------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    ("0.5", 0.5), ("2", 2.0), (1, 1.0), (0.25, 0.25), (" 3 ", 3.0), (".5", 0.5), ("30", 30.0),
])
def test_valid_timeouts(value, expected):
    assert parse_timeout(value) == expected


@pytest.mark.parametrize("bad", [
    "0", 0, -1, "-1", "0.01", 31, "31", "abc", "", "1e2", "nan", "inf",
    float("nan"), float("inf"), True, None, [1],
])
def test_invalid_timeouts_rejected(bad):
    with pytest.raises(ValidationError):
        parse_timeout(bad)


@pytest.mark.parametrize("value,expected", [("1", 1), ("20", 20), (100, 100), (" 5 ", 5)])
def test_valid_workers(value, expected):
    assert parse_workers(value) == expected


@pytest.mark.parametrize("bad", ["0", 0, -3, "-3", "101", 101, 10**9, "9999999", "ten", "1.5", "", True, None])
def test_invalid_workers_rejected(bad):
    with pytest.raises(ValidationError):
        parse_workers(bad)


def test_error_messages_are_user_facing_not_tracebacks():
    with pytest.raises(ValidationError) as info:
        parse_network("192.168.10.999")
    assert "192.168.10.999" in str(info.value)
    # long hostile input is truncated in messages
    with pytest.raises(ValidationError) as info:
        parse_network("a" * 31)
    assert len(str(info.value)) < 200