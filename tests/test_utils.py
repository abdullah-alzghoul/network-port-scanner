"""
Tests for scanner.utils — target resolution, port-spec parsing, host liveness.
"""
import socket
import subprocess
from unittest.mock import patch, MagicMock

from scanner.utils import resolve_target, parse_port_range, parse_targets, check_host_alive
from scanner.services import COMMON_PORTS


# ── parse_port_range: pure logic, no network, no mocking needed ──

def test_common_returns_common_ports_list():
    assert parse_port_range("common") == sorted(set(COMMON_PORTS))


def test_all_returns_full_range():
    result = parse_port_range("all")
    assert result == list(range(1, 65536))


def test_top100_is_non_empty_and_within_common():
    # Stage 3 finding: COMMON_PORTS only has 72 entries, so "top100" and
    # "common" currently return identical results. This test documents
    # that known, low-priority behavior rather than silently assuming
    # top100 slices down to something smaller.
    result = parse_port_range("top100")
    assert result == sorted(set(COMMON_PORTS))


def test_single_port():
    assert parse_port_range("443") == [443]


def test_simple_range():
    assert parse_port_range("20-25") == [20, 21, 22, 23, 24, 25]


def test_comma_separated_list():
    assert parse_port_range("22,80,443") == [22, 80, 443]


def test_mixed_ranges_and_singles():
    result = parse_port_range("1-3,80,443")
    assert result == [1, 2, 3, 80, 443]


def test_duplicates_across_pieces_are_deduplicated():
    result = parse_port_range("80,80,80-82")
    assert result == [80, 81, 82]


def test_reversed_range_silently_produces_nothing():
    # Stage 3 finding: "100-50" isn't rejected, it just contributes zero
    # ports (range(100, 51) is empty). Documenting the current behavior,
    # not asserting it's correct — a user with a typo gets no warning.
    assert parse_port_range("100-50") == []


def test_reversed_range_inside_a_mixed_spec_silently_drops_only_that_piece():
    result = parse_port_range("443,100-50,8080")
    assert result == [443, 8080]


def test_out_of_bounds_port_is_ignored():
    assert parse_port_range("0") == []
    assert parse_port_range("70000") == []
    assert parse_port_range("1-70000") == []


def test_non_numeric_junk_is_ignored_not_raised():
    # Should not raise — malformed pieces are silently skipped.
    result = parse_port_range("80,notaport,443")
    assert result == [80, 443]


def test_empty_string_returns_empty_list():
    assert parse_port_range("") == []


def test_malformed_range_token_is_ignored_not_raised():
    # A dash present but not flanked by valid integers (e.g. a typo like
    # "abc-100") should be skipped like any other malformed piece, not
    # raise and abort the whole spec.
    result = parse_port_range("abc-100,443")
    assert result == [443]


# ── parse_targets ──

def test_parse_targets_single_ip():
    assert parse_targets("192.168.1.1") == ["192.168.1.1"]


def test_parse_targets_single_hostname_passed_through():
    assert parse_targets("example.com") == ["example.com"]


def test_parse_targets_comma_list_mixed_ip_and_hostname():
    result = parse_targets("192.168.1.1,example.com,10.0.0.5")
    assert result == ["192.168.1.1", "example.com", "10.0.0.5"]


def test_parse_targets_cidr_expands_to_usable_hosts():
    # /29 = 8 addresses, minus network + broadcast = 6 usable hosts
    result = parse_targets("192.168.1.0/29")
    assert result == [
        "192.168.1.1", "192.168.1.2", "192.168.1.3",
        "192.168.1.4", "192.168.1.5", "192.168.1.6",
    ]


def test_parse_targets_full_ip_range():
    result = parse_targets("192.168.1.1-192.168.1.5")
    assert result == ["192.168.1.1", "192.168.1.2", "192.168.1.3",
                       "192.168.1.4", "192.168.1.5"]


def test_parse_targets_short_last_octet_range_matches_full_form():
    short = parse_targets("192.168.1.1-5")
    full  = parse_targets("192.168.1.1-192.168.1.5")
    assert short == full


def test_parse_targets_reversed_range_is_silently_empty():
    # Same precedent as parse_port_range's reversed-range behavior.
    assert parse_targets("192.168.1.10-1") == []


def test_parse_targets_dedupes_while_preserving_order():
    result = parse_targets("192.168.1.1,192.168.1.2,192.168.1.1")
    assert result == ["192.168.1.1", "192.168.1.2"]


def test_parse_targets_mixed_cidr_and_single_hosts():
    result = parse_targets("192.168.1.0/30,example.com")
    assert result == ["192.168.1.1", "192.168.1.2", "example.com"]


def test_parse_targets_oversized_cidr_raises_instead_of_hanging():
    # A /8 is 16 million+ addresses — must fail fast and clearly, not
    # silently try to build a list that size.
    with pytest.raises(ValueError, match="over the .* limit"):
        parse_targets("10.0.0.0/8")


def test_parse_targets_oversized_range_raises():
    with pytest.raises(ValueError, match="over the .* limit"):
        parse_targets("10.0.0.1-10.1.0.1")


def test_parse_targets_respects_custom_max_targets():
    # A /28 is 16 addresses, 14 usable — fine at the default cap, but
    # should still be rejected against a smaller explicit cap.
    parse_targets("192.168.1.0/28")  # should not raise at the default
    with pytest.raises(ValueError, match="over the .* limit"):
        parse_targets("192.168.1.0/28", max_targets=10)


def test_parse_targets_malformed_piece_falls_back_to_literal():
    # Something that looks range-ish but isn't a valid IP on either side
    # should be treated as a literal target string, not raise.
    result = parse_targets("not-an-ip-1.2.3.999")
    assert result == ["not-an-ip-1.2.3.999"]


# ── resolve_target: needs real DNS/socket, no mocking (these are cheap
# and deterministic — no external service dependency beyond loopback
# and the resolver already required for the tool to work at all) ──

def test_resolve_target_with_loopback_ip():
    target, hostname = resolve_target("127.0.0.1")
    assert target == "127.0.0.1"
    assert hostname  # some string, even if it's just "127.0.0.1" itself


def test_resolve_target_with_invalid_hostname_returns_none():
    result = resolve_target("this-host-does-not-exist.invalid.")
    assert result is None


def test_resolve_target_with_resolvable_hostname():
    # Covers the success branch of the hostname path — "localhost" is
    # about as close to a guaranteed-resolvable name as exists.
    result = resolve_target("localhost")
    assert result is not None
    ip, hostname = result
    assert hostname == "localhost"
    assert ip  # some IP string came back


def test_resolve_target_ip_with_no_reverse_dns_falls_back_to_ip_itself():
    # Covers the socket.herror fallback: an IP with no PTR record should
    # still succeed, just using the IP itself as the "hostname".
    with patch("socket.gethostbyaddr", side_effect=socket.herror):
        target, hostname = resolve_target("198.51.100.7")  # TEST-NET-2
    assert target == "198.51.100.7"
    assert hostname == "198.51.100.7"

def test_resolve_target_rejects_ipv6():
    # Stage 8: every downstream socket call is AF_INET-only, so an IPv6
    # literal used to "resolve" successfully here and then fail
    # confusingly deep in the scan. Should fail cleanly at this point
    # instead, same as any other unresolvable target.
    assert resolve_target("::1") is None
    assert resolve_target("2001:db8::1") is None

# ── check_host_alive: mock subprocess so results are deterministic
# regardless of what's actually reachable from wherever tests run ──

def test_check_host_alive_true_when_ping_succeeds():
    fake_result = MagicMock(returncode=0)
    with patch("platform.system", return_value="Linux"):
        with patch("subprocess.run", return_value=fake_result):
            assert check_host_alive("127.0.0.1", timeout=1.0) is True


def test_check_host_alive_falls_back_to_tcp_when_ping_fails():
    fake_ping_result = MagicMock(returncode=1)
    fake_socket = MagicMock()
    fake_socket.connect_ex.return_value = 0  # TCP connect succeeds
    with patch("platform.system", return_value="Linux"):
        with patch("subprocess.run", return_value=fake_ping_result):
            with patch("socket.socket") as mock_socket_cls:
                mock_socket_cls.return_value.__enter__ = MagicMock(return_value=fake_socket)
                mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)
                mock_socket_cls.return_value.connect_ex = fake_socket.connect_ex
                result = check_host_alive("127.0.0.1", timeout=1.0)
    assert result is True


def test_check_host_alive_false_when_ping_and_tcp_both_fail():
    fake_ping_result = MagicMock(returncode=1)
    with patch("platform.system", return_value="Linux"):
        with patch("subprocess.run", return_value=fake_ping_result):
            with patch("socket.socket") as mock_socket_cls:
                mock_socket_cls.return_value.__enter__.return_value.connect_ex.return_value = 111
                mock_socket_cls.return_value.__exit__.return_value = False
                result = check_host_alive("203.0.113.1", timeout=0.5)  # TEST-NET-3, never routable
    assert result is False


def test_check_host_alive_survives_socket_errors_during_tcp_fallback():
    # If every TCP probe in the fallback loop raises (not just returns
    # nonzero), the function must still return False, not propagate the
    # exception and take the whole liveness check down with it.
    fake_ping_result = MagicMock(returncode=1)
    with patch("platform.system", return_value="Linux"):
        with patch("subprocess.run", return_value=fake_ping_result):
            with patch("socket.socket", side_effect=OSError("network unreachable")):
                result = check_host_alive("203.0.113.1", timeout=0.5)
    assert result is False


def test_check_host_alive_handles_subprocess_timeout_gracefully():
    with patch("platform.system", return_value="Linux"):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="ping", timeout=1)):
            with patch("socket.socket") as mock_socket_cls:
                mock_socket_cls.return_value.__enter__.return_value.connect_ex.return_value = 111
                mock_socket_cls.return_value.__exit__.return_value = False
                # Must not raise — a hung/timed-out ping should fall through
                # to the TCP fallback, not crash the whole scan.
                result = check_host_alive("203.0.113.1", timeout=0.5)
    assert result is False