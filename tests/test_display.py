"""
Tests for scanner.display — the Rich-based terminal UI.

_risk_badge and _category_cell are pure functions, tested directly.
The print_* functions have side effects (writing to a module-level
Console), so they're tested by swapping that Console for one backed
by an in-memory buffer and asserting on the actual rendered text —
not just on what arguments were passed in.
"""
import io

import pytest
from rich.console import Console

import scanner.display as display
from scanner.core import PortResult, PortState


@pytest.fixture
def captured_console(monkeypatch):
    """Redirect scanner.display's module-level console to an in-memory
    buffer for the duration of a test, and hand back a function to read
    what was actually rendered."""
    buf = io.StringIO()
    test_console = Console(file=buf, width=130, no_color=True, force_terminal=False)
    monkeypatch.setattr(display, "console", test_console)
    return lambda: buf.getvalue()


def _open_port(port, banner=None):
    from scanner.services import get_service_info
    return PortResult(port, PortState.OPEN, get_service_info(port), banner, 1.0)


# ── pure helpers ──

def test_risk_badge_known_levels():
    for risk in ("HIGH", "MEDIUM", "LOW"):
        badge = display._risk_badge(risk)
        assert badge.plain == risk


def test_risk_badge_unrecognized_value_does_not_raise():
    # RISK_COLOR.get(..., "dim white") is the fallback — confirm an
    # unexpected string doesn't crash the whole render.
    badge = display._risk_badge("SOMETHING_UNEXPECTED")
    assert badge.plain == "SOMETHING_UNEXPECTED"


def test_category_cell_returns_plain_text():
    # Stage 3 removed the CATEGORY_ICON lookup here — confirm it's
    # genuinely just a passthrough now, not silently still prefixing
    # something.
    assert display._category_cell("Web") == "Web"
    assert display._category_cell("AnythingAtAll") == "AnythingAtAll"


# ── print_error / print_warning / print_success ──

def test_print_error_contains_message_and_x_mark(captured_console):
    display.print_error("something broke")
    out = captured_console()
    assert "something broke" in out
    assert "✗" in out  # kept deliberately — Stage 1 decision, not an emoji


def test_print_warning_contains_message_no_emoji(captured_console):
    display.print_warning("heads up")
    out = captured_console()
    assert "heads up" in out
    assert "Warning:" in out
    assert not any(ord(c) >= 0x2600 for c in out)


def test_print_success_contains_message_and_check_mark(captured_console):
    display.print_success("all good")
    out = captured_console()
    assert "all good" in out
    assert "✓" in out


# ── _print_security_notes ──

def test_security_notes_labels_warning_tier_correctly(captured_console):
    display._print_security_notes([_open_port(23)])  # Telnet
    out = captured_console()
    assert "WARNING" in out
    assert "23/Telnet" in out
    assert "CRITICAL" not in out


def test_security_notes_labels_critical_tier_correctly(captured_console):
    display._print_security_notes([_open_port(6379)])  # Redis
    out = captured_console()
    assert "CRITICAL" in out
    assert "6379/Redis" in out
    assert "WARNING" not in out


def test_security_notes_handles_both_tiers_together(captured_console):
    display._print_security_notes([_open_port(23), _open_port(6379)])
    out = captured_console()
    assert "WARNING" in out
    assert "CRITICAL" in out


def test_security_notes_silent_when_nothing_notable_open(captured_console):
    # A port with no special-cased risk shouldn't produce a panel at all.
    display._print_security_notes([_open_port(8888)])
    out = captured_console()
    assert out.strip() == ""


def test_security_notes_output_contains_no_emoji(captured_console):
    # Full regression check for the Stage 3 CATEGORY_ICON/emoji removal —
    # exercise every branch in one pass.
    all_special_ports = [23, 21, 69, 3389, 445, 135, 1433, 3306, 5432, 5900,
                          6379, 27017, 9200, 4444]
    display._print_security_notes([_open_port(p) for p in all_special_ports])
    out = captured_console()
    assert not any(ord(c) >= 0x2600 for c in out), (
        "Emoji found in _print_security_notes output — regression from Stage 3/1"
    )
    assert out.count("WARNING") == 10
    assert out.count("CRITICAL") == 4

# ── print_scan_config ──

def test_scan_config_shows_target_and_settings(captured_console):
    display.print_scan_config(
        ip="192.0.2.1", hostname="192.0.2.1", ports=[22, 80, 443],
        scan_type="tcp", threads=150, timeout=1.0, grab_banners=False,
    )
    out = captured_console()
    assert "192.0.2.1" in out
    assert "3 ports" in out
    assert "TCP" in out
    assert "150" in out
    assert "1.0s" in out


def test_scan_config_hides_hostname_row_when_same_as_ip(captured_console):
    display.print_scan_config(
        ip="192.0.2.1", hostname="192.0.2.1", ports=[80],
        scan_type="tcp", threads=150, timeout=1.0, grab_banners=False,
    )
    out = captured_console()
    assert "Hostname" not in out


def test_scan_config_shows_hostname_row_when_different_from_ip(captured_console):
    display.print_scan_config(
        ip="192.0.2.1", hostname="example.com", ports=[80],
        scan_type="tcp", threads=150, timeout=1.0, grab_banners=False,
    )
    out = captured_console()
    assert "Hostname" in out
    assert "example.com" in out


def test_scan_config_banners_yes_when_enabled(captured_console):
    display.print_scan_config(
        ip="192.0.2.1", hostname="192.0.2.1", ports=[80],
        scan_type="tcp", threads=150, timeout=1.0, grab_banners=True,
    )
    out = captured_console()
    assert "yes" in out


def test_scan_config_banners_no_when_disabled(captured_console):
    display.print_scan_config(
        ip="192.0.2.1", hostname="192.0.2.1", ports=[80],
        scan_type="tcp", threads=150, timeout=1.0, grab_banners=False,
    )
    out = captured_console()
    assert "no" in out
    assert "yes" not in out


def test_scan_config_port_count_uses_thousands_separator(captured_console):
    display.print_scan_config(
        ip="192.0.2.1", hostname="192.0.2.1", ports=list(range(1, 1001)),
        scan_type="tcp", threads=150, timeout=1.0, grab_banners=False,
    )
    out = captured_console()
    assert "1,000 ports" in out


# ── print_results ──

class _FakeResult:
    """Minimal stand-in matching what print_results actually reads off
    a ScanResult, without needing the real dataclass's full field set."""
    def __init__(self, target="192.0.2.1", scan_type="tcp", open_ports=None,
                 closed_count=0, filtered_count=0, total_ports=0):
        self.target = target
        self.scan_type = scan_type
        self.open_ports = open_ports or []
        self.closed_count = closed_count
        self.filtered_count = filtered_count
        self.total_ports = total_ports


def test_results_summary_shows_correct_counts(captured_console):
    result = _FakeResult(closed_count=5, filtered_count=2, total_ports=8,
                          open_ports=[_open_port(80)])
    display.print_results(result, elapsed=1.23)
    out = captured_console()
    assert "Open: 1" in out
    assert "Closed: 5" in out
    assert "Filtered: 2" in out
    assert "1.23s" in out
    assert "8 ports scanned" in out


def test_results_no_table_when_nothing_open(captured_console):
    result = _FakeResult(closed_count=3, filtered_count=1, total_ports=4, open_ports=[])
    display.print_results(result, elapsed=0.5)
    out = captured_console()
    assert "Open: 0" in out
    assert "Open Ports on" not in out  # table title never rendered — early return


def test_results_table_shows_open_port_details(captured_console):
    result = _FakeResult(open_ports=[_open_port(80, banner="nginx/1.18.0")],
                          total_ports=1)
    display.print_results(result, elapsed=0.5)
    out = captured_console()
    assert "Open Ports on 192.0.2.1" in out
    assert "80" in out
    assert "HTTP" in out
    assert "nginx/1.18.0" in out


def test_results_long_banner_gets_truncated(captured_console):
    long_banner = "X" * 60
    result = _FakeResult(open_ports=[_open_port(80, banner=long_banner)],
                          total_ports=1)
    display.print_results(result, elapsed=0.5)
    out = captured_console()
    assert long_banner not in out       # the full 60-char string never appears
    assert ("X" * 42 + "…") in out      # truncated to 42 chars plus ellipsis


def test_results_missing_response_ms_shows_dash(captured_console):
    from scanner.core import PortResult, PortState
    from scanner.services import get_service_info
    pr = PortResult(80, PortState.OPEN, get_service_info(80), None, response_ms=None)
    result = _FakeResult(open_ports=[pr], total_ports=1)
    display.print_results(result, elapsed=0.5)
    out = captured_console()
    assert "—" in out


def test_results_udp_scan_shows_udp_protocol(captured_console):
    result = _FakeResult(scan_type="udp", open_ports=[_open_port(53)], total_ports=1)
    display.print_results(result, elapsed=0.5)
    out = captured_console()
    assert "UDP" in out


def test_results_calls_security_notes_for_risky_open_port(captured_console):
    # Confirms print_results actually invokes _print_security_notes as
    # part of its own flow, end to end — not tested in isolation only.
    result = _FakeResult(open_ports=[_open_port(23)], total_ports=1)  # Telnet
    display.print_results(result, elapsed=0.5)
    out = captured_console()
    assert "WARNING" in out
    assert "23/Telnet" in out


# ── the remaining static/simple output functions ──

def test_print_banner_shows_title_no_emoji(captured_console):
    display.print_banner()
    out = captured_console()
    assert "Advanced Network Port Scanner" in out
    assert not any(ord(c) >= 0x2600 for c in out)


def test_print_legal_warning_shows_disclaimer_no_emoji(captured_console):
    display.print_legal_warning()
    out = captured_console()
    assert "LEGAL WARNING" in out
    assert "Only scan systems you own" in out
    assert not any(ord(c) >= 0x2600 for c in out)


def test_print_open_port_live_shows_port_number(captured_console):
    display.print_open_port_live(_open_port(443))
    out = captured_console()
    assert "443" in out
    assert "open" in out