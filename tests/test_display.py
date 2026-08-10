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