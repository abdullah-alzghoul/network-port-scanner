"""
Tests for scanner.report.ReportGenerator — JSON, HTML, and TXT output.

Two of these tests exist specifically because Stage 3 found real bugs in
this exact file: ReportGenerator's signature was broken by an earlier
fix, and the HTML report didn't escape network-supplied content. Both
get a permanent regression test here, not just a one-time manual check.
"""
import os
import json
import inspect
import tempfile

from scanner.core import ScanResult, PortResult, PortState
from scanner.report import ReportGenerator


def _sample_result(banner=None, hostname="example.com"):
    return ScanResult(
        target="192.0.2.1",
        hostname=hostname,
        scan_type="tcp",
        timestamp="2026-08-09T12:00:00",
        open_ports=[
            PortResult(
                port=80,
                state=PortState.OPEN,
                service={"name": "HTTP", "category": "Web", "description": "HTTP", "risk": "MEDIUM"},
                banner=banner,
                response_ms=12.3,
            )
        ],
        closed_count=1,
        filtered_count=0,
        total_ports=2,
        scan_time=0.45,
    )


# ── Regression test: Stage 3's ReportGenerator signature break ──

def test_reportgenerator_constructor_takes_exactly_result_and_elapsed():
    # main.py calls ReportGenerator(result, elapsed) with no third argument.
    # This broke once already when an unused `args` param was removed from
    # __init__ but a call site wasn't updated. Pin the signature so that
    # regression can't happen silently again.
    sig = inspect.signature(ReportGenerator.__init__)
    params = list(sig.parameters.keys())
    assert params == ["self", "result", "elapsed"], (
        f"ReportGenerator.__init__ signature changed to {params} — "
        f"check main.py's call site still matches"
    )


def test_reportgenerator_actually_constructs_with_two_args():
    # Not just a signature check — actually call it the way main.py does.
    gen = ReportGenerator(_sample_result(), 1.23)
    assert gen.elapsed == 1.23


# ── Regression test: Stage 3's HTML-escaping gap ──

def test_html_report_escapes_malicious_banner():
    payload = '<script>alert("pwned")</script>'
    result = _sample_result(banner=payload)
    gen = ReportGenerator(result, 1.0)
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
        path = f.name
    try:
        gen.save(path)
        content = open(path, encoding="utf-8").read()
        assert "<script>alert" not in content, (
            "Raw <script> tag made it into the HTML report unescaped — "
            "a malicious banner could execute JS when the report is opened"
        )
        assert "&lt;script&gt;" in content
    finally:
        os.unlink(path)


def test_html_report_escapes_malicious_hostname():
    # hostname comes from reverse DNS — attacker-controllable via a
    # crafted PTR record on the scanned target's network, not from the
    # person running the scan.
    payload = '<img src=x onerror=alert(1)>'
    result = _sample_result(hostname=payload)
    gen = ReportGenerator(result, 1.0)
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
        path = f.name
    try:
        gen.save(path)
        content = open(path, encoding="utf-8").read()
        assert "<img src=x onerror" not in content
        assert "&lt;img" in content
    finally:
        os.unlink(path)


def test_html_report_still_renders_normal_banner_readably():
    # The escaping fix shouldn't mangle ordinary, non-malicious banners.
    result = _sample_result(banner="Apache/2.4.41 (Ubuntu)")
    gen = ReportGenerator(result, 1.0)
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
        path = f.name
    try:
        gen.save(path)
        content = open(path, encoding="utf-8").read()
        assert "Apache/2.4.41 (Ubuntu)" in content
    finally:
        os.unlink(path)


# ── JSON output ──

def test_json_report_structure_and_content():
    result = _sample_result(banner="nginx/1.18.0")
    gen = ReportGenerator(result, 2.5)
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    try:
        gen.save(path)
        data = json.load(open(path, encoding="utf-8"))
        assert data["scan_info"]["target"] == "192.0.2.1"
        assert data["scan_info"]["duration_seconds"] == 2.5
        assert data["scan_info"]["open_count"] == 1
        assert data["open_ports"][0]["port"] == 80
        assert data["open_ports"][0]["banner"] == "nginx/1.18.0"
    finally:
        os.unlink(path)


# ── TXT output ──

def test_txt_report_contains_key_fields():
    result = _sample_result(banner="nginx/1.18.0")
    gen = ReportGenerator(result, 2.5)
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        path = f.name
    try:
        gen.save(path)
        content = open(path, encoding="utf-8").read()
        assert "192.0.2.1" in content
        assert "80" in content
        assert "nginx/1.18.0" in content
    finally:
        os.unlink(path)


# ── Format dispatch by extension ──

def test_unrecognized_extension_falls_back_to_txt():
    result = _sample_result()
    gen = ReportGenerator(result, 1.0)
    with tempfile.NamedTemporaryFile(suffix=".unknown", delete=False) as f:
        path = f.name
    try:
        gen.save(path)
        content = open(path, encoding="utf-8").read()
        assert "192.0.2.1" in content  # got the TXT format, not an error
    finally:
        os.unlink(path)