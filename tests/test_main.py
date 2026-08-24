"""
Whole-program tests for main.py — things that only make sense as a real
subprocess invocation, not a unit-level import: specifically, the
--version flag's interaction with argparse's required arguments.

The Ctrl+C / KeyboardInterrupt fix has its own test, but not here —
see test_core.py::test_scan_shuts_down_executor_without_waiting_on_keyboard_interrupt.
Sending a real SIGINT via subprocess isn't portable: Windows' Popen
doesn't support plain SIGINT the way POSIX does (only SIGTERM,
CTRL_C_EVENT, or CTRL_BREAK_EVENT, and CTRL_C_EVENT needs the child
spawned in its own process group to avoid also interrupting whatever
is running the tests) — so that fix is tested by driving the same
code path directly instead of depending on OS signal delivery.
"""
import json
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_version_flag_prints_version_and_exits_zero():
    result = subprocess.run(
        [sys.executable, "main.py", "--version"],
        cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0
    assert "portscanner" in result.stdout
    assert "1.0.0" in result.stdout


def test_version_flag_works_without_required_target():
    # --version (like -h) must short-circuit before the required -t check —
    # confirming it doesn't fail with "the following arguments are required".
    result = subprocess.run(
        [sys.executable, "main.py", "--version"],
        cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=10,
    )
    assert "required" not in result.stderr.lower()


def _serve(ip: str, port: int) -> socket.socket:
    """Real listening socket on a specific loopback address, for tests
    that need genuinely distinct hosts rather than mocking the network."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.listen(5)
    s.settimeout(10)

    def loop():
        while True:
            try:
                conn, _ = s.accept()
                conn.close()
            except socket.timeout:
                break

    threading.Thread(target=loop, daemon=True).start()
    return s


def test_multi_target_scans_each_host_and_writes_separate_reports(tmp_path):
    # 127.0.0.2 and 127.0.0.3 are genuinely distinct loopback addresses on
    # Linux, not a mock — this exercises the real multi-target loop, the
    # per-target report-filename suffixing, and the batch summary panel
    # together in one pass.
    servers = [_serve("127.0.0.2", 6100), _serve("127.0.0.3", 6100)]
    out_file = tmp_path / "batch.json"
    try:
        result = subprocess.run(
            [sys.executable, "main.py",
             "-t", "127.0.0.2,127.0.0.3",
             "-p", "6100", "--no-ping", "-o", str(out_file)],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=30,
        )
    finally:
        for s in servers:
            s.close()

    assert result.returncode == 0
    assert "Batch Summary" in result.stdout
    assert "2 scanned" in result.stdout

    # One filename can't serve two targets — each gets its IP inserted
    # before the extension instead of the bare name that was passed in.
    report_2 = tmp_path / "batch_127.0.0.2.json"
    report_3 = tmp_path / "batch_127.0.0.3.json"
    assert report_2.exists()
    assert report_3.exists()

    data_2 = json.loads(report_2.read_text())
    data_3 = json.loads(report_3.read_text())
    assert data_2["scan_info"]["target"] == "127.0.0.2"
    assert data_3["scan_info"]["target"] == "127.0.0.3"
    assert data_2["open_ports"][0]["port"] == 6100
    assert data_3["open_ports"][0]["port"] == 6100


def test_single_target_output_filename_is_unchanged():
    # Backward compatibility: with exactly one target, -o's filename
    # should be used exactly as given, no suffix inserted.
    server = _serve("127.0.0.2", 6101)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "single.json"
            result = subprocess.run(
                [sys.executable, "main.py", "-t", "127.0.0.2",
                 "-p", "6101", "--no-ping", "-o", str(out_file)],
                cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=15,
            )
            assert result.returncode == 0
            assert out_file.exists()
            assert not (Path(tmp) / "single_127.0.0.2.json").exists()
    finally:
        server.close()


def test_oversized_target_range_fails_fast_with_clean_exit():
    # Must not hang trying to expand a /8 — should error out immediately
    # with a clear message and a normal (non-crash) exit code.
    result = subprocess.run(
        [sys.executable, "main.py", "-t", "10.0.0.0/8", "-p", "80",
         "--no-ping", "--quiet"],
        cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 1
    assert "limit" in result.stdout.lower()