"""
Whole-program tests for main.py — things that only make sense as a real
subprocess invocation, not a unit-level import (the --version flag's
interaction with argparse's required arguments, and how the process
actually responds to a real SIGINT while a scan is mid-flight).
"""
import signal
import subprocess
import sys
import time
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


def test_ctrl_c_interrupts_a_running_scan_promptly():
    # Regression test for the Stage 8 fix: previously, SIGINT during a scan
    # didn't actually stop anything until every queued port had been
    # processed, because ThreadPoolExecutor's context manager waits for
    # the full queue on exit. A wide port range against an unreachable
    # target keeps this scan running long enough to interrupt mid-flight.
    proc = subprocess.Popen(
        [sys.executable, "main.py", "-t", "203.0.113.5", "-p", "1-2000",
         "--timeout", "3", "--no-ping"],
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    time.sleep(1.0)  # let it actually get into the scan loop
    proc.send_signal(signal.SIGINT)
    try:
        out, _ = proc.communicate(timeout=6)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        assert False, "process did not exit within 6s of SIGINT — Ctrl+C is not interrupting the scan promptly"

    assert proc.returncode == 0
    assert "interrupted" in out.lower()