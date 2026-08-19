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
import subprocess
import sys
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