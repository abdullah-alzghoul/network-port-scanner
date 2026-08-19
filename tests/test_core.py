"""
Tests for scanner.core.PortScanner — the actual scan engine.

Uses real local sockets (a background server thread on 127.0.0.1)
rather than mocking the socket layer, so these tests exercise the
genuine TCP connect / open / closed logic, not a description of it.
SYN scanning's raw-socket path is tested for its fallback behavior
only (ImportError, PermissionError) — the actual raw-packet crafting
is scapy's responsibility, not this project's, and isn't something
that can be honestly tested in an ordinary CI runner anyway.
"""
import socket
import sys
import threading
import time
import concurrent.futures

import pytest

from scanner.core import PortScanner, PortState, PortResult, ScanResult


# ── fixtures: a real listening socket and a guaranteed-closed port ──

@pytest.fixture
def open_tcp_port():
    """A real server socket on 127.0.0.1, accepting one connection at a
    time and sending a fixed banner. Yields the port number; tears the
    server down afterward."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    port = server.getsockname()[1]
    stop = threading.Event()

    def serve():
        server.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
                conn.sendall(b"TEST-BANNER-READY\r\n")
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                break

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    time.sleep(0.05)  # let the server actually start listening
    yield port
    stop.set()
    server.close()
    thread.join(timeout=1)


@pytest.fixture
def closed_tcp_port():
    """A port number nothing is listening on: bind briefly to grab a
    free ephemeral port, then close it immediately."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ── real end-to-end TCP scan behavior ──

def test_open_port_detected_as_open(open_tcp_port):
    scanner = PortScanner("127.0.0.1", [open_tcp_port], scan_type="tcp",
                           threads=5, timeout=2.0)
    result = scanner.scan()
    assert len(result.open_ports) == 1
    assert result.open_ports[0].port == open_tcp_port
    assert result.open_ports[0].state == PortState.OPEN


def test_closed_port_detected_as_closed(closed_tcp_port):
    scanner = PortScanner("127.0.0.1", [closed_tcp_port], scan_type="tcp",
                           threads=5, timeout=2.0)
    result = scanner.scan()
    assert len(result.open_ports) == 0
    assert result.closed_count == 1
    assert result.filtered_count == 0


def test_mixed_open_and_closed_ports_both_correct(open_tcp_port, closed_tcp_port):
    scanner = PortScanner("127.0.0.1", [open_tcp_port, closed_tcp_port],
                           scan_type="tcp", threads=5, timeout=2.0)
    result = scanner.scan()
    assert [p.port for p in result.open_ports] == [open_tcp_port]
    assert result.closed_count == 1


def test_banner_grabbed_on_open_port_when_requested(open_tcp_port):
    scanner = PortScanner("127.0.0.1", [open_tcp_port], scan_type="tcp",
                           threads=5, timeout=2.0, grab_banners=True)
    result = scanner.scan()
    assert result.open_ports[0].banner is not None
    assert "TEST-BANNER-READY" in result.open_ports[0].banner


def test_banner_not_grabbed_when_not_requested(open_tcp_port):
    scanner = PortScanner("127.0.0.1", [open_tcp_port], scan_type="tcp",
                           threads=5, timeout=2.0, grab_banners=False)
    result = scanner.scan()
    assert result.open_ports[0].banner is None


def test_open_ports_are_sorted_by_port_number(open_tcp_port, closed_tcp_port):
    # Scan several open sockets out of order and confirm the result is
    # sorted, since threaded completion order isn't guaranteed.
    servers = []
    ports = []
    try:
        for _ in range(3):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            servers.append(s)
            ports.append(s.getsockname()[1])

        scanner = PortScanner("127.0.0.1", sorted(ports, reverse=True),
                               scan_type="tcp", threads=10, timeout=2.0)
        result = scanner.scan()
        result_ports = [p.port for p in result.open_ports]
        assert result_ports == sorted(ports)
    finally:
        for s in servers:
            s.close()


def test_response_ms_is_populated_and_reasonable(open_tcp_port):
    scanner = PortScanner("127.0.0.1", [open_tcp_port], scan_type="tcp",
                           threads=5, timeout=2.0)
    result = scanner.scan()
    ms = result.open_ports[0].response_ms
    assert ms is not None
    assert 0 <= ms < 2000  # local loopback, should be fast, well under the 2s timeout


def test_scan_result_totals_match_ports_scanned(open_tcp_port, closed_tcp_port):
    scanner = PortScanner("127.0.0.1", [open_tcp_port, closed_tcp_port],
                           scan_type="tcp", threads=5, timeout=2.0)
    result = scanner.scan()
    assert result.total_ports == 2
    assert len(result.open_ports) + result.closed_count + result.filtered_count == 2


def test_progress_callback_fires_once_per_port(open_tcp_port, closed_tcp_port):
    calls = []
    scanner = PortScanner("127.0.0.1", [open_tcp_port, closed_tcp_port],
                           scan_type="tcp", threads=5, timeout=2.0)
    scanner.scan(progress_callback=lambda done, total, pr: calls.append((done, total, pr.port)))
    assert len(calls) == 2
    assert {c[2] for c in calls} == {open_tcp_port, closed_tcp_port}
    assert max(c[0] for c in calls) == 2
    assert all(c[1] == 2 for c in calls)


def test_progress_callback_exception_does_not_abort_scan(open_tcp_port):
    # scan() wraps the callback in try/except — a broken callback
    # shouldn't take the whole scan down with it.
    scanner = PortScanner("127.0.0.1", [open_tcp_port], scan_type="tcp",
                           threads=5, timeout=2.0)
    result = scanner.scan(progress_callback=lambda *a: 1 / 0)
    assert len(result.open_ports) == 1  # scan still completed correctly


# ── dispatch routing ──

def test_dispatch_routes_tcp_to_tcp_scan(closed_tcp_port):
    scanner = PortScanner("127.0.0.1", [closed_tcp_port], scan_type="tcp")
    called = {}
    scanner._tcp_scan = lambda port: called.setdefault("tcp", port) or PortResult(port, PortState.CLOSED, {})
    scanner._dispatch(closed_tcp_port)
    assert called.get("tcp") == closed_tcp_port


def test_dispatch_routes_udp_to_udp_scan():
    scanner = PortScanner("127.0.0.1", [53], scan_type="udp")
    called = {}
    scanner._udp_scan = lambda port: called.setdefault("udp", port) or PortResult(port, PortState.OPEN, {})
    scanner._dispatch(53)
    assert called.get("udp") == 53


def test_dispatch_routes_syn_to_syn_scan():
    scanner = PortScanner("127.0.0.1", [80], scan_type="syn")
    called = {}
    scanner._syn_scan = lambda port: called.setdefault("syn", port) or PortResult(port, PortState.OPEN, {})
    scanner._dispatch(80)
    assert called.get("syn") == 80

# ── KeyboardInterrupt handling in scan() ──

def test_scan_shuts_down_executor_without_waiting_on_keyboard_interrupt(monkeypatch):
    # Regression test for the Stage 8 Ctrl+C fix — done at the unit level
    # rather than via a real OS signal to a subprocess: sending SIGINT
    # through subprocess.Popen isn't portable (Windows doesn't support
    # plain SIGINT the way POSIX does, only CTRL_C_EVENT with extra
    # process-group setup), so this drives the same code path directly
    # instead of depending on platform-specific signal delivery.
    scanner = PortScanner("127.0.0.1", [1, 2, 3], scan_type="tcp", threads=3, timeout=1.0)

    shutdown_calls = []
    real_executor_cls = concurrent.futures.ThreadPoolExecutor

    class TrackedExecutor(real_executor_cls):
        def shutdown(self, wait=True, *, cancel_futures=False):
            shutdown_calls.append({"wait": wait, "cancel_futures": cancel_futures})
            return super().shutdown(wait=wait, cancel_futures=cancel_futures)

    def fake_dispatch(port):
        if port == 2:
            raise KeyboardInterrupt()
        return PortResult(port, PortState.CLOSED, {})

    monkeypatch.setattr(concurrent.futures, "ThreadPoolExecutor", TrackedExecutor)
    scanner._dispatch = fake_dispatch

    with pytest.raises(KeyboardInterrupt):
        scanner.scan()

    # The explicit shutdown in the except block is what matters — it must
    # have fired with cancel_futures=True. (A second, default shutdown()
    # call also happens afterward, from the `with` statement's own
    # __exit__ once the exception propagates — that one is harmless: by
    # then everything not yet started has already been cancelled, so it
    # only waits on whatever was already in flight, which is exactly the
    # bounded wait the fix is meant to produce.)
    assert {"wait": False, "cancel_futures": True} in shutdown_calls


def test_unrecognized_scan_type_defaults_to_tcp(closed_tcp_port):
    # scan_type isn't validated against a fixed set in PortScanner itself
    # (argparse restricts it at the CLI layer) — confirm the internal
    # default is the safe one, not a crash.
    scanner = PortScanner("127.0.0.1", [closed_tcp_port], scan_type="anything-else")
    result = scanner._dispatch(closed_tcp_port)
    assert result.state == PortState.CLOSED  # real TCP scan actually ran


# ── SYN scan: fallback behavior only, not real packet crafting ──

def test_syn_scan_falls_back_to_tcp_when_scapy_unavailable(closed_tcp_port):
    scanner = PortScanner("127.0.0.1", [closed_tcp_port], scan_type="syn", timeout=2.0)
    with pytest.MonkeyPatch.context() as mp:
        mp.setitem(sys.modules, "scapy.all", None)  # forces ImportError on `from scapy.all import ...`
        result = scanner._syn_scan(closed_tcp_port)
    # Should have silently done a real TCP scan instead of erroring out.
    assert result.state == PortState.CLOSED


def test_syn_scan_falls_back_to_tcp_on_permission_error(closed_tcp_port, monkeypatch):
    # Simulates running -s syn without root/admin: scapy imports fine,
    # but the raw-socket call it makes raises PermissionError. Stage 4
    # fixed this to fall back to TCP instead of reporting every port
    # as a misleading "filtered". Skipped if scapy isn't installed —
    # it's an optional dependency, and this test needs the real module
    # importable to patch a real attribute on it.
    scapy_all = pytest.importorskip("scapy.all")
    monkeypatch.setattr(scapy_all, "sr1", lambda *a, **k: (_ for _ in ()).throw(PermissionError()))
    scanner = PortScanner("127.0.0.1", [closed_tcp_port], scan_type="syn", timeout=2.0)
    result = scanner._syn_scan(closed_tcp_port)
    assert result.state == PortState.CLOSED  # real TCP fallback ran, not a fake FILTERED