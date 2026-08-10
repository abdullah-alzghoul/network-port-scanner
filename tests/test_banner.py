"""
Tests for scanner.banner — banner grabbing over real local sockets.

Two real servers are used: an ephemeral high port (exercises the
_generic_grab fallback path, since _PROBES is keyed by well-known
port numbers) and a real bind on port 80 (exercises the actual
_PROBES-driven HTTP probe path). Binding port 80 needs root — these
tests skip themselves cleanly if that's not available rather than
failing.
"""
import socket
import threading
import time

import pytest

from scanner.banner import grab_banner, _generic_grab, _clean


def _can_bind_privileged_port():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 80))
        s.close()
        return True
    except (PermissionError, OSError):
        return False


requires_port_80 = pytest.mark.skipif(
    not _can_bind_privileged_port(),
    reason="binding port 80 needs root/admin in this environment",
)


def _serve_once(port, response_bytes, wait_for_probe=False):
    """Accept exactly one connection on *port*, optionally wait for the
    client to send something first, then send *response_bytes* back."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(1)
    ready = threading.Event()

    def serve():
        server.settimeout(3.0)
        ready.set()
        try:
            conn, _ = server.accept()
            conn.settimeout(2.0)
            if wait_for_probe:
                try:
                    conn.recv(1024)  # drain the probe the client sends
                except socket.timeout:
                    pass
            conn.sendall(response_bytes)
            time.sleep(0.05)
            conn.close()
        except socket.timeout:
            pass
        finally:
            server.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    ready.wait(timeout=1.0)
    time.sleep(0.05)
    return thread


# ── _clean: pure string logic, no sockets needed ──

def test_clean_strips_ansi_and_collapses_lines():
    raw = "\x1b[31mHello\x1b[0m\nWorld\r\n"
    result = _clean(raw)
    assert "\x1b" not in result  # ANSI escape codes are stripped
    assert "Hello" in result
    assert "World" in result
    assert " | " in result  # multiple lines get joined with this separator


def test_clean_truncates_long_input():
    raw = "A" * 500
    result = _clean(raw)
    assert len(result) <= 200  # matches the module's own cap


# ── _generic_grab: real socket, ephemeral (non-well-known) port ──

def test_generic_grab_retrieves_real_banner():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    thread = _serve_once(port, b"SSH-2.0-OpenSSH_9.0\r\n")
    result = _generic_grab("127.0.0.1", port, timeout=2.0)
    thread.join(timeout=2)
    assert result is not None
    assert "SSH-2.0-OpenSSH_9.0" in result


def test_generic_grab_returns_none_when_nothing_listening():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    result = _generic_grab("127.0.0.1", port, timeout=1.0)
    assert result is None


def test_grab_banner_uses_generic_path_for_non_probe_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    thread = _serve_once(port, b"Custom-Service-Banner-XYZ\r\n")
    result = grab_banner("127.0.0.1", port, timeout=2.0)
    thread.join(timeout=2)
    assert result is not None
    assert "Custom-Service-Banner-XYZ" in result


# ── grab_banner via the real _PROBES-driven path (port 80) ──

@requires_port_80
def test_grab_banner_sends_http_probe_on_port_80():
    thread = _serve_once(
        80,
        b"HTTP/1.1 200 OK\r\nServer: TestServer/1.0\r\n\r\n",
        wait_for_probe=True,
    )
    result = grab_banner("127.0.0.1", 80, timeout=2.0)
    thread.join(timeout=2)
    assert result is not None
    assert "HTTP/1.1 200 OK" in result or "TestServer" in result