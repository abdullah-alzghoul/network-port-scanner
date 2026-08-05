"""
Banner grabbing with protocol-specific probes.

For each open port we try to elicit a server greeting that reveals
the software name and version (e.g. "OpenSSH_9.3", "Apache/2.4.57").
"""
import re
import socket
import ssl
from typing import Optional

# ──────────────────────────────────────────────
# Port → HTTP-style probe (bytes)
# ──────────────────────────────────────────────
_HTTP_PROBE = b"HEAD / HTTP/1.0\r\n\r\n"

_PROBES: dict[int, bytes] = {
    80:    _HTTP_PROBE,
    81:    _HTTP_PROBE,
    443:   _HTTP_PROBE,
    2082:  _HTTP_PROBE,
    2083:  _HTTP_PROBE,
    2086:  _HTTP_PROBE,
    2087:  _HTTP_PROBE,
    3000:  _HTTP_PROBE,
    7001:  _HTTP_PROBE,
    8000:  _HTTP_PROBE,
    8008:  _HTTP_PROBE,
    8080:  _HTTP_PROBE,
    8081:  _HTTP_PROBE,
    8443:  _HTTP_PROBE,
    8888:  _HTTP_PROBE,
    9000:  _HTTP_PROBE,
    9090:  _HTTP_PROBE,
    9200:  _HTTP_PROBE,
    10000: _HTTP_PROBE,
    # These send a greeting on connect – send nothing, just read
    21:    b"",   # FTP
    22:    b"",   # SSH
    25:    b"",   # SMTP
    110:   b"",   # POP3
    143:   b"",   # IMAP
    6379:  b"",   # Redis
    27017: b"",   # MongoDB (may send a server greeting)
}

# Ports that need TLS wrapping
_SSL_PORTS = {443, 465, 636, 993, 995, 8443, 2083, 2087}

_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def grab_banner(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """
    Connect to *host:port*, optionally send a probe, and return the
    first meaningful response lines as a single string.

    Returns ``None`` if no banner could be grabbed.
    """
    if port not in _PROBES:
        return _generic_grab(host, port, timeout)

    probe = _PROBES[port]
    use_ssl = port in _SSL_PORTS

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
            raw.settimeout(timeout)
            raw.connect((host, port))

            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = ctx.wrap_socket(raw, server_hostname=host)
            else:
                conn = raw

            if probe:
                conn.sendall(probe)

            data = _recv_all(conn, max_bytes=4096)
            return _clean(data.decode("utf-8", errors="replace")) if data else None

    except Exception:
        return None


def _generic_grab(host: str, port: int, timeout: float) -> Optional[str]:
    """Attempt a plain TCP grab for ports not in the probe table."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            data = _recv_all(s, max_bytes=2048)
        return _clean(data.decode("utf-8", errors="replace")) if data else None
    except Exception:
        return None


def _recv_all(sock: socket.socket, max_bytes: int = 4096) -> bytes:
    """Read until the socket closes, times out, or we hit *max_bytes*."""
    buf = b""
    try:
        while len(buf) < max_bytes:
            chunk = sock.recv(1024)
            if not chunk:
                break
            buf += chunk
    except (socket.timeout, OSError):
        pass
    return buf


def _clean(raw: str) -> Optional[str]:
    """Strip ANSI codes, collapse whitespace, cap at 200 chars."""
    text = _ANSI_RE.sub("", raw)
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    useful = " | ".join(lines[:4])           # keep up to 4 lines
    useful = useful[:200]                     # hard cap
    return useful if len(useful) > 3 else None


