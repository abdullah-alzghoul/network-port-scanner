"""
Utility helpers: target resolution, port parsing, host discovery.
"""
import socket
import ipaddress
import subprocess
import platform
from typing import List, Optional, Tuple

from .services import COMMON_PORTS


# ──────────────────────────────────────────────
# Target resolution
# ──────────────────────────────────────────────

def resolve_target(target: str) -> Optional[Tuple[str, str]]:
    """
    Resolve *target* (IP or hostname) to ``(ip, hostname)``.
    Returns ``None`` when resolution fails.
    """
    try:
        ipaddress.ip_address(target)          # already an IP?
        try:
            hostname = socket.gethostbyaddr(target)[0]
        except socket.herror:
            hostname = target
        return target, hostname

    except ValueError:                        # it's a hostname
        try:
            ip = socket.gethostbyname(target)
            return ip, target
        except socket.gaierror:
            return None


# ──────────────────────────────────────────────
# Host liveness check
# ──────────────────────────────────────────────

def check_host_alive(target: str, timeout: float = 1.0) -> bool:
    """
    Return True when the host appears reachable.

    Strategy:
      1. ICMP ping (fastest, may need privileges).
      2. TCP probe on ports 80/443/22/8080 as fallback.
    """
    # --- ICMP ping ---
    is_windows = platform.system().lower() == "windows"
    cmd = (["ping", "-n", "1", "-w", str(int(timeout * 1000)), target]
           if is_windows else
           ["ping", "-c", "1", "-W", str(max(1, int(timeout))), target])
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=3)
        if result.returncode == 0:
            return True
    except Exception:
        pass

    # --- TCP fallback ---
    for port in (80, 443, 22, 8080):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((target, port)) == 0:
                s.close()
                return True
            s.close()
        except Exception:
            pass

    return False


# ──────────────────────────────────────────────
# Port range parsing
# ──────────────────────────────────────────────

def parse_port_range(spec: str) -> List[int]:
    """
    Parse a port specification string into a sorted list of port numbers.

    Supported formats
    -----------------
    ``common``       → well-known ports (~80 entries)
    ``all``          → 1-65535
    ``top100``       → first 100 common ports
    ``80``           → single port
    ``1-1024``       → range
    ``22,80,443``    → comma-separated
    ``1-100,443,8080`` → mixed
    """
    spec = spec.strip().lower()

    if spec == "common":
        return sorted(COMMON_PORTS)
    if spec == "all":
        return list(range(1, 65536))
    if spec == "top100":
        return sorted(COMMON_PORTS[:100])

    ports: set = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                lo, hi = part.split("-", 1)
                lo, hi = int(lo.strip()), int(hi.strip())
                if 1 <= lo <= 65535 and 1 <= hi <= 65535:
                    ports.update(range(lo, hi + 1))
            except ValueError:
                pass
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                pass

    return sorted(ports)
