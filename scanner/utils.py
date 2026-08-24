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
        ip_obj = ipaddress.ip_address(target)     # already an IP?
        if isinstance(ip_obj, ipaddress.IPv6Address):
            # Every socket call downstream is AF_INET-only — an IPv6
            # literal would previously "resolve" successfully here and
            # then fail confusingly later. Fail honestly at this point
            # instead, with the same signature as any other unresolvable
            # target.
            return None
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



def parse_targets(spec: str, max_targets: int = 1024) -> List[str]:
    """
    Expand a target specification into a list of individual target
    strings (IPs or hostnames) — same spirit as parse_port_range().

    Supports, comma-separated and freely mixed:
      - A single IP or hostname          192.168.1.1 / example.com
      - CIDR notation                    192.168.1.0/28
      - A full IP-to-IP range            192.168.1.1-192.168.1.10
      - A short last-octet range         192.168.1.1-10

    Hostnames are passed through unexpanded — DNS resolution happens
    later, per-target, in resolve_target(). Only numeric IP/CIDR/range
    syntax is expanded here. A reversed range (end before start) is
    silently empty, the same precedent parse_port_range already sets
    for a reversed port range.

    Raises ValueError if a single piece — or the specification as a
    whole — would expand past max_targets, so a typo like a /8 can't
    silently attempt to queue sixteen million hosts.
    """
    targets: List[str] = []

    for piece in spec.split(","):
        piece = piece.strip()
        if not piece:
            continue

        # CIDR notation
        if "/" in piece:
            try:
                network = ipaddress.ip_network(piece, strict=False)
            except ValueError:
                network = None
            if network is not None:
                if network.num_addresses > max_targets:
                    raise ValueError(
                        f"'{piece}' expands to {network.num_addresses} addresses, "
                        f"over the {max_targets}-host limit — use a smaller range."
                    )
                targets.extend(str(ip) for ip in network.hosts())
                if len(targets) > max_targets:
                    raise ValueError(f"Target list exceeds {max_targets} hosts.")
                continue

        # IP range: "a.b.c.d-w.x.y.z" (full) or "a.b.c.d-z" (short last octet)
        if "-" in piece:
            left, _, right = piece.partition("-")
            left, right = left.strip(), right.strip()
            start_ip = end_ip = None
            try:
                start_ip = ipaddress.ip_address(left)
                if "." in right:
                    end_ip = ipaddress.ip_address(right)
                else:
                    octets = left.split(".")
                    octets[-1] = right
                    end_ip = ipaddress.ip_address(".".join(octets))
            except ValueError:
                start_ip = end_ip = None
            if start_ip is not None and end_ip is not None:
                span = int(end_ip) - int(start_ip)
                if span < 0:
                    continue  # reversed range — silently empty
                if span + 1 > max_targets:
                    raise ValueError(
                        f"'{piece}' expands to {span + 1} addresses, over the "
                        f"{max_targets}-host limit — use a smaller range."
                    )
                targets.extend(
                    str(ipaddress.ip_address(i))
                    for i in range(int(start_ip), int(end_ip) + 1)
                )
                if len(targets) > max_targets:
                    raise ValueError(f"Target list exceeds {max_targets} hosts.")
                continue

        # Single IP or hostname, passed through as-is
        targets.append(piece)
        if len(targets) > max_targets:
            raise ValueError(f"Target list exceeds {max_targets} hosts.")

    return list(dict.fromkeys(targets))  # dedupe, preserve first-seen order

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
