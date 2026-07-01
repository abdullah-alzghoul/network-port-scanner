"""
Core scanning engine.

Supported scan types
--------------------
tcp   – Full TCP connect scan  (works everywhere, no root needed)
syn   – SYN (half-open) scan   (requires root + scapy; falls back to tcp)
udp   – UDP scan                (open|filtered status only)
"""
import concurrent.futures
import datetime
import socket
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional

from .banner import grab_banner
from .services import get_service_info


# ──────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────

class PortState(Enum):
    OPEN     = "open"
    CLOSED   = "closed"
    FILTERED = "filtered"


@dataclass
class PortResult:
    port:          int
    state:         PortState
    service:       Dict
    banner:        Optional[str] = None
    response_ms:   float = 0.0


@dataclass
class ScanResult:
    target:         str
    hostname:       str
    scan_type:      str
    timestamp:      str       = ""
    open_ports:     List[PortResult] = field(default_factory=list)
    closed_count:   int  = 0
    filtered_count: int  = 0
    total_ports:    int  = 0
    scan_time:      float = 0.0


# ──────────────────────────────────────────────
# Scanner
# ──────────────────────────────────────────────

class PortScanner:
    """
    Multi-threaded port scanner supporting TCP, SYN, and UDP.

    Parameters
    ----------
    target      : IP address of the host to scan
    ports       : sorted list of port numbers to check
    scan_type   : "tcp" | "syn" | "udp"
    threads     : max concurrent workers (capped at 1 000)
    timeout     : per-port socket timeout in seconds
    grab_banners: attempt service banner grabbing on open ports
    verbose     : if True, open ports are emitted immediately via callback
    """

    _MAX_THREADS = 1000

    def __init__(
        self,
        target:       str,
        ports:        List[int],
        scan_type:    str   = "tcp",
        threads:      int   = 150,
        timeout:      float = 1.0,
        grab_banners: bool  = False,
        verbose:      bool  = False,
    ) -> None:
        self.target       = target
        self.ports        = ports
        self.scan_type    = scan_type.lower()
        self.threads      = min(threads, self._MAX_THREADS)
        self.timeout      = timeout
        self.grab_banners = grab_banners
        self.verbose      = verbose
        self._lock        = threading.Lock()
        self._done        = 0

    # ── public ──

    def scan(self, progress_callback: Optional[Callable] = None) -> ScanResult:
        """
        Scan all ports and return a :class:`ScanResult`.

        ``progress_callback(scanned: int, total: int, result: PortResult)``
        is called after every port completes (thread-safe).
        """
        result = ScanResult(
            target    = self.target,
            hostname  = self.target,
            scan_type = self.scan_type,
            timestamp = datetime.datetime.now().isoformat(timespec="seconds"),
            total_ports = len(self.ports),
        )

        open_ports:     List[PortResult] = []
        closed_count  = 0
        filtered_count = 0
        start         = time.perf_counter()

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.threads
        ) as executor:
            futures = {
                executor.submit(self._dispatch, port): port
                for port in self.ports
            }
            for future in concurrent.futures.as_completed(futures):
                pr: PortResult = future.result()

                with self._lock:
                    self._done += 1
                    done_snap = self._done

                if pr.state == PortState.OPEN:
                    open_ports.append(pr)
                elif pr.state == PortState.CLOSED:
                    closed_count += 1
                else:
                    filtered_count += 1

                if progress_callback:
                    try:
                        progress_callback(done_snap, len(self.ports), pr)
                    except Exception:
                        pass

        result.scan_time      = time.perf_counter() - start
        result.open_ports     = sorted(open_ports, key=lambda x: x.port)
        result.closed_count   = closed_count
        result.filtered_count = filtered_count
        return result

    # ── dispatch ──

    def _dispatch(self, port: int) -> PortResult:
        if self.scan_type == "syn":
            return self._syn_scan(port)
        if self.scan_type == "udp":
            return self._udp_scan(port)
        return self._tcp_scan(port)

    # ── TCP connect scan ──

    def _tcp_scan(self, port: int) -> PortResult:
        t0 = time.perf_counter()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            err = s.connect_ex((self.target, port))
            ms  = round((time.perf_counter() - t0) * 1000, 2)
            s.close()

            if err == 0:
                svc    = get_service_info(port)
                banner = grab_banner(self.target, port, self.timeout) \
                         if self.grab_banners else None
                return PortResult(port, PortState.OPEN, svc, banner, ms)

            return PortResult(port, PortState.CLOSED, get_service_info(port),
                              response_ms=ms)

        except socket.timeout:
            return PortResult(port, PortState.FILTERED, get_service_info(port))
        except OSError:
            return PortResult(port, PortState.FILTERED, get_service_info(port))

    # ── SYN scan (requires scapy + root) ──

    def _syn_scan(self, port: int) -> PortResult:
        try:
            from scapy.all import IP, TCP, sr1, conf  # type: ignore
            conf.verb = 0

            pkt  = IP(dst=self.target) / TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=self.timeout, verbose=0)

            if resp is None:
                return PortResult(port, PortState.FILTERED, get_service_info(port))

            if resp.haslayer(TCP):
                flags = resp[TCP].flags
                if flags == 0x12:          # SYN-ACK → OPEN
                    rst = IP(dst=self.target) / TCP(dport=port, flags="R")
                    sr1(rst, timeout=self.timeout, verbose=0)
                    svc    = get_service_info(port)
                    banner = grab_banner(self.target, port, self.timeout) \
                             if self.grab_banners else None
                    return PortResult(port, PortState.OPEN, svc, banner)
                if flags & 0x04:           # RST → CLOSED
                    return PortResult(port, PortState.CLOSED, get_service_info(port))

            return PortResult(port, PortState.FILTERED, get_service_info(port))

        except ImportError:
            # scapy not installed → graceful fallback
            return self._tcp_scan(port)
        except Exception:
            return PortResult(port, PortState.FILTERED, get_service_info(port))

    # ── UDP scan ──

    def _udp_scan(self, port: int) -> PortResult:
        """
        UDP is connectionless; we send an empty datagram and:
        - If we get data back        → OPEN
        - If socket times out        → OPEN|FILTERED (we mark OPEN)
        - If ICMP port-unreachable   → CLOSED
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)
            s.sendto(b"\x00", (self.target, port))
            try:
                s.recvfrom(1024)
                s.close()
                return PortResult(port, PortState.OPEN, get_service_info(port))
            except socket.timeout:
                s.close()
                # Cannot distinguish open from filtered without raw sockets
                return PortResult(port, PortState.OPEN, get_service_info(port))
        except ConnectionRefusedError:
            return PortResult(port, PortState.CLOSED, get_service_info(port))
        except OSError:
            return PortResult(port, PortState.FILTERED, get_service_info(port))
