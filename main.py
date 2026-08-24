#!/usr/bin/env python3
"""
Network Port Scanner — main entry point.

Usage examples
--------------
  python main.py -t scanme.nmap.org -p common
  python main.py -t 192.168.1.1 -p 1-1024 --banner
  python main.py -t 10.0.0.1   -p 22,80,443,3306,3389
  python main.py -t 192.168.1.1 -p all --threads 300 -o report.html
  python main.py -t 192.168.1.1 -p 1-500 -s syn          # root only
  python main.py -t 192.168.1.1 -p common -s udp
  python main.py -t 10.0.0.0/28 -p common -o report.html # multi-target CIDR
  python main.py -t 10.0.0.1,10.0.0.5,10.0.0.10 -p 22,80  # multi-target list

Only scan systems you own or have explicit written permission to test.
"""

import argparse
import sys
import textwrap
import time
from pathlib import Path

from rich.console  import Console
from rich.panel    import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeRemainingColumn,
)

from scanner.core    import PortScanner, PortState
from scanner.report  import ReportGenerator
from scanner.utils   import resolve_target, parse_port_range, parse_targets, check_host_alive
from scanner         import __version__
import scanner.display as ui

console = Console(width=130)


# ──────────────────────────────────────────────
# CLI definition
# ──────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portscanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Advanced Network Port Scanner",
        epilog=textwrap.dedent("""
        Port specification examples:
          common          → 72 well-known ports  (default)
          all             → full 1-65535 sweep
          top100          → first 100 common ports
          1-1024          → range
          22,80,443,3306  → comma list
          1-200,443,8080  → mixed

        Scan types:
          tcp  → Full TCP connect  (default; works everywhere)
          syn  → SYN/half-open     (stealth; requires root + pip install scapy)
          udp  → UDP scan          (open|filtered only)

        Unauthorized scanning is illegal. Use responsibly.
        """),
    )

    # ── Required ──
    parser.add_argument(
        "-t", "--target", required=True,
        metavar="SPEC",
        help="Target(s): single IP/host, comma list, CIDR, or IP range "
             "(e.g. 10.0.0.1 | 10.0.0.1,10.0.0.2 | 10.0.0.0/28 | 10.0.0.1-20)",
    )

    # ── Meta ──
    parser.add_argument(
        "--version", action="version",
        version=f"portscanner {__version__}",
    )

    # ── Ports ──
    parser.add_argument(
        "-p", "--ports", default="common",
        metavar="SPEC",
        help="Port spec: common | all | top100 | 1-1024 | 80,443 (default: common)",
    )

    # ── Scan type ──
    parser.add_argument(
        "-s", "--scan-type",
        choices=["tcp", "syn", "udp"], default="tcp",
        help="Scan technique (default: tcp)",
    )

    # ── Performance ──
    parser.add_argument(
        "--threads", type=int, default=150, metavar="N",
        help="Concurrent threads (default: 150)",
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0, metavar="SEC",
        help="Per-port socket timeout in seconds (default: 1.0)",
    )

    # ── Features ──
    parser.add_argument(
        "--banner", action="store_true",
        help="Grab service banners from open ports",
    )
    parser.add_argument(
        "--no-ping", action="store_true",
        help="Skip host-alive check and scan anyway",
    )

    # ── Output ──
    parser.add_argument(
        "-o", "--output", metavar="FILE",
        help="Save report: report.json | report.html | report.txt",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Print each open port as it is discovered",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="Suppress banner and config output",
    )

    return parser


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    # ── Banner ──
    if not args.quiet:
        ui.print_banner()
        ui.print_legal_warning()

    # ── Parse ports (shared across every target) ──
    ports = parse_port_range(args.ports)
    if not ports:
        ui.print_error("No valid ports parsed from the supplied spec.")
        sys.exit(1)

    # ── Expand target(s): single host, comma list, CIDR, or IP range ──
    try:
        target_specs = parse_targets(args.target)
    except ValueError as exc:
        ui.print_error(str(exc))
        sys.exit(1)

    if not target_specs:
        ui.print_error(f"No valid targets parsed from: [bold]{args.target}[/bold]")
        sys.exit(1)

    multi = len(target_specs) > 1

    if not args.quiet and multi:
        console.print(
            f"[bold blue]{len(target_specs)} targets[/bold blue] queued — "
            f"{len(ports)} ports each, {args.scan_type.upper()} scan\n"
        )

    # ── Aggregate tallies across the whole batch ──
    batch_scanned = 0
    batch_skipped = 0
    batch_open    = 0

    for idx, target_spec in enumerate(target_specs, start=1):
        # ── Resolve this target ──
        resolved = resolve_target(target_spec)
        if not resolved:
            ui.print_error(f"Cannot resolve target: [bold]{target_spec}[/bold]")
            batch_skipped += 1
            continue

        ip, hostname = resolved

        # ── Config display ──
        if not args.quiet:
            if multi:
                console.print(f"[dim]── [{idx}/{len(target_specs)}] {ip} ──[/dim]")
            ui.print_scan_config(
                ip, hostname, ports,
                args.scan_type, args.threads,
                args.timeout, args.banner,
            )

        # ── Host liveness ──
        if not args.no_ping:
            console.print("[dim]  Checking host liveness…[/dim]")
            alive = check_host_alive(ip, args.timeout)
            if not alive:
                ui.print_warning(
                    f"{ip} appears unreachable. "
                    "Use [bold]--no-ping[/bold] to scan anyway."
                )
                if multi:
                    # Prompting once per unreachable host across a whole
                    # batch isn't practical — skip and move on instead of
                    # blocking on input for every dead host in the range.
                    ui.print_warning(f"Skipping {ip} (unreachable).")
                    batch_skipped += 1
                    continue
                try:
                    choice = input("  Continue anyway? [y/N]: ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    choice = "n"
                if choice != "y":
                    sys.exit(0)

        # ── Build scanner ──
        scanner = PortScanner(
            target       = ip,
            ports        = ports,
            scan_type    = args.scan_type,
            threads      = args.threads,
            timeout      = args.timeout,
            grab_banners = args.banner,
            verbose      = args.verbose,
        )

        # ── Progress bar callback ──
        open_count = [0]

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            MofNCompleteColumn(),
            TextColumn("│ [bold green]{task.fields[found]}[/bold green] open"),
            TimeRemainingColumn(),
            console=console,
            transient=False,
        )

        task_id = progress.add_task(
            f"Scanning {ip}", total=len(ports), found=0
        )

        def progress_callback(done: int, total: int, pr) -> None:
            if pr.state == PortState.OPEN:
                open_count[0] += 1
                progress.update(task_id, advance=1, found=open_count[0])
                if args.verbose:
                    ui.print_open_port_live(pr)
            else:
                progress.update(task_id, advance=1)

        # ── Run scan ──
        start = time.perf_counter()
        try:
            with progress:
                result = scanner.scan(progress_callback=progress_callback)
        except KeyboardInterrupt:
            console.print("\n[yellow]Scan interrupted by user.[/yellow]")
            sys.exit(0)

        elapsed = time.perf_counter() - start
        result.hostname = hostname

        # ── Print results ──
        ui.print_results(result, elapsed)

        batch_scanned += 1
        batch_open    += len(result.open_ports)

        # ── Save report ──
        if args.output:
            out_path = args.output
            if multi:
                # One filename can't hold every target's report — insert
                # the IP before the extension so nothing overwrites the
                # previous target's file.
                p = Path(args.output)
                out_path = str(p.with_name(f"{p.stem}_{ip}{p.suffix}"))
            try:
                reporter = ReportGenerator(result, elapsed)
                reporter.save(out_path)
                ui.print_success(f"Report saved → [bold]{out_path}[/bold]")
            except Exception as exc:
                ui.print_error(f"Could not save report: {exc}")

    # ── Batch summary ──
    if multi:
        console.print(
            Panel(
                f"[bold]{batch_scanned}[/bold] scanned  │  "
                f"[bold]{batch_skipped}[/bold] skipped  │  "
                f"[bold green]{batch_open}[/bold green] total open ports "
                f"across {len(target_specs)} targets",
                title="[bold]Batch Summary[/bold]",
                border_style="blue",
            )
        )


if __name__ == "__main__":
    main()