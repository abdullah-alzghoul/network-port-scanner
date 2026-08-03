"""
Terminal UI built on the Rich library.
"""
from rich.console import Console
from rich.panel   import Panel
from rich.table   import Table
from rich.text    import Text
from rich         import box

# Shared console instance
console = Console(width=130)

# ──────────────────────────────────────────────
# Visual constants
# ──────────────────────────────────────────────

ASCII_LOGO = r"""
 ____  ____  ____  ____   ____   ___  ____   ____
|  _ \/ ___||  _ \/ ___| / ___| / _ \|  _ \ / ___|
| |_) \___ \| |_) \___ \| |    | | | | |_) | |
|  __/ ___) |  __/ ___) | |___ | |_| |  _ <| |___
|_|   |____/|_|   |____/ \____| \___/|_| \_\\____|
"""

RISK_COLOR = {
    "HIGH":    "bold red",
    "MEDIUM":  "yellow",
    "LOW":     "green",
    "UNKNOWN": "dim white",
}


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _risk_badge(risk: str) -> Text:
    color = RISK_COLOR.get(risk, "dim white")
    return Text(risk, style=color)


def _category_cell(cat: str) -> str:
    return cat

def _print_security_notes(open_ports: list) -> None:
    """Print contextual security warnings for high-risk open ports."""
    notes = []
    for pr in open_ports:
        p = pr.port
        if p == 23:
            notes.append("[bold yellow]WARNING:[/bold yellow] [bold red]23/Telnet[/bold red] — Credentials sent in cleartext. Disable and use SSH.")
        elif p == 21:
            notes.append("[bold yellow]WARNING:[/bold yellow] [bold red]21/FTP[/bold red] — Credentials sent in cleartext. Prefer SFTP/FTPS.")
        elif p == 69:
            notes.append("[bold yellow]WARNING:[/bold yellow] [bold red]69/TFTP[/bold red] — No authentication. Disable if not needed.")
        elif p == 3389:
            notes.append("[bold yellow]WARNING:[/bold yellow] [bold red]3389/RDP[/bold red] — Common brute-force target. Enable NLA, restrict with firewall.")
        elif p == 445:
            notes.append("[bold yellow]WARNING:[/bold yellow] [bold red]445/SMB[/bold red] — EternalBlue/WannaCry vector. Keep patched; block externally.")
        elif p in (135, 137, 138, 139):
            notes.append(f"[bold yellow]WARNING:[/bold yellow] [bold red]{p}/NetBIOS[/bold red] — Windows legacy exposure. Firewall from public networks.")
        elif p == 1433:
            notes.append("[bold yellow]WARNING:[/bold yellow] [bold red]1433/MSSQL[/bold red] — Database should not face the internet. Restrict to LAN.")
        elif p == 3306:
            notes.append("[bold yellow]WARNING:[/bold yellow] [bold red]3306/MySQL[/bold red] — Database exposed publicly. Bind to localhost or firewall.")
        elif p == 5432:
            notes.append("[bold yellow]WARNING:[/bold yellow] [bold red]5432/PostgreSQL[/bold red] — Database exposed. Restrict to trusted hosts.")
        elif p in (5900, 5901):
            notes.append("[bold yellow]WARNING:[/bold yellow] [bold red]590x/VNC[/bold red] — Graphical desktop exposed. Tunnel through SSH VPN.")
        elif p == 6379:
            notes.append("[bold red]CRITICAL: 6379/Redis[/bold red] — Often no auth by default. Exposed Redis = data breach risk.")
        elif p == 27017:
            notes.append("[bold red]CRITICAL: 27017/MongoDB[/bold red] — No-auth MongoDB = critical. Enable authentication NOW.")
        elif p == 9200:
            notes.append("[bold red]CRITICAL: 9200/Elasticsearch[/bold red] — Unauthenticated by default. Enable security plugin.")
        elif p == 4444:
            notes.append("[bold red]CRITICAL: 4444[/bold red] — Metasploit default port detected. Possible backdoor/C2 shell!")

    if notes:
        console.print()
        console.print(
            Panel(
                "\n".join(notes),
                title="[bold red]Security Observations[/bold red]",
                border_style="red",
                padding=(0, 2),
            )
        )
    console.print()

# ──────────────────────────────────────────────
# Public display functions
# ──────────────────────────────────────────────

def print_banner() -> None:
    console.print(f"[bold cyan]{ASCII_LOGO}[/bold cyan]")
    console.print(
        "  [bold white]Advanced Network Port Scanner[/bold white]  "
        "[dim]│ Python Portfolio Project[/dim]\n"
    )


def print_legal_warning() -> None:
    console.print(
        Panel(
            "[bold yellow]  LEGAL WARNING[/bold yellow]\n"
            "[white]Only scan systems you own or have explicit written permission to test.\n"
            "Unauthorized port scanning may be illegal in your jurisdiction.[/white]",
            border_style="yellow",
            padding=(0, 2),
        )
    )
    console.print()


def print_scan_config(
    ip: str,
    hostname: str,
    ports: list,
    scan_type: str,
    threads: int,
    timeout: float,
    grab_banners: bool,
) -> None:
    t = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
    t.add_column("key",   style="bold blue",  no_wrap=True)
    t.add_column("value", style="white")

    t.add_row("Target IP",  f"[bold green]{ip}[/bold green]")
    if hostname != ip:
        t.add_row("Hostname", f"[cyan]{hostname}[/cyan]")
    t.add_row("Ports",     f"{len(ports):,} ports")
    t.add_row("Scan type", f"[yellow]{scan_type.upper()}[/yellow]")
    t.add_row("Threads",   str(threads))
    t.add_row("Timeout",   f"{timeout}s")
    t.add_row("Banners",   "[green]yes[/green]" if grab_banners else "[dim]no[/dim]")

    console.print(
        Panel(t, title="[bold]Scan Configuration[/bold]", border_style="blue")
    )
    console.print()


def print_open_port_live(pr) -> None:
    """Print a single open port as it is discovered (live feedback)."""
    svc      = pr.service
    risk     = svc.get("risk", "UNKNOWN")
    color    = RISK_COLOR.get(risk, "white")
    svc_name = svc.get("name", "?")
    console.print(
        f"  [bold green]OPEN[/bold green]  "
        f"[bold white]{pr.port:5d}[/bold white]  "
        f"[cyan]{svc_name:<14}[/cyan]  "
        f"[{color}]{risk}[/{color}]"
        + (f"  [dim]{pr.response_ms}ms[/dim]" if pr.response_ms else "")
    )


def print_results(result, elapsed: float) -> None:
    """Render the final results table and security observations."""
    open_ports = result.open_ports

    # ── Summary ──
    summary = (
        f"[bold green]✓ Open:[/bold green] {len(open_ports)}  "
        f"[red]✗ Closed:[/red] {result.closed_count}  "
        f"[yellow]⟳ Filtered:[/yellow] {result.filtered_count}  "
        f"[dim]│  {elapsed:.2f}s  │  {result.total_ports:,} ports scanned[/dim]"
    )
    console.print()
    console.print(
        Panel(
            summary,
            title=f"[bold]Results — {result.target}[/bold]",
            border_style="green",
        )
    )
    console.print()

    if not open_ports:
        console.print("[yellow]  No open ports found.[/yellow]\n")
        return

    # ── Table ──
    table = Table(
        title        = f"Open Ports on [bold]{result.target}[/bold]",
        box          = box.ROUNDED,
        border_style = "green",
        show_lines   = True,
        header_style = "bold cyan",
        expand       = False,
    )
    table.add_column("Port",        justify="right",  width=7)
    table.add_column("Protocol",    width=5)
    table.add_column("Service",     width=13)
    table.add_column("Category",    width=18)
    table.add_column("Risk",        justify="center", width=8)
    table.add_column("RTT",         justify="right",  width=8)
    table.add_column("Description / Banner", width=42)

    for pr in open_ports:
        svc    = pr.service
        risk   = svc.get("risk", "UNKNOWN")
        cat    = svc.get("category", "Unknown")
        proto  = "UDP" if result.scan_type == "udp" else "TCP"
        desc   = pr.banner or svc.get("description", "")
        if len(desc) > 45:
            desc = desc[:42] + "…"

        table.add_row(
            str(pr.port),
            f"[dim]{proto}[/dim]",
            f"[cyan]{svc.get('name','?')}[/cyan]",
            _category_cell(cat),
            _risk_badge(risk),
            f"{pr.response_ms}ms" if pr.response_ms else "—",
            desc,
        )

    console.print(table)
    _print_security_notes(open_ports)


def _print_security_notes(open_ports: list) -> None:
    """Print contextual security warnings for high-risk open ports."""
    notes = []
    for pr in open_ports:
        p = pr.port
        if p == 23:
            notes.append("⚠️  [bold red]23/Telnet[/bold red] — Credentials sent in cleartext. Disable and use SSH.")
        elif p == 21:
            notes.append("⚠️  [bold red]21/FTP[/bold red]    — Credentials sent in cleartext. Prefer SFTP/FTPS.")
        elif p == 69:
            notes.append("⚠️  [bold red]69/TFTP[/bold red]   — No authentication. Disable if not needed.")
        elif p == 3389:
            notes.append("⚠️  [bold red]3389/RDP[/bold red]  — Common brute-force target. Enable NLA, restrict with firewall.")
        elif p == 445:
            notes.append("⚠️  [bold red]445/SMB[/bold red]   — EternalBlue/WannaCry vector. Keep patched; block externally.")
        elif p in (135, 137, 138, 139):
            notes.append(f"⚠️  [bold red]{p}/NetBIOS[/bold red] — Windows legacy exposure. Firewall from public networks.")
        elif p == 1433:
            notes.append("⚠️  [bold red]1433/MSSQL[/bold red]— Database should not face the internet. Restrict to LAN.")
        elif p == 3306:
            notes.append("⚠️  [bold red]3306/MySQL[/bold red]— Database exposed publicly. Bind to localhost or firewall.")
        elif p == 5432:
            notes.append("⚠️  [bold red]5432/PostgreSQL[/bold red] — Database exposed. Restrict to trusted hosts.")
        elif p in (5900, 5901):
            notes.append("⚠️  [bold red]590x/VNC[/bold red]  — Graphical desktop exposed. Tunnel through SSH VPN.")
        elif p == 6379:
            notes.append("🚨 [bold red]6379/Redis[/bold red] — Often no auth by default. Exposed Redis = data breach risk.")
        elif p == 27017:
            notes.append("🚨 [bold red]27017/MongoDB[/bold red] — No-auth MongoDB = critical. Enable authentication NOW.")
        elif p == 9200:
            notes.append("🚨 [bold red]9200/Elasticsearch[/bold red] — Unauthenticated by default. Enable security plugin.")
        elif p == 4444:
            notes.append("🚨 [bold red]4444[/bold red] — Metasploit default port detected. Possible backdoor/C2 shell!")

    if notes:
        console.print()
        console.print(
            Panel(
                "\n".join(notes),
                title="[bold red]🔒  Security Observations[/bold red]",
                border_style="red",
                padding=(0, 2),
            )
        )
    console.print()


def print_error(msg: str) -> None:
    console.print(f"[bold red]✗  Error:[/bold red] {msg}")


def print_warning(msg: str) -> None:
    console.print(f"[yellow]Warning:[/yellow] {msg}")


def print_success(msg: str) -> None:
    console.print(f"[bold green]✓[/bold green]  {msg}")
