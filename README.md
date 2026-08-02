#  Network Port Scanner

> **Advanced multi-technique port scanner built in Python — Cybersecurity Portfolio Project**

---

## Features

| Category | What it does |
|---|---|
| **Scan Techniques** | TCP Connect · SYN Half-Open (scapy) · UDP |
| **Service Detection** | 80+ well-known ports with name, category & risk level |
| **Banner Grabbing** | Protocol-aware probes (HTTP, SSH, FTP, SMTP, Redis…) |
| **Live Feedback** | Real-time progress bar + instant open-port reporting |
| **Risk Analysis** | Automatic HIGH / MEDIUM / LOW risk tagging |
| **Security Notes** | Contextual warnings for dangerous open ports |
| **Report Formats** | JSON · HTML (dark-themed) · TXT |
| **Performance** | Multi-threaded (up to 1 000 workers) |

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/network-port-scanner.git
cd network-port-scanner
pip install -r requirements.txt          # only needs 'rich'

# Optional SYN scan support (Linux/macOS, requires root):
pip install scapy
```

**Requirements:** Python 3.10+

---

## Usage

```
python main.py -t <TARGET> [options]
```

### Options

```
Target:
  -t, --target IP/HOST   Target IP address or hostname  (required)

Port specification:
  -p, --ports SPEC
    common               ~80 well-known ports (default)
    all                  full 1–65535 sweep
    top100               first 100 common ports
    1-1024               numeric range
    22,80,443,3306       comma-separated list
    1-200,443,8080       mixed syntax

Scan type:
  -s, --scan-type        tcp (default) | syn (root) | udp

Performance:
  --threads N            Concurrent workers (default: 150)
  --timeout SEC          Per-port timeout in seconds (default: 1.0)

Features:
  --banner               Grab service banners from open ports
  --no-ping              Skip host-alive check

Output:
  -o, --output FILE      Save report (.json / .html / .txt)
  -v, --verbose          Print each open port as discovered
  -q, --quiet            Minimal output
```

---

## Examples

```bash
# Scan common ports on the official Nmap test host
python main.py -t scanme.nmap.org -p common

# Full range scan with banner grabbing, save HTML report
python main.py -t 192.168.1.1 -p 1-65535 --threads 300 --banner -o report.html

# Target specific ports, verbose mode
python main.py -t 10.0.0.50 -p 22,80,443,3306,3389,5432 -v

# SYN scan (requires root + scapy)
sudo python main.py -t 192.168.1.1 -p 1-1024 -s syn

# UDP scan
python main.py -t 192.168.1.1 -p 53,67,68,123,161 -s udp

# Save JSON report
python main.py -t 192.168.1.1 -p common -o scan_result.json
```

---

## Project Structure

```
network-port-scanner/
├── main.py                ← CLI entry point (argparse + Rich progress)
├── requirements.txt
├── README.md
└── scanner/
    ├── __init__.py        ← Package exports
    ├── core.py            ← PortScanner engine (TCP / SYN / UDP)
    ├── services.py        ← Port-to-service database + risk levels
    ├── banner.py          ← Protocol-aware banner grabbing
    ├── utils.py           ← Target resolution, port parsing, host discovery
    ├── display.py         ← Rich terminal UI (tables, panels, live feedback)
    └── report.py          ← JSON / HTML / TXT report generation
```

---

## How It Works

### TCP Connect Scan (default)
Performs a full three-way handshake using `socket.connect_ex()`.  
- **Connection success (errno 0)** → `OPEN`  
- **Connection refused** → `CLOSED`  
- **Timeout** → `FILTERED`  

### SYN Scan (`-s syn`)
Sends a raw SYN packet using Scapy and inspects the response:
- **SYN-ACK** → `OPEN` (then immediately sends RST to avoid full handshake)  
- **RST-ACK** → `CLOSED`  
- **No reply / ICMP unreachable** → `FILTERED`  

Stealthier than TCP connect — does not complete the handshake.  
Requires **root privileges** and **scapy** installed.

### UDP Scan (`-s udp`)
Sends an empty UDP datagram and checks the response:
- **UDP reply** → `OPEN`  
- **ICMP port unreachable** → `CLOSED`  
- **Timeout** → `OPEN|FILTERED`  

### Banner Grabbing (`--banner`)
For each open port, sends a protocol-specific probe (HTTP HEAD for web ports, nothing for self-announcing services like SSH/FTP/SMTP) and parses the first response lines to identify the software and version.

### Risk Classification
Every service in the database is tagged:

| Level | Examples |
|---|---|
|  HIGH | Telnet (23), FTP (21), RDP (3389), SMB (445), MySQL (3306) |
|  MEDIUM | SSH (22), HTTP (80), Redis (6379), PostgreSQL (5432) |
|  LOW | HTTPS (443), DNS (53), NTP (123) |

---

## Output Example

```
Target IP  : 192.168.1.1
Ports      : 83 ports
Scan type  : TCP
Threads    : 150
Timeout    : 1.0s

  ✓ Open  22  SSH          Remote Access   MEDIUM   12ms
  ✓ Open  80  HTTP         Web             LOW      8ms
  ✓ Open 443  HTTPS        Web             LOW      9ms
  ✓ Open 3306 MySQL        Database        HIGH     15ms

Results — 192.168.1.1
  Open: 4  Closed: 71  Filtered: 8  │ 2.31s

 Security Observations
    3306/MySQL — Database exposed publicly. Bind to localhost or firewall.
```

---

## Ethical & Legal Disclaimer

> **This tool is for educational and authorized security testing only.**
>
> Scanning systems without explicit written permission from the owner is
> illegal in most jurisdictions (Computer Fraud and Abuse Act, Computer
> Misuse Act, etc.). The author assumes no liability for misuse.
>
> **Test only on: systems you own, dedicated lab VMs, or authorized
> targets such as [scanme.nmap.org](http://scanme.nmap.org).**

---

## Skills Demonstrated

- Python networking with `socket` and `ssl`
- Multi-threading with `concurrent.futures.ThreadPoolExecutor`
- Protocol-aware service fingerprinting
- CLI design with `argparse`
- Beautiful terminal UIs with `rich`
- Multiple output formats (JSON, HTML, TXT)
- Raw packet crafting with `scapy` (SYN scan)
- Defensive coding and error handling

---

## License

MIT License — free for personal and educational use.
