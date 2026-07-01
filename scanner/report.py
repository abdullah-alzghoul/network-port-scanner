"""
Report generation in JSON, HTML, and plain-text formats.
"""
import json
from pathlib import Path
from typing import Any, Dict, List

from .core import ScanResult, PortResult


# ──────────────────────────────────────────────
# Serialisation helpers
# ──────────────────────────────────────────────

def _port_to_dict(pr: PortResult) -> Dict[str, Any]:
    return {
        "port":          pr.port,
        "state":         pr.state.value,
        "service":       pr.service,
        "banner":        pr.banner,
        "response_ms":   pr.response_ms,
    }


def _result_to_dict(result: ScanResult, elapsed: float, args: Any) -> Dict[str, Any]:
    return {
        "scan_info": {
            "target":               result.target,
            "hostname":             result.hostname,
            "scan_type":            result.scan_type,
            "timestamp":            result.timestamp,
            "duration_seconds":     round(elapsed, 3),
            "total_ports_scanned":  result.total_ports,
            "open_count":           len(result.open_ports),
            "closed_count":         result.closed_count,
            "filtered_count":       result.filtered_count,
        },
        "open_ports": [_port_to_dict(p) for p in result.open_ports],
    }


# ──────────────────────────────────────────────
# ReportGenerator
# ──────────────────────────────────────────────

class ReportGenerator:
    def __init__(
        self,
        result:  ScanResult,
        elapsed: float,
        args:    Any,
    ) -> None:
        self.result  = result
        self.elapsed = elapsed
        self.args    = args
        self._data   = _result_to_dict(result, elapsed, args)

    def save(self, filepath: str) -> None:
        ext = Path(filepath).suffix.lower()
        if ext == ".json":
            self._to_json(filepath)
        elif ext == ".html":
            self._to_html(filepath)
        else:
            self._to_txt(filepath)

    # ── JSON ──

    def _to_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, default=str)

    # ── TXT ──

    def _to_txt(self, path: str) -> None:
        d  = self._data
        si = d["scan_info"]
        lines = [
            "=" * 64,
            "  NETWORK PORT SCANNER — SCAN REPORT",
            "=" * 64,
            f"  Target      : {si['target']}  ({si['hostname']})",
            f"  Scan type   : {si['scan_type'].upper()}",
            f"  Timestamp   : {si['timestamp']}",
            f"  Duration    : {si['duration_seconds']}s",
            f"  Ports scanned: {si['total_ports_scanned']}",
            f"  Open / Closed / Filtered: "
            f"{si['open_count']} / {si['closed_count']} / {si['filtered_count']}",
            "=" * 64,
            "  OPEN PORTS",
            "-" * 64,
        ]
        for p in d["open_ports"]:
            svc   = p["service"]
            rtt   = f"{p['response_ms']}ms" if p["response_ms"] else ""
            lines.append(
                f"  {p['port']:5d}/tcp  {svc.get('name','?'):<14} "
                f"{svc.get('category',''):<16} [{svc.get('risk','')}]  {rtt}"
            )
            if p["banner"]:
                lines.append(f"           └─ {p['banner'][:80]}")
        lines += ["=" * 64, "  ⚠ Authorized testing only.", "=" * 64]
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    # ── HTML ──

    def _to_html(self, path: str) -> None:
        si    = self._data["scan_info"]
        rows  = self._build_html_rows()
        html  = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Port Scan — {si['target']}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #0d1117; color: #e6edf3; padding: 2rem;
  }}
  h1 {{ color: #58a6ff; font-size: 1.8rem; margin-bottom: .25rem; }}
  .sub {{ color: #8b949e; font-size: .9rem; margin-bottom: 2rem; }}

  /* Meta card */
  .meta {{
    background: #161b22; border: 1px solid #30363d;
    border-radius: 10px; padding: 1.2rem 1.5rem; margin-bottom: 1.5rem;
  }}
  .meta p {{ margin: .25rem 0; color: #8b949e; font-size: .9rem; }}
  .meta strong {{ color: #e6edf3; }}

  /* Stats */
  .stats {{ display: flex; gap: 1rem; margin-bottom: 1.5rem; flex-wrap: wrap; }}
  .stat {{
    background: #161b22; border: 1px solid #30363d;
    border-radius: 10px; padding: .9rem 1.4rem; min-width: 110px; text-align: center;
  }}
  .stat-num {{ font-size: 2rem; font-weight: 700; line-height: 1; }}
  .stat-label {{ font-size: .78rem; color: #8b949e; margin-top: .3rem; }}
  .open-color {{ color: #3fb950; }}
  .closed-color {{ color: #f85149; }}
  .filtered-color {{ color: #d29922; }}

  /* Table */
  .wrap {{ overflow-x: auto; }}
  table {{
    width: 100%; border-collapse: collapse;
    background: #161b22; border-radius: 10px; overflow: hidden;
    border: 1px solid #30363d; font-size: .88rem;
  }}
  th {{
    background: #21262d; color: #58a6ff; text-align: left;
    padding: .65rem 1rem; font-size: .78rem; text-transform: uppercase;
    letter-spacing: .06em;
  }}
  td {{ padding: .65rem 1rem; border-top: 1px solid #21262d; }}
  tr:hover td {{ background: #1c2128; }}

  /* Risk badges */
  .badge {{
    padding: .15rem .5rem; border-radius: 4px;
    font-size: .72rem; font-weight: 700; text-transform: uppercase;
  }}
  .high   {{ background: rgba(248,81,73,.18); color: #f85149; }}
  .medium {{ background: rgba(210,153,34,.2);  color: #d29922; }}
  .low    {{ background: rgba(63,185,80,.15);  color: #3fb950; }}
  .unknown {{ background: rgba(255,255,255,.08); color: #8b949e; }}

  .port   {{ font-weight: 700; color: #e6edf3; font-size: .95rem; }}
  .svc    {{ color: #58a6ff; }}
  .banner {{ font-family: monospace; font-size: .78rem; color: #8b949e; }}

  footer  {{
    margin-top: 2rem; text-align: center;
    color: #8b949e; font-size: .82rem;
  }}
</style>
</head>
<body>
<h1>🔍 Port Scan Report</h1>
<p class="sub">Generated by <strong>Network Port Scanner</strong></p>

<div class="meta">
  <p><strong>Target</strong>: {si['target']}  ({si['hostname']})</p>
  <p><strong>Scan Type</strong>: {si['scan_type'].upper()} &nbsp;│&nbsp;
     <strong>Timestamp</strong>: {si['timestamp']}</p>
  <p><strong>Duration</strong>: {si['duration_seconds']}s &nbsp;│&nbsp;
     <strong>Ports Scanned</strong>: {si['total_ports_scanned']:,}</p>
</div>

<div class="stats">
  <div class="stat"><div class="stat-num open-color">{si['open_count']}</div>
       <div class="stat-label">Open</div></div>
  <div class="stat"><div class="stat-num closed-color">{si['closed_count']}</div>
       <div class="stat-label">Closed</div></div>
  <div class="stat"><div class="stat-num filtered-color">{si['filtered_count']}</div>
       <div class="stat-label">Filtered</div></div>
</div>

<div class="wrap">
<table>
  <thead>
    <tr>
      <th>Port</th><th>Proto</th><th>Service</th><th>Category</th>
      <th>Risk</th><th>RTT</th><th>Description / Banner</th>
    </tr>
  </thead>
  <tbody>
{rows}
  </tbody>
</table>
</div>

<footer>
  ⚠️ This report is for authorized security testing only.
  Unauthorized scanning is illegal.
</footer>
</body>
</html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def _build_html_rows(self) -> str:
        risk_class = {
            "HIGH": "high", "MEDIUM": "medium",
            "LOW": "low", "UNKNOWN": "unknown",
        }
        proto = "UDP" if self.result.scan_type == "udp" else "TCP"
        rows  = []
        for p in self._data["open_ports"]:
            svc    = p["service"]
            risk   = svc.get("risk", "UNKNOWN")
            banner = (p.get("banner") or "")[:80]
            rtt    = f"{p['response_ms']} ms" if p["response_ms"] else "—"
            rc     = risk_class.get(risk, "unknown")
            rows.append(
                f'    <tr>'
                f'<td class="port">{p["port"]}</td>'
                f'<td><small>{proto}</small></td>'
                f'<td class="svc">{svc.get("name","?")}</td>'
                f'<td>{svc.get("category","")}</td>'
                f'<td><span class="badge {rc}">{risk}</span></td>'
                f'<td><small>{rtt}</small></td>'
                f'<td class="banner">{banner or "<em>—</em>"}</td>'
                f'</tr>'
            )
        return "\n".join(rows)
