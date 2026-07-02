"""
reporter.py — Report Generation Module
----------------------------------------
Takes an AnalysisReport and renders it as:
  1. A rich terminal output (using the 'rich' library)
  2. A standalone HTML report with a hacker-aesthetic dashboard
  3. A JSON export for programmatic use / SIEM integration

The HTML report is self-contained (no external CDN dependencies that
might be unavailable in an air-gapped/lab environment).
"""

import json
import time
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

from .analyzer import AnalysisReport, ServiceFinding
from .cve_engine import CVEFinding


# ---------------------------------------------------------------------------
# Rich terminal reporter
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "dim white",
    "SECURE":   "bold green",
}

RISK_COLORS = {
    "CRITICAL": "red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "SECURE":   "green",
    "UNKNOWN":  "dim white",
}


class TerminalReporter:
    """Renders scan results to the terminal using Rich."""

    def __init__(self):
        self.console = Console()

    def print_banner(self):
        banner = Text()
        banner.append("╔══════════════════════════════════════════╗\n", style="bold cyan")
        banner.append("║  ", style="bold cyan")
        banner.append("⚡ RECON SCANNER", style="bold white")
        banner.append(" — Network Vuln Scanner  ║\n", style="bold cyan")
        banner.append("║  Nmap + Shodan + NVD CVE Intelligence    ║\n", style="cyan")
        banner.append("╚══════════════════════════════════════════╝", style="bold cyan")
        self.console.print(banner)
        self.console.print()

    def print_report(self, report: AnalysisReport):
        """Print a full analysis report to terminal."""

        # ── Header ─────────────────────────────────────────────────
        scan_dt = datetime.fromtimestamp(report.scan_time).strftime("%Y-%m-%d %H:%M:%S")

        risk_color = RISK_COLORS.get(report.risk_label, "white")
        header_lines = [
            f"[bold]Target:[/bold] {report.target}",
            f"[bold]IP:[/bold] {report.resolved_ip}" +
            (f"  [dim]({report.hostname})[/dim]" if report.hostname else ""),
            f"[bold]Scan time:[/bold] {scan_dt}  |  Duration: {report.duration_secs:.1f}s",
            f"[bold]OS:[/bold] {report.os_info or 'Not detected'}",
            f"[bold]Open ports:[/bold] {report.open_port_count}",
            f"[bold]Risk Score:[/bold] [{risk_color}]{report.risk_score}/100  ▶  {report.risk_label}[/{risk_color}]",
        ]

        self.console.print(Panel(
            "\n".join(header_lines),
            title="[bold white]SCAN RESULTS[/bold white]",
            border_style="cyan",
            padding=(0, 1),
        ))
        self.console.print()

        if not report.findings:
            self.console.print("[bold green]✓ No significant vulnerabilities detected.[/bold green]")
            return

        # ── Findings table ──────────────────────────────────────────
        table = Table(
            title="[bold white]FINDINGS[/bold white]",
            box=box.SIMPLE_HEAVY,
            show_header=True,
            header_style="bold white on grey23",
        )
        table.add_column("SEV",     style="bold", width=10, no_wrap=True)
        table.add_column("PORT",    style="cyan",  width=7)
        table.add_column("SERVICE", style="white", width=12)
        table.add_column("FINDING", style="white", width=35)
        table.add_column("CVEs",    style="dim",   width=12)

        for f in report.findings:
            color = SEVERITY_COLORS.get(f.severity, "white")
            cve_text = ", ".join(c.cve_id for c in f.cves[:2])
            if len(f.cves) > 2:
                cve_text += f" +{len(f.cves)-2}"

            table.add_row(
                Text(f.severity, style=color),
                str(f.port) if f.port else "—",
                f.service[:12],
                f.title[:35],
                cve_text or "—",
            )

        self.console.print(table)
        self.console.print()

        # ── Detailed findings ───────────────────────────────────────
        for f in report.findings:
            if f.severity in ("CRITICAL", "HIGH"):
                self._print_finding_detail(f)

        # ── Shodan info ─────────────────────────────────────────────
        if report.shodan_info and not report.shodan_info.error:
            s = report.shodan_info
            info = [
                f"[bold]Org:[/bold] {s.org}  |  [bold]ISP:[/bold] {s.isp}",
                f"[bold]Location:[/bold] {s.city}, {s.country}",
                f"[bold]Shodan-observed ports:[/bold] {', '.join(str(p) for p in s.open_ports[:20])}",
            ]
            if s.tags:
                info.append(f"[bold]Tags:[/bold] {', '.join(s.tags)}")
            if s.vulns:
                info.append(f"[bold red]Shodan CVEs:[/bold red] {', '.join(s.vulns[:10])}")

            self.console.print(Panel(
                "\n".join(info),
                title="[bold white]SHODAN INTELLIGENCE[/bold white]",
                border_style="blue",
            ))
            self.console.print()

    def _print_finding_detail(self, f: ServiceFinding):
        color = SEVERITY_COLORS.get(f.severity, "white")
        detail_text = [f"[{color}]▶ {f.severity}[/{color}]  Port {f.port}/{f.protocol}  {f.service}"]
        detail_text.append(f"[bold]{f.title}[/bold]")
        detail_text.append(f.detail[:300])

        if f.cves:
            detail_text.append("\n[dim]Related CVEs:[/dim]")
            for cve in f.cves[:3]:
                sev_c = SEVERITY_COLORS.get(cve.severity, "white")
                detail_text.append(
                    f"  [{sev_c}]{cve.cve_id}[/{sev_c}]  CVSS:{cve.cvss_score}  {cve.description[:100]}..."
                )

        self.console.print(Panel(
            "\n".join(detail_text),
            border_style=color,
            padding=(0, 1),
        ))


# ---------------------------------------------------------------------------
# HTML Reporter
# ---------------------------------------------------------------------------

class HTMLReporter:
    """Generates a standalone HTML report."""

    def generate(self, report: AnalysisReport, output_path: str) -> str:
        """Write HTML report to file. Returns the file path."""
        html = self._build_html(report)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html, encoding="utf-8")
        return str(path)

    def _build_html(self, report: AnalysisReport) -> str:
        scan_dt = datetime.fromtimestamp(report.scan_time).strftime("%Y-%m-%d %H:%M:%S")

        # Build findings HTML
        findings_html = self._build_findings_html(report.findings)

        # Shodan section
        shodan_html = self._build_shodan_html(report.shodan_info)

        # CVE table
        all_cves = []
        for f in report.findings:
            for c in f.cves:
                all_cves.append((f.port, f.service, c))
        cve_table_html = self._build_cve_table(all_cves)

        risk_class = report.risk_label.lower()
        risk_pct = report.risk_score

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconScanner Report — {report.target}</title>
<style>
  :root {{
    --bg:         #0a0e1a;
    --bg2:        #0f1628;
    --bg3:        #151e35;
    --border:     #1e3a5f;
    --accent:     #00d4ff;
    --accent2:    #0099cc;
    --text:       #c8d8e8;
    --text-dim:   #5a7a9a;
    --critical:   #ff3355;
    --high:       #ff6633;
    --medium:     #ffaa00;
    --low:        #44ccff;
    --info:       #888888;
    --secure:     #00ff88;
    --font-mono:  'Courier New', 'Consolas', monospace;
    --font-ui:    'Segoe UI', system-ui, -apple-system, sans-serif;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-ui);
    font-size: 14px;
    line-height: 1.6;
  }}

  /* ── Scanlines overlay ── */
  body::before {{
    content: '';
    position: fixed; inset: 0; pointer-events: none; z-index: 9999;
    background: repeating-linear-gradient(
      0deg, transparent, transparent 2px,
      rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px
    );
  }}

  /* ── Layout ── */
  .wrapper {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}

  /* ── Header ── */
  .header {{
    border: 1px solid var(--border);
    border-top: 3px solid var(--accent);
    background: var(--bg2);
    padding: 24px 28px;
    margin-bottom: 24px;
    position: relative;
    overflow: hidden;
  }}
  .header::after {{
    content: '⚡ RECON SCANNER';
    position: absolute; right: 24px; top: 50%; transform: translateY(-50%);
    font-size: 56px; opacity: 0.03; font-weight: 900;
    font-family: var(--font-mono); letter-spacing: -2px;
    color: var(--accent);
  }}
  .header h1 {{
    font-family: var(--font-mono);
    font-size: 22px; font-weight: 700;
    color: var(--accent);
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 4px;
  }}
  .header .subtitle {{ color: var(--text-dim); font-size: 12px; letter-spacing: 1px; }}

  /* ── Stats grid ── */
  .stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 12px;
    margin-bottom: 24px;
  }}
  .stat-card {{
    background: var(--bg2);
    border: 1px solid var(--border);
    padding: 16px 20px;
    position: relative;
  }}
  .stat-card .label {{
    font-size: 10px; letter-spacing: 2px; text-transform: uppercase;
    color: var(--text-dim); margin-bottom: 6px;
  }}
  .stat-card .value {{
    font-family: var(--font-mono);
    font-size: 28px; font-weight: 700; line-height: 1;
    color: var(--accent);
  }}
  .stat-card.risk-critical .value {{ color: var(--critical); }}
  .stat-card.risk-high     .value {{ color: var(--high); }}
  .stat-card.risk-medium   .value {{ color: var(--medium); }}
  .stat-card.risk-low      .value {{ color: var(--low); }}
  .stat-card.risk-secure   .value {{ color: var(--secure); }}

  /* ── Risk meter ── */
  .risk-bar-wrap {{
    background: var(--bg3); border: 1px solid var(--border);
    padding: 16px 20px; margin-bottom: 24px;
  }}
  .risk-bar-label {{
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 8px;
    font-size: 11px; letter-spacing: 2px; text-transform: uppercase;
    color: var(--text-dim);
  }}
  .risk-bar-track {{
    height: 8px; background: var(--bg);
    border: 1px solid var(--border);
    position: relative; overflow: hidden;
  }}
  .risk-bar-fill {{
    height: 100%;
    width: {risk_pct}%;
    background: linear-gradient(90deg,
      var(--secure) 0%, var(--low) 25%, var(--medium) 50%,
      var(--high) 75%, var(--critical) 100%
    );
    background-size: 1200px 100%;
    background-position: -{(100 - risk_pct)}% 0;
    transition: width 1s ease;
  }}

  /* ── Section ── */
  .section {{ margin-bottom: 28px; }}
  .section-title {{
    font-family: var(--font-mono);
    font-size: 11px; letter-spacing: 3px; text-transform: uppercase;
    color: var(--accent2);
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 14px;
    display: flex; align-items: center; gap: 8px;
  }}
  .section-title::before {{
    content: '';
    display: inline-block;
    width: 3px; height: 14px;
    background: var(--accent);
  }}

  /* ── Findings ── */
  .finding {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-left: 4px solid var(--border);
    padding: 14px 16px;
    margin-bottom: 8px;
  }}
  .finding.sev-critical {{ border-left-color: var(--critical); }}
  .finding.sev-high     {{ border-left-color: var(--high); }}
  .finding.sev-medium   {{ border-left-color: var(--medium); }}
  .finding.sev-low      {{ border-left-color: var(--low); }}

  .finding-header {{
    display: flex; align-items: center; gap: 10px;
    margin-bottom: 6px; flex-wrap: wrap;
  }}
  .badge {{
    font-family: var(--font-mono);
    font-size: 10px; font-weight: 700; letter-spacing: 1px;
    padding: 2px 8px;
    text-transform: uppercase;
  }}
  .badge-critical {{ background: var(--critical); color: #000; }}
  .badge-high     {{ background: var(--high);     color: #000; }}
  .badge-medium   {{ background: var(--medium);   color: #000; }}
  .badge-low      {{ background: var(--low);      color: #000; }}
  .badge-info     {{ background: var(--info);     color: #000; }}

  .port-chip {{
    font-family: var(--font-mono); font-size: 11px;
    color: var(--accent); background: rgba(0,212,255,0.08);
    border: 1px solid rgba(0,212,255,0.2);
    padding: 1px 7px;
  }}

  .finding-title {{
    font-weight: 600; font-size: 14px; color: var(--text); flex: 1;
  }}
  .finding-detail {{ color: var(--text-dim); font-size: 13px; }}

  /* ── CVE Table ── */
  .cve-table {{ width: 100%; border-collapse: collapse; }}
  .cve-table th, .cve-table td {{
    padding: 8px 12px; text-align: left;
    border-bottom: 1px solid var(--border);
    font-size: 12px;
  }}
  .cve-table th {{
    background: var(--bg3); color: var(--text-dim);
    font-family: var(--font-mono); letter-spacing: 1px;
    text-transform: uppercase; font-size: 10px;
  }}
  .cve-table tr:hover td {{ background: rgba(0,212,255,0.03); }}
  .cve-id {{
    font-family: var(--font-mono); color: var(--accent);
    font-weight: 700; font-size: 11px;
  }}
  .cvss-badge {{
    display: inline-block; min-width: 34px; text-align: center;
    font-family: var(--font-mono); font-weight: 700;
    font-size: 11px; padding: 1px 6px;
  }}
  .cvss-critical {{ background: var(--critical); color: #000; }}
  .cvss-high     {{ background: var(--high);     color: #000; }}
  .cvss-medium   {{ background: var(--medium);   color: #000; }}
  .cvss-low      {{ background: var(--low);      color: #000; }}

  /* ── Shodan ── */
  .info-grid {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1px; background: var(--border);
    border: 1px solid var(--border);
  }}
  .info-cell {{
    background: var(--bg2); padding: 12px 14px;
  }}
  .info-cell .k {{ font-size: 10px; letter-spacing: 1px; text-transform: uppercase; color: var(--text-dim); margin-bottom: 3px; }}
  .info-cell .v {{ font-family: var(--font-mono); font-size: 13px; color: var(--text); }}

  /* ── Footer ── */
  .footer {{
    margin-top: 40px; padding-top: 16px;
    border-top: 1px solid var(--border);
    color: var(--text-dim); font-size: 11px; letter-spacing: 1px;
    font-family: var(--font-mono);
    display: flex; justify-content: space-between;
  }}

  /* ── Meta row ── */
  .meta-row {{
    display: flex; gap: 20px; flex-wrap: wrap; margin-top: 12px;
    font-family: var(--font-mono); font-size: 12px;
  }}
  .meta-item {{ color: var(--text-dim); }}
  .meta-item span {{ color: var(--text); }}
</style>
</head>
<body>
<div class="wrapper">

  <!-- Header -->
  <div class="header">
    <div class="subtitle">NETWORK RECONNAISSANCE &amp; VULNERABILITY REPORT</div>
    <h1>⚡ {report.target}</h1>
    <div class="meta-row">
      <div class="meta-item">IP: <span>{report.resolved_ip}</span></div>
      {f'<div class="meta-item">HOSTNAME: <span>{report.hostname}</span></div>' if report.hostname else ''}
      <div class="meta-item">SCANNED: <span>{scan_dt}</span></div>
      <div class="meta-item">DURATION: <span>{report.duration_secs:.1f}s</span></div>
      {f'<div class="meta-item">OS: <span>{report.os_info}</span></div>' if report.os_info else ''}
    </div>
  </div>

  <!-- Stats -->
  <div class="stats-grid">
    <div class="stat-card risk-{risk_class}">
      <div class="label">Risk Score</div>
      <div class="value">{report.risk_score}</div>
      <div style="font-size:10px;color:var(--text-dim);margin-top:4px;letter-spacing:1px">/100 — {report.risk_label}</div>
    </div>
    <div class="stat-card">
      <div class="label">Open Ports</div>
      <div class="value">{report.open_port_count}</div>
    </div>
    <div class="stat-card">
      <div class="label">Findings</div>
      <div class="value">{len(report.findings)}</div>
    </div>
    <div class="stat-card">
      <div class="label">CVEs</div>
      <div class="value">{sum(len(f.cves) for f in report.findings)}</div>
    </div>
    <div class="stat-card">
      <div class="label">Critical</div>
      <div class="value" style="color:var(--critical)">{sum(1 for f in report.findings if f.severity=='CRITICAL')}</div>
    </div>
    <div class="stat-card">
      <div class="label">High</div>
      <div class="value" style="color:var(--high)">{sum(1 for f in report.findings if f.severity=='HIGH')}</div>
    </div>
  </div>

  <!-- Risk Meter -->
  <div class="risk-bar-wrap">
    <div class="risk-bar-label">
      <span>RISK METER</span>
      <span style="color:var(--text);font-weight:700">{report.risk_score}/100 — {report.risk_label}</span>
    </div>
    <div class="risk-bar-track">
      <div class="risk-bar-fill"></div>
    </div>
  </div>

  <!-- Findings -->
  <div class="section">
    <div class="section-title">Security Findings ({len(report.findings)})</div>
    {findings_html if findings_html else '<div style="color:var(--secure)">✓ No significant vulnerabilities detected.</div>'}
  </div>

  <!-- CVE Table -->
  {cve_table_html}

  <!-- Shodan -->
  {shodan_html}

  <div class="footer">
    <span>RECON SCANNER — Ethical Use Only</span>
    <span>Generated: {scan_dt}</span>
  </div>

</div>
</body>
</html>"""

    def _build_findings_html(self, findings: list[ServiceFinding]) -> str:
        if not findings:
            return ""
        parts = []
        for f in findings:
            sev = f.severity.lower()
            cve_html = ""
            if f.cves:
                cve_items = " ".join(
                    f'<span style="font-family:var(--font-mono);font-size:10px;'
                    f'color:var(--accent);margin-right:6px">{c.cve_id} (CVSS:{c.cvss_score})</span>'
                    for c in f.cves[:5]
                )
                cve_html = f'<div style="margin-top:6px">{cve_items}</div>'

            port_html = f'<span class="port-chip">{f.port}/{f.protocol}</span>' if f.port else ''

            parts.append(f"""<div class="finding sev-{sev}">
  <div class="finding-header">
    <span class="badge badge-{sev}">{f.severity}</span>
    {port_html}
    <span class="badge" style="background:var(--bg3);color:var(--text-dim)">{f.service}</span>
    <span class="finding-title">{f.title}</span>
  </div>
  <div class="finding-detail">{f.detail[:400]}</div>
  {cve_html}
</div>""")
        return "\n".join(parts)

    def _build_cve_table(self, cves: list[tuple]) -> str:
        if not cves:
            return ""

        rows = []
        for port, service, c in cves[:50]:
            cvss_cls = ("critical" if c.cvss_score >= 9 else
                        "high" if c.cvss_score >= 7 else
                        "medium" if c.cvss_score >= 4 else "low")
            rows.append(f"""<tr>
  <td><span class="cve-id">{c.cve_id}</span></td>
  <td><span class="cvss-badge cvss-{cvss_cls}">{c.cvss_score}</span></td>
  <td><span style="font-family:var(--font-mono);font-size:10px;color:var(--text-dim)">{c.severity}</span></td>
  <td style="font-family:var(--font-mono);font-size:10px;color:var(--text-dim)">{port}/{service}</td>
  <td style="color:var(--text-dim);font-size:12px">{c.description[:120]}...</td>
</tr>""")

        if not rows:
            return ""

        return f"""<div class="section">
  <div class="section-title">CVE Reference Table ({len(cves)})</div>
  <table class="cve-table">
    <thead><tr><th>CVE ID</th><th>CVSS</th><th>Severity</th><th>Port/Service</th><th>Description</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</div>"""

    def _build_shodan_html(self, shodan_info) -> str:
        if not shodan_info or shodan_info.error:
            err = shodan_info.error if shodan_info else "Not configured"
            return f"""<div class="section">
  <div class="section-title">Shodan Intelligence</div>
  <div style="color:var(--text-dim);font-style:italic">{err}</div>
</div>"""

        s = shodan_info
        ports_str = ", ".join(str(p) for p in s.open_ports[:20])
        vulns_html = ""
        if s.vulns:
            vuln_chips = " ".join(
                f'<span style="font-family:var(--font-mono);font-size:10px;'
                f'color:var(--critical);background:rgba(255,51,85,0.1);'
                f'border:1px solid rgba(255,51,85,0.3);padding:1px 6px">{v}</span>'
                for v in s.vulns[:15]
            )
            vulns_html = f'<div class="info-cell" style="grid-column:1/-1"><div class="k">Shodan CVEs ({len(s.vulns)})</div><div>{vuln_chips}</div></div>'

        return f"""<div class="section">
  <div class="section-title">Shodan Intelligence</div>
  <div class="info-grid">
    <div class="info-cell"><div class="k">Organization</div><div class="v">{s.org or '—'}</div></div>
    <div class="info-cell"><div class="k">ISP</div><div class="v">{s.isp or '—'}</div></div>
    <div class="info-cell"><div class="k">Location</div><div class="v">{s.city}, {s.country}</div></div>
    <div class="info-cell"><div class="k">Last Indexed</div><div class="v">{s.last_update[:10] if s.last_update else '—'}</div></div>
    <div class="info-cell"><div class="k">Hostnames</div><div class="v">{', '.join(s.hostnames[:3]) or '—'}</div></div>
    <div class="info-cell"><div class="k">Tags</div><div class="v">{', '.join(s.tags) or '—'}</div></div>
    <div class="info-cell" style="grid-column:1/-1"><div class="k">Observed Open Ports</div><div class="v">{ports_str or '—'}</div></div>
    {vulns_html}
  </div>
</div>"""


# ---------------------------------------------------------------------------
# JSON exporter
# ---------------------------------------------------------------------------

class JSONReporter:
    """Exports the analysis report as structured JSON."""

    def generate(self, report: AnalysisReport, output_path: str) -> str:
        data = {
            "meta": {
                "tool": "ReconScanner",
                "version": "1.0",
                "generated": datetime.utcnow().isoformat() + "Z",
            },
            "target": {
                "input": report.target,
                "resolved_ip": report.resolved_ip,
                "hostname": report.hostname,
                "os": report.os_info,
            },
            "scan": {
                "time": report.scan_time,
                "duration_secs": report.duration_secs,
                "open_ports": report.open_port_count,
            },
            "risk": {
                "score": report.risk_score,
                "label": report.risk_label,
                "summary": report.summary,
            },
            "findings": [
                {
                    "severity": f.severity,
                    "port": f.port,
                    "protocol": f.protocol,
                    "service": f.service,
                    "title": f.title,
                    "detail": f.detail,
                    "cves": [
                        {
                            "id": c.cve_id,
                            "cvss": c.cvss_score,
                            "severity": c.severity,
                            "description": c.description,
                            "published": c.published_date,
                        }
                        for c in f.cves
                    ],
                }
                for f in report.findings
            ],
        }

        if report.shodan_info and not report.shodan_info.error:
            s = report.shodan_info
            data["shodan"] = {
                "org": s.org,
                "country": s.country,
                "city": s.city,
                "open_ports": s.open_ports,
                "vulns": s.vulns,
                "last_update": s.last_update,
            }

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return str(path)
