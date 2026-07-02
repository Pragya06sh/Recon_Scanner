#!/usr/bin/env python3
"""
demo.py — Offline Demo / Test Runner
--------------------------------------
Runs the full pipeline using MOCK scan data so you can see the entire
system working without needing root/nmap/API keys.

Perfect for:
  - Understanding the output format
  - Testing the dashboard and reporter
  - CI environments
  - Demos and presentations

Run: python3 demo.py
"""

import sys, time, os
sys.path.insert(0, os.path.dirname(__file__))

from core.scanner   import ScanResult, PortInfo, OSGuess
from core.analyzer  import RiskAnalyzer, AnalysisReport
from core.reporter  import TerminalReporter, HTMLReporter, JSONReporter
from core.exploit_suggester import ExploitSuggester
from core.cve_engine import CVEFinding
from core.dashboard  import DashboardState, LiveDashboard
from rich.console    import Console

console = Console()


# ---------------------------------------------------------------------------
# Build realistic mock scan data
# ---------------------------------------------------------------------------

def make_mock_scan() -> ScanResult:
    """Simulate what nmap would return for a typical misconfigured server."""

    result = ScanResult(
        target       = "192.168.1.100",
        resolved_ip  = "192.168.1.100",
        hostname     = "target.lab.local",
        scan_time    = time.time(),
        duration_secs= 8.42,
    )

    result.os_guesses = [
        OSGuess("Ubuntu 20.04 Linux", 95, "cpe:/o:linux:linux_kernel:5.4"),
        OSGuess("Linux 5.x",          80, "cpe:/o:linux:linux_kernel"),
    ]

    result.ports = [
        PortInfo(21,   "tcp", "open", "ftp",   "vsftpd",          "2.3.4", "",
                 "cpe:/a:vsftpd:vsftpd:2.3.4",
                 scripts={"ftp-anon": "Anonymous FTP login allowed"}),

        PortInfo(22,   "tcp", "open", "ssh",   "OpenSSH",         "7.4",   "",
                 "cpe:/a:openbsd:openssh:7.4",
                 scripts={"ssh-auth-methods": "publickey,password"}),

        PortInfo(23,   "tcp", "open", "telnet","Linux telnetd",   "",      "",
                 "cpe:/a:gnu:inetutils:1.9",  scripts={}),

        PortInfo(80,   "tcp", "open", "http",  "Apache httpd",    "2.4.49","",
                 "cpe:/a:apache:http_server:2.4.49",
                 scripts={"http-server-header": "Apache/2.4.49",
                          "http-title": "Site title: Example Server"}),

        PortInfo(443,  "tcp", "open", "https", "Apache httpd",    "2.4.49","",
                 "cpe:/a:apache:http_server:2.4.49",  scripts={}),

        PortInfo(445,  "tcp", "open", "microsoft-ds", "Samba smbd", "4.6.2", "",
                 "cpe:/a:samba:samba:4.6.2",
                 scripts={"smb-vuln-ms17-010":
                          "VULNERABLE\nRisk factor: HIGH\nCVE:CVE-2017-0144"}),

        PortInfo(3306, "tcp", "open", "mysql", "MySQL",           "5.7.38","",
                 "cpe:/a:mysql:mysql:5.7.38",  scripts={}),

        PortInfo(6379, "tcp", "open", "redis", "Redis key-value", "6.0.16","",
                 "cpe:/a:redis:redis:6.0.16",  scripts={}),

        PortInfo(8080, "tcp", "open", "http",  "nginx",           "1.14.0","",
                 "cpe:/a:nginx:nginx:1.14.0",  scripts={}),

        PortInfo(27017,"tcp", "open", "mongod","MongoDB",         "4.4.6", "",
                 "cpe:/a:mongodb:mongodb:4.4.6", scripts={}),
    ]

    return result


def make_mock_cves() -> dict[int, list[CVEFinding]]:
    """Pre-built CVE data to inject (avoids NVD API calls in demo)."""
    return {
        21: [
            CVEFinding("CVE-2011-2523", "vsftpd 2.3.4 backdoor — opens shell on port 6200",
                       10.0, "2.0", "HIGH", "2011-07-07"),
        ],
        80: [
            CVEFinding("CVE-2021-41773", "Apache 2.4.49 path traversal & RCE (mod_cgi)",
                       9.8, "3.1", "CRITICAL", "2021-10-05"),
            CVEFinding("CVE-2021-42013", "Apache 2.4.49/2.4.50 path traversal bypass",
                       9.8, "3.1", "CRITICAL", "2021-10-07"),
        ],
        445: [
            CVEFinding("CVE-2017-0144", "EternalBlue SMBv1 RCE — WannaCry/NotPetya vector",
                       9.8, "3.1", "CRITICAL", "2017-03-14"),
        ],
        6379: [
            CVEFinding("CVE-2022-0543", "Redis Lua sandbox escape — unauthenticated RCE",
                       10.0, "3.1", "CRITICAL", "2022-02-18"),
        ],
        22: [
            CVEFinding("CVE-2016-6210", "OpenSSH 7.x username enumeration via timing",
                       5.9, "3.1", "MEDIUM", "2016-08-07"),
        ],
    }


# ---------------------------------------------------------------------------
# Mock pipeline with dashboard
# ---------------------------------------------------------------------------

def run_demo_with_dashboard():
    """Simulate the full scan pipeline with the live dashboard."""

    state = DashboardState(target="192.168.1.100 (DEMO)", start_time=time.time())
    dash  = LiveDashboard(state)

    def mock_pipeline(state=None):
        """Simulate the orchestrator with artificial delays."""

        # Phase 1: Nmap
        state.update(phase="Running Nmap scan (simulated)...")
        state.set_phase_progress("nmap_scan", 0.1)
        time.sleep(0.5)

        scan = make_mock_scan()
        mock_cves = make_mock_cves()

        for i, p in enumerate(scan.ports):
            time.sleep(0.15)
            state.add_port(p.port, p.service, p.state, p.product)
            state.set_phase_progress("nmap_scan", (i + 1) / len(scan.ports))

        state.set_phase_progress("nmap_scan", 1.0, done=True)
        state.update(os_guess="Ubuntu 20.04 Linux (95%)")

        # Phase 2: Fingerprint
        state.update(phase="Fingerprinting services...")
        state.set_phase_progress("fingerprint", 0.0)
        for i in range(5):
            time.sleep(0.3)
            state.set_phase_progress("fingerprint", (i + 1) / 5)
        state.set_phase_progress("fingerprint", 1.0, done=True)

        # Phase 3: Shodan
        state.update(phase="Shodan: skipped (demo mode)")
        time.sleep(0.2)
        state.set_phase_progress("shodan", 1.0, done=True)

        # Phase 4: CVE lookup
        state.update(phase="Fetching CVEs from NVD (demo data)...")
        for port, cves in mock_cves.items():
            time.sleep(0.3)
            for cve in cves:
                state.add_cve(cve.cve_id, cve.cvss_score,
                              next((p.service for p in scan.ports if p.port == port), "?"))
            svc_count = list(mock_cves.keys()).index(port) + 1
            state.set_phase_progress("cve_lookup", svc_count / len(mock_cves))
        state.set_phase_progress("cve_lookup", 1.0, done=True)

        # Phase 5: Analysis
        state.update(phase="Running risk analysis...")
        state.set_phase_progress("analysis", 0.3)
        time.sleep(0.4)

        # Inject mock CVEs into analyzer
        analyzer = RiskAnalyzer(nvd_client=None)

        # Monkey-patch: give the analyzer pre-fetched CVEs
        original_fetch = analyzer._fetch_cves_for_port
        def patched_fetch(port_info):
            return mock_cves.get(port_info.port, original_fetch(port_info))
        analyzer._fetch_cves_for_port = patched_fetch

        report = analyzer.analyze(scan, shodan_info=None, fetch_cves=False)

        # Manually add our mock CVEs to findings
        from core.analyzer import ServiceFinding
        for finding in report.findings:
            if finding.port in mock_cves:
                finding.cves = mock_cves[finding.port]

        # Recalculate score with CVEs
        report.risk_score, report.risk_label = analyzer._calculate_risk_score(
            report.findings, scan.ports
        )

        state.set_phase_progress("analysis", 1.0, done=True)
        state.update(risk_score=report.risk_score, risk_label=report.risk_label)

        for f in report.findings:
            state.add_finding(f.severity, f.title, f.port)

        state.update(phase=f"✓ Complete — Risk: {report.risk_score}/100 ({report.risk_label})")
        time.sleep(1.5)  # Let the dashboard be visible
        state.update(complete=True)

        return {"report": report, "scan_result": scan, "suggestions": []}

    results = dash.run(mock_pipeline)
    return results


# ---------------------------------------------------------------------------
# Post-dashboard output
# ---------------------------------------------------------------------------

def print_full_results(results):
    if not results:
        return

    report = results.get("report")
    if not report:
        return

    console.print()

    # Terminal report
    TerminalReporter().print_report(report)

    # Exploit suggestions
    exp = ExploitSuggester()
    suggestions = exp.suggest_for_findings(report.findings)
    if suggestions:
        console.print()
        from rich.rule import Rule
        console.rule("[bold red]EXPLOIT SUGGESTIONS — AUTHORIZED USE ONLY[/bold red]")
        plan = exp.generate_pentest_plan(suggestions, report.resolved_ip)
        console.print(plan, style="dim")

    # HTML report
    html_path = "reports/demo_report.html"
    HTMLReporter().generate(report, html_path)
    console.print(f"\n[green]✓[/green] HTML report saved: [bold]{html_path}[/bold]")

    # JSON report
    json_path = "reports/demo_report.json"
    JSONReporter().generate(report, json_path)
    console.print(f"[green]✓[/green] JSON report saved: [bold]{json_path}[/bold]")

    console.print("\n[bold green]Demo complete.[/bold green] "
                  "Open [bold]reports/demo_report.html[/bold] in a browser.\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    console.print("\n[bold cyan]⚡ RECON SCANNER — Demo Mode[/bold cyan]")
    console.print("[dim]Simulating a full scan against a misconfigured lab target...[/dim]\n")

    try:
        results = run_demo_with_dashboard()
        print_full_results(results)
    except KeyboardInterrupt:
        console.print("\n[yellow]Demo interrupted.[/yellow]")
        sys.exit(0)
