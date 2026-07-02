"""
analyzer.py — Risk Analysis & Correlation Engine
--------------------------------------------------
Takes raw ScanResult + CVE/Shodan data and:
  1. Correlates each open port/service with relevant CVEs
  2. Assigns a risk score (0-100) to the overall target
  3. Generates actionable findings with severity levels
  4. Flags dangerous misconfigurations (telnet, anonymous FTP, etc.)

Design principle: this module is PURE (no I/O, no API calls).
It only transforms data structures into richer data structures.
This makes it easy to test and keeps concerns separated.
"""

from dataclasses import dataclass, field
from typing import Optional

from .scanner import ScanResult, PortInfo
from .cve_engine import CVEFinding, ShodanHostInfo, NVDClient, cvss_to_severity


# ---------------------------------------------------------------------------
# Well-known dangerous service fingerprints
# ---------------------------------------------------------------------------

# Ports/services that are inherently risky when exposed
DANGEROUS_SERVICES = {
    21:   ("FTP", "HIGH",    "FTP transmits credentials in plaintext. Check for anonymous access."),
    22:   ("SSH", "LOW",     "SSH exposed. Ensure key-based auth only; disable password auth."),
    23:   ("Telnet", "CRITICAL", "Telnet transmits ALL data in plaintext. Replace with SSH immediately."),
    25:   ("SMTP", "MEDIUM", "SMTP open relay can be abused for spam. Verify authentication required."),
    53:   ("DNS", "MEDIUM",  "DNS exposed. Check for zone transfer (AXFR) vulnerability."),
    80:   ("HTTP", "LOW",    "HTTP (unencrypted). Check for sensitive data exposure, forced HTTPS redirect."),
    110:  ("POP3", "MEDIUM", "POP3 (plaintext email retrieval). Use POP3S (port 995) instead."),
    111:  ("RPC", "HIGH",    "RPC portmapper exposed. Common target for information gathering."),
    135:  ("MSRPC", "HIGH",  "Windows RPC. Historically targeted (MS03-026, MS08-067). Restrict access."),
    137:  ("NetBIOS-NS", "HIGH", "NetBIOS Name Service. Leaks network info. Should be firewalled."),
    139:  ("NetBIOS-SSN", "HIGH", "NetBIOS Session. Disable if SMB over TCP/445 is used instead."),
    143:  ("IMAP", "MEDIUM", "IMAP (plaintext). Use IMAPS (port 993) instead."),
    161:  ("SNMP", "HIGH",   "SNMP v1/v2c uses community strings (effectively plaintext passwords)."),
    389:  ("LDAP", "HIGH",   "LDAP exposed. Verify anonymous bind is disabled. Use LDAPS (636)."),
    443:  ("HTTPS", "LOW",   "HTTPS. Check TLS version (avoid TLS 1.0/1.1), cert validity."),
    445:  ("SMB", "CRITICAL","SMB directly exposed. EternalBlue (MS17-010) target. Patch and firewall."),
    512:  ("rexec", "CRITICAL","Remote exec — transmits passwords in cleartext. Disable immediately."),
    513:  ("rlogin", "CRITICAL","Remote login — no encryption. Disable immediately."),
    514:  ("rsh/syslog", "HIGH","Remote shell or syslog. rsh has no auth. Disable rsh; restrict syslog."),
    1433: ("MSSQL", "HIGH",  "Microsoft SQL Server exposed to network. Restrict to application servers only."),
    1521: ("Oracle DB", "HIGH","Oracle DB exposed. Restrict to application servers only."),
    2049: ("NFS", "HIGH",    "NFS exposed. Check for world-readable exports."),
    3306: ("MySQL", "HIGH",  "MySQL exposed to network. Bind to localhost or restrict with firewall."),
    3389: ("RDP", "HIGH",    "RDP exposed. BlueKeep (CVE-2019-0708) target. Enforce NLA; use VPN."),
    4444: ("Metasploit", "CRITICAL","Common Metasploit listener port. Investigate immediately."),
    5432: ("PostgreSQL", "HIGH","PostgreSQL exposed. Bind to localhost or restrict with firewall."),
    5900: ("VNC", "HIGH",    "VNC exposed. Often poorly authenticated. Use VPN; enable strong passwords."),
    6379: ("Redis", "CRITICAL","Redis exposed. Defaults to no authentication. Bind to localhost."),
    8080: ("HTTP-Alt", "LOW","Alternate HTTP. May expose admin panels or dev servers."),
    8443: ("HTTPS-Alt", "LOW","Alternate HTTPS. Check TLS configuration."),
    9200: ("Elasticsearch", "CRITICAL","Elasticsearch exposed. Defaults to no auth. Massive data breach risk."),
    27017:("MongoDB", "CRITICAL","MongoDB exposed. Older versions default to no auth. Critical risk."),
}

# NSE script outputs that indicate specific vulnerabilities
DANGEROUS_SCRIPT_PATTERNS = {
    "ftp-anon": ("CRITICAL", "Anonymous FTP login is ENABLED — files are publicly readable/writable."),
    "smb-vuln-ms17-010": ("CRITICAL", "EternalBlue (MS17-010) confirmed VULNERABLE — patch immediately."),
    "smb-vuln-ms08-067": ("CRITICAL", "MS08-067 confirmed VULNERABLE — critical unpatched system."),
    "http-shellshock": ("CRITICAL", "ShellShock (CVE-2014-6271) confirmed VULNERABLE."),
    "ssl-heartbleed": ("CRITICAL", "Heartbleed (CVE-2014-0160) confirmed VULNERABLE — TLS key material exposed."),
    "ssl-poodle": ("HIGH", "POODLE vulnerability detected — SSLv3 should be disabled."),
    "http-robots": ("LOW", "robots.txt found — may reveal hidden directories/endpoints."),
    "ssh-auth-methods": ("INFO", "SSH authentication methods enumerated."),
    "http-auth": ("MEDIUM", "HTTP authentication required — check for weak credentials."),
    "smtp-open-relay": ("HIGH", "SMTP open relay confirmed — can be abused for spam."),
    "ms-sql-empty-password": ("CRITICAL", "MSSQL with empty SA password found."),
    "mysql-empty-password": ("CRITICAL", "MySQL root with empty password."),
    "vnc-info": ("MEDIUM", "VNC server information disclosed."),
    "snmp-info": ("MEDIUM", "SNMP information disclosure — community string 'public' or 'private'."),
}


# ---------------------------------------------------------------------------
# Output structures
# ---------------------------------------------------------------------------

@dataclass
class ServiceFinding:
    """A vulnerability or risk finding for a specific port/service."""
    port: int
    protocol: str
    service: str
    severity: str                   # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    cves: list[CVEFinding] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class AnalysisReport:
    """Complete analysis of a scan result."""
    target: str
    resolved_ip: str
    hostname: str
    scan_time: float
    duration_secs: float
    risk_score: int                  # 0–100 overall risk score
    risk_label: str                  # CRITICAL / HIGH / MEDIUM / LOW / SECURE
    open_port_count: int
    findings: list[ServiceFinding] = field(default_factory=list)
    shodan_info: Optional[ShodanHostInfo] = None
    os_info: str = ""
    summary: str = ""


# ---------------------------------------------------------------------------
# The analyzer
# ---------------------------------------------------------------------------

class RiskAnalyzer:
    """
    Correlates nmap results with CVE data and known dangerous patterns
    to produce a prioritized list of findings and an overall risk score.
    """

    def __init__(self, nvd_client: Optional[NVDClient] = None):
        self.nvd = nvd_client or NVDClient()

    def analyze(
        self,
        scan_result: ScanResult,
        shodan_info: Optional[ShodanHostInfo] = None,
        fetch_cves: bool = True,
    ) -> AnalysisReport:
        """
        Main entry point. Takes a ScanResult, returns a full AnalysisReport.
        """
        report = AnalysisReport(
            target=scan_result.target,
            resolved_ip=scan_result.resolved_ip,
            hostname=scan_result.hostname,
            scan_time=scan_result.scan_time,
            duration_secs=scan_result.duration_secs,
            risk_score=0,
            risk_label="UNKNOWN",
            open_port_count=len(scan_result.ports),
            shodan_info=shodan_info,
        )

        if scan_result.error:
            report.summary = f"Scan failed: {scan_result.error}"
            return report

        # OS info
        if scan_result.os_guesses:
            best = scan_result.os_guesses[0]
            report.os_info = f"{best.name} ({best.accuracy}% confidence)"

        # Analyze each port
        for port_info in scan_result.ports:
            findings = self._analyze_port(port_info, fetch_cves)
            report.findings.extend(findings)

        # Add Shodan-specific CVE findings
        if shodan_info and not shodan_info.error:
            shodan_findings = self._analyze_shodan(shodan_info)
            report.findings.extend(shodan_findings)

        # Calculate overall risk score
        report.risk_score, report.risk_label = self._calculate_risk_score(
            report.findings, scan_result.ports
        )

        # Generate summary
        report.summary = self._generate_summary(report)

        # Sort findings by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        report.findings.sort(key=lambda f: severity_order.get(f.severity, 5))

        return report

    # ------------------------------------------------------------------
    # Port analysis
    # ------------------------------------------------------------------

    def _analyze_port(self, port_info: PortInfo, fetch_cves: bool) -> list[ServiceFinding]:
        """Generate findings for a single open port."""
        findings = []

        # 1. Check against our dangerous service database
        if port_info.port in DANGEROUS_SERVICES:
            svc_name, severity, detail = DANGEROUS_SERVICES[port_info.port]
            finding = ServiceFinding(
                port=port_info.port,
                protocol=port_info.protocol,
                service=port_info.service or svc_name,
                severity=severity,
                title=f"{svc_name} service detected",
                detail=detail,
            )
            # Look up CVEs for this service if we have version info
            if fetch_cves and (port_info.cpe or port_info.product):
                finding.cves = self._fetch_cves_for_port(port_info)

            findings.append(finding)

        elif port_info.port > 0:
            # Unknown/unusual port — still report it
            svc_label = port_info.service or "unknown"
            findings.append(ServiceFinding(
                port=port_info.port,
                protocol=port_info.protocol,
                service=svc_label,
                severity="LOW",
                title=f"Non-standard port {port_info.port} open",
                detail=f"Service: {svc_label}. Product: {port_info.product or 'unknown'}. "
                       f"Investigate if this port should be exposed.",
            ))

        # 2. Check NSE script outputs for known vulnerability patterns
        for script_name, script_output in port_info.scripts.items():
            script_key = script_name.lower()
            for pattern, (sev, msg) in DANGEROUS_SCRIPT_PATTERNS.items():
                if pattern in script_key:
                    # Check if the script output actually confirmed the vuln
                    # (some scripts report "NOT vulnerable" — we don't want false positives)
                    if self._script_confirmed_vuln(script_output):
                        findings.append(ServiceFinding(
                            port=port_info.port,
                            protocol=port_info.protocol,
                            service=port_info.service,
                            severity=sev,
                            title=f"Script [{script_name}] flagged vulnerability",
                            detail=f"{msg}\n\nScript output: {str(script_output)[:300]}",
                        ))

        return findings

    def _fetch_cves_for_port(self, port_info: PortInfo) -> list[CVEFinding]:
        """Query NVD for CVEs related to this port's service."""
        cves = []

        # Strategy: try CPE first (more precise), fall back to keyword search
        if port_info.cpe:
            cves = self.nvd.lookup_by_cpe(port_info.cpe, max_results=5)

        if not cves and port_info.product and port_info.version:
            keyword = f"{port_info.product} {port_info.version}"
            cves = self.nvd.lookup_by_keyword(keyword, max_results=5)
        elif not cves and port_info.product:
            cves = self.nvd.lookup_by_keyword(port_info.product, max_results=3)

        # Only return HIGH+ severity CVEs to avoid noise
        return [c for c in cves if c.cvss_score >= 4.0][:5]

    def _script_confirmed_vuln(self, output) -> bool:
        """
        NSE scripts often output 'NOT vulnerable' when clean.
        We only want to flag actual confirmed vulnerabilities.
        """
        if isinstance(output, str):
            text = output.lower()
            return (
                "not vulnerable" not in text
                and "not affected" not in text
                and len(text) > 5
            )
        return True  # dict/complex output → assume it found something

    # ------------------------------------------------------------------
    # Shodan analysis
    # ------------------------------------------------------------------

    def _analyze_shodan(self, shodan_info: ShodanHostInfo) -> list[ServiceFinding]:
        """Convert Shodan CVE data into findings."""
        findings = []

        for cve_id in shodan_info.vulns[:20]:  # cap at 20
            finding = ServiceFinding(
                port=0,
                protocol="",
                service="(Shodan intelligence)",
                severity="HIGH",    # Shodan only lists confirmed/observed vulns
                title=f"Shodan flagged {cve_id}",
                detail=f"Shodan's scanner observed this host to be vulnerable to {cve_id}. "
                       f"Verify and patch immediately.",
                cves=[CVEFinding(
                    cve_id=cve_id,
                    description="See NVD for details.",
                    cvss_score=0.0,
                    cvss_version="",
                    severity="HIGH",
                    published_date="",
                )],
            )
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def _calculate_risk_score(
        self,
        findings: list[ServiceFinding],
        ports: list[PortInfo],
    ) -> tuple[int, str]:
        """
        Calculate a 0–100 risk score based on findings.

        Scoring logic:
          CRITICAL finding → +25 pts (capped)
          HIGH finding     → +15 pts (capped)
          MEDIUM finding   → +8 pts  (capped)
          LOW finding      → +3 pts  (capped)
          Each open port   → +2 pts  (max +20)
          CVE with CVSS>9  → +5 pts per (max +15)
        """
        score = 0

        severity_points = {
            "CRITICAL": 25,
            "HIGH": 15,
            "MEDIUM": 8,
            "LOW": 3,
            "INFO": 0,
        }
        severity_caps = {
            "CRITICAL": 50,
            "HIGH": 45,
            "MEDIUM": 24,
            "LOW": 9,
        }

        severity_totals: dict[str, int] = {s: 0 for s in severity_points}

        for finding in findings:
            sev = finding.severity
            pts = severity_points.get(sev, 0)
            cap = severity_caps.get(sev, 0)
            severity_totals[sev] = min(severity_totals[sev] + pts, cap)

            # Bonus for high-CVSS CVEs
            for cve in finding.cves:
                if cve.cvss_score >= 9.0:
                    score = min(score + 5, score + 15)

        for sev_score in severity_totals.values():
            score += sev_score

        # Exposure bonus: more open ports = higher attack surface
        exposure = min(len(ports) * 2, 20)
        score = min(score + exposure, 100)

        # Label
        if score >= 75:   label = "CRITICAL"
        elif score >= 55: label = "HIGH"
        elif score >= 30: label = "MEDIUM"
        elif score >= 10: label = "LOW"
        else:             label = "SECURE"

        return score, label

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def _generate_summary(self, report: AnalysisReport) -> str:
        counts = {}
        for f in report.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        total_cves = sum(len(f.cves) for f in report.findings)

        parts = [
            f"Risk Score: {report.risk_score}/100 ({report.risk_label})",
            f"Open Ports: {report.open_port_count}",
            f"Findings: {len(report.findings)} total",
        ]

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if counts.get(sev):
                parts.append(f"  • {counts[sev]} {sev}")

        if total_cves:
            parts.append(f"CVEs Referenced: {total_cves}")

        if report.os_info:
            parts.append(f"OS: {report.os_info}")

        return " | ".join(parts[:3]) + "\n" + "\n".join(parts[3:])
