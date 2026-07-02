"""
orchestrator.py — Master Scan Pipeline
----------------------------------------
Wires together every module into a single cohesive pipeline:

  scanner → fingerprinter → topology mapper → CVE engine
        → exploit suggester → risk analyzer → reporter

Designed to run with the live dashboard OR in quiet/CI mode.
"""

import os
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from .scanner        import ReconScanner, SCAN_PROFILES
from .cve_engine     import NVDClient, ShodanClient
from .analyzer       import RiskAnalyzer, AnalysisReport
from .fingerprint    import ServiceFingerprinter
from .topology       import NetworkTopologyMapper
from .exploit_suggester import ExploitSuggester
from .reporter       import TerminalReporter, HTMLReporter, JSONReporter
from .dashboard      import DashboardState


# ---------------------------------------------------------------------------
# Orchestration config
# ---------------------------------------------------------------------------

class ScanConfig:
    """Everything needed to configure a full scan."""
    def __init__(
        self,
        target: str,
        profile: str = "standard",
        use_shodan: bool = False,
        fetch_cves: bool = True,
        do_fingerprint: bool = True,
        do_topology: bool = False,
        do_exploit_suggest: bool = True,
        output_dir: str = "reports",
        save_html: bool = False,
        save_json: bool = False,
        shodan_api_key: Optional[str] = None,
        nvd_api_key: Optional[str] = None,
    ):
        self.target             = target
        self.profile            = profile
        self.use_shodan         = use_shodan
        self.fetch_cves         = fetch_cves
        self.do_fingerprint     = do_fingerprint
        self.do_topology        = do_topology
        self.do_exploit_suggest = do_exploit_suggest
        self.output_dir         = output_dir
        self.save_html          = save_html
        self.save_json          = save_json
        self.shodan_api_key     = shodan_api_key or os.getenv("SHODAN_API_KEY", "")
        self.nvd_api_key        = nvd_api_key or os.getenv("NVD_API_KEY", "")


# ---------------------------------------------------------------------------
# Master pipeline
# ---------------------------------------------------------------------------

class ScanOrchestrator:
    """
    Runs the complete scan pipeline, optionally updating a DashboardState
    for the live terminal UI.
    """

    def __init__(self, config: ScanConfig):
        self.cfg     = config
        self.scanner = ReconScanner()
        self.nvd     = NVDClient(api_key=config.nvd_api_key)
        self.shodan  = ShodanClient(api_key=config.shodan_api_key)
        self.fp      = ServiceFingerprinter()
        self.topo    = NetworkTopologyMapper()
        self.exp     = ExploitSuggester()
        self.analyze = RiskAnalyzer(nvd_client=self.nvd)

    def run(self, state: Optional[DashboardState] = None) -> dict:
        """
        Execute the full pipeline. Returns a results dict containing
        all intermediate and final artifacts.
        """

        def upd(phase=None, **kwargs):
            """Helper to update dashboard state if available."""
            if state:
                if phase:
                    state.update(phase=phase)
                state.update(**kwargs)

        results = {
            "config":       self.cfg,
            "scan_result":  None,
            "fingerprint":  None,
            "topology":     None,
            "shodan_info":  None,
            "report":       None,
            "suggestions":  [],
            "saved_files":  [],
            "errors":       [],
        }

        target = self.cfg.target
        upd(phase=f"Resolving {target}...", target=target)

        # ── Phase 1: Nmap scan ─────────────────────────────────────────
        upd(phase="Running Nmap scan...", **{"phases": state.phases} if state else {})
        if state:
            state.set_phase_progress("nmap_scan", 0.1)

        try:
            scan_result = self.scanner.scan(target, profile=self.cfg.profile)
            results["scan_result"] = scan_result

            if scan_result.error:
                results["errors"].append(f"Scan: {scan_result.error}")
                upd(phase=f"Scan error: {scan_result.error}")
                if state:
                    state.set_phase_progress("nmap_scan", 1.0, done=True)
                return results

            # Feed ports into dashboard
            if state:
                for p in scan_result.ports:
                    state.add_port(
                        port=p.port,
                        service=p.service or "unknown",
                        state=p.state,
                        product=p.product or "",
                    )
                state.update(
                    os_guess=scan_result.os_guesses[0].name if scan_result.os_guesses else ""
                )
                state.set_phase_progress("nmap_scan", 1.0, done=True)

            upd(phase=f"Nmap done — {len(scan_result.ports)} open ports")

        except Exception as e:
            results["errors"].append(f"Nmap exception: {e}")
            if state:
                state.set_phase_progress("nmap_scan", 1.0, done=True)
            return results

        # ── Phase 2: Service fingerprinting ───────────────────────────
        if self.cfg.do_fingerprint and scan_result.ports:
            upd(phase="Fingerprinting services...")
            if state:
                state.set_phase_progress("fingerprint", 0.2)

            try:
                fp_result = self.fp.fingerprint_host(
                    scan_result.resolved_ip,
                    scan_result.ports,
                )
                results["fingerprint"] = fp_result

                if state:
                    # Feed interesting TLS/HTTP findings back into the dashboard
                    for note in fp_result.interesting_findings:
                        state.add_finding("MEDIUM", note)
                    state.set_phase_progress("fingerprint", 1.0, done=True)

            except Exception as e:
                results["errors"].append(f"Fingerprint: {e}")
                if state:
                    state.set_phase_progress("fingerprint", 1.0, done=True)

        else:
            if state:
                state.set_phase_progress("fingerprint", 1.0, done=True)

        # ── Phase 3: Shodan intelligence ──────────────────────────────
        if self.cfg.use_shodan:
            upd(phase="Querying Shodan...")
            if state:
                state.set_phase_progress("shodan", 0.3)

            try:
                shodan_info = self.shodan.get_host_info(scan_result.resolved_ip)
                results["shodan_info"] = shodan_info

                if state and not shodan_info.error:
                    # Feed Shodan CVEs into the dashboard stream
                    for cve_id in shodan_info.vulns[:10]:
                        state.add_cve(cve_id, 0.0, "Shodan")
                    state.set_phase_progress("shodan", 1.0, done=True)
                else:
                    if state:
                        state.set_phase_progress("shodan", 1.0, done=True)

            except Exception as e:
                results["errors"].append(f"Shodan: {e}")
                if state:
                    state.set_phase_progress("shodan", 1.0, done=True)
        else:
            if state:
                state.set_phase_progress("shodan", 1.0, done=True)

        # ── Phase 4: CVE lookup ────────────────────────────────────────
        if self.cfg.fetch_cves and scan_result.ports:
            upd(phase="Fetching CVEs from NVD...")
            if state:
                state.set_phase_progress("cve_lookup", 0.1)

            # We do CVE lookup inside the analyzer, but we can stream
            # results to the dashboard by doing it incrementally here
            total  = len(scan_result.ports)
            for i, port_info in enumerate(scan_result.ports):
                if state:
                    state.set_phase_progress("cve_lookup", (i + 1) / total)

                # Fetch CVEs for this port
                if port_info.cpe or port_info.product:
                    try:
                        if port_info.cpe:
                            cves = self.nvd.lookup_by_cpe(port_info.cpe, max_results=3)
                        else:
                            cves = self.nvd.lookup_by_keyword(
                                f"{port_info.product} {port_info.version}".strip(),
                                max_results=3,
                            )

                        for cve in cves:
                            if state and cve.cvss_score >= 4.0:
                                state.add_cve(cve.cve_id, cve.cvss_score, port_info.service)

                    except Exception:
                        pass

            if state:
                state.set_phase_progress("cve_lookup", 1.0, done=True)
        else:
            if state:
                state.set_phase_progress("cve_lookup", 1.0, done=True)

        # ── Phase 5: Network topology ──────────────────────────────────
        if self.cfg.do_topology:
            upd(phase="Mapping network topology...")
            try:
                topo = self.topo.map_network(
                    target=target,
                    resolved_ip=scan_result.resolved_ip,
                    open_ports=scan_result.ports,
                )
                results["topology"] = topo
                if state:
                    state.update(
                        live_hosts=len(topo.live_hosts),
                        trace_hops=len(topo.trace_hops),
                    )
            except Exception as e:
                results["errors"].append(f"Topology: {e}")

        # ── Phase 6: Risk analysis ─────────────────────────────────────
        upd(phase="Analyzing risk posture...")
        if state:
            state.set_phase_progress("analysis", 0.5)

        try:
            report = self.analyze.analyze(
                scan_result=scan_result,
                shodan_info=results.get("shodan_info"),
                fetch_cves=False,  # Already fetched above
            )
            results["report"] = report

            # Push all findings into the dashboard
            if state:
                for finding in report.findings:
                    state.add_finding(
                        severity=finding.severity,
                        title=finding.title,
                        port=finding.port,
                    )
                    for cve in finding.cves:
                        state.add_cve(cve.cve_id, cve.cvss_score, finding.service)

                state.update(
                    risk_score=report.risk_score,
                    risk_label=report.risk_label,
                )
                state.set_phase_progress("analysis", 1.0, done=True)

        except Exception as e:
            results["errors"].append(f"Analysis: {e}")
            if state:
                state.set_phase_progress("analysis", 1.0, done=True)
            return results

        # ── Phase 7: Exploit suggestions ──────────────────────────────
        if self.cfg.do_exploit_suggest and report:
            try:
                suggestions = self.exp.suggest_for_findings(report.findings)
                results["suggestions"] = suggestions
            except Exception as e:
                results["errors"].append(f"Exploit suggestions: {e}")

        # ── Phase 8: Save reports ──────────────────────────────────────
        upd(phase="Generating reports...")
        timestamp  = datetime.fromtimestamp(report.scan_time).strftime("%Y%m%d_%H%M%S")
        safe_name  = target.replace(".", "_").replace(":", "_")
        base_name  = f"{safe_name}_{timestamp}"

        if self.cfg.save_html:
            html_path = os.path.join(self.cfg.output_dir, f"{base_name}.html")
            try:
                HTMLReporter().generate(report, html_path)
                results["saved_files"].append(html_path)
            except Exception as e:
                results["errors"].append(f"HTML save: {e}")

        if self.cfg.save_json:
            json_path = os.path.join(self.cfg.output_dir, f"{base_name}.json")
            try:
                JSONReporter().generate(report, json_path)
                results["saved_files"].append(json_path)
            except Exception as e:
                results["errors"].append(f"JSON save: {e}")

        upd(phase="✓ Scan complete", complete=True)
        return results
