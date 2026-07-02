"""
scanner.py — Core Nmap scanning engine
---------------------------------------
Wraps python-nmap to run multiple scan profiles against a target,
parses the raw XML output, and returns structured ScanResult objects.

Key concepts used here:
  • nmap.PortScanner()   — python-nmap's main class; spawns nmap as a subprocess
  • scan(host, ports, args) — runs nmap with given flags, populates the scanner state
  • scanner[host]['tcp']  — dict keyed by port number → state, name, product, version
  • We run TWO passes:
      1. Fast SYN scan  (-sS -O -sV)  — stealth, OS detect, version detect
      2. Script scan    (-sC)          — default NSE scripts (grab banners, check vulns)
"""

import nmap
import socket
import time
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Data containers (pure Python dataclasses — no ORM magic needed)
# ---------------------------------------------------------------------------

@dataclass
class PortInfo:
    """Everything we know about one open port."""
    port: int
    protocol: str          # 'tcp' or 'udp'
    state: str             # 'open', 'filtered', 'closed'
    service: str           # e.g. 'http', 'ssh', 'ftp'
    product: str           # e.g. 'Apache httpd'
    version: str           # e.g. '2.4.51'
    extra_info: str        # banner / extra text nmap grabbed
    cpe: str               # Common Platform Enumeration string (used to look up CVEs)
    scripts: dict = field(default_factory=dict)  # NSE script outputs


@dataclass
class OSGuess:
    """OS detection result from nmap -O."""
    name: str
    accuracy: int          # percentage confidence (0-100)
    cpe: str               # e.g. cpe:/o:linux:linux_kernel:5


@dataclass
class ScanResult:
    """Top-level result for a single host scan."""
    target: str                         # original input (IP or hostname)
    resolved_ip: str                    # resolved IPv4
    hostname: str                       # reverse-DNS hostname if available
    scan_time: float                    # epoch timestamp when scan ran
    duration_secs: float                # how long nmap took
    ports: list[PortInfo] = field(default_factory=list)
    os_guesses: list[OSGuess] = field(default_factory=list)
    raw_nmap_xml: str = ""              # full XML from nmap (for archival)
    error: Optional[str] = None         # set if something went wrong


# ---------------------------------------------------------------------------
# Scan profiles — different nmap flag combinations for different scenarios
# ---------------------------------------------------------------------------

SCAN_PROFILES = {
    "quick": {
        "description": "Fast top-1000 ports, no scripts",
        "args": "-sS -T4 --open",
        "ports": "1-1000",
    },
    "standard": {
        "description": "Top 1000 ports + version detection + default scripts",
        "args": "-sS -sV -sC -O -T4 --open",
        "ports": "1-1000",
    },
    "full": {
        "description": "All 65535 ports + version + scripts + OS detect",
        "args": "-sS -sV -sC -O -T4 --open",
        "ports": "1-65535",
    },
    "udp": {
        "description": "UDP top-200 ports (requires root)",
        "args": "-sU -T4 --open",
        "ports": "1-200",
    },
    "stealth": {
        "description": "SYN scan, slow timing to evade IDS (T2)",
        "args": "-sS -T2 --open",
        "ports": "1-1000",
    },
}


# ---------------------------------------------------------------------------
# The main scanner class
# ---------------------------------------------------------------------------

class ReconScanner:
    """
    Orchestrates nmap scans.

    Usage:
        scanner = ReconScanner()
        result  = scanner.scan("192.168.1.1", profile="standard")
    """

    def __init__(self):
        # PortScanner is the main python-nmap entry point.
        # It internally calls subprocess to run the system 'nmap' binary.
        self.nm = nmap.PortScanner()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, target: str, profile: str = "standard") -> ScanResult:
        """
        Run a full recon scan on `target` using the given profile.
        Returns a populated ScanResult.
        """
        profile_cfg = SCAN_PROFILES.get(profile, SCAN_PROFILES["standard"])

        # Resolve the target to an IP address first (helps with error messages)
        try:
            resolved_ip = socket.gethostbyname(target)
        except socket.gaierror:
            return ScanResult(
                target=target,
                resolved_ip="",
                hostname="",
                scan_time=time.time(),
                duration_secs=0,
                error=f"Could not resolve hostname: {target}",
            )

        result = ScanResult(
            target=target,
            resolved_ip=resolved_ip,
            hostname=self._reverse_dns(resolved_ip),
            scan_time=time.time(),
            duration_secs=0,
        )

        start = time.time()

        try:
            # -------------------------------------------------------
            # THE CORE CALL:
            # nm.scan(hosts, ports, arguments)
            #   hosts     — IP or CIDR range
            #   ports     — e.g. "1-1000" or "22,80,443"
            #   arguments — raw nmap flags passed as a string
            #
            # Under the hood python-nmap builds:
            #   nmap -oX - <arguments> -p <ports> <hosts>
            # and parses the XML output it receives on stdout.
            # -------------------------------------------------------
            self.nm.scan(
                hosts=resolved_ip,
                ports=profile_cfg["ports"],
                arguments=profile_cfg["args"],
                sudo=True,   # SYN scans need raw socket access (root/sudo)
            )

        except nmap.PortScannerError as e:
            result.error = f"Nmap error: {e}"
            result.duration_secs = time.time() - start
            return result
        except Exception as e:
            result.error = f"Unexpected error: {e}"
            result.duration_secs = time.time() - start
            return result

        result.duration_secs = time.time() - start

        # The nmap scan might not find the host at all (offline / firewall)
        if resolved_ip not in self.nm.all_hosts():
            result.error = "Host appears to be down or not responding."
            return result

        host_data = self.nm[resolved_ip]

        # ------------------------------------------------------------------
        # Parse open ports
        # ------------------------------------------------------------------
        for proto in host_data.all_protocols():           # 'tcp', 'udp'
            ports = sorted(host_data[proto].keys())
            for port in ports:
                p = host_data[proto][port]
                if p["state"] not in ("open", "open|filtered"):
                    continue

                # CPE is a structured identifier like:
                # cpe:/a:apache:http_server:2.4.51
                # We'll use this later to look up CVEs
                cpe_list = p.get("cpe", "")

                port_info = PortInfo(
                    port=port,
                    protocol=proto,
                    state=p["state"],
                    service=p.get("name", "unknown"),
                    product=p.get("product", ""),
                    version=p.get("version", ""),
                    extra_info=p.get("extrainfo", ""),
                    cpe=cpe_list,
                    scripts=p.get("script", {}),   # dict of script_name → output
                )
                result.ports.append(port_info)

        # ------------------------------------------------------------------
        # Parse OS detection results
        # ------------------------------------------------------------------
        if "osmatch" in host_data:
            for os_match in host_data["osmatch"][:3]:   # top 3 guesses
                cpe_str = ""
                if os_match.get("osclass"):
                    cpe_str = os_match["osclass"][0].get("cpe", [""])[0]

                result.os_guesses.append(OSGuess(
                    name=os_match.get("name", "Unknown"),
                    accuracy=int(os_match.get("accuracy", 0)),
                    cpe=cpe_str,
                ))

        # Store raw XML for export
        result.raw_nmap_xml = self.nm.get_nmap_last_output()

        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _reverse_dns(self, ip: str) -> str:
        """Try to get a hostname from an IP via reverse DNS."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return ""

    def check_nmap_available(self) -> bool:
        """Return True if nmap binary exists on system PATH."""
        try:
            self.nm.scan("127.0.0.1", "22", arguments="-sn")
            return True
        except nmap.PortScannerError:
            return False

    @staticmethod
    def list_profiles() -> dict:
        return SCAN_PROFILES
