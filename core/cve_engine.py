"""
cve_engine.py — CVE / Vulnerability Intelligence Layer
--------------------------------------------------------
This module does two things:

  1. NIST NVD (National Vulnerability Database) lookup
     - Free public REST API (no key needed, but rate-limited to 5 req/30s)
     - We query by CPE string (from nmap) OR by keyword (product + version)
     - Returns CVE IDs, CVSS scores, descriptions, and severity ratings

  2. Shodan host intelligence
     - Shodan is a search engine for internet-connected devices
     - Their API returns open ports, banners, known vulnerabilities, and
       geolocation for any public IP address
     - Requires a free API key from https://shodan.io

WHY BOTH?
  NVD   = deep technical CVE database (canonical source of truth)
  Shodan = real-time observed data (what's actually exposed right now)
  Together they give you both "what COULD be vulnerable" and
  "what HAS BEEN seen exposed in the wild."
"""

import os
import time
import requests
from dataclasses import dataclass, field
from typing import Optional
import shodan


# ---------------------------------------------------------------------------
# Data structures for vulnerability findings
# ---------------------------------------------------------------------------

@dataclass
class CVEFinding:
    """A single CVE associated with a port/service."""
    cve_id: str              # e.g. "CVE-2021-44228"
    description: str         # human-readable description
    cvss_score: float        # 0.0–10.0 severity score
    cvss_version: str        # "3.1", "3.0", or "2.0"
    severity: str            # CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL
    published_date: str      # ISO date string
    references: list[str] = field(default_factory=list)
    affected_cpe: str = ""


@dataclass
class ShodanHostInfo:
    """What Shodan knows about a public IP."""
    ip: str
    hostnames: list[str] = field(default_factory=list)
    country: str = ""
    city: str = ""
    org: str = ""
    isp: str = ""
    open_ports: list[int] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)      # CVE IDs Shodan has flagged
    tags: list[str] = field(default_factory=list)        # e.g. "cloud", "cdn", "tor"
    banners: list[dict] = field(default_factory=list)    # raw service banners
    last_update: str = ""
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# CVSS score → human severity label
# ---------------------------------------------------------------------------

def cvss_to_severity(score: float, version: str = "3.x") -> str:
    """
    Convert a numeric CVSS score to a severity label.
    CVSS v3.x scale:   0.0=None, 0.1-3.9=Low, 4.0-6.9=Medium,
                        7.0-8.9=High, 9.0-10.0=Critical
    CVSS v2.0 scale:   0-3.9=Low, 4-6.9=Medium, 7-10=High
    """
    if version.startswith("2"):
        if score >= 7.0:   return "HIGH"
        if score >= 4.0:   return "MEDIUM"
        return "LOW"
    else:  # v3.x
        if score >= 9.0:   return "CRITICAL"
        if score >= 7.0:   return "HIGH"
        if score >= 4.0:   return "MEDIUM"
        if score > 0.0:    return "LOW"
        return "INFORMATIONAL"


# ---------------------------------------------------------------------------
# NVD (National Vulnerability Database) client
# ---------------------------------------------------------------------------

class NVDClient:
    """
    Queries the NIST NVD REST API v2.0 for CVE data.

    API docs: https://nvd.nist.gov/developers/vulnerabilities
    Rate limit: 5 requests per 30 seconds WITHOUT an API key
                50 requests per 30 seconds WITH a free API key
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    RATE_LIMIT_SLEEP = 7   # seconds to wait between requests (conservative)

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "ReconScanner/1.0 (educational use)",
        })
        if self.api_key:
            self.session.headers["apiKey"] = self.api_key

        self._last_request_time = 0.0

    def _rate_limit(self):
        """Ensure we don't exceed NVD's rate limit."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self.RATE_LIMIT_SLEEP:
            time.sleep(self.RATE_LIMIT_SLEEP - elapsed)
        self._last_request_time = time.time()

    def lookup_by_cpe(self, cpe_string: str, max_results: int = 10) -> list[CVEFinding]:
        """
        Look up CVEs that affect a specific CPE (software/hardware identifier).

        CPE format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
        Example:    cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*

        nmap's CPE strings use the older 2.2 format (cpe:/a:vendor:product:version)
        The NVD API v2 accepts both.
        """
        if not cpe_string:
            return []

        self._rate_limit()

        params = {
            "cpeName": cpe_string,
            "resultsPerPage": max_results,
        }

        try:
            response = self.session.get(self.BASE_URL, params=params, timeout=15)
            response.raise_for_status()
            data = response.json()
            return self._parse_nvd_response(data)
        except requests.exceptions.Timeout:
            return []
        except requests.exceptions.RequestException:
            return []

    def lookup_by_keyword(self, keyword: str, max_results: int = 10) -> list[CVEFinding]:
        """
        Search CVEs by keyword (product name, version string, etc.)
        Useful when we don't have a CPE string from nmap.
        """
        if not keyword or len(keyword.strip()) < 3:
            return []

        self._rate_limit()

        params = {
            "keywordSearch": keyword,
            "keywordExactMatch": "",
            "resultsPerPage": max_results,
        }

        try:
            response = self.session.get(self.BASE_URL, params=params, timeout=15)
            response.raise_for_status()
            data = response.json()
            return self._parse_nvd_response(data)
        except requests.exceptions.RequestException:
            return []

    def _parse_nvd_response(self, data: dict) -> list[CVEFinding]:
        """
        Parse the NVD API v2 JSON response into CVEFinding objects.

        The response structure is:
        {
          "vulnerabilities": [
            {
              "cve": {
                "id": "CVE-2021-44228",
                "descriptions": [{"lang": "en", "value": "..."}],
                "metrics": {
                  "cvssMetricV31": [{"cvssData": {"baseScore": 10.0, ...}}],
                  "cvssMetricV2":  [{"cvssData": {"baseScore": 9.3, ...}}]
                },
                "published": "2021-12-10T...",
                "references": [{"url": "..."}]
              }
            }, ...
          ]
        }
        """
        findings = []

        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")

            # Extract English description
            description = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Extract CVSS score — prefer v3.1 > v3.0 > v2.0
            cvss_score = 0.0
            cvss_version = "unknown"
            metrics = cve.get("metrics", {})

            if "cvssMetricV31" in metrics:
                m = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score = m.get("baseScore", 0.0)
                cvss_version = "3.1"
            elif "cvssMetricV30" in metrics:
                m = metrics["cvssMetricV30"][0]["cvssData"]
                cvss_score = m.get("baseScore", 0.0)
                cvss_version = "3.0"
            elif "cvssMetricV2" in metrics:
                m = metrics["cvssMetricV2"][0]["cvssData"]
                cvss_score = m.get("baseScore", 0.0)
                cvss_version = "2.0"

            # Extract reference URLs
            refs = [r["url"] for r in cve.get("references", [])
                    if "url" in r][:5]   # limit to first 5

            findings.append(CVEFinding(
                cve_id=cve_id,
                description=description[:300] + "..." if len(description) > 300 else description,
                cvss_score=cvss_score,
                cvss_version=cvss_version,
                severity=cvss_to_severity(cvss_score, cvss_version),
                published_date=cve.get("published", "")[:10],
                references=refs,
            ))

        # Sort by severity (highest CVSS first)
        findings.sort(key=lambda x: x.cvss_score, reverse=True)
        return findings


# ---------------------------------------------------------------------------
# Shodan client wrapper
# ---------------------------------------------------------------------------

class ShodanClient:
    """
    Wraps the official Shodan Python library to get host intelligence.

    Shodan maintains a continuously updated index of internet-connected
    devices. For any public IP it can tell you:
      - What ports are open (as observed by Shodan's scanners)
      - What software/versions are running (from banner grabbing)
      - Known CVEs associated with those services
      - Geographic and network metadata

    Note: Shodan only works for PUBLIC IPs. Private ranges
    (10.x, 172.16-31.x, 192.168.x) will return an error.
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("SHODAN_API_KEY", "")
        self._client = None
        self._initialized = False

        if self.api_key and self.api_key != "YOUR_SHODAN_API_KEY":
            try:
                self._client = shodan.Shodan(self.api_key)
                self._initialized = True
            except Exception:
                pass

    @property
    def available(self) -> bool:
        return self._initialized

    def get_host_info(self, ip: str) -> ShodanHostInfo:
        """
        Fetch everything Shodan knows about an IP address.
        """
        info = ShodanHostInfo(ip=ip)

        if not self._initialized:
            info.error = "Shodan API key not configured. Set SHODAN_API_KEY env var."
            return info

        # Check if this is a private IP (Shodan won't have data for these)
        if self._is_private_ip(ip):
            info.error = f"Private IP ({ip}) — Shodan only indexes public internet addresses."
            return info

        try:
            host = self._client.host(ip)
            # ------------------------------------------------------------------
            # The Shodan host() response is a large dict containing:
            # {
            #   "ip_str": "1.2.3.4",
            #   "hostnames": ["example.com"],
            #   "country_name": "US",
            #   "city": "San Francisco",
            #   "org": "AS12345 Example Corp",
            #   "isp": "Example ISP",
            #   "ports": [22, 80, 443],
            #   "vulns": {"CVE-2021-44228": {"cvss": 10.0, "summary": "..."}},
            #   "tags": ["cloud"],
            #   "data": [   ← array of banner objects, one per port
            #     {"port": 22, "transport": "tcp", "data": "SSH-2.0-OpenSSH_8.4\n", ...}
            #   ],
            #   "last_update": "2024-01-15T12:00:00.000000"
            # }
            # ------------------------------------------------------------------

            info.hostnames = host.get("hostnames", [])
            info.country = host.get("country_name", "")
            info.city = host.get("city", "")
            info.org = host.get("org", "")
            info.isp = host.get("isp", "")
            info.open_ports = host.get("ports", [])
            info.tags = host.get("tags", [])
            info.last_update = host.get("last_update", "")

            # Extract CVE IDs from Shodan's vuln data
            vulns = host.get("vulns", {})
            info.vulns = sorted(vulns.keys()) if isinstance(vulns, dict) else []

            # Extract service banners (limit to first 10 to avoid huge output)
            banners = []
            for svc in host.get("data", [])[:10]:
                banners.append({
                    "port": svc.get("port"),
                    "transport": svc.get("transport", "tcp"),
                    "product": svc.get("product", ""),
                    "version": svc.get("version", ""),
                    "banner": (svc.get("data", "")[:200]),   # first 200 chars
                    "cpe": svc.get("cpe", []),
                })
            info.banners = banners

        except shodan.APIError as e:
            info.error = f"Shodan API error: {e}"
        except Exception as e:
            info.error = f"Shodan error: {e}"

        return info

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in RFC1918 private address space."""
        import ipaddress
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def search_cve(self, cve_id: str) -> dict:
        """
        Search Shodan's CVE database for details on a specific CVE.
        Returns dict with summary, cvss, references.
        """
        if not self._initialized:
            return {}
        try:
            return self._client.cve(cve_id)
        except Exception:
            return {}
