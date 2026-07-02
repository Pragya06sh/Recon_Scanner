"""
fingerprint.py — Deep Service & Technology Fingerprinting
----------------------------------------------------------
Goes beyond nmap's basic version detection to build a complete
picture of what's running on each open port.

Techniques used:
  1. Banner grabbing   — raw TCP/UDP connects to read service banners
  2. HTTP probing      — GET requests to detect web server, frameworks, CMS
  3. TLS inspection    — cipher suites, certificate info, TLS version
  4. Header analysis   — HTTP security headers scoring
  5. Tech stack heuristics — fingerprint frameworks from response patterns

This module is entirely PASSIVE from the target's perspective
(it only reads what the service sends back — no exploitation).
"""

import socket
import ssl
import time
import re
import threading
from dataclasses import dataclass, field
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError


# ---------------------------------------------------------------------------
# Fingerprint data structures
# ---------------------------------------------------------------------------

@dataclass
class BannerGrab:
    port: int
    protocol: str
    raw_banner: str
    cleaned: str
    software: str        # e.g. "OpenSSH 8.9p1"
    version_string: str
    extra: dict = field(default_factory=dict)


@dataclass
class TLSInfo:
    port: int
    tls_version: str          # "TLSv1.3", "TLSv1.2", etc.
    cipher_suite: str
    cert_subject: str
    cert_issuer: str
    cert_expiry: str
    cert_san: list[str]       # Subject Alternative Names
    is_self_signed: bool
    supports_tls10: bool = False   # dangerous — old protocol
    supports_tls11: bool = False   # deprecated
    supports_tls12: bool = False
    supports_tls13: bool = False
    vulnerabilities: list[str] = field(default_factory=list)


@dataclass
class HTTPFingerprint:
    port: int
    server_header: str
    powered_by: str
    framework: str
    cms: str
    status_code: int
    redirect_to: str
    title: str
    security_headers: dict = field(default_factory=dict)
    security_score: int = 0      # 0-100 based on present security headers
    technologies: list[str] = field(default_factory=list)
    cookies: list[dict] = field(default_factory=list)


@dataclass
class TargetFingerprint:
    """Complete fingerprint for a host."""
    ip: str
    banners: list[BannerGrab] = field(default_factory=list)
    tls_info: list[TLSInfo] = field(default_factory=list)
    http_info: list[HTTPFingerprint] = field(default_factory=list)
    open_ports_confirmed: list[int] = field(default_factory=list)
    tech_stack: list[str] = field(default_factory=list)
    interesting_findings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# HTTP security headers we care about
# ---------------------------------------------------------------------------

SECURITY_HEADERS = {
    "strict-transport-security":         ("HSTS — prevents protocol downgrade attacks", 15),
    "content-security-policy":           ("CSP — prevents XSS and injection attacks", 20),
    "x-frame-options":                   ("Clickjacking protection", 10),
    "x-content-type-options":            ("MIME-type sniffing prevention", 10),
    "x-xss-protection":                  ("Legacy XSS filter header", 5),
    "referrer-policy":                   ("Controls referrer information leakage", 10),
    "permissions-policy":                ("Controls browser feature access", 10),
    "cross-origin-opener-policy":        ("Isolation from cross-origin windows", 5),
    "cross-origin-resource-policy":      ("Prevents cross-origin resource loading", 5),
    "cross-origin-embedder-policy":      ("Prevents embedding of cross-origin resources", 5),
    "cache-control":                     ("Cache control — prevents sensitive data caching", 5),
}

DANGEROUS_HEADERS = {
    "server":                "Discloses server software — set to generic value",
    "x-powered-by":          "Discloses backend technology — remove this header",
    "x-aspnet-version":      "Discloses .NET version — remove this header",
    "x-aspnetmvc-version":   "Discloses MVC version — remove this header",
}

# Technology fingerprints: (header_name, regex_pattern, tech_label)
TECH_PATTERNS = [
    ("server",          r"nginx",               "Nginx"),
    ("server",          r"apache",              "Apache"),
    ("server",          r"iis",                 "Microsoft IIS"),
    ("server",          r"lighttpd",            "Lighttpd"),
    ("server",          r"caddy",               "Caddy"),
    ("x-powered-by",    r"php/([\d.]+)",        "PHP"),
    ("x-powered-by",    r"asp\.net",            "ASP.NET"),
    ("x-powered-by",    r"express",             "Node.js/Express"),
    ("x-generator",     r"wordpress",           "WordPress"),
    ("x-generator",     r"drupal",              "Drupal"),
    ("set-cookie",      r"wp-settings",         "WordPress"),
    ("set-cookie",      r"laravel_session",     "Laravel"),
    ("set-cookie",      r"django",              "Django"),
    ("set-cookie",      r"phpsessid",           "PHP"),
    ("set-cookie",      r"jsessionid",          "Java/Tomcat"),
    ("set-cookie",      r"aspsessionid",        "ASP Classic"),
    ("via",             r"cloudflare",          "Cloudflare CDN"),
    ("cf-ray",          r".",                   "Cloudflare"),
    ("x-varnish",       r".",                   "Varnish Cache"),
    ("x-cache",         r".",                   "Caching Layer"),
]


# ---------------------------------------------------------------------------
# Fingerprinter class
# ---------------------------------------------------------------------------

class ServiceFingerprinter:
    """
    Performs deep fingerprinting of services found by nmap.
    Uses concurrent threads for speed.
    """

    CONNECT_TIMEOUT = 5     # seconds for TCP connections
    BANNER_WAIT     = 3     # seconds to wait for banner data
    MAX_WORKERS     = 10    # concurrent fingerprint threads

    def __init__(self):
        self._lock = threading.Lock()

    def fingerprint_host(self, ip: str, ports: list) -> TargetFingerprint:
        """
        Main entry point. Fingerprints all given ports concurrently.
        """
        result = TargetFingerprint(ip=ip)

        # Separate HTTP/HTTPS ports from others
        http_ports   = [p for p in ports if p.port in (80, 8080, 8000, 8888, 3000, 5000)]
        https_ports  = [p for p in ports if p.port in (443, 8443, 4443, 9443)]
        other_ports  = [p for p in ports if p.port not in
                        {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 4443, 9443}]

        tasks = []
        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as executor:
            # HTTP probing
            for p in http_ports:
                tasks.append(executor.submit(self._probe_http, ip, p.port, False))
            for p in https_ports:
                tasks.append(executor.submit(self._probe_http, ip, p.port, True))
                tasks.append(executor.submit(self._probe_tls, ip, p.port))

            # Banner grabbing for everything else
            for p in other_ports:
                tasks.append(executor.submit(self._grab_banner, ip, p.port, p.protocol))

            for future in as_completed(tasks, timeout=60):
                try:
                    res = future.result(timeout=10)
                    if res is None:
                        continue
                    if isinstance(res, HTTPFingerprint):
                        result.http_info.append(res)
                        result.tech_stack.extend(res.technologies)
                    elif isinstance(res, TLSInfo):
                        result.tls_info.append(res)
                        result.vulnerabilities_from_tls(res, result)
                    elif isinstance(res, BannerGrab):
                        result.banners.append(res)
                except Exception:
                    pass

        # Deduplicate tech stack
        result.tech_stack = list(dict.fromkeys(result.tech_stack))

        # Add TLS findings to interesting findings
        for tls in result.tls_info:
            for vuln in tls.vulnerabilities:
                result.interesting_findings.append(f"Port {tls.port}: {vuln}")

        # HTTP security header findings
        for http in result.http_info:
            if http.security_score < 40:
                result.interesting_findings.append(
                    f"Port {http.port}: Poor HTTP security headers (score: {http.security_score}/100)"
                )

        return result

    # ------------------------------------------------------------------
    # Banner grabbing
    # ------------------------------------------------------------------

    def _grab_banner(self, ip: str, port: int, proto: str = "tcp") -> Optional[BannerGrab]:
        """
        Connect to a port and read whatever the service sends first.
        Many services (SSH, FTP, SMTP, POP3, IMAP) immediately send an
        identifying banner when you connect.
        """
        if proto == "udp":
            return None  # UDP banners need protocol-specific probes

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.CONNECT_TIMEOUT)
            sock.connect((ip, port))
            sock.settimeout(self.BANNER_WAIT)

            # For some services, we need to send a probe to get a response
            probes = {
                80:    b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n",
                25:    b"EHLO recon.scanner\r\n",
                110:   b"",    # POP3 sends banner immediately
                143:   b"",    # IMAP sends banner immediately
                21:    b"",    # FTP sends banner immediately
                22:    b"",    # SSH sends banner immediately
                23:    b"",    # Telnet sends banner immediately
            }

            probe = probes.get(port, b"")
            if probe:
                sock.sendall(probe)

            data = b""
            try:
                while len(data) < 4096:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                    # Most banners end with \n
                    if b"\n" in data:
                        break
            except socket.timeout:
                pass

            sock.close()

            if not data:
                return None

            raw = data.decode("utf-8", errors="replace").strip()
            cleaned = raw[:500]   # first 500 chars

            # Extract software/version from common banner formats
            software, version = self._parse_banner(port, cleaned)

            return BannerGrab(
                port=port,
                protocol="tcp",
                raw_banner=raw,
                cleaned=cleaned,
                software=software,
                version_string=version,
            )

        except (ConnectionRefusedError, socket.timeout, OSError):
            return None

    def _parse_banner(self, port: int, banner: str) -> tuple[str, str]:
        """Extract software name and version from a banner string."""
        patterns = [
            # SSH: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
            (r"SSH-[\d.]+-(\S+)", "SSH"),
            # FTP: "220 vsftpd 3.0.5"
            (r"220[- ](.+?)\r?\n", "FTP"),
            # SMTP: "220 mail.example.com ESMTP Postfix"
            (r"220 \S+ ESMTP (\S+)", "SMTP"),
            # HTTP Server header
            (r"Server: ([^\r\n]+)", "HTTP"),
            # Generic version pattern
            (r"([\w.-]+)/([\d.]+)", None),
        ]

        for pattern, svc in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                full = match.group(1).strip()
                # Try to split "Product Version"
                parts = full.split()
                if len(parts) >= 2:
                    return parts[0], parts[1]
                return full, ""

        return "unknown", ""

    # ------------------------------------------------------------------
    # HTTP/HTTPS probing
    # ------------------------------------------------------------------

    def _probe_http(self, ip: str, port: int, use_tls: bool) -> Optional[HTTPFingerprint]:
        """
        Make an HTTP(S) GET request and analyze the response.
        Uses raw sockets to get full header access without abstraction.
        """
        scheme = "https" if use_tls else "http"

        try:
            import urllib.request
            import urllib.error

            url = f"{scheme}://{ip}:{port}/"

            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Mozilla/5.0 ReconScanner/1.0")

            # Create SSL context that doesn't verify certs (we're fingerprinting)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            try:
                with urllib.request.urlopen(req, timeout=8, context=ctx if use_tls else None) as resp:
                    headers = dict(resp.headers)
                    status  = resp.status
                    body    = resp.read(8192).decode("utf-8", errors="replace")
                    final_url = resp.url

            except urllib.error.HTTPError as e:
                headers  = dict(e.headers)
                status   = e.code
                body     = ""
                final_url = url

            fp = HTTPFingerprint(
                port=port,
                server_header=headers.get("Server", headers.get("server", "")),
                powered_by=headers.get("X-Powered-By", headers.get("x-powered-by", "")),
                framework="",
                cms="",
                status_code=status,
                redirect_to=headers.get("Location", "") if status in (301, 302, 303, 307, 308) else "",
                title=self._extract_title(body),
            )

            # Security headers analysis
            fp.security_headers = self._analyze_security_headers(headers)
            fp.security_score   = self._score_security_headers(headers)

            # Technology detection
            fp.technologies = self._detect_technologies(headers, body)

            # Cookie analysis
            fp.cookies = self._analyze_cookies(headers)

            return fp

        except Exception:
            return None

    def _extract_title(self, html: str) -> str:
        match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
        return match.group(1).strip()[:100] if match else ""

    def _analyze_security_headers(self, headers: dict) -> dict:
        """Check which security headers are present/missing."""
        lower_headers = {k.lower(): v for k, v in headers.items()}
        result = {}

        for header, (desc, _) in SECURITY_HEADERS.items():
            present = header in lower_headers
            result[header] = {
                "present": present,
                "value": lower_headers.get(header, ""),
                "description": desc,
            }

        # Flag dangerous disclosure headers
        for header, concern in DANGEROUS_HEADERS.items():
            if header in lower_headers:
                result[f"WARN_{header}"] = {
                    "present": True,
                    "value": lower_headers[header],
                    "description": f"⚠ {concern}",
                }

        return result

    def _score_security_headers(self, headers: dict) -> int:
        """Score 0-100 based on security headers present."""
        lower = {k.lower() for k in headers.keys()}
        score = 0
        for header, (_, pts) in SECURITY_HEADERS.items():
            if header in lower:
                score += pts
        return min(score, 100)

    def _detect_technologies(self, headers: dict, body: str) -> list[str]:
        """Detect tech stack from headers and HTML body."""
        techs = set()
        lower_headers = {k.lower(): v.lower() for k, v in headers.items()}

        for hdr, pattern, tech in TECH_PATTERNS:
            val = lower_headers.get(hdr, "")
            if re.search(pattern, val, re.IGNORECASE):
                techs.add(tech)

        # Body-based detection
        body_patterns = [
            (r"wp-content|wordpress",         "WordPress"),
            (r"joomla",                        "Joomla"),
            (r"drupal\.settings",              "Drupal"),
            (r"react|__NEXT_DATA__",           "React/Next.js"),
            (r"ng-version|angular",            "Angular"),
            (r"__vue",                         "Vue.js"),
            (r"laravel_token",                 "Laravel"),
            (r"django|csrfmiddlewaretoken",    "Django"),
            (r"ruby on rails|rails",           "Ruby on Rails"),
            (r"jsf\.|javax\.faces",            "JavaServer Faces"),
            (r"wp-json",                       "WordPress REST API"),
            (r"graphql",                       "GraphQL"),
        ]

        for pattern, tech in body_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                techs.add(tech)

        return list(techs)

    def _analyze_cookies(self, headers: dict) -> list[dict]:
        """Parse Set-Cookie headers and flag missing security attributes."""
        cookies = []
        lower = {k.lower(): v for k, v in headers.items()}
        raw = lower.get("set-cookie", "")
        if not raw:
            return cookies

        # Each Set-Cookie is one header (urllib merges them with comma — imperfect)
        for cookie_str in raw.split(","):
            name = cookie_str.split("=")[0].strip() if "=" in cookie_str else cookie_str
            cookie = {
                "name": name,
                "has_httponly": "httponly" in cookie_str.lower(),
                "has_secure":   "secure"   in cookie_str.lower(),
                "has_samesite": "samesite" in cookie_str.lower(),
                "issues": [],
            }
            if not cookie["has_httponly"]:
                cookie["issues"].append("Missing HttpOnly — accessible to JavaScript")
            if not cookie["has_secure"]:
                cookie["issues"].append("Missing Secure — can be sent over HTTP")
            if not cookie["has_samesite"]:
                cookie["issues"].append("Missing SameSite — CSRF risk")
            cookies.append(cookie)

        return cookies

    # ------------------------------------------------------------------
    # TLS inspection
    # ------------------------------------------------------------------

    def _probe_tls(self, ip: str, port: int) -> Optional[TLSInfo]:
        """
        Connect with TLS and inspect the negotiated parameters.
        Checks: TLS version, cipher suite, certificate details.
        """
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # Request as high a TLS version as available
            ctx.minimum_version = ssl.TLSVersion.TLSv1

            with socket.create_connection((ip, port), timeout=self.CONNECT_TIMEOUT) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=ip) as tls_sock:
                    # Get negotiated TLS version and cipher
                    tls_version = tls_sock.version() or "unknown"
                    cipher      = tls_sock.cipher()
                    cipher_name = cipher[0] if cipher else "unknown"

                    # Get certificate
                    der_cert  = tls_sock.getpeercert(binary_form=True)
                    cert_dict = tls_sock.getpeercert()

            # Parse certificate info
            subject = self._parse_cert_field(cert_dict.get("subject", []))
            issuer  = self._parse_cert_field(cert_dict.get("issuer", []))
            expiry  = cert_dict.get("notAfter", "")
            san     = [v for _type, v in cert_dict.get("subjectAltName", [])]

            is_self_signed = (subject == issuer)

            tls_info = TLSInfo(
                port=port,
                tls_version=tls_version,
                cipher_suite=cipher_name,
                cert_subject=subject,
                cert_issuer=issuer,
                cert_expiry=expiry,
                cert_san=san[:10],
                is_self_signed=is_self_signed,
                supports_tls12=tls_version in ("TLSv1.2",),
                supports_tls13=tls_version in ("TLSv1.3",),
            )

            # Flag vulnerabilities
            vulns = []
            if tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                vulns.append(f"Outdated TLS version: {tls_version} (deprecated/insecure)")
            if is_self_signed:
                vulns.append("Self-signed certificate — browsers will show security warning")
            if "RC4" in cipher_name:
                vulns.append("RC4 cipher suite detected — cryptographically broken")
            if "NULL" in cipher_name:
                vulns.append("NULL cipher — no encryption")
            if "EXPORT" in cipher_name:
                vulns.append("EXPORT-grade cipher — weak (FREAK vulnerability)")
            if "DES" in cipher_name and "3DES" not in cipher_name:
                vulns.append("DES cipher — 56-bit key, cryptographically broken")
            if "3DES" in cipher_name or "DES-CBC3" in cipher_name:
                vulns.append("3DES (SWEET32 attack) — deprecated, should use AES")
            if not cipher_name.startswith("TLS_") and "ECDHE" not in cipher_name and "DHE" not in cipher_name:
                vulns.append("Cipher suite lacks forward secrecy (PFS)")

            tls_info.vulnerabilities = vulns
            return tls_info

        except Exception:
            return None

    def _parse_cert_field(self, rdns: list) -> str:
        """Convert certificate RDN list to a readable string."""
        parts = []
        for rdn in rdns:
            for key, val in rdn:
                parts.append(f"{key}={val}")
        return ", ".join(parts)


# Monkey-patch TargetFingerprint to add TLS vulnerability helper
def _vulnerabilities_from_tls(self, tls: TLSInfo, result: "TargetFingerprint"):
    for v in tls.vulnerabilities:
        self.interesting_findings.append(f"TLS port {tls.port}: {v}")

TargetFingerprint.vulnerabilities_from_tls = _vulnerabilities_from_tls
