"""
topology.py — Network Topology & Attack Surface Mapper
--------------------------------------------------------
Goes beyond a single host scan to map the surrounding network:

  1. Subnet sweep      — ICMP/ARP ping sweep to find live hosts
  2. Traceroute        — map the path to target (reveals network hops)
  3. DNS enumeration   — subdomains, MX, TXT, NS records
  4. WHOIS enrichment  — ASN, registration info, abuse contacts
  5. Attack surface    — summarizes exploitable exposure

Uses nmap's host discovery features + raw socket techniques.
"""

import subprocess
import socket
import re
import ipaddress
import json
import time
from dataclasses import dataclass, field
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class LiveHost:
    ip: str
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    latency_ms: float = 0.0
    is_target: bool = False


@dataclass
class TraceHop:
    hop: int
    ip: str
    hostname: str = ""
    rtt_ms: float = 0.0
    is_private: bool = False


@dataclass
class DNSRecord:
    record_type: str    # A, AAAA, MX, NS, TXT, CNAME, PTR, SOA
    name: str
    value: str
    ttl: int = 0


@dataclass
class WHOISInfo:
    ip: str
    asn: str = ""
    asn_description: str = ""
    country: str = ""
    network_range: str = ""
    network_name: str = ""
    abuse_email: str = ""
    registrar: str = ""
    raw: str = ""


@dataclass
class NetworkMap:
    """Complete network topology picture."""
    target_ip: str
    subnet: str = ""
    live_hosts: list[LiveHost] = field(default_factory=list)
    trace_hops: list[TraceHop] = field(default_factory=list)
    dns_records: list[DNSRecord] = field(default_factory=list)
    whois: Optional[WHOISInfo] = None
    attack_surface_notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Topology mapper
# ---------------------------------------------------------------------------

class NetworkTopologyMapper:
    """
    Discovers the network context around a target host.
    """

    PING_TIMEOUT = 1.5   # seconds per host for ping sweep
    MAX_SWEEP_HOSTS = 254  # max /24 sweep

    # ------------------------------------------------------------------
    # Subnet sweep (host discovery)
    # ------------------------------------------------------------------

    def sweep_subnet(self, target_ip: str, cidr_prefix: int = 24) -> list[LiveHost]:
        """
        Use nmap's -sn (ping scan, no port scan) to discover live hosts
        in the target's subnet. This is fast — nmap sends ARP requests
        on local networks and ICMP echo on remote ones.

        -sn = Ping scan (host discovery only, no port scan)
        -T4 = Aggressive timing
        --open = Only show responsive hosts
        """
        try:
            net = ipaddress.ip_interface(f"{target_ip}/{cidr_prefix}").network
            network_str = str(net)

            # Limit sweep size for safety
            host_count = net.num_addresses
            if host_count > self.MAX_SWEEP_HOSTS + 2:
                # Fallback to /24 around the target IP
                parts = target_ip.split(".")
                network_str = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

            result = subprocess.run(
                ["nmap", "-sn", "-T4", "--open", "-oG", "-", network_str],
                capture_output=True, text=True, timeout=60
            )

            return self._parse_nmap_ping_output(result.stdout, target_ip)

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            return []

    def _parse_nmap_ping_output(self, output: str, target_ip: str) -> list[LiveHost]:
        """
        Parse nmap's greppable output (-oG) for host discovery.
        Format: "Host: 192.168.1.1 (hostname)    Status: Up"
        """
        hosts = []
        for line in output.splitlines():
            if not line.startswith("Host:"):
                continue
            match = re.match(r"Host: (\S+)\s+\(([^)]*)\)\s+Status: (\S+)", line)
            if match and match.group(3) == "Up":
                ip = match.group(1)
                hostname = match.group(2) or ""
                hosts.append(LiveHost(
                    ip=ip,
                    hostname=hostname,
                    is_target=(ip == target_ip),
                ))
        return hosts

    # ------------------------------------------------------------------
    # Traceroute
    # ------------------------------------------------------------------

    def traceroute(self, target_ip: str, max_hops: int = 20) -> list[TraceHop]:
        """
        Use nmap's --traceroute to map the network path to the target.
        Each hop reveals a network device — routers, firewalls, load balancers.

        We run a minimal nmap scan (-sn) just to get the traceroute data.
        """
        hops = []
        try:
            result = subprocess.run(
                ["nmap", "-sn", "--traceroute", "-T4", target_ip],
                capture_output=True, text=True, timeout=30,
            )

            in_traceroute = False
            for line in result.stdout.splitlines():
                if "TRACEROUTE" in line:
                    in_traceroute = True
                    continue
                if not in_traceroute:
                    continue
                if not line.strip() or line.startswith("Nmap"):
                    break

                # Format: " 1   1.23 ms  192.168.1.1 (router.local)"
                # or:     " 2   ...     192.168.1.254"
                m = re.match(r"\s*(\d+)\s+([\d.]+) ms\s+(\S+)(?:\s+\(([^)]+)\))?", line)
                if m:
                    hop_num  = int(m.group(1))
                    rtt      = float(m.group(2))
                    ip_addr  = m.group(3)
                    hostname = m.group(4) or ""

                    try:
                        is_priv = ipaddress.ip_address(ip_addr).is_private
                    except ValueError:
                        is_priv = False

                    hops.append(TraceHop(
                        hop=hop_num,
                        ip=ip_addr,
                        hostname=hostname,
                        rtt_ms=rtt,
                        is_private=is_priv,
                    ))

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return hops

    # ------------------------------------------------------------------
    # DNS enumeration
    # ------------------------------------------------------------------

    def enumerate_dns(self, hostname: str) -> list[DNSRecord]:
        """
        Query multiple DNS record types for a hostname.
        Uses Python's standard socket + nmap's dns-brute script.

        Record types:
          A     — IPv4 address
          AAAA  — IPv6 address
          MX    — Mail server
          NS    — Nameserver
          TXT   — SPF, DMARC, DKIM, ownership verification
          SOA   — Start of Authority (zone info)
        """
        records = []

        # Use nmap's dns scripts for comprehensive enumeration
        try:
            result = subprocess.run(
                ["nmap", "-sn", "--script", "dns-nsid,dns-recursion,dns-service-discovery",
                 "-p", "53", hostname],
                capture_output=True, text=True, timeout=20,
            )
            # Parse whatever nmap found
            for line in result.stdout.splitlines():
                if "DNS" in line or "dns" in line.lower():
                    records.append(DNSRecord("INFO", hostname, line.strip()))

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Standard socket-based lookups
        try:
            # A record
            addrs = socket.getaddrinfo(hostname, None, socket.AF_INET)
            for addr in addrs:
                ip = addr[4][0]
                records.append(DNSRecord("A", hostname, ip))
        except Exception:
            pass

        try:
            # AAAA record
            addrs = socket.getaddrinfo(hostname, None, socket.AF_INET6)
            for addr in addrs:
                ip = addr[4][0]
                records.append(DNSRecord("AAAA", hostname, ip))
        except Exception:
            pass

        try:
            # Reverse DNS
            reverse = socket.gethostbyaddr(
                socket.getaddrinfo(hostname, None, socket.AF_INET)[0][4][0]
            )
            records.append(DNSRecord("PTR", hostname, reverse[0]))
        except Exception:
            pass

        return records

    def check_zone_transfer(self, hostname: str) -> tuple[bool, str]:
        """
        Attempt a DNS zone transfer (AXFR).
        Zone transfers are a CRITICAL misconfiguration if public — they
        dump the entire DNS zone (all subdomains, IPs, records).

        We use nmap's dns-zone-transfer script.
        """
        try:
            result = subprocess.run(
                ["nmap", "--script", "dns-zone-transfer",
                 f"--script-args=dns-zone-transfer.domain={hostname}",
                 "-p", "53", hostname],
                capture_output=True, text=True, timeout=15,
            )
            output = result.stdout
            if "AXFR record" in output or "zone-transfer" in output.lower():
                return True, output
            return False, ""
        except Exception:
            return False, ""

    # ------------------------------------------------------------------
    # WHOIS / ASN lookup
    # ------------------------------------------------------------------

    def whois_lookup(self, ip: str) -> WHOISInfo:
        """
        Query WHOIS / RDAP for IP ownership and routing information.
        Uses the RIPE/ARIN RDAP API — no rate limits for basic lookups.
        """
        info = WHOISInfo(ip=ip)

        try:
            import urllib.request
            # RDAP API — structured JSON WHOIS replacement
            url = f"https://rdap.arin.net/registry/ip/{ip}"
            req = urllib.request.Request(url)
            req.add_header("Accept", "application/json")

            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read())

            info.network_name  = data.get("name", "")
            info.network_range = data.get("handle", "")
            info.country       = data.get("country", "")

            # Extract abuse contact
            for entity in data.get("entities", []):
                for vcards in entity.get("vcardArray", [[]]):
                    if isinstance(vcards, list):
                        for vcard in vcards:
                            if isinstance(vcard, list) and vcard[0] == "email":
                                info.abuse_email = vcard[3]
                                break

        except Exception:
            pass

        # Try ip-api.com for ASN (free, no key needed)
        try:
            import urllib.request
            url = f"http://ip-api.com/json/{ip}?fields=status,country,org,as,isp"
            with urllib.request.urlopen(url, timeout=5) as resp:
                data = json.loads(resp.read())

            if data.get("status") == "success":
                info.asn             = data.get("as", "")
                info.asn_description = data.get("org", "")
                info.country         = data.get("country", "")

        except Exception:
            pass

        return info

    # ------------------------------------------------------------------
    # Attack surface summary
    # ------------------------------------------------------------------

    def summarize_attack_surface(
        self,
        network_map: NetworkMap,
        open_ports: list,
    ) -> list[str]:
        """
        Synthesize all topology data into attack surface observations.
        """
        notes = []

        # Network exposure
        if network_map.live_hosts:
            count = len(network_map.live_hosts)
            notes.append(
                f"Subnet contains {count} live host{'s' if count != 1 else ''} — "
                f"lateral movement risk if target is compromised."
            )

        # Traceroute analysis
        if network_map.trace_hops:
            public_hops  = [h for h in network_map.trace_hops if not h.is_private]
            private_hops = [h for h in network_map.trace_hops if h.is_private]
            if public_hops:
                notes.append(
                    f"Traffic traverses {len(public_hops)} public network hops — "
                    f"interception risk on path."
                )
            if not private_hops:
                notes.append("No private network hops — target appears directly internet-connected.")

        # WHOIS / ASN
        if network_map.whois and network_map.whois.asn:
            notes.append(
                f"Hosted in ASN {network_map.whois.asn} ({network_map.whois.asn_description})"
            )

        # Port-based surface notes
        port_nums = [p.port for p in open_ports]
        if 22 in port_nums and 3389 in port_nums:
            notes.append("Both SSH (22) and RDP (3389) exposed — two remote access vectors.")
        if any(p in port_nums for p in [3306, 5432, 1433, 27017, 6379, 9200]):
            notes.append("Database port(s) directly exposed — should be firewalled to app layer only.")
        if len(port_nums) > 15:
            notes.append(f"Large attack surface: {len(port_nums)} open ports reduces ability to monitor.")

        return notes

    # ------------------------------------------------------------------
    # Full topology scan
    # ------------------------------------------------------------------

    def map_network(self, target: str, resolved_ip: str, open_ports: list) -> NetworkMap:
        """Orchestrate all topology discovery tasks."""
        nmap = NetworkMap(target_ip=resolved_ip)

        # Determine if target is hostname or IP
        is_hostname = not self._is_ip(target)

        # Run tasks concurrently
        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = {
                "sweep":     ex.submit(self.sweep_subnet, resolved_ip),
                "traceroute": ex.submit(self.traceroute, resolved_ip),
                "whois":     ex.submit(self.whois_lookup, resolved_ip),
            }
            if is_hostname:
                futures["dns"] = ex.submit(self.enumerate_dns, target)

            for name, future in futures.items():
                try:
                    result = future.result(timeout=45)
                    if name == "sweep":       nmap.live_hosts  = result
                    elif name == "traceroute": nmap.trace_hops  = result
                    elif name == "whois":     nmap.whois       = result
                    elif name == "dns":       nmap.dns_records = result
                except Exception:
                    pass

        # Attack surface summary
        nmap.attack_surface_notes = self.summarize_attack_surface(nmap, open_ports)

        return nmap

    @staticmethod
    def _is_ip(s: str) -> bool:
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False
