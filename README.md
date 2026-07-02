# ⚡ ReconScanner v2 — Network Recon & Vulnerability Scanner

> **Ethical Hacking & Penetration Testing Portfolio Project**  
> Nmap + Shodan API + NVD CVE Intelligence + Live Terminal Dashboard

---

## Architecture Overview

```
main.py / demo.py
      │
      ▼
orchestrator.py ─── ScanConfig
      │
      ├── scanner.py           (Nmap wrapper → ScanResult)
      ├── fingerprint.py       (Banner grab, HTTP probe, TLS inspect)
      ├── topology.py          (Subnet sweep, traceroute, DNS, WHOIS)
      ├── cve_engine.py        (NVD API + Shodan API)
      ├── analyzer.py          (Risk scoring, finding correlation)
      ├── exploit_suggester.py (Metasploit modules, ATT&CK mapping)
      ├── reporter.py          (Terminal Rich + HTML + JSON)
      └── dashboard.py         (Rich Live 6-panel real-time UI)
```

---

## Features

| Module | What It Does |
|---|---|
| **scanner.py** | Wraps python-nmap, runs SYN/version/script scans, parses XML |
| **fingerprint.py** | Deep service fingerprinting — banner grab, HTTP headers, TLS certs, cookie security |
| **topology.py** | Subnet host discovery, traceroute, DNS enumeration, WHOIS/ASN lookup |
| **cve_engine.py** | NVD REST API v2 CVE lookup by CPE/keyword + Shodan host intelligence |
| **analyzer.py** | Correlates findings → risk score 0–100, severity-graded findings |
| **exploit_suggester.py** | Maps findings to Metasploit modules, ExploitDB IDs, MITRE ATT&CK |
| **reporter.py** | Rich terminal output + standalone HTML report + JSON export |
| **dashboard.py** | 6-panel live terminal dashboard (Rich Live + Layout) |
| **orchestrator.py** | Wires all modules into one pipeline, feeds dashboard state |

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
sudo apt install nmap       # if not installed
```

### 2. Run the offline demo (no root/nmap/API keys needed)
```bash
python3 demo.py
```
This simulates a full scan against a realistic misconfigured server and opens an HTML report.

### 3. Real scan (requires root for SYN scan)
```bash
# Scan your own lab VM
sudo python3 main.py 192.168.1.100

# Full scan with all features
sudo python3 main.py 192.168.1.100 \
    --profile full \
    --shodan \
    --topo \
    --html \
    --json \
    --output-dir reports/

# Quick scan, no CVE lookup
sudo python3 main.py 192.168.1.100 --profile quick --no-cve

# Scan a hostname
sudo python3 main.py scanme.nmap.org --profile standard --html

# Multiple targets from file
sudo python3 main.py --targets targets.txt --profile standard --html
```

### 4. Set API keys
```bash
export SHODAN_API_KEY="your_key_here"   # free at shodan.io
export NVD_API_KEY="your_key_here"      # free at nvd.nist.gov/developers

# Or pass inline:
sudo python3 main.py 192.168.1.100 --shodan-key YOUR_KEY
```

---

## CLI Reference

```
usage: recon_scanner [-h] [--targets FILE] [--profile PROFILE]
                     [--shodan] [--topo] [--no-cve] [--no-fp]
                     [--no-exploit] [--html] [--json]
                     [--output-dir DIR] [--shodan-key KEY]
                     [--nvd-key KEY] [--quiet] [--no-dashboard]
                     [--list-profiles] [--check-tools]
                     [target]

Options:
  target                  Target IP address or hostname
  --targets FILE          File with targets (one per line)
  --profile/-p            Scan profile: quick|standard|full|udp|stealth
  --shodan/-s             Enable Shodan API intelligence
  --topo/-t               Enable network topology mapping
  --no-cve                Skip NVD CVE lookups (faster)
  --no-fp                 Skip service fingerprinting
  --no-exploit            Skip exploit suggestions
  --html                  Save HTML report
  --json                  Save JSON report
  --output-dir/-o DIR     Output directory (default: reports/)
  --shodan-key KEY        Shodan API key
  --nvd-key KEY           NVD API key
  --quiet/-q              Suppress terminal output
  --no-dashboard          Disable live dashboard UI
  --list-profiles         Show scan profiles
  --check-tools           Check nmap installation
```

---

## Scan Profiles

| Profile | Description | Ports | Speed |
|---|---|---|---|
| `quick` | Top 1000, no scripts | 1–1000 | Fast |
| `standard` | Version + scripts + OS detect | 1–1000 | Medium |
| `full` | All 65535 ports + scripts | 1–65535 | Slow |
| `udp` | UDP top 200 | 1–200 | Slow |
| `stealth` | Slow timing, IDS evasion | 1–1000 | Very slow |

---

## Core Technical Concepts

### How Nmap Integration Works
```python
import nmap
nm = nmap.PortScanner()

# Under the hood this runs:
# nmap -oX - -sS -sV -sC -O -T4 --open -p 1-1000 192.168.1.1
nm.scan(hosts="192.168.1.1", ports="1-1000", arguments="-sS -sV -sC -O -T4 --open", sudo=True)

# Access results
for port in nm["192.168.1.1"]["tcp"]:
    print(nm["192.168.1.1"]["tcp"][port])
    # {'state': 'open', 'name': 'http', 'product': 'Apache httpd',
    #  'version': '2.4.49', 'cpe': 'cpe:/a:apache:http_server:2.4.49'}
```

### How CVE Lookup Works
```python
# CPE (Common Platform Enumeration) from nmap → NVD API
# cpe:/a:apache:http_server:2.4.49 → query NVD → CVE-2021-41773 (CVSS 9.8)

import requests
resp = requests.get(
    "https://services.nvd.nist.gov/rest/json/cves/2.0",
    params={"cpeName": "cpe:/a:apache:http_server:2.4.49"}
)
vulns = resp.json()["vulnerabilities"]
```

### How Risk Scoring Works
```
CRITICAL finding → +25 pts (max 50)
HIGH finding     → +15 pts (max 45)
MEDIUM finding   → +8 pts  (max 24)
Each open port   → +2 pts  (max 20)
CVE CVSS ≥ 9.0   → +5 pts  (max 15)
─────────────────────────────────────
Score 0-9:   SECURE
Score 10-29: LOW
Score 30-54: MEDIUM
Score 55-74: HIGH
Score 75+:   CRITICAL
```

### MITRE ATT&CK Mapping
Each exploit suggestion maps to a MITRE ATT&CK technique:
- `T1190` — Exploit Public-Facing Application
- `T1210` — Exploitation of Remote Services
- `T1040` — Network Sniffing
- `T1078` — Valid Accounts
- `T1021` — Remote Services

---

## Output Files

### HTML Report
Self-contained, no CDN dependencies. Opens in any browser. Contains:
- Risk score gauge
- Severity-graded finding cards
- CVE reference table with CVSS scores
- Shodan intelligence panel
- Dark hacker aesthetic UI

### JSON Report
Machine-readable export for SIEM/ticketing integration:
```json
{
  "target": {"input": "192.168.1.100", "resolved_ip": "...", "os": "..."},
  "risk": {"score": 95, "label": "CRITICAL"},
  "findings": [
    {
      "severity": "CRITICAL",
      "port": 445,
      "service": "microsoft-ds",
      "title": "EternalBlue confirmed VULNERABLE",
      "cves": [{"id": "CVE-2017-0144", "cvss": 9.8}]
    }
  ]
}
```

---

## Project Structure

```
recon_scanner/
├── main.py                # CLI entry point
├── demo.py                # Offline demo (no root/nmap needed)
├── requirements.txt
├── reports/               # Output directory
└── core/
    ├── __init__.py
    ├── scanner.py          # Nmap wrapper
    ├── fingerprint.py      # Deep service fingerprinting
    ├── topology.py         # Network topology mapping
    ├── cve_engine.py       # NVD + Shodan API clients
    ├── analyzer.py         # Risk analysis engine
    ├── exploit_suggester.py # MSF/EDB/ATT&CK mapping
    ├── reporter.py         # Terminal + HTML + JSON output
    ├── dashboard.py        # Live terminal dashboard
    └── orchestrator.py     # Master pipeline controller
```

---

## Legal & Ethics

> **⚠️ AUTHORIZED USE ONLY**
>
> This tool is for educational purposes and authorized penetration testing only.
> Only scan systems you own or have explicit written permission to test.
> Unauthorized network scanning is illegal in most jurisdictions.
>
> Reference: [Computer Fraud and Abuse Act (CFAA)](https://www.justice.gov/jm/jm-9-48000-computer-fraud)

---

## API Keys (Free)

| Service | URL | Usage |
|---|---|---|
| Shodan | https://account.shodan.io | Free tier: 1 query/sec, 100 results |
| NVD | https://nvd.nist.gov/developers/request-an-api-key | Free: 50 req/30s |

Without keys: Shodan skipped, NVD rate-limited to 5 req/30s (still works, just slower).
