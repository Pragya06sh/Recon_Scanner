#!/usr/bin/env python3
"""
main.py — ReconScanner v2 — Full CLI Entry Point
-------------------------------------------------
Usage:
  sudo python3 main.py 127.0.0.1
  sudo python3 main.py 192.168.1.1 --profile full --shodan --html --topo
  sudo python3 main.py scanme.nmap.org --profile quick --no-cve
  sudo python3 main.py --targets targets.txt --profile standard --html
  python3 main.py --list-profiles
"""

import argparse, os, sys, time, ipaddress, re
from pathlib import Path
from rich.console import Console
from rich.table   import Table
from rich         import box

sys.path.insert(0, str(Path(__file__).parent))

from core import (
    ScanOrchestrator, ScanConfig, DashboardState, LiveDashboard,
    TerminalReporter, SCAN_PROFILES,
)

console = Console()


# ── Arg parser ─────────────────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="recon_scanner",
        description="⚡ ReconScanner v2 — Network Recon & Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 main.py 127.0.0.1
  sudo python3 main.py 192.168.1.1 --profile full --shodan --html --topo
  sudo python3 main.py scanme.nmap.org --profile quick --no-cve
  sudo python3 main.py --targets targets.txt --html --json
  python3 main.py --list-profiles
        """
    )

    tg = p.add_mutually_exclusive_group()
    tg.add_argument("target",    nargs="?",       help="Target IP or hostname")
    tg.add_argument("--targets", metavar="FILE",  help="File of targets (one per line)")

    p.add_argument("--profile",  "-p", choices=list(SCAN_PROFILES.keys()), default="standard")
    p.add_argument("--shodan",   "-s", action="store_true", help="Enable Shodan API lookup")
    p.add_argument("--topo",     "-t", action="store_true", help="Enable network topology mapping")
    p.add_argument("--no-cve",         action="store_true", help="Skip CVE lookups (faster)")
    p.add_argument("--no-fp",          action="store_true", help="Skip service fingerprinting")
    p.add_argument("--no-exploit",     action="store_true", help="Skip exploit suggestions")
    p.add_argument("--html",           action="store_true", help="Save HTML report")
    p.add_argument("--json",           action="store_true", help="Save JSON report")
    p.add_argument("--output-dir", "-o", default="reports")
    p.add_argument("--shodan-key",     metavar="KEY")
    p.add_argument("--nvd-key",        metavar="KEY")
    p.add_argument("--quiet",    "-q", action="store_true", help="No terminal output")
    p.add_argument("--no-dashboard",   action="store_true", help="Disable live dashboard")
    p.add_argument("--list-profiles",  action="store_true")
    p.add_argument("--check-tools",    action="store_true")
    return p


# ── Helpers ─────────────────────────────────────────────────────────────────

def validate_target(t):
    t = t.strip()
    try:
        addr = ipaddress.ip_address(t)
        if addr.is_loopback:  return True, "localhost"
        if addr.is_private:   return True, "private LAN"
        return True, "public IP"
    except ValueError:
        pass
    if re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', t):
        return True, "hostname"
    return False, f"'{t}' is not a valid IP or hostname"


def check_root():
    import platform
    if platform.system() == "Windows":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            console.print("[yellow]⚠  Not running as Administrator.[/yellow]")
            console.print("   Right-click VS Code → 'Run as administrator' for full SYN scans.\n")
    else:
        if os.geteuid() != 0:
            console.print("[yellow]⚠  Not root — SYN scans need sudo for raw sockets.[/yellow]")
            console.print("   Run: [bold]sudo python3 main.py ...[/bold]\n")


def print_exploit_suggestions(results, target_ip):
    suggestions = results.get("suggestions", [])
    if not suggestions:
        return
    console.print()
    console.rule("[bold red]EXPLOIT SUGGESTIONS (AUTHORIZED USE ONLY)[/bold red]")
    console.print()

    from core.exploit_suggester import ExploitSuggester
    exp = ExploitSuggester()
    plan = exp.generate_pentest_plan(suggestions, target_ip)
    console.print(plan, style="dim")


def print_topology(results):
    topo = results.get("topology")
    if not topo:
        return
    console.print()
    console.rule("[bold cyan]NETWORK TOPOLOGY[/bold cyan]")

    if topo.live_hosts:
        console.print(f"\n[cyan]Subnet live hosts ({len(topo.live_hosts)}):[/cyan]")
        for h in topo.live_hosts[:10]:
            flag = " [bold yellow]← TARGET[/bold yellow]" if h.is_target else ""
            console.print(f"  {h.ip:<18} {h.hostname or ''}{flag}")

    if topo.trace_hops:
        console.print(f"\n[cyan]Traceroute ({len(topo.trace_hops)} hops):[/cyan]")
        for hop in topo.trace_hops:
            priv = "[dim](private)[/dim]" if hop.is_private else ""
            console.print(f"  {hop.hop:>2}.  {hop.ip:<18} {hop.rtt_ms:.1f}ms  {priv}")

    if topo.whois and topo.whois.asn:
        w = topo.whois
        console.print(f"\n[cyan]WHOIS:[/cyan] {w.asn}  {w.asn_description}  {w.country}")

    if topo.attack_surface_notes:
        console.print("\n[cyan]Attack surface observations:[/cyan]")
        for note in topo.attack_surface_notes:
            console.print(f"  • {note}")


def print_fingerprint(results):
    fp = results.get("fingerprint")
    if not fp:
        return
    console.print()
    console.rule("[bold cyan]SERVICE FINGERPRINTS[/bold cyan]")

    if fp.tech_stack:
        console.print(f"\n[cyan]Tech stack:[/cyan] {', '.join(fp.tech_stack)}")

    for http in fp.http_info:
        score = http.security_score
        color = "green" if score >= 70 else ("yellow" if score >= 40 else "red")
        console.print(f"\n[cyan]HTTP port {http.port}:[/cyan]  "
                      f"[{color}]Security headers: {score}/100[/{color}]  "
                      f"Status: {http.status_code}")
        if http.server_header:
            console.print(f"  Server: [dim]{http.server_header}[/dim]")
        if http.title:
            console.print(f"  Title: [dim]{http.title}[/dim]")
        if http.technologies:
            console.print(f"  Technologies: {', '.join(http.technologies)}")
        # Flag poor cookie security
        for cookie in http.cookies:
            if cookie["issues"]:
                console.print(f"  Cookie [{cookie['name']}]: [yellow]{'; '.join(cookie['issues'][:2])}[/yellow]")

    for tls in fp.tls_info:
        color = "green" if not tls.vulnerabilities else "red"
        console.print(f"\n[cyan]TLS port {tls.port}:[/cyan]  [{color}]{tls.tls_version}[/{color}]  "
                      f"Cipher: [dim]{tls.cipher_suite}[/dim]")
        if tls.cert_subject:
            console.print(f"  Cert: [dim]{tls.cert_subject[:60]}[/dim]")
        if tls.is_self_signed:
            console.print("  [yellow]⚠  Self-signed certificate[/yellow]")
        for v in tls.vulnerabilities:
            console.print(f"  [red]✗  {v}[/red]")

    if fp.interesting_findings:
        console.print("\n[cyan]Interesting findings:[/cyan]")
        for note in fp.interesting_findings[:10]:
            console.print(f"  [yellow]•[/yellow] {note}")


# ── Single target scan ───────────────────────────────────────────────────────

def run_scan(target, args):
    valid, msg = validate_target(target)
    if not valid:
        console.print(f"[red]✗ {msg}[/red]")
        return None

    if not args.quiet:
        console.print(f"\n[bold cyan]Target:[/bold cyan] {target}  [dim]({msg})[/dim]")

    if args.shodan_key:
        os.environ["SHODAN_API_KEY"] = args.shodan_key
    if args.nvd_key:
        os.environ["NVD_API_KEY"] = args.nvd_key

    cfg = ScanConfig(
        target            = target,
        profile           = args.profile,
        use_shodan        = args.shodan,
        fetch_cves        = not args.no_cve,
        do_fingerprint    = not args.no_fp,
        do_topology       = args.topo,
        do_exploit_suggest= not args.no_exploit,
        output_dir        = args.output_dir,
        save_html         = args.html,
        save_json         = args.json,
    )

    # ── With live dashboard ───────────────────────────────────────────
    if not args.quiet and not args.no_dashboard:
        state = DashboardState(target=target, start_time=time.time())
        dash  = LiveDashboard(state)

        orchestrator = ScanOrchestrator(cfg)
        results = dash.run(orchestrator.run)

    # ── Quiet / no-dashboard mode ─────────────────────────────────────
    else:
        orchestrator = ScanOrchestrator(cfg)
        results = orchestrator.run()

    if not results:
        console.print("[red]Scan returned no results.[/red]")
        return None

    # ── Post-scan output ──────────────────────────────────────────────
    if not args.quiet:
        report = results.get("report")
        if report:
            TerminalReporter().print_report(report)

        print_fingerprint(results)
        print_topology(results)

        if not args.no_exploit:
            print_exploit_suggestions(results, report.resolved_ip if report else target)

        if results.get("saved_files"):
            console.print()
            for f in results["saved_files"]:
                console.print(f"[green]✓[/green] Saved: [bold]{f}[/bold]")

        if results.get("errors"):
            console.print()
            for err in results["errors"]:
                console.print(f"[dim yellow]⚠  {err}[/dim yellow]")

    return results


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args   = parser.parse_args()

    if args.list_profiles:
        t = Table(box=box.SIMPLE_HEAVY, title="Scan Profiles")
        t.add_column("Name",        style="bold cyan")
        t.add_column("Description")
        t.add_column("Ports",       style="dim")
        t.add_column("Nmap flags",  style="dim")
        for name, cfg in SCAN_PROFILES.items():
            t.add_row(name, cfg["description"], cfg["ports"], cfg["args"])
        console.print(t)
        sys.exit(0)

    if args.check_tools:
        from core import ReconScanner
        ok = ReconScanner().check_nmap_available()
        console.print("[green]✓ nmap OK[/green]" if ok else "[red]✗ nmap missing — sudo apt install nmap[/red]")
        sys.exit(0 if ok else 1)

    targets = []
    if args.targets:
        tf = Path(args.targets)
        if not tf.exists():
            console.print(f"[red]✗ File not found: {args.targets}[/red]"); sys.exit(1)
        targets = [l.strip() for l in tf.read_text().splitlines()
                   if l.strip() and not l.startswith("#")]
    elif args.target:
        targets = [args.target]
    else:
        parser.print_help()
        console.print("\n[red]✗ No target specified.[/red]")
        sys.exit(1)

    if not args.quiet:
        console.print("[bold cyan]⚡ RECON SCANNER v2[/bold cyan]  "
                      "[dim]Nmap + Shodan + NVD CVE Intelligence[/dim]")
        check_root()

    for i, target in enumerate(targets):
        if len(targets) > 1:
            console.rule(f"[bold cyan]Target {i+1}/{len(targets)}: {target}[/bold cyan]")
        run_scan(target, args)
        if i < len(targets) - 1:
            time.sleep(1)

    if not args.quiet:
        console.print("\n[dim]⚠  Authorized/educational use only. "
                      "Unauthorized network scanning is illegal.[/dim]\n")


if __name__ == "__main__":
    main()
