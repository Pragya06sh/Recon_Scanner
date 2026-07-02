"""
dashboard.py — Real-Time Terminal Dashboard
---------------------------------------------
A live-updating terminal UI built with Rich's Live + Layout system.

Shows 6 panels updating in real-time as the scan progresses:
  ┌─────────────────────┬──────────────────────┐
  │  Scan Progress      │  Live Port Feed      │
  ├─────────────────────┼──────────────────────┤
  │  Risk Meter         │  Finding Stream      │
  ├─────────────────────┼──────────────────────┤
  │  Service Map        │  CVE Intelligence    │
  └─────────────────────┴──────────────────────┘

Uses Rich's Live context manager which refreshes the terminal
output at a set rate (10 fps) using ANSI escape codes.
"""

import time
import threading
from dataclasses import dataclass, field
from typing import Optional, Callable
from datetime import datetime

from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, SpinnerColumn
from rich.console import Console
from rich import box
from rich.columns import Columns
from rich.align import Align
from rich.rule import Rule


# ---------------------------------------------------------------------------
# Shared dashboard state — updated from scan thread, read by UI thread
# ---------------------------------------------------------------------------

@dataclass
class DashboardState:
    """Shared mutable state for the live dashboard."""

    # Scan metadata
    target: str = ""
    phase: str = "Initializing..."
    start_time: float = field(default_factory=time.time)
    elapsed: float = 0.0

    # Port discovery
    ports_found: list[dict] = field(default_factory=list)
    ports_scanned: int = 0

    # Findings
    findings: list[dict] = field(default_factory=list)
    risk_score: int = 0
    risk_label: str = "SCANNING"

    # CVE stream
    cve_stream: list[dict] = field(default_factory=list)

    # Phase progress (0.0–1.0)
    phases: dict = field(default_factory=lambda: {
        "nmap_scan":    {"label": "Nmap Port Scan",       "progress": 0.0, "done": False},
        "fingerprint":  {"label": "Service Fingerprint",  "progress": 0.0, "done": False},
        "shodan":       {"label": "Shodan Intelligence",  "progress": 0.0, "done": False},
        "cve_lookup":   {"label": "CVE Lookup (NVD)",     "progress": 0.0, "done": False},
        "analysis":     {"label": "Risk Analysis",        "progress": 0.0, "done": False},
    })

    # Network topology
    live_hosts: int = 0
    trace_hops: int = 0
    os_guess: str = ""

    # Final state
    complete: bool = False
    error: Optional[str] = None

    _lock: threading.Lock = field(default_factory=threading.Lock)

    def update(self, **kwargs):
        with self._lock:
            for k, v in kwargs.items():
                if hasattr(self, k):
                    setattr(self, k, v)

    def add_port(self, port: int, service: str, state: str, product: str = ""):
        with self._lock:
            self.ports_found.append({
                "port": port, "service": service,
                "state": state, "product": product,
                "time": time.time() - self.start_time,
            })

    def add_finding(self, severity: str, title: str, port: int = 0):
        with self._lock:
            self.findings.append({
                "severity": severity, "title": title,
                "port": port, "time": time.time() - self.start_time,
            })

    def add_cve(self, cve_id: str, cvss: float, service: str):
        with self._lock:
            self.cve_stream.append({
                "cve_id": cve_id, "cvss": cvss,
                "service": service, "time": time.time() - self.start_time,
            })

    def set_phase_progress(self, phase: str, progress: float, done: bool = False):
        with self._lock:
            if phase in self.phases:
                self.phases[phase]["progress"] = progress
                self.phases[phase]["done"]     = done


# ---------------------------------------------------------------------------
# Dashboard renderer
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "dim white",
}
SEVERITY_ICONS = {
    "CRITICAL": "💀",
    "HIGH":     "🔴",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}
RISK_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "SECURE":   "bold green",
    "SCANNING": "bold cyan",
    "UNKNOWN":  "dim",
}


class LiveDashboard:
    """
    Rich-powered live terminal dashboard.

    How it works:
      - Rich's Live() context manager takes a renderable (our layout)
      - Every REFRESH_RATE seconds it calls live.refresh()
      - We rebuild the layout from DashboardState each frame
      - A background thread updates DashboardState as scan progresses
    """

    REFRESH_RATE = 0.2   # seconds between UI refreshes (5 fps)
    MAX_PORT_ROWS  = 12
    MAX_FINDING_ROWS = 10
    MAX_CVE_ROWS = 8

    def __init__(self, state: DashboardState):
        self.state = state
        self.console = Console()

    def build_layout(self) -> Layout:
        """Build the full dashboard layout from current state."""
        layout = Layout()

        layout.split_column(
            Layout(name="header",  size=3),
            Layout(name="body",    ratio=1),
            Layout(name="footer",  size=1),
        )

        layout["body"].split_row(
            Layout(name="left",  ratio=1),
            Layout(name="right", ratio=1),
        )

        layout["left"].split_column(
            Layout(name="progress",    size=14),
            Layout(name="risk_meter",  size=7),
            Layout(name="service_map", ratio=1),
        )

        layout["right"].split_column(
            Layout(name="port_feed",  ratio=1),
            Layout(name="cve_feed",   size=12),
        )

        # Populate each panel
        layout["header"].update(self._render_header())
        layout["progress"].update(self._render_progress())
        layout["risk_meter"].update(self._render_risk_meter())
        layout["service_map"].update(self._render_service_map())
        layout["port_feed"].update(self._render_port_feed())
        layout["cve_feed"].update(self._render_cve_feed())
        layout["footer"].update(self._render_footer())

        return layout

    # ------------------------------------------------------------------
    # Panel renderers
    # ------------------------------------------------------------------

    def _render_header(self) -> Panel:
        s = self.state
        elapsed = time.time() - s.start_time
        dt_str  = datetime.now().strftime("%H:%M:%S")

        t = Text(justify="center")
        t.append("⚡ RECON SCANNER", style="bold cyan")
        t.append("  ──  ", style="dim")
        t.append(s.target or "...", style="bold white")
        t.append("  ──  ", style="dim")
        t.append(s.phase, style="bold yellow")
        t.append(f"  [{dt_str}  {elapsed:.0f}s]", style="dim")

        return Panel(t, style="bold cyan", box=box.HORIZONTALS, padding=(0, 1))

    def _render_progress(self) -> Panel:
        s = self.state

        table = Table(box=None, show_header=False, padding=(0, 0), expand=True)
        table.add_column("phase",    width=22)
        table.add_column("bar",      ratio=1)
        table.add_column("status",   width=6, justify="right")

        BAR_WIDTH = 20

        for phase_key, phase_data in s.phases.items():
            label    = phase_data["label"]
            progress = phase_data["progress"]
            done     = phase_data["done"]

            filled = int(BAR_WIDTH * progress)
            empty  = BAR_WIDTH - filled

            if done:
                bar = Text("█" * BAR_WIDTH, style="green")
                status = Text("✓", style="bold green")
            elif progress > 0:
                bar = Text("█" * filled + "▒" * empty, style="cyan")
                status = Text(f"{int(progress*100)}%", style="yellow")
            else:
                bar = Text("░" * BAR_WIDTH, style="dim")
                status = Text("—", style="dim")

            label_text = Text(label[:21], style="white" if progress > 0 else "dim")
            table.add_row(label_text, bar, status)

        return Panel(
            table,
            title="[bold white]SCAN PHASES[/bold white]",
            border_style="blue",
            box=box.ROUNDED,
            padding=(0, 1),
        )

    def _render_risk_meter(self) -> Panel:
        s = self.state
        score = s.risk_score
        label = s.risk_label
        color = RISK_COLORS.get(label, "white")

        BAR_W = 40
        filled = int(BAR_W * score / 100)

        # Gradient bar: green → yellow → red
        bar = Text()
        for i in range(BAR_W):
            pct = i / BAR_W
            if pct < 0.3:   style = "green"
            elif pct < 0.6: style = "yellow"
            elif pct < 0.8: style = "red"
            else:           style = "bold red"
            bar.append("█" if i < filled else "░", style=style)

        content = Text()
        content.append(f" {bar}\n")
        content.append(f"\n  Score: ", style="dim")
        content.append(f"{score}/100", style=f"bold {color}")
        content.append("  │  Label: ", style="dim")
        content.append(f"{label}", style=f"bold {color}")

        # Finding counts
        counts = {}
        for f in s.findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        if counts:
            content.append("  │  ", style="dim")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if sev in counts:
                    sev_c = SEVERITY_COLORS.get(sev, "white")
                    content.append(f"{counts[sev]}{sev[0]} ", style=sev_c)

        return Panel(
            content,
            title="[bold white]RISK SCORE[/bold white]",
            border_style=color,
            box=box.ROUNDED,
            padding=(0, 0),
        )

    def _render_service_map(self) -> Panel:
        s = self.state

        # Group ports by service category
        categories = {
            "Web":      [p for p in s.ports_found if p["port"] in (80, 443, 8080, 8443)],
            "Remote":   [p for p in s.ports_found if p["port"] in (22, 23, 3389, 5900)],
            "Database": [p for p in s.ports_found if p["port"] in (3306, 5432, 1433, 27017, 6379, 9200)],
            "Network":  [p for p in s.ports_found if p["port"] in (21, 25, 53, 161, 389, 445)],
            "Other":    [p for p in s.ports_found if p["port"] not in
                         (80, 443, 8080, 8443, 22, 23, 3389, 5900, 3306, 5432, 1433, 27017,
                          6379, 9200, 21, 25, 53, 161, 389, 445)],
        }

        content = Text()

        if s.os_guess:
            content.append(f"OS: {s.os_guess[:50]}\n", style="dim italic")

        if s.live_hosts:
            content.append(f"Subnet: {s.live_hosts} live hosts  ", style="dim")
        if s.trace_hops:
            content.append(f"Hops: {s.trace_hops}\n", style="dim")
        if s.live_hosts or s.trace_hops:
            content.append("\n")

        for cat, ports in categories.items():
            if not ports:
                continue
            content.append(f"{cat}: ", style="bold cyan")
            for p in ports[:6]:
                sev_hint = self._port_severity_hint(p["port"])
                content.append(f"{p['port']}", style=SEVERITY_COLORS.get(sev_hint, "white"))
                if p["product"]:
                    content.append(f"({p['product'][:8]})", style="dim")
                content.append(" ")
            content.append("\n")

        if not any(categories.values()):
            content.append("No open ports discovered yet...", style="dim italic")

        return Panel(
            content,
            title="[bold white]SERVICE MAP[/bold white]",
            border_style="blue",
            box=box.ROUNDED,
            padding=(0, 1),
        )

    def _render_port_feed(self) -> Panel:
        s = self.state

        table = Table(
            box=box.SIMPLE,
            show_header=True,
            header_style="bold dim",
            expand=True,
            padding=(0, 1),
        )
        table.add_column("PORT",    width=7,  style="cyan", no_wrap=True)
        table.add_column("SERVICE", width=10, no_wrap=True)
        table.add_column("PRODUCT", ratio=1)
        table.add_column("t+",      width=5,  style="dim", no_wrap=True)

        # Show most recent ports
        recent = list(reversed(s.ports_found))[:self.MAX_PORT_ROWS]

        for p in recent:
            sev   = self._port_severity_hint(p["port"])
            color = SEVERITY_COLORS.get(sev, "white")
            table.add_row(
                Text(str(p["port"]), style=color),
                Text(p["service"][:10], style=color),
                Text(p["product"][:22] if p["product"] else "", style="dim"),
                Text(f"{p['time']:.0f}s", style="dim"),
            )

        if not s.ports_found:
            table.add_row(Text("...", style="dim italic"), "", "", "")

        return Panel(
            table,
            title=f"[bold white]PORT DISCOVERY ({len(s.ports_found)} open)[/bold white]",
            border_style="cyan",
            box=box.ROUNDED,
        )

    def _render_cve_feed(self) -> Panel:
        s = self.state

        table = Table(
            box=box.SIMPLE,
            show_header=True,
            header_style="bold dim",
            expand=True,
            padding=(0, 1),
        )
        table.add_column("CVE",     width=18, no_wrap=True)
        table.add_column("CVSS",    width=5,  no_wrap=True)
        table.add_column("SERVICE", ratio=1)

        recent = list(reversed(s.cve_stream))[:self.MAX_CVE_ROWS]

        for c in recent:
            if c["cvss"] >= 9.0:   style = "bold red"
            elif c["cvss"] >= 7.0: style = "red"
            elif c["cvss"] >= 4.0: style = "yellow"
            else:                  style = "cyan"

            table.add_row(
                Text(c["cve_id"], style="cyan"),
                Text(str(c["cvss"]), style=style),
                Text(c["service"][:20], style="dim"),
            )

        if not s.cve_stream:
            table.add_row(Text("Awaiting CVE data...", style="dim italic"), "", "")

        return Panel(
            table,
            title=f"[bold white]CVE STREAM ({len(s.cve_stream)} found)[/bold white]",
            border_style="red",
            box=box.ROUNDED,
        )

    def _render_footer(self) -> Text:
        t = Text(justify="center", style="dim")
        t.append("⚠  AUTHORIZED USE ONLY  │  "
                 "Nmap + NVD + Shodan  │  "
                 "Press Ctrl+C to stop")
        return t

    def _port_severity_hint(self, port: int) -> str:
        critical = {445, 23, 6379, 9200, 27017, 4444, 512, 513}
        high     = {21, 135, 139, 161, 389, 1433, 3306, 3389, 5432, 5900}
        if port in critical:  return "CRITICAL"
        if port in high:      return "HIGH"
        return "LOW"

    # ------------------------------------------------------------------
    # Run the live dashboard
    # ------------------------------------------------------------------

    def run(self, scan_fn: Callable, *scan_args, **scan_kwargs):
        """
        Run scan_fn in a background thread while displaying the live dashboard.

        scan_fn should accept `state` as a keyword arg and update it
        as scanning progresses.
        """
        result_container = {}

        def scan_thread():
            try:
                result = scan_fn(*scan_args, state=self.state, **scan_kwargs)
                result_container["result"] = result
            except Exception as e:
                self.state.update(error=str(e))
            finally:
                self.state.update(complete=True)

        thread = threading.Thread(target=scan_thread, daemon=True)
        thread.start()

        try:
            with Live(
                self.build_layout(),
                refresh_per_second=int(1 / self.REFRESH_RATE),
                screen=False,
                console=self.console,
            ) as live:
                while not self.state.complete:
                    self.state.update(elapsed=time.time() - self.state.start_time)
                    live.update(self.build_layout())
                    time.sleep(self.REFRESH_RATE)

                # Final refresh
                live.update(self.build_layout())

        except KeyboardInterrupt:
            self.state.update(complete=True, phase="Interrupted by user")
            thread.join(timeout=2)

        thread.join(timeout=10)
        return result_container.get("result")
