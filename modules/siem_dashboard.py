"""
TRAIN Framework - modules/siem_dashboard.py
SIEM-style dashboard: live-updating statistics over a growing log file.

Registers: siem-dashboard <file> --format <type> [--interval N]

Watches a log file (the same formats log_engine.py already parses: auth,
syslog, nginx, json-alerts) and re-renders a summary dashboard - event
counts by kind, top source IPs, brute-force candidates, severity
breakdown - every few seconds as new lines are appended. This mirrors
what a SIEM's live view does (Splunk/ELK dashboards refreshing as new
events arrive), built directly on top of TRAIN's existing log parsers.

Purely a read + aggregate + display loop over a file already on disk -
no data collection happens here, no network access, nothing is written.
Press Ctrl+C to stop and return to the prompt.
"""

from __future__ import annotations

import time
from collections import Counter
from pathlib import Path

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from core.tui_engine import Session, register_command
from modules.log_engine import PARSERS

console = Console()

DEFAULT_INTERVAL = 3.0
TOP_N = 8


def _build_dashboard(events: list, cumulative_lines: int, file_path: str, fmt: str) -> Layout:
    kind_counts = Counter(e.kind for e in events)
    source_counts = Counter(e.source for e in events)

    header = Panel(
        f"[bold]{file_path}[/bold]  (format: {fmt})  |  "
        f"{cumulative_lines} lines processed  |  {len(events)} events total",
        border_style="cyan",
    )

    kind_table = Table(title="Events by Kind")
    kind_table.add_column("Kind", style="bold")
    kind_table.add_column("Count", justify="right")
    for kind, count in kind_counts.most_common():
        kind_table.add_row(kind, str(count))

    top_table = Table(title=f"Top {TOP_N} Sources")
    top_table.add_column("Source", style="bold cyan")
    top_table.add_column("Events", justify="right")
    for source, count in source_counts.most_common(TOP_N):
        top_table.add_row(source, str(count))

    fail_counter: Counter[str] = Counter()
    for e in events:
        if e.kind == "ssh_failed_login":
            fail_counter[e.source] += 1
    brute_candidates = {ip: c for ip, c in fail_counter.items() if c >= 5}

    alert_panel_lines = []
    if brute_candidates:
        for ip, count in sorted(brute_candidates.items(), key=lambda x: -x[1])[:5]:
            alert_panel_lines.append(f"[red bold]BRUTE-FORCE[/red bold] {ip}: {count} failed attempts")
    if not alert_panel_lines:
        alert_panel_lines.append("[dim]No active alerts.[/dim]")
    alert_panel = Panel("\n".join(alert_panel_lines), title="Active Alerts", border_style="red")

    recent = events[-6:]
    recent_lines = [f"[dim]{e.kind}[/dim]  {e.source}  —  {e.detail[:60]}" for e in reversed(recent)]
    if not recent_lines:
        recent_lines = ["[dim]No events yet.[/dim]"]
    recent_panel = Panel("\n".join(recent_lines), title="Recent Activity", border_style="blue")

    layout = Layout()
    layout.split_column(
        Layout(header, size=3),
        Layout(name="body"),
    )
    layout["body"].split_row(
        Layout(name="left"),
        Layout(name="right"),
    )
    layout["left"].split_column(Layout(kind_table), Layout(top_table))
    layout["right"].split_column(Layout(alert_panel), Layout(recent_panel))

    return layout


@register_command("siem-dashboard")
def cmd_siem_dashboard(session: Session, args: list[str]) -> None:
    """
    Usage: siem-dashboard <file> --format <auth|syslog|nginx|json-alerts> [--interval N]
    Live-updating SIEM-style dashboard over a log file. Re-parses the
    file every N seconds (default 3) and refreshes counts, top sources,
    brute-force alerts, and recent activity. Press Ctrl+C to stop.
    """
    if not args:
        console.print("[red]Usage:[/red] siem-dashboard <file> --format <type> [--interval N]")
        return

    file_path = Path(args[0])
    fmt = "auth"
    interval = DEFAULT_INTERVAL

    rest = args[1:]
    i = 0
    while i < len(rest):
        if rest[i] == "--format" and i + 1 < len(rest):
            fmt = rest[i + 1]
            i += 2
        elif rest[i] == "--interval" and i + 1 < len(rest):
            try:
                interval = float(rest[i + 1])
            except ValueError:
                console.print("[red]--interval must be a number.[/red]")
                return
            i += 2
        else:
            i += 1

    if fmt not in PARSERS:
        console.print(f"[red]Unknown format:[/red] {fmt}  (use: {', '.join(PARSERS)})")
        return
    if not file_path.exists():
        console.print(f"[red]File not found:[/red] {file_path}")
        return

    parser = PARSERS[fmt]
    console.print(f"[cyan]Starting SIEM dashboard on[/cyan] {file_path}  [dim](Ctrl+C to stop)[/dim]\n")

    try:
        with Live(console=console, refresh_per_second=2, screen=False) as live:
            while True:
                text = file_path.read_text(encoding="utf-8", errors="replace")
                events = parser(text)
                line_count = len(text.splitlines())
                live.update(_build_dashboard(events, line_count, str(file_path), fmt))
                time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[dim]Dashboard stopped.[/dim]")
