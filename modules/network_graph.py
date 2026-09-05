"""
TRAIN Framework - modules/network_graph.py
Terminal-rendered network topology graph.

Registers: net-graph

Renders whatever this session has already discovered (scan results,
net-discover hosts, TSE findings) as a tree: host -> open ports ->
service/banner -> any TSE findings on that port. Pure visualization over
data TRAIN's own modules already gathered - runs no new scans itself.
"""

from __future__ import annotations

from rich.console import Console
from rich.tree import Tree

from core.tui_engine import Session, register_command

console = Console()


def _severity_style(severity: str) -> str:
    return {"finding": "red bold", "warning": "yellow", "info": "dim", "fail": "red bold",
            "warn": "yellow", "pass": "green"}.get(severity, "white")


@register_command("net-graph")
def cmd_net_graph(session: Session, args: list[str]) -> None:
    """
    Usage: net-graph
    Renders a tree of this session's discovered hosts, open ports,
    services, and TSE findings - built from 'scan', 'net-discover', and
    'run-tse' results already gathered this session. Run those first.
    """
    scan = session.state.get("last_scan")
    discover = session.state.get("last_net_discover")
    tse = session.state.get("last_tse_report")

    if not scan and not discover:
        console.print(
            "[yellow]Nothing to graph yet.[/yellow] Run 'scan' and/or 'net-discover <cidr>' "
            "first, then 'net-graph'."
        )
        return

    root_label = session.target or "Network"
    tree = Tree(f"[bold cyan]{root_label}[/bold cyan]")

    # Discovered LAN hosts (from net-discover), if any.
    if discover and discover.hosts:
        hosts_branch = tree.add(f"[bold]Discovered Hosts[/bold] ({len(discover.hosts)})")
        for h in discover.hosts:
            label = f"[cyan]{h.ip}[/cyan]"
            if h.hostname:
                label += f"  [dim]{h.hostname}[/dim]"
            if h.mac:
                label += f"  [dim]({h.mac})[/dim]"
            hosts_branch.add(label)

    # Scanned target: host -> ports -> service/banner -> TSE findings.
    if scan and scan.get("open_ports"):
        target_label = f"[bold]{scan.get('target', 'target')}[/bold]  [dim]({scan.get('elapsed_seconds', 0):.2f}s scan)[/dim]"
        host_branch = tree.add(target_label)

        tse_by_port: dict[int, list] = {}
        if tse:
            for f in tse.findings:
                tse_by_port.setdefault(f.port, []).append(f)

        for entry in scan["open_ports"]:
            port = entry.get("port")
            service = entry.get("service_guess", "unknown")
            banner = (entry.get("banner") or "").strip()

            port_label = f"[green]{port}/tcp[/green]  [bold]{service}[/bold]"
            port_node = host_branch.add(port_label)

            if banner:
                port_node.add(f"[dim]banner: {banner[:70]}[/dim]")

            for finding in tse_by_port.get(port, []):
                style = _severity_style(finding.severity)
                port_node.add(f"[{style}]{finding.check}: {finding.result}[/{style}]")

    console.print(tree)
