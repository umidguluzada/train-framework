"""
TRAIN Framework - modules/wifi_audit.py
Passive wireless network audit + router management-port exposure check.

Registers:
  wifi-scan                -> lists visible wireless networks and flags weak encryption
  router-audit <router_ip> -> checks a router/AP's own management ports for
                               risky exposure (Telnet, UPnP, web admin)

Both commands are read-only / passive:
  - wifi-scan simply reads what nearby access points already broadcast in
    their beacon frames (SSID, signal, encryption type) via NetworkManager's
    `nmcli` - the same information any phone or laptop's Wi-Fi picker shows.
    It does NOT capture handshakes, deauthenticate clients, or attempt to
    crack any password - that would require active attack tooling
    (aircrack-ng-style) which is out of scope for this module.
  - router-audit reuses the existing port-scan approach (a handful of
    well-known ports) against a router's own IP and flags commonly risky
    findings (Telnet enabled, UPnP reachable from the LAN, web admin
    panel exposed) - no credential guessing, no login attempts.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
from dataclasses import dataclass, field

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.tui_engine import Session, register_command

console = Console()

# Encryption types considered weak/deprecated for Wi-Fi.
WEAK_ENCRYPTION = {"", "WEP", "WPA1"}

ROUTER_CHECK_PORTS = {
    23: ("Telnet", "Unencrypted remote admin access - a major risk if reachable."),
    1900: ("UPnP/SSDP", "Universal Plug and Play - has a history of remote exploits; "
                          "should not be reachable outside the LAN, ideally disabled."),
    80: ("HTTP admin", "Web admin panel over plain HTTP - credentials sent unencrypted."),
    443: ("HTTPS admin", "Web admin panel over HTTPS - check the certificate is valid."),
    7547: ("TR-069/CWMP", "ISP remote management protocol - has had serious RCE vulnerabilities."),
}


# ---------------------------------------------------------------------------
# Wireless network scan (passive)
# ---------------------------------------------------------------------------

@dataclass
class WifiNetwork:
    ssid: str
    signal: str
    security: str


@dataclass
class WifiScanReport:
    networks: list[WifiNetwork] = field(default_factory=list)
    error: str | None = None


def run_wifi_scan() -> WifiScanReport:
    if not shutil.which("nmcli"):
        return WifiScanReport(error=(
            "nmcli not found. Install NetworkManager (usually preinstalled on Kali/Ubuntu "
            "desktop) or run this from a machine with a wireless adapter."
        ))

    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "device", "wifi", "list"],
            capture_output=True, text=True, timeout=20,
        )
    except (subprocess.SubprocessError, OSError) as e:
        return WifiScanReport(error=f"Failed to run nmcli: {e}")

    if result.returncode != 0:
        return WifiScanReport(error=result.stderr.strip() or "nmcli scan failed (no wireless adapter?).")

    report = WifiScanReport()
    for line in result.stdout.splitlines():
        # nmcli -t uses ':' as a field separator; SSIDs containing ':' are escaped as '\:'.
        parts = line.replace("\\:", "\x00").split(":")
        parts = [p.replace("\x00", ":") for p in parts]
        if len(parts) < 3:
            continue
        ssid, signal, security = parts[0], parts[1], parts[2]
        if not ssid:
            continue
        report.networks.append(WifiNetwork(ssid=ssid, signal=signal, security=security))

    return report


def _render_wifi_report(report: WifiScanReport) -> None:
    if report.error:
        console.print(Panel(f"[red]{report.error}[/red]", title="Wi-Fi Scan", border_style="red"))
        return

    if not report.networks:
        console.print(Panel("No wireless networks found nearby.", title="Wi-Fi Scan", border_style="yellow"))
        return

    table = Table(title=f"Nearby Wireless Networks ({len(report.networks)} found)")
    table.add_column("SSID", style="bold")
    table.add_column("Signal", justify="right")
    table.add_column("Security")

    weak_count = 0
    for net in sorted(report.networks, key=lambda n: -int(n.signal or 0)):
        is_weak = net.security in WEAK_ENCRYPTION
        if is_weak:
            weak_count += 1
        style = "red bold" if is_weak else "green"
        security_label = net.security if net.security else "Open (no encryption)"
        table.add_row(net.ssid, f"{net.signal}%", f"[{style}]{security_label}[/{style}]")

    console.print(table)
    if weak_count:
        console.print(f"[red bold]{weak_count} network(s) use weak or no encryption.[/red bold]")
    console.print("[dim]This only reads what nearby access points broadcast - no packets are "
                   "injected and no handshakes are captured.[/dim]")


@register_command("wifi-scan")
def cmd_wifi_scan(session: Session, args: list[str]) -> None:
    """Usage: wifi-scan   (lists visible Wi-Fi networks and flags weak encryption, via nmcli)"""
    console.print("[cyan]Scanning for nearby wireless networks...[/cyan]")
    report = run_wifi_scan()
    _render_wifi_report(report)
    session.state["last_wifi_scan"] = report


# ---------------------------------------------------------------------------
# Router / access point management-port exposure audit
# ---------------------------------------------------------------------------

@dataclass
class RouterFinding:
    port: int
    name: str
    open: bool
    note: str


@dataclass
class RouterAuditReport:
    target: str
    findings: list[RouterFinding] = field(default_factory=list)


def _check_port(target: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return True
    except (socket.error, OSError):
        return False


def run_router_audit(target: str) -> RouterAuditReport:
    report = RouterAuditReport(target=target)
    for port, (name, note) in ROUTER_CHECK_PORTS.items():
        is_open = _check_port(target, port)
        report.findings.append(RouterFinding(port=port, name=name, open=is_open, note=note))
    return report


def _render_router_report(report: RouterAuditReport) -> None:
    table = Table(title=f"Router/AP Management Port Audit — {report.target}")
    table.add_column("Port", justify="right")
    table.add_column("Service")
    table.add_column("Status")
    table.add_column("Note", style="dim")

    risky_open = 0
    for f in report.findings:
        status_style = "red bold" if f.open else "green"
        status_text = "OPEN" if f.open else "closed"
        if f.open and f.port in (23, 1900, 7547):
            risky_open += 1
        table.add_row(str(f.port), f.name, f"[{status_style}]{status_text}[/{status_style}]", f.note)

    console.print(table)
    if risky_open:
        console.print(f"[red bold]{risky_open} risky management port(s) reachable — "
                       f"consider disabling Telnet/UPnP/TR-069 if not needed.[/red bold]")
    else:
        console.print("[green]No high-risk management ports found open.[/green]")


@register_command("router-audit")
def cmd_router_audit(session: Session, args: list[str]) -> None:
    """
    Usage: router-audit <router_ip>
    Checks a router/access point's own management ports (Telnet, UPnP,
    web admin, TR-069) for risky exposure. Point this at your own
    router's LAN IP (e.g. 192.168.1.1) - it does not guess credentials
    or log in anywhere, it only checks which ports respond.
    """
    target = args[0] if args else session.target
    if not target:
        console.print("[red]No target set.[/red] Use 'router-audit <router_ip>' or 'set target <router_ip>' first.")
        return

    console.print(f"[cyan]Auditing router management ports on[/cyan] {target}...")
    report = run_router_audit(target)
    _render_router_report(report)
    session.state["last_router_audit"] = report


# ---------------------------------------------------------------------------
# Network host discovery (which devices are alive on the LAN)
# ---------------------------------------------------------------------------

import ipaddress  # noqa: E402
import re  # noqa: E402
import subprocess as _subprocess  # noqa: E402
import concurrent.futures  # noqa: E402


@dataclass
class DiscoveredHost:
    ip: str
    alive: bool
    hostname: str = ""
    mac: str = ""
    vendor: str = ""


@dataclass
class DiscoverReport:
    cidr: str
    hosts: list[DiscoveredHost] = field(default_factory=list)


def _ping_host(ip: str, timeout: float = 1.0) -> bool:
    """
    Sends a single ICMP echo request via the system 'ping' command (one
    packet, short timeout) - the same lightweight liveness check any
    network troubleshooting tool uses. No payload, no repeated flooding.
    """
    try:
        result = _subprocess.run(
            ["ping", "-c", "1", "-W", str(int(timeout)), ip],
            capture_output=True, text=True, timeout=timeout + 1,
        )
        return result.returncode == 0
    except (_subprocess.SubprocessError, OSError):
        return False


def _read_arp_table() -> dict[str, str]:
    """Reads the local ARP/neighbor cache (ip -> MAC), populated by the pings above."""
    mac_by_ip: dict[str, str] = {}
    try:
        result = _subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            m = re.match(r"^(\S+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]+)", line)
            if m:
                mac_by_ip[m.group(1)] = m.group(2).lower()
    except (_subprocess.SubprocessError, OSError, FileNotFoundError):
        pass
    return mac_by_ip


def _reverse_lookup(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def run_net_discover(cidr: str, threads: int = 32) -> DiscoverReport:
    network = ipaddress.ip_network(cidr, strict=False)
    hosts_to_check = [str(ip) for ip in network.hosts()]

    report = DiscoverReport(cidr=cidr)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        alive_map = dict(zip(hosts_to_check, pool.map(_ping_host, hosts_to_check)))

    alive_ips = [ip for ip, alive in alive_map.items() if alive]
    mac_table = _read_arp_table()

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        hostnames = dict(zip(alive_ips, pool.map(_reverse_lookup, alive_ips)))

    for ip in alive_ips:
        report.hosts.append(DiscoveredHost(
            ip=ip, alive=True,
            hostname=hostnames.get(ip, ""),
            mac=mac_table.get(ip, ""),
        ))

    report.hosts.sort(key=lambda h: tuple(int(p) for p in h.ip.split(".")))
    return report


def _render_discover_report(report: DiscoverReport) -> None:
    if not report.hosts:
        console.print(Panel(
            f"No live hosts found on {report.cidr}. (Some devices/firewalls silently "
            f"drop ping requests, so this isn't always exhaustive.)",
            title="Network Discovery", border_style="yellow",
        ))
        return

    table = Table(title=f"Live Hosts on {report.cidr} ({len(report.hosts)} found)")
    table.add_column("IP", style="bold cyan")
    table.add_column("Hostname")
    table.add_column("MAC Address")

    for h in report.hosts:
        table.add_row(h.ip, h.hostname or "-", h.mac or "-")

    console.print(table)
    console.print("[dim]Discovery via ICMP ping + local ARP cache + reverse DNS - "
                   "no port scanning performed here (use 'scan <ip>' for that).[/dim]")


@register_command("net-discover")
def cmd_net_discover(session: Session, args: list[str]) -> None:
    """
    Usage: net-discover <cidr>
    Finds live devices on a network range, e.g.:
      net-discover 192.168.1.0/24
    Shows each responding IP's hostname (via reverse DNS, if available)
    and MAC address (via the local ARP cache, if the device is on the
    same LAN segment). Uses simple ICMP ping - one packet per host, no
    port scanning (use 'scan <ip>' on a specific host for that).
    """
    if not args:
        console.print("[red]Usage:[/red] net-discover <cidr>  (e.g. net-discover 192.168.1.0/24)")
        return

    cidr = args[0]
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        console.print(f"[red]Invalid network range:[/red] {e}")
        return

    if network.num_addresses > 1024:
        console.print(f"[red]Range too large ({network.num_addresses} addresses).[/red] "
                       f"Use a /22 or smaller (e.g. /24, /28).")
        return

    console.print(f"[cyan]Discovering live hosts on[/cyan] {cidr}  "
                   f"[dim]({network.num_addresses - 2} addresses to check)...[/dim]")
    report = run_net_discover(cidr)
    _render_discover_report(report)
    session.state["last_net_discover"] = report
