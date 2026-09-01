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
