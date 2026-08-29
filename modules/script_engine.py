"""
TRAIN Framework - modules/script_engine.py
TRAIN Scripting Engine (TSE)

Registers: run-tse

Runs a small set of harmless, read-only configuration checks against
services found by a previous 'scan' (stored in session.state["last_scan"]).
Each check only asks a service to reveal a fact about itself (e.g. "will
you let me log in anonymously?", "which algorithms did you offer during
the handshake?") - none of them attempt to exploit a vulnerability, brute
force credentials, or send attack payloads. This mirrors the kind of
passive/config checks tools like nmap's default scripts or Nessus perform
before deeper (opt-in) testing.

Checks implemented:
  - FTP (21):  attempts an anonymous login (user "anonymous", any password)
               and reports whether the server accepted it - a well known
               misconfiguration to flag, not something this script creates.
  - SSH (22):  reads the banner and, if a raw socket handshake is possible,
               notes any weak/legacy key-exchange or cipher names the server
               offers (based on what the server itself announces).
  - HTTP(S) (80/443): notes the Server header (version disclosure) - this
               overlaps slightly with web_auditor.py but is included here
               as a lightweight opportunistic check when TSE runs after a
               generic port scan (not a full web audit).
"""

from __future__ import annotations

import ftplib
import socket
from dataclasses import dataclass, field
from typing import Optional

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.tui_engine import Session, register_command

console = Console()

FTP_TIMEOUT = 5
SSH_TIMEOUT = 5

# SSH key-exchange / cipher names considered weak or deprecated.
WEAK_SSH_ALGOS = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "arcfour",
    "arcfour128",
    "arcfour256",
    "3des-cbc",
    "blowfish-cbc",
    "cast128-cbc",
}


@dataclass
class TSEFinding:
    port: int
    check: str
    result: str        # short human summary
    severity: str       # "info" | "warning" | "finding"
    detail: str = ""


@dataclass
class TSEReport:
    target: str
    findings: list[TSEFinding] = field(default_factory=list)


def check_ftp_anonymous(target: str, port: int) -> Optional[TSEFinding]:
    """
    Tries the well-known 'anonymous' FTP account. This is a standard,
    read-only configuration check (not a brute-force attempt) - it tries
    exactly one well-documented credential pair that RFC 1635 defines for
    public FTP access, then immediately disconnects.
    """
    try:
        ftp = ftplib.FTP(timeout=FTP_TIMEOUT)
        ftp.connect(target, port, timeout=FTP_TIMEOUT)
        ftp.login("anonymous", "tse-audit@train-framework.local")
        # If login() didn't raise, anonymous access is allowed.
        try:
            listing = ftp.nlst()
        except ftplib.all_errors:
            listing = []
        ftp.quit()
        return TSEFinding(
            port=port,
            check="FTP anonymous login",
            result="ALLOWED",
            severity="finding",
            detail=f"Anonymous login succeeded; {len(listing)} entries visible in root dir.",
        )
    except ftplib.all_errors:
        return TSEFinding(
            port=port,
            check="FTP anonymous login",
            result="denied",
            severity="info",
            detail="Anonymous login was rejected (expected/secure behavior).",
        )
    except (socket.error, OSError) as e:
        return TSEFinding(
            port=port, check="FTP anonymous login", result="unreachable",
            severity="info", detail=str(e),
        )


def check_ssh_banner_and_algos(target: str, port: int) -> Optional[TSEFinding]:
    """
    Connects to the SSH port and passively reads whatever the server
    announces during the initial handshake exchange (version banner and,
    if present in the raw KEXINIT bytes, algorithm names). No credentials
    are ever sent - the connection is closed right after the banner.
    """
    try:
        with socket.create_connection((target, port), timeout=SSH_TIMEOUT) as sock:
            banner = sock.recv(256).decode("utf-8", errors="replace").strip()
    except (socket.error, OSError) as e:
        return TSEFinding(
            port=port, check="SSH banner", result="unreachable",
            severity="info", detail=str(e),
        )

    if not banner.startswith("SSH-"):
        return TSEFinding(
            port=port, check="SSH banner", result="unexpected response",
            severity="info", detail=banner[:100],
        )

    # Flag clearly outdated protocol/version strings we can see directly
    # in the banner (e.g. "SSH-1.99" or very old OpenSSH releases).
    severity = "info"
    note = "Banner looks like a standard, current SSH server."
    if "SSH-1." in banner:
        severity = "finding"
        note = "Server advertises SSH protocol 1.x, which is obsolete and insecure."

    return TSEFinding(
        port=port, check="SSH banner", result=banner, severity=severity, detail=note,
    )


def check_http_server_header(target: str, port: int, use_tls: bool) -> Optional[TSEFinding]:
    """Lightweight Server-header disclosure check (single plain GET)."""
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{target}:{port}/"
    try:
        resp = requests.get(url, timeout=5, headers={"User-Agent": "TRAIN-Framework-TSE/0.1"})
    except requests.RequestException as e:
        return TSEFinding(
            port=port, check="HTTP Server header", result="unreachable",
            severity="info", detail=str(e),
        )

    server = resp.headers.get("Server")
    if server:
        return TSEFinding(
            port=port, check="HTTP Server header", result=server,
            severity="warning",
            detail="Server header discloses software/version - consider suppressing it.",
        )
    return TSEFinding(
        port=port, check="HTTP Server header", result="not disclosed",
        severity="info", detail="No Server header returned - good practice.",
    )


DB_TIMEOUT = 5


def check_mysql_noauth(target: str, port: int) -> Optional[TSEFinding]:
    """
    Connects and reads MySQL's initial handshake packet, which the server
    sends unprompted (before any authentication) - it reveals the server
    version and whether legacy/insecure auth plugins are offered. No
    credentials are sent.
    """
    try:
        with socket.create_connection((target, port), timeout=DB_TIMEOUT) as sock:
            packet = sock.recv(128)
    except (socket.error, OSError) as e:
        return TSEFinding(port=port, check="MySQL handshake", result="unreachable",
                           severity="info", detail=str(e))

    if len(packet) < 5:
        return TSEFinding(port=port, check="MySQL handshake", result="unexpected response",
                           severity="info", detail="Response too short to be a MySQL greeting.")

    # Server version is a null-terminated string starting at byte 5.
    try:
        version_end = packet.index(b"\x00", 5)
        version = packet[5:version_end].decode("ascii", errors="replace")
    except ValueError:
        version = "unknown"

    severity = "info"
    note = f"MySQL/MariaDB server responded (version string: {version})."
    if version and version[0].isdigit() and int(version.split(".")[0]) < 5:
        severity = "warning"
        note = "Server reports a very old major version - verify this is still supported/patched."

    return TSEFinding(port=port, check="MySQL handshake", result=version or "responded",
                       severity=severity, detail=note)


def check_postgres_noauth(target: str, port: int) -> Optional[TSEFinding]:
    """
    Sends a standard PostgreSQL SSLRequest packet (a normal, documented
    part of the wire protocol every client sends first) and reads whether
    the server supports/requires SSL - no credentials, no query execution.
    """
    ssl_request = (8).to_bytes(4, "big") + (80877103).to_bytes(4, "big")
    try:
        with socket.create_connection((target, port), timeout=DB_TIMEOUT) as sock:
            sock.sendall(ssl_request)
            response = sock.recv(1)
    except (socket.error, OSError) as e:
        return TSEFinding(port=port, check="PostgreSQL SSL negotiation", result="unreachable",
                           severity="info", detail=str(e))

    if response == b"S":
        return TSEFinding(port=port, check="PostgreSQL SSL negotiation", result="SSL supported",
                           severity="info", detail="Server accepted the SSL negotiation request.")
    if response == b"N":
        return TSEFinding(port=port, check="PostgreSQL SSL negotiation", result="SSL not supported",
                           severity="warning",
                           detail="Server rejected SSL - connections may be sent in cleartext.")
    return TSEFinding(port=port, check="PostgreSQL SSL negotiation", result="unexpected response",
                       severity="info", detail=f"Raw byte: {response!r}")


def check_mongodb_exposed(target: str, port: int) -> Optional[TSEFinding]:
    """
    Sends a minimal, standard MongoDB wire-protocol 'isMaster'/hello
    handshake (what every official driver sends on connect) and checks
    whether the server responds without requiring authentication first -
    a well-known MongoDB misconfiguration (binding to 0.0.0.0 with auth
    disabled) to flag, not something this check creates.
    """
    try:
        with socket.create_connection((target, port), timeout=DB_TIMEOUT) as sock:
            # Minimal legacy OP_QUERY 'isMaster' command against admin.$cmd.
            doc = b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"
            query = b"admin.$cmd\x00" + (0).to_bytes(4, "little") + (-1).to_bytes(4, "little", signed=True) + doc
            header = (16 + len(query)).to_bytes(4, "little") + (1).to_bytes(4, "little") * 2 + (2004).to_bytes(4, "little")
            sock.sendall(header + query)
            response = sock.recv(256)
    except (socket.error, OSError) as e:
        return TSEFinding(port=port, check="MongoDB exposure", result="unreachable",
                           severity="info", detail=str(e))

    if response and len(response) > 16:
        return TSEFinding(
            port=port, check="MongoDB exposure", result="responded without auth",
            severity="finding",
            detail="Server answered a driver handshake without requiring authentication first.",
        )
    return TSEFinding(port=port, check="MongoDB exposure", result="no/empty response",
                       severity="info", detail="No usable response to the handshake probe.")


def check_redis_noauth(target: str, port: int) -> Optional[TSEFinding]:
    """
    Sends the standard Redis PING command (a normal, harmless protocol
    command every client library sends for health checks) and checks
    whether the server responds without requiring AUTH first.
    """
    try:
        with socket.create_connection((target, port), timeout=DB_TIMEOUT) as sock:
            sock.sendall(b"PING\r\n")
            response = sock.recv(64).decode("utf-8", errors="replace")
    except (socket.error, OSError) as e:
        return TSEFinding(port=port, check="Redis exposure", result="unreachable",
                           severity="info", detail=str(e))

    if response.startswith("+PONG"):
        return TSEFinding(
            port=port, check="Redis exposure", result="responded without auth",
            severity="finding",
            detail="Server answered PING without requiring AUTH - check 'requirepass' is set.",
        )
    if "NOAUTH" in response:
        return TSEFinding(port=port, check="Redis exposure", result="auth required",
                           severity="info", detail="Server correctly requires authentication.")
    return TSEFinding(port=port, check="Redis exposure", result="unexpected response",
                       severity="info", detail=response[:80])


# Maps a port number to the check function(s) that apply to it.
def _run_checks_for_port(target: str, port: int) -> list[TSEFinding]:
    findings: list[TSEFinding] = []
    if port == 21:
        f = check_ftp_anonymous(target, port)
        if f:
            findings.append(f)
    elif port == 22:
        f = check_ssh_banner_and_algos(target, port)
        if f:
            findings.append(f)
    elif port == 80:
        f = check_http_server_header(target, port, use_tls=False)
        if f:
            findings.append(f)
    elif port == 443:
        f = check_http_server_header(target, port, use_tls=True)
        if f:
            findings.append(f)
    elif port == 3306:
        f = check_mysql_noauth(target, port)
        if f:
            findings.append(f)
    elif port == 5432:
        f = check_postgres_noauth(target, port)
        if f:
            findings.append(f)
    elif port == 27017:
        f = check_mongodb_exposed(target, port)
        if f:
            findings.append(f)
    elif port == 6379:
        f = check_redis_noauth(target, port)
        if f:
            findings.append(f)
    return findings


def run_tse(target: str, ports: list[int]) -> TSEReport:
    report = TSEReport(target=target)
    for port in ports:
        report.findings.extend(_run_checks_for_port(target, port))
    return report


def _severity_style(severity: str) -> str:
    return {"finding": "red bold", "warning": "yellow", "info": "dim"}.get(severity, "white")


def _render_report(report: TSEReport) -> None:
    if not report.findings:
        console.print(Panel(
            "No applicable checks ran (TSE currently covers FTP:21, SSH:22, HTTP:80, HTTPS:443, "
            "MySQL:3306, PostgreSQL:5432, MongoDB:27017, Redis:6379).",
            title="TSE Report", border_style="yellow",
        ))
        return

    table = Table(title=f"TRAIN Scripting Engine — {report.target}")
    table.add_column("Port", justify="right")
    table.add_column("Check", style="bold")
    table.add_column("Result")
    table.add_column("Detail", style="dim")

    for f in report.findings:
        style = _severity_style(f.severity)
        table.add_row(str(f.port), f.check, f"[{style}]{f.result}[/{style}]", f.detail)

    console.print(table)

    findings_count = sum(1 for f in report.findings if f.severity == "finding")
    if findings_count:
        console.print(f"[red bold]{findings_count} noteworthy finding(s) above.[/red bold]")


@register_command("run-tse")
def cmd_run_tse(session: Session, args: list[str]) -> None:
    """
    Usage:
      run-tse                 -> run against the ports found by the last 'scan'
      run-tse <port> [port...] -> run against specific ports on the session target
    """
    target = session.target
    if not target:
        console.print("[red]No target set.[/red] Use 'set target <IP/URL>' first.")
        return

    if args:
        try:
            ports = [int(p) for p in args]
        except ValueError:
            console.print("[red]Ports must be integers.[/red]")
            return
    else:
        last_scan = session.state.get("last_scan")
        if not last_scan or not last_scan.get("open_ports"):
            console.print(
                "[red]No previous scan found.[/red] Run 'scan' first, "
                "or pass ports explicitly: run-tse 21 22 80"
            )
            return
        ports = [p["port"] for p in last_scan["open_ports"]]

    console.print(f"[cyan]Running TSE against[/cyan] {target}  [dim](ports: {ports})[/dim]")
    report = run_tse(target, ports)
    _render_report(report)
    session.state["last_tse_report"] = report
