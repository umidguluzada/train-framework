"""
TRAIN Framework - modules/log_engine.py
Log correlation engine.

Registers: audit-logs <path> [--format auth|syslog|nginx|json-alerts]

Reads a local log file (auth.log, syslog, an nginx access log, or a
JSON-lines file of IDS alerts produced by native_modules/sniffer.go) and
extracts simple, well-known patterns:
  - repeated failed SSH logins from the same source (possible brute force)
  - sudo/su privilege-escalation attempts
  - IDS alerts already captured via 'sniff' (session.state["sniffer_alerts"])

This is pattern *matching* over text already on disk - it never modifies
logs, never executes anything found inside them, and never reaches out to
the network. Findings are exported as structured events that
threat_hunter.py can map to MITRE ATT&CK techniques.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.tui_engine import Session, register_command

console = Console()

# --- Pattern library -------------------------------------------------------

FAILED_SSH_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port \d+"
)
ACCEPTED_SSH_RE = re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+) port \d+")
SUDO_RE = re.compile(r"sudo:\s*(?P<user>\S+)\s*:.*COMMAND=(?P<cmd>.+)")
NGINX_ACCESS_RE = re.compile(
    r'(?P<ip>[\d.]+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\w+) (?P<path>\S+) [^"]*" (?P<status>\d{3})'
)


@dataclass
class LogEvent:
    kind: str          # "ssh_failed_login" | "ssh_success" | "sudo_command" | "http_request" | "ids_alert" | ...
    source: str         # IP or user, whichever is most relevant
    detail: str
    raw_line: str = ""
    timestamp: Optional[datetime] = None  # parsed when the source format includes one (e.g. nginx)


@dataclass
class LogReport:
    events: list[LogEvent] = field(default_factory=list)
    brute_force_candidates: dict[str, int] = field(default_factory=dict)


def parse_auth_log(text: str) -> list[LogEvent]:
    events = []
    for line in text.splitlines():
        m = FAILED_SSH_RE.search(line)
        if m:
            events.append(LogEvent("ssh_failed_login", m.group("ip"),
                                    f"failed login as '{m.group('user')}'", line))
            continue
        m = ACCEPTED_SSH_RE.search(line)
        if m:
            events.append(LogEvent("ssh_success", m.group("ip"),
                                    f"successful login as '{m.group('user')}'", line))
            continue
        m = SUDO_RE.search(line)
        if m:
            events.append(LogEvent("sudo_command", m.group("user"),
                                    f"ran: {m.group('cmd').strip()}", line))
    return events


def parse_nginx_access_log(text: str) -> list[LogEvent]:
    events = []
    for line in text.splitlines():
        m = NGINX_ACCESS_RE.search(line)
        if m:
            ts = None
            try:
                # nginx default log_format timestamp: 27/Aug/2026:10:00:01 +0000
                ts = datetime.strptime(m.group("ts").split()[0], "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                pass
            events.append(LogEvent(
                "http_request", m.group("ip"),
                f"{m.group('method')} {m.group('path')} -> {m.group('status')}", line,
                timestamp=ts,
            ))
    return events


def parse_json_alerts(text: str) -> list[LogEvent]:
    """Parses JSON-lines output from native_modules/sniffer.go (or a saved copy of it)."""
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue
        events.append(LogEvent(
            "ids_alert", alert.get("src_ip", "?"),
            f"sid={alert.get('sid')} {alert.get('msg')} -> {alert.get('dst_ip')}:{alert.get('dst_port')}",
            line,
        ))
    return events


# --- Windows Event Log (text export) parsers --------------------------------
#
# These parse the plain-text export format produced by:
#   wevtutil qe "Microsoft-Windows-PowerShell/Operational" /f:text > ps.log
#   wevtutil qe Security /f:text > security.log
# (or the equivalent Get-WinEvent | Format-List export from PowerShell).
# Each event is a blank-line-separated block of "Field: value" lines - the
# same shape wevtutil's /f:text output always produces.

WIN_EVENT_BLOCK_RE = re.compile(r"Event\[\d+\]:", re.MULTILINE)


def _split_event_blocks(text: str) -> list[str]:
    """Splits a wevtutil /f:text export into individual event blocks."""
    blocks = WIN_EVENT_BLOCK_RE.split(text)
    return [b for b in blocks if b.strip()]


def _extract_field(block: str, field_name: str) -> Optional[str]:
    m = re.search(rf"^\s*{re.escape(field_name)}\s*[:=]\s*(.+)$", block, re.MULTILINE)
    return m.group(1).strip() if m else None


def _extract_message_field(block: str) -> Optional[str]:
    """
    The 'Message' field in wevtutil /f:text output is often multi-line
    (e.g. the full PowerShell script block text follows on subsequent
    lines) - this captures everything after 'Message:' to the end of
    the event block, not just the first line.
    """
    m = re.search(r"^\s*Message\s*[:=]\s*(.+)$", block, re.MULTILINE | re.DOTALL)
    return m.group(1).strip() if m else None


def parse_powershell_log(text: str) -> list[LogEvent]:
    """
    Parses PowerShell Operational log exports, focused on Event ID 4104
    (Script Block Logging) - which records the actual script text that was
    executed. Useful for spotting obfuscated/encoded commands, download
    cradles, or other suspicious script content.
    """
    events = []
    for block in _split_event_blocks(text):
        event_id = _extract_field(block, "Event ID")
        if event_id != "4104":
            continue

        script_text = _extract_message_field(block) or _extract_field(block, "ScriptBlockText") or ""
        user = _extract_field(block, "User") or _extract_field(block, "Sid") or "unknown"

        suspicious_markers = [
            "-enc", "-encodedcommand", "invoke-expression", "iex ", "downloadstring",
            "frombase64string", "bypass", "hidden", "-nop",
        ]
        lowered = script_text.lower()
        flagged = [m for m in suspicious_markers if m in lowered]

        detail = script_text[:150] + ("..." if len(script_text) > 150 else "")
        if flagged:
            detail = f"[suspicious markers: {', '.join(flagged)}] {detail}"

        events.append(LogEvent("powershell_scriptblock", user, detail, block.strip()[:300]))
    return events


def parse_lsass_access_log(text: str) -> list[LogEvent]:
    """
    Parses Security log exports for Event ID 4656 (a handle was requested
    to an object) and 4663 (an attempt was made to access an object),
    filtered to entries mentioning lsass.exe - the classic target of
    credential-dumping tools (e.g. Mimikatz-style attacks read LSASS
    process memory to extract credentials).
    """
    events = []
    for block in _split_event_blocks(text):
        event_id = _extract_field(block, "Event ID")
        if event_id not in ("4656", "4663"):
            continue
        if "lsass.exe" not in block.lower():
            continue

        process = _extract_field(block, "Process Name") or "unknown process"
        user = _extract_field(block, "Account Name") or _extract_field(block, "Subject") or "unknown"
        access_mask = _extract_field(block, "Accesses") or _extract_field(block, "Access Mask") or ""

        events.append(LogEvent(
            "lsass_access_attempt", user,
            f"Event {event_id}: {process} requested access to lsass.exe "
            f"({access_mask})".strip(),
            block.strip()[:300],
        ))
    return events


PARSERS = {
    "auth": parse_auth_log,
    "syslog": parse_auth_log,   # syslog often contains the same auth lines
    "nginx": parse_nginx_access_log,
    "json-alerts": parse_json_alerts,
    "powershell": parse_powershell_log,
    "lsass": parse_lsass_access_log,
}


def _detect_brute_force(events: list[LogEvent], threshold: int = 5) -> dict[str, int]:
    fail_counter: Counter[str] = Counter()
    for e in events:
        if e.kind == "ssh_failed_login":
            fail_counter[e.source] += 1
    return {ip: count for ip, count in fail_counter.items() if count >= threshold}


def _detect_suspicious_powershell(events: list[LogEvent]) -> list[LogEvent]:
    return [e for e in events if e.kind == "powershell_scriptblock" and "suspicious markers" in e.detail]


def run_log_correlation(path: Path, fmt: str) -> LogReport:
    parser = PARSERS.get(fmt)
    if not parser:
        raise ValueError(f"Unknown format: {fmt} (use: {', '.join(PARSERS)})")

    text = path.read_text(encoding="utf-8", errors="replace")
    events = parser(text)
    report = LogReport(events=events)
    report.brute_force_candidates = _detect_brute_force(events)
    return report


def _render_report(report: LogReport) -> None:
    if not report.events:
        console.print(Panel("No recognizable events found in this log.",
                             title="Log Correlation", border_style="yellow"))
        return

    kind_counts = Counter(e.kind for e in report.events)
    summary = "  ".join(f"{k}: {v}" for k, v in kind_counts.items())
    console.print(Panel(summary, title=f"Events found ({len(report.events)} total)", border_style="cyan"))

    if report.brute_force_candidates:
        table = Table(title="Possible Brute-Force Sources")
        table.add_column("Source IP", style="red bold")
        table.add_column("Failed attempts")
        for ip, count in sorted(report.brute_force_candidates.items(), key=lambda x: -x[1]):
            table.add_row(ip, str(count))
        console.print(table)

    suspicious_ps = _detect_suspicious_powershell(report.events)
    if suspicious_ps:
        ps_table = Table(title="Suspicious PowerShell Script Blocks")
        ps_table.add_column("User", style="red bold")
        ps_table.add_column("Detail", style="dim")
        for e in suspicious_ps:
            ps_table.add_row(e.source, e.detail[:100])
        console.print(ps_table)

    # Show a small sample of the most recent events for context.
    sample_table = Table(title="Recent Events (sample)")
    sample_table.add_column("Kind", style="bold")
    sample_table.add_column("Source")
    sample_table.add_column("Detail", style="dim")
    for e in report.events[-10:]:
        sample_table.add_row(e.kind, e.source, e.detail[:80])
    console.print(sample_table)


@register_command("audit-logs")
def cmd_audit_logs(session: Session, args: list[str]) -> None:
    """
    Usage:
      audit-logs <path> [--format auth|syslog|nginx|json-alerts]
      (default format: auth)
    """
    if not args:
        console.print("[red]Usage:[/red] audit-logs <path> [--format auth|syslog|nginx|json-alerts]")
        return

    fmt = "auth"
    if "--format" in args:
        idx = args.index("--format")
        if idx + 1 < len(args):
            fmt = args[idx + 1]
            args = args[:idx] + args[idx + 2:]

    path = Path(args[0])
    if not path.exists():
        console.print(f"[red]Log file not found:[/red] {path}")
        return

    try:
        report = run_log_correlation(path, fmt)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        return

    _render_report(report)
    session.state["last_log_report"] = report
