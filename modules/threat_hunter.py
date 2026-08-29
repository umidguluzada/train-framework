"""
TRAIN Framework - modules/threat_hunter.py
MITRE ATT&CK mapping engine + C2 beaconing detection.

Registers:
  hunt-mitre       -> maps findings already gathered this session to MITRE
                       ATT&CK techniques
  hunt-beacon      -> analyzes timestamped connection logs for periodic
                       "beaconing" patterns (a classic C2 communication
                       signature: malware checking in with its controller
                       at regular intervals)

Takes the structured findings already produced by other TRAIN modules this
session (log_engine's LogReport, script_engine's TSEReport, bridge's IDS
alerts) and maps recognizable patterns to MITRE ATT&CK techniques. This is
a lookup/classification step over data already gathered - it does not
collect any new data itself and does not touch the network.

The mapping table here is intentionally small and clearly sourced (each
entry cites the technique ID so the user can look it up on
attack.mitre.org for the authoritative description).

Beaconing detection is purely statistical: it looks at the *timing*
pattern of connections already recorded in a log (from log_engine's
http_request events) and flags sources whose inter-connection intervals
are unusually regular (low variance) - a pattern normal human browsing
essentially never produces, but scheduled check-ins do. This is a
detection heuristic over existing log data, not network monitoring.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.tui_engine import Session, register_command

console = Console()


@dataclass
class MitreMapping:
    technique_id: str
    technique_name: str
    tactic: str
    evidence: str


@dataclass
class MitreReport:
    mappings: list[MitreMapping] = field(default_factory=list)


def _map_log_report(log_report) -> list[MitreMapping]:
    mappings = []
    if getattr(log_report, "brute_force_candidates", None):
        for ip, count in log_report.brute_force_candidates.items():
            mappings.append(MitreMapping(
                technique_id="T1110.001",
                technique_name="Brute Force: Password Guessing",
                tactic="Credential Access",
                evidence=f"{count} failed SSH logins from {ip}",
            ))
    for e in getattr(log_report, "events", []):
        if e.kind == "sudo_command":
            mappings.append(MitreMapping(
                technique_id="T1548.003",
                technique_name="Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
                tactic="Privilege Escalation / Defense Evasion",
                evidence=f"{e.source}: {e.detail}",
            ))
    return mappings


def _map_tse_report(tse_report) -> list[MitreMapping]:
    mappings = []
    for f in getattr(tse_report, "findings", []):
        if f.check == "FTP anonymous login" and f.result == "ALLOWED":
            mappings.append(MitreMapping(
                technique_id="T1078",
                technique_name="Valid Accounts",
                tactic="Initial Access / Defense Evasion",
                evidence=f"Port {f.port}: anonymous FTP login succeeded",
            ))
        if f.check == "HTTP Server header" and f.severity == "warning":
            mappings.append(MitreMapping(
                technique_id="T1592.002",
                technique_name="Gather Victim Host Information: Software",
                tactic="Reconnaissance",
                evidence=f"Port {f.port}: Server header discloses '{f.result}'",
            ))
        if f.check == "SSH banner" and f.severity == "finding":
            mappings.append(MitreMapping(
                technique_id="T1592.002",
                technique_name="Gather Victim Host Information: Software",
                tactic="Reconnaissance",
                evidence=f"Port {f.port}: outdated SSH protocol advertised ({f.result})",
            ))
    return mappings


def _map_ids_alerts(alerts: list[dict]) -> list[MitreMapping]:
    mappings = []
    for alert in alerts:
        msg = (alert.get("msg") or "").lower()
        if "ssh" in msg:
            mappings.append(MitreMapping(
                technique_id="T1021.004",
                technique_name="Remote Services: SSH",
                tactic="Lateral Movement",
                evidence=f"IDS alert sid={alert.get('sid')}: {alert.get('msg')} "
                         f"from {alert.get('src_ip')}",
            ))
        elif "scan" in msg or "nmap" in msg:
            mappings.append(MitreMapping(
                technique_id="T1595.001",
                technique_name="Active Scanning: Scanning IP Blocks",
                tactic="Reconnaissance",
                evidence=f"IDS alert sid={alert.get('sid')}: {alert.get('msg')} "
                         f"from {alert.get('src_ip')}",
            ))
    return mappings


def build_mitre_report(session: Session) -> MitreReport:
    report = MitreReport()

    log_report = session.state.get("last_log_report")
    if log_report:
        report.mappings.extend(_map_log_report(log_report))

    tse_report = session.state.get("last_tse_report")
    if tse_report:
        report.mappings.extend(_map_tse_report(tse_report))

    ids_alerts = session.state.get("sniffer_alerts")
    if ids_alerts:
        report.mappings.extend(_map_ids_alerts(ids_alerts))

    beacon_report = session.state.get("last_beacon_report")
    if beacon_report:
        for b in beacon_report.candidates:
            report.mappings.append(MitreMapping(
                technique_id="T1071",
                technique_name="Application Layer Protocol (C2)",
                tactic="Command and Control",
                evidence=f"{b.source}: {b.count} connections, avg interval "
                         f"{b.avg_interval_seconds:.1f}s (stddev {b.stddev_seconds:.1f}s) - "
                         f"regular enough to suggest automated beaconing",
            ))

    return report


def _render_report(report: MitreReport) -> None:
    if not report.mappings:
        console.print(Panel(
            "No mappable findings yet. Run 'audit-logs', 'run-tse', or capture some "
            "'sniff' alerts first, then run 'hunt-mitre' again.",
            title="MITRE ATT&CK Mapping", border_style="yellow",
        ))
        return

    table = Table(title="MITRE ATT&CK Mapping")
    table.add_column("Technique", style="bold cyan")
    table.add_column("Tactic")
    table.add_column("Evidence", style="dim")

    seen = set()
    for m in report.mappings:
        key = (m.technique_id, m.evidence)
        if key in seen:
            continue
        seen.add(key)
        table.add_row(f"{m.technique_id}\n{m.technique_name}", m.tactic, m.evidence)

    console.print(table)
    console.print("[dim]Technique IDs reference attack.mitre.org for full details.[/dim]")


@register_command("hunt-mitre")
def cmd_hunt_mitre(session: Session, args: list[str]) -> None:
    """Usage: hunt-mitre   (maps findings already gathered this session)"""
    report = build_mitre_report(session)
    _render_report(report)
    session.state["last_mitre_report"] = report


# ---------------------------------------------------------------------------
# C2 beaconing detection
# ---------------------------------------------------------------------------

BEACON_MIN_CONNECTIONS = 5      # need at least this many connections to judge regularity
BEACON_MAX_STDDEV_RATIO = 0.15  # stddev/mean below this ratio looks "too regular" for a human


@dataclass
class BeaconCandidate:
    source: str
    count: int
    avg_interval_seconds: float
    stddev_seconds: float


@dataclass
class BeaconReport:
    candidates: list[BeaconCandidate] = field(default_factory=list)
    sources_analyzed: int = 0


def detect_beaconing(events: list, min_connections: int = BEACON_MIN_CONNECTIONS) -> BeaconReport:
    """
    Groups http_request-style events (must have a timestamp) by source IP,
    computes the gaps between consecutive connection times, and flags
    sources whose gaps are unusually consistent (low relative standard
    deviation) - the statistical signature of a scheduled check-in rather
    than organic human browsing.
    """
    by_source: dict[str, list[datetime]] = {}
    for e in events:
        ts = getattr(e, "timestamp", None)
        if ts is None:
            continue
        by_source.setdefault(e.source, []).append(ts)

    report = BeaconReport(sources_analyzed=len(by_source))

    for source, timestamps in by_source.items():
        if len(timestamps) < min_connections:
            continue

        timestamps.sort()
        gaps = [
            (timestamps[i + 1] - timestamps[i]).total_seconds()
            for i in range(len(timestamps) - 1)
        ]
        gaps = [g for g in gaps if g > 0]  # ignore same-second duplicates
        if len(gaps) < min_connections - 1:
            continue

        mean_gap = statistics.mean(gaps)
        stddev_gap = statistics.pstdev(gaps)
        if mean_gap == 0:
            continue

        ratio = stddev_gap / mean_gap
        if ratio <= BEACON_MAX_STDDEV_RATIO:
            report.candidates.append(BeaconCandidate(
                source=source,
                count=len(timestamps),
                avg_interval_seconds=mean_gap,
                stddev_seconds=stddev_gap,
            ))

    return report


def _render_beacon_report(report: BeaconReport) -> None:
    if not report.candidates:
        console.print(Panel(
            f"No beaconing pattern detected across {report.sources_analyzed} source(s) analyzed. "
            f"(Needs >= {BEACON_MIN_CONNECTIONS} timestamped connections per source with a "
            f"consistent interval.)",
            title="C2 Beacon Detection", border_style="yellow",
        ))
        return

    table = Table(title="Possible C2 Beaconing Sources")
    table.add_column("Source", style="red bold")
    table.add_column("Connections", justify="right")
    table.add_column("Avg Interval", justify="right")
    table.add_column("Std Dev", justify="right")

    for b in sorted(report.candidates, key=lambda c: -c.count):
        table.add_row(
            b.source, str(b.count),
            f"{b.avg_interval_seconds:.1f}s", f"{b.stddev_seconds:.1f}s",
        )
    console.print(table)
    console.print(
        "[dim]Low standard deviation relative to the average interval suggests an "
        "automated, scheduled check-in rather than organic browsing. This is a "
        "heuristic, not proof - verify manually before acting on it.[/dim]"
    )


@register_command("hunt-beacon")
def cmd_hunt_beacon(session: Session, args: list[str]) -> None:
    """
    Usage: hunt-beacon
    Analyzes timestamped connections from the last 'audit-logs --format nginx'
    run for periodic beaconing patterns. Run 'audit-logs <path> --format nginx'
    first.
    """
    log_report = session.state.get("last_log_report")
    if not log_report or not log_report.events:
        console.print(
            "[yellow]No log data to analyze.[/yellow] Run "
            "'audit-logs <path> --format nginx' first (needs timestamped events), "
            "then 'hunt-beacon'."
        )
        return

    timestamped_events = [e for e in log_report.events if getattr(e, "timestamp", None)]
    if not timestamped_events:
        console.print(
            "[yellow]The last log report has no timestamped events.[/yellow] "
            "Beaconing detection currently needs the 'nginx' format (timestamps parsed)."
        )
        return

    console.print(f"[cyan]Analyzing {len(timestamped_events)} timestamped connection(s) for beaconing...[/cyan]")
    report = detect_beaconing(timestamped_events)
    _render_beacon_report(report)
    session.state["last_beacon_report"] = report
