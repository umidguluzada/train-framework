"""
TRAIN Framework - modules/report_generator.py
Aggregates every finding collected this session into a single HTML report.

Registers: generate-report [output_path]

Pulls together whatever this session has already produced (stored in
session.state by other modules) - port scan, TSE, web audit, compliance,
CVE lookups, log correlation, MITRE mapping, C2 beaconing, dir-brute - and
renders it as one self-contained HTML file. This is purely a formatting/
aggregation step over data TRAIN's own modules already gathered; it does
not run any new scans or checks itself.
"""

from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from core.tui_engine import Session, register_command

console = Console()

DEFAULT_OUTPUT = "train_report.html"

CSS = """
body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 1000px;
       margin: 40px auto; padding: 0 20px; background: #0d1117; color: #c9d1d9; }
h1 { color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px; }
h2 { color: #79c0ff; margin-top: 40px; border-bottom: 1px solid #21262d; padding-bottom: 6px; }
.meta { color: #8b949e; font-size: 0.9em; margin-bottom: 30px; }
table { width: 100%; border-collapse: collapse; margin: 12px 0 24px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #21262d; font-size: 0.92em; }
th { color: #8b949e; font-weight: 600; }
.sev-fail, .sev-finding, .sev-high { color: #f85149; font-weight: 600; }
.sev-warn, .sev-warning, .sev-medium { color: #d29922; }
.sev-pass, .sev-info, .sev-low { color: #3fb950; }
.empty { color: #6e7681; font-style: italic; }
.section { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
           padding: 16px 20px; margin-bottom: 20px; }
code { background: #21262d; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }
"""


def _esc(value) -> str:
    return html.escape(str(value)) if value is not None else ""


def _sev_class(sev: str) -> str:
    return f"sev-{sev.lower()}" if sev else ""


def _render_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return '<p class="empty">No entries.</p>'
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
        for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _section_scan(session: Session) -> str:
    scan = session.state.get("last_scan")
    if not scan or not scan.get("open_ports"):
        return '<div class="section"><h2>Port Scan</h2><p class="empty">No scan run this session.</p></div>'
    rows = [
        [_esc(p.get("port")), _esc(p.get("service_guess", "unknown")), _esc(p.get("banner", "").strip() or "-")]
        for p in scan["open_ports"]
    ]
    return (
        f'<div class="section"><h2>Port Scan — {_esc(scan.get("target"))}</h2>'
        + _render_table(["Port", "Service", "Banner"], rows)
        + "</div>"
    )


def _section_tse(session: Session) -> str:
    tse = session.state.get("last_tse_report")
    if not tse or not tse.findings:
        return '<div class="section"><h2>TSE Audit</h2><p class="empty">No TSE run this session.</p></div>'
    rows = [
        [_esc(f.port), _esc(f.check), f'<span class="{_sev_class(f.severity)}">{_esc(f.result)}</span>', _esc(f.detail)]
        for f in tse.findings
    ]
    return (
        f'<div class="section"><h2>TSE Audit — {_esc(tse.target)}</h2>'
        + _render_table(["Port", "Check", "Result", "Detail"], rows)
        + "</div>"
    )


def _section_web(session: Session) -> str:
    web = session.state.get("last_web_audit")
    if not web:
        return '<div class="section"><h2>Web Audit</h2><p class="empty">No web audit run this session.</p></div>'
    missing = getattr(web, "headers_missing", []) or []
    exposed = getattr(web, "exposed_paths", []) or []
    rows_h = [[_esc(h)] for h in missing]
    rows_e = [[_esc(p), _esc(s)] for p, s in exposed]
    return (
        f'<div class="section"><h2>Web Audit — {_esc(getattr(web, "url", ""))}</h2>'
        f"<h3>Missing Security Headers</h3>" + _render_table(["Header"], rows_h)
        + f"<h3>Exposed Paths</h3>" + _render_table(["Path", "Status"], rows_e)
        + "</div>"
    )


def _section_compliance(session: Session) -> str:
    comp = session.state.get("last_compliance_report")
    if not comp:
        return '<div class="section"><h2>Compliance Audit</h2><p class="empty">No compliance audit run this session.</p></div>'
    rows = [
        [_esc(c.check_id), _esc(c.description), f'<span class="{_sev_class(c.status)}">{_esc(c.status.upper())}</span>', _esc(c.detail)]
        for c in comp.checks
    ]
    return (
        '<div class="section"><h2>Compliance Audit (CIS-inspired)</h2>'
        + _render_table(["ID", "Check", "Status", "Detail"], rows)
        + "</div>"
    )


def _section_cve(session: Session) -> str:
    cves = session.state.get("last_cve_results")
    if not cves:
        return '<div class="section"><h2>CVE Lookup</h2><p class="empty">No CVE lookup run this session.</p></div>'
    rows = [
        [_esc(c.cve_id), f'<span class="{_sev_class(c.severity)}">{_esc(c.severity)}</span>',
         _esc(c.score if c.score is not None else "-"), _esc(c.published), _esc(c.description)]
        for c in cves
    ]
    return (
        '<div class="section"><h2>CVE Lookup</h2>'
        + _render_table(["CVE ID", "Severity", "Score", "Published", "Description"], rows)
        + "</div>"
    )


def _section_logs(session: Session) -> str:
    log_report = session.state.get("last_log_report")
    if not log_report or not log_report.events:
        return '<div class="section"><h2>Log Correlation</h2><p class="empty">No log analysis run this session.</p></div>'
    bf_rows = [[_esc(ip), _esc(count)] for ip, count in log_report.brute_force_candidates.items()]
    event_rows = [[_esc(e.kind), _esc(e.source), _esc(e.detail[:100])] for e in log_report.events[-25:]]
    return (
        f'<div class="section"><h2>Log Correlation ({len(log_report.events)} events)</h2>'
        + "<h3>Brute-Force Candidates</h3>" + _render_table(["Source IP", "Failed Attempts"], bf_rows)
        + "<h3>Recent Events (last 25)</h3>" + _render_table(["Kind", "Source", "Detail"], event_rows)
        + "</div>"
    )


def _section_mitre(session: Session) -> str:
    mitre = session.state.get("last_mitre_report")
    if not mitre or not mitre.mappings:
        return '<div class="section"><h2>MITRE ATT&CK Mapping</h2><p class="empty">No MITRE mapping run this session.</p></div>'
    rows = [
        [f"{_esc(m.technique_id)}<br><small>{_esc(m.technique_name)}</small>", _esc(m.tactic), _esc(m.evidence)]
        for m in mitre.mappings
    ]
    return (
        '<div class="section"><h2>MITRE ATT&CK Mapping</h2>'
        + _render_table(["Technique", "Tactic", "Evidence"], rows)
        + "</div>"
    )


def _section_beacon(session: Session) -> str:
    beacon = session.state.get("last_beacon_report")
    if not beacon or not beacon.candidates:
        return '<div class="section"><h2>C2 Beacon Detection</h2><p class="empty">No beaconing candidates found this session.</p></div>'
    rows = [
        [_esc(b.source), _esc(b.count), f"{b.avg_interval_seconds:.1f}s", f"{b.stddev_seconds:.1f}s"]
        for b in beacon.candidates
    ]
    return (
        '<div class="section"><h2>C2 Beacon Detection</h2>'
        + _render_table(["Source", "Connections", "Avg Interval", "Std Dev"], rows)
        + "</div>"
    )


def _section_dirbrute(session: Session) -> str:
    brute = session.state.get("last_dir_brute")
    if not brute or not brute.found:
        return '<div class="section"><h2>Directory Brute-Force</h2><p class="empty">No dir-brute run this session.</p></div>'
    rows = [[f"/{_esc(r.path)}", _esc(r.status_code), _esc(r.size_bytes)] for r in brute.found]
    return (
        f'<div class="section"><h2>Directory Brute-Force — {_esc(brute.base_url)}</h2>'
        + _render_table(["Path", "Status", "Size"], rows)
        + "</div>"
    )


SECTION_BUILDERS = [
    _section_scan,
    _section_tse,
    _section_web,
    _section_dirbrute,
    _section_compliance,
    _section_cve,
    _section_logs,
    _section_mitre,
    _section_beacon,
]


def build_html_report(session: Session) -> str:
    sections_html = "\n".join(builder(session) for builder in SECTION_BUILDERS)
    target = _esc(session.target or "not set")
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>TRAIN Framework — Pentest Report</title>
<style>{CSS}</style>
</head>
<body>
<h1>TRAIN Framework — Session Report</h1>
<div class="meta">Target: <code>{target}</code> &nbsp;|&nbsp; Generated: {generated_at}</div>
{sections_html}
<div class="meta" style="margin-top:40px;">Generated by TRAIN Framework (Threat Response &amp; Automated Intelligence Network).</div>
</body>
</html>"""


@register_command("generate-report")
def cmd_generate_report(session: Session, args: list[str]) -> None:
    """Usage: generate-report [output_path.html]   (default: train_report.html)"""
    output_path = Path(args[0]) if args else Path(DEFAULT_OUTPUT)

    console.print("[cyan]Aggregating this session's findings into a report...[/cyan]")
    report_html = build_html_report(session)

    try:
        output_path.write_text(report_html, encoding="utf-8")
    except OSError as e:
        console.print(f"[red]Could not write report:[/red] {e}")
        return

    console.print(Panel(
        f"Report written to [bold]{output_path.resolve()}[/bold]\n"
        f"Open it in a browser to view.",
        title="Report Generated", border_style="green",
    ))
