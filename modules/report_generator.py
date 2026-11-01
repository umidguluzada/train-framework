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
import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from core.findings import ReportDocument, collect_report
from core.tui_engine import Session, register_command

console = Console()

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
.risk-grid { display: flex; gap: 16px; margin: 16px 0; }
.risk-box { flex: 1; text-align: center; background: #0d1117; border: 1px solid #30363d;
            border-radius: 8px; padding: 16px; }
.risk-number { font-size: 2em; font-weight: 700; }
.risk-label { color: #8b949e; font-size: 0.85em; margin-top: 4px; }
.toolbar { display: flex; gap: 8px; flex-wrap: wrap; margin: 12px 0; }
.toolbar button, .toolbar input { background: #0d1117; color: #c9d1d9; border: 1px solid #30363d;
  border-radius: 6px; padding: 6px 10px; }
.toolbar button.active { border-color: #58a6ff; color: #58a6ff; }
tr[hidden] { display: none; }
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


def _level_class(level: str) -> str:
    return {"HIGH": "sev-high", "MEDIUM": "sev-medium", "LOW": "sev-low"}.get(level, "sev-pass")


def _section_executive_summary(report: ReportDocument) -> str:
    risk = report.risk
    level_class = _level_class(risk["level"])
    return f"""<div class="section exec-summary">
<h2>Executive Summary</h2>
<div class="risk-grid">
  <div class="risk-box"><div class="risk-number {level_class}">{_esc(risk['level'])}</div><div class="risk-label">Overall Risk ({_esc(risk['score'])})</div></div>
  <div class="risk-box"><div class="risk-number sev-high">{_esc(risk['high'])}</div><div class="risk-label">High</div></div>
  <div class="risk-box"><div class="risk-number sev-medium">{_esc(risk['medium'])}</div><div class="risk-label">Medium</div></div>
  <div class="risk-box"><div class="risk-number sev-pass">{_esc(risk['low'])}</div><div class="risk-label">Low</div></div>
</div>
<p class="empty">Risk score is a weighted count of this session's findings
(High x10 + Medium x4 + Low x1, capped at 100). Informational rows are listed
below and are not added to the score.</p>
</div>"""


def _section_findings(report: ReportDocument) -> str:
    if not report.findings:
        rows = '<tr data-sev="info"><td colspan="4" class="empty">No findings recorded this session.</td></tr>'
    else:
        rows = "".join(
            "<tr data-sev=\"{sev}\"><td>{source}</td><td class=\"{cls}\">{sev}</td><td>{title}</td><td>{detail}</td></tr>".format(
                sev=_esc(item.severity),
                source=_esc(item.source),
                cls=_sev_class(item.severity),
                title=_esc(item.title),
                detail=_esc(item.detail),
            )
            for item in report.findings
        )
    return f"""<div class="section">
<h2>Findings</h2>
<div class="toolbar">
  <button type="button" class="active" data-filter="all">All</button>
  <button type="button" data-filter="high">High</button>
  <button type="button" data-filter="medium">Medium</button>
  <button type="button" data-filter="low">Low</button>
  <button type="button" data-filter="info">Info</button>
  <input id="finding-filter" type="search" placeholder="Filter findings" aria-label="Filter findings">
</div>
<table id="findings"><thead><tr><th>Source</th><th>Severity</th><th>Title</th><th>Detail</th></tr></thead>
<tbody>{rows}</tbody></table>
</div>
<script>
(function () {{
  const input = document.getElementById("finding-filter");
  const buttons = document.querySelectorAll("[data-filter]");
  const rows = document.querySelectorAll("#findings tbody tr");
  let active = "all";
  function apply() {{
    const query = (input.value || "").toLowerCase();
    rows.forEach(function (row) {{
      const sevOk = active === "all" || row.dataset.sev === active;
      const textOk = !query || row.innerText.toLowerCase().indexOf(query) !== -1;
      row.hidden = !(sevOk && textOk);
    }});
  }}
  buttons.forEach(function (button) {{
    button.addEventListener("click", function () {{
      buttons.forEach(function (item) {{ item.classList.remove("active"); }});
      button.classList.add("active");
      active = button.dataset.filter;
      apply();
    }});
  }});
  input.addEventListener("input", apply);
}})();
</script>"""


DETAIL_BUILDERS = [
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
    report = collect_report(session)
    sections_html = "\n".join([
        _section_executive_summary(report),
        _section_findings(report),
        *(builder(session) for builder in DETAIL_BUILDERS),
    ])
    target = _esc(report.target or "not set")
    generated_at = _esc(report.generated_at)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>TRAIN Framework — Session Report</title>
<style>{CSS}</style>
</head>
<body>
<h1>TRAIN Framework — Session Report</h1>
<div class="meta">Target: <code>{target}</code> &nbsp;|&nbsp; Generated: {generated_at}</div>
{sections_html}
<div class="meta" style="margin-top:40px;">Generated by TRAIN Framework { _esc(report.version) } (Threat Response &amp; Automated Intelligence Network).</div>
</body>
</html>"""


def _report_paths(arg: str | None) -> tuple[Path, Path, Path]:
    if not arg:
        base = Path("train_report")
    else:
        path = Path(arg)
        base = path.with_suffix("") if path.suffix.lower() in {".html", ".json", ".pdf"} else path
    return base.with_suffix(".html"), base.with_suffix(".json"), base.with_suffix(".pdf")


def write_json_report(session: Session, output_path: Path) -> ReportDocument:
    report = collect_report(session)
    output_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    session.state["last_report"] = report
    return report


@register_command("generate-report")
def cmd_generate_report(session: Session, args: list[str]) -> None:
    """Usage: generate-report [name.html]   Writes HTML, JSON, and PDF (default: train_report.*)."""
    html_path, json_path, pdf_path = _report_paths(args[0] if args else None)
    console.print("[cyan]Aggregating this session's findings...[/cyan]")
    try:
        html_path.write_text(build_html_report(session), encoding="utf-8")
        write_json_report(session, json_path)
    except OSError as exc:
        console.print(f"[red]Could not write report:[/red] {exc}")
        return

    pdf_note = f"PDF written to [bold]{pdf_path.resolve()}[/bold]"
    try:
        _build_pdf_report(session, pdf_path)
    except ImportError:
        pdf_note = "PDF skipped. Install reportlab to write the PDF summary."
    except Exception as exc:  # noqa: BLE001 - keep HTML and JSON if PDF rendering fails
        pdf_note = f"PDF skipped: {exc}"

    console.print(Panel(
        f"HTML written to [bold]{html_path.resolve()}[/bold]\n"
        f"JSON written to [bold]{json_path.resolve()}[/bold]\n"
        f"{pdf_note}",
        title="Report Generated", border_style="green",
    ))


def _build_pdf_report(session: Session, output_path: Path) -> None:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table as RLTable, TableStyle,
    )

    report = collect_report(session)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TrainTitle", parent=styles["Title"], textColor=colors.HexColor("#0f2744"))
    heading_style = ParagraphStyle(
        "TrainHeading", parent=styles["Heading2"], textColor=colors.HexColor("#0f2744"),
        spaceBefore=14, spaceAfter=8,
    )
    normal = styles["BodyText"]
    cell_style = ParagraphStyle("Cell", parent=styles["BodyText"], fontSize=8, leading=10)
    header_style = ParagraphStyle(
        "CellHeader", parent=cell_style, textColor=colors.white, fontName="Helvetica-Bold",
    )

    def _on_page(canvas, doc) -> None:
        canvas.saveState()
        canvas.setFillColor(colors.HexColor("#0f2744"))
        canvas.rect(0, letter[1] - 36, letter[0], 36, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 10)
        canvas.drawString(48, letter[1] - 23, f"TRAIN Framework  {report.version}")
        canvas.setFillColor(colors.HexColor("#5c6b7a"))
        canvas.setFont("Helvetica", 8)
        canvas.drawString(48, 24, "Session summary")
        canvas.drawRightString(letter[0] - 48, 24, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        str(output_path), pagesize=letter,
        topMargin=0.8 * inch, bottomMargin=0.7 * inch,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
    )
    level_color = {
        "HIGH": colors.HexColor("#c0392b"),
        "MEDIUM": colors.HexColor("#d68910"),
        "LOW": colors.HexColor("#1e8449"),
    }.get(report.risk["level"], colors.HexColor("#1e8449"))

    story = [
        Paragraph("Session summary", title_style),
        Paragraph(
            f"Target: {report.target or 'not set'}<br/>Generated: {report.generated_at}",
            normal,
        ),
        Spacer(1, 12),
        Paragraph("Risk", heading_style),
    ]
    summary = RLTable(
        [
            ["Overall", "Score", "High", "Medium", "Low"],
            [
                report.risk["level"], str(report.risk["score"]),
                str(report.risk["high"]), str(report.risk["medium"]), str(report.risk["low"]),
            ],
        ],
        colWidths=[1.4 * inch] * 5,
    )
    summary.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f2744")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("TEXTCOLOR", (0, 1), (0, 1), level_color),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (0, 1), "Helvetica-Bold"),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#f4f7fb")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d7de")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(summary)
    story.append(Spacer(1, 12))
    story.append(Paragraph("Findings", heading_style))

    if not report.findings:
        story.append(Paragraph("No findings recorded this session.", normal))
    else:
        header = [Paragraph(text, header_style) for text in ("Source", "Severity", "Title", "Detail")]
        body = [[
            Paragraph(item.source, cell_style),
            Paragraph(item.severity, cell_style),
            Paragraph(item.title, cell_style),
            Paragraph(item.detail[:240], cell_style),
        ] for item in report.findings]
        table = RLTable([header] + body, colWidths=[1.1 * inch, 0.8 * inch, 2.2 * inch, 3.1 * inch], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f2744")),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d0d7de")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f7fb")]),
        ]))
        story.append(table)

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)


@register_command("generate-pdf-report")
def cmd_generate_pdf_report(session: Session, args: list[str]) -> None:
    """
    Usage: generate-pdf-report [output_path.pdf]   (default: train_report.pdf)
    Writes the styled PDF summary: risk counts plus the normalized findings table.
    """
    output_path = Path(args[0]) if args else Path("train_report.pdf")

    console.print("[cyan]Building PDF report...[/cyan]")
    try:
        _build_pdf_report(session, output_path)
    except ImportError:
        console.print("[red]The 'reportlab' package is required:[/red] pip install reportlab --break-system-packages")
        return
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Could not build PDF report:[/red] {e}")
        return

    console.print(Panel(
        f"PDF report written to [bold]{output_path.resolve()}[/bold]",
        title="PDF Report Generated", border_style="green",
    ))
