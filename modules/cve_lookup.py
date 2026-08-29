"""
TRAIN Framework - modules/cve_lookup.py
CVE lookup (NVD API) + YAML template-based configuration scanning.

Registers:
  audit-cve <keyword/product>   -> looks up known CVEs from the NVD public API
  audit-cve --scan-last-tse     -> looks up CVEs for products found by run-tse/scan banners
  template-scan <file.yaml>     -> runs a local YAML-defined check against the session target

This module is purely informational/read-only:
  - The NVD lookup is a plain read against a public government database
    (nvd.nist.gov), the same one every vulnerability scanner references.
  - The YAML template scanner only evaluates simple, declarative checks
    (does a URL path exist? does a banner match a regex?) - it does not
    execute arbitrary code from the YAML file, and it never performs
    exploitation - only detection.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import requests
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.tui_engine import Session, register_command

console = Console()

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT = 10
NVD_RESULTS_PER_PAGE = 8


@dataclass
class CVEEntry:
    cve_id: str
    description: str
    severity: str
    score: Optional[float]
    published: str


def search_nvd(keyword: str, results_limit: int = NVD_RESULTS_PER_PAGE) -> list[CVEEntry]:
    """
    Queries the public NVD REST API for CVEs matching a keyword
    (e.g. a product/version string like "OpenSSH 8.2" or "Apache 2.4.49").
    No API key is required for light usage; NVD rate-limits unauthenticated
    requests, so this module makes a single request per lookup.
    """
    params = {"keywordSearch": keyword, "resultsPerPage": results_limit}
    try:
        resp = requests.get(NVD_API_URL, params=params, timeout=NVD_TIMEOUT,
                             headers={"User-Agent": "TRAIN-Framework-CVELookup/0.1"})
        resp.raise_for_status()
    except requests.RequestException as e:
        raise RuntimeError(f"NVD lookup failed: {e}") from e

    data = resp.json()
    entries: list[CVEEntry] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "?")

        descriptions = cve.get("descriptions", [])
        desc_text = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        metrics = cve.get("metrics", {})
        severity, score = "UNKNOWN", None
        # NVD exposes multiple CVSS versions; prefer the newest available.
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metric_key in metrics and metrics[metric_key]:
                cvss_data = metrics[metric_key][0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity = (
                    metrics[metric_key][0].get("baseSeverity")
                    or cvss_data.get("baseSeverity")
                    or "UNKNOWN"
                )
                break

        entries.append(CVEEntry(
            cve_id=cve_id,
            description=desc_text[:200] + ("..." if len(desc_text) > 200 else ""),
            severity=severity,
            score=score,
            published=cve.get("published", "")[:10],
        ))
    return entries


def _severity_style(severity: str) -> str:
    return {
        "CRITICAL": "red bold",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
    }.get(severity.upper(), "dim")


def _render_cve_results(keyword: str, entries: list[CVEEntry]) -> None:
    if not entries:
        console.print(Panel(f"No CVEs found for [bold]{keyword}[/bold].",
                             title="CVE Lookup", border_style="yellow"))
        return

    table = Table(title=f"CVEs matching '{keyword}'")
    table.add_column("CVE ID", style="bold cyan")
    table.add_column("Severity")
    table.add_column("Score")
    table.add_column("Published")
    table.add_column("Description", style="dim")

    for e in entries:
        style = _severity_style(e.severity)
        table.add_row(
            e.cve_id,
            f"[{style}]{e.severity}[/{style}]",
            f"{e.score:.1f}" if e.score is not None else "-",
            e.published,
            e.description,
        )
    console.print(table)


@register_command("audit-cve")
def cmd_audit_cve(session: Session, args: list[str]) -> None:
    """
    Usage:
      audit-cve <keyword...>       -> search NVD directly, e.g. "audit-cve OpenSSH 8.2"
      audit-cve --from-tse         -> search using banners captured by the last run-tse
    """
    if not args:
        console.print("[red]Usage:[/red] audit-cve <keyword...>  |  audit-cve --from-tse")
        return

    keywords: list[str] = []
    if args == ["--from-tse"]:
        tse_report = session.state.get("last_tse_report")
        if not tse_report or not tse_report.findings:
            console.print("[red]No TSE report found.[/red] Run 'run-tse' first.")
            return
        # Use SSH/HTTP banner text as search keywords (best-effort).
        for f in tse_report.findings:
            if f.check in ("SSH banner", "HTTP Server header") and f.result not in (
                "unreachable", "not disclosed",
            ):
                keywords.append(f.result)
        if not keywords:
            console.print("[yellow]No usable banners found in the last TSE report.[/yellow]")
            return
    else:
        keywords = [" ".join(args)]

    for kw in keywords:
        console.print(f"[cyan]Searching NVD for:[/cyan] {kw}")
        try:
            entries = search_nvd(kw)
        except RuntimeError as e:
            console.print(f"[red]{e}[/red]")
            continue
        _render_cve_results(kw, entries)
        session.state["last_cve_results"] = entries
        time.sleep(1)  # be polite to the unauthenticated NVD rate limit


# ---------------------------------------------------------------------------
# YAML template-based configuration scanner
# ---------------------------------------------------------------------------

@dataclass
class TemplateCheckResult:
    name: str
    matched: bool
    severity: str
    detail: str = ""


def _load_template(path: Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("Template root must be a YAML mapping (id, name, checks, ...).")
    return data


def _run_http_path_check(target: str, check: dict[str, Any]) -> TemplateCheckResult:
    """
    check: {type: http-path, path: "/admin", expect_status: 200,
            match_regex: "optional pattern in body"}
    """
    path = check.get("path", "/")
    expect_status = check.get("expect_status")
    match_regex = check.get("match_regex")

    url = target.rstrip("/") + path
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        resp = requests.get(url, timeout=6, headers={"User-Agent": "TRAIN-Framework-Templates/0.1"})
    except requests.RequestException as e:
        return TemplateCheckResult(name=check.get("name", path), matched=False,
                                    severity="info", detail=f"unreachable: {e}")

    status_ok = expect_status is None or resp.status_code == expect_status
    regex_ok = True
    if match_regex:
        regex_ok = re.search(match_regex, resp.text) is not None

    matched = status_ok and regex_ok
    return TemplateCheckResult(
        name=check.get("name", path),
        matched=matched,
        severity=check.get("severity", "info") if matched else "info",
        detail=f"HTTP {resp.status_code} at {path}",
    )


def run_template(target: str, template_path: Path) -> list[TemplateCheckResult]:
    template = _load_template(template_path)
    results: list[TemplateCheckResult] = []
    for check in template.get("checks", []):
        check_type = check.get("type")
        if check_type == "http-path":
            results.append(_run_http_path_check(target, check))
        else:
            results.append(TemplateCheckResult(
                name=check.get("name", "unknown"), matched=False,
                severity="info", detail=f"unsupported check type: {check_type}",
            ))
    return results


@register_command("template-scan")
def cmd_template_scan(session: Session, args: list[str]) -> None:
    """Usage: template-scan <path/to/template.yaml>"""
    if not args:
        console.print("[red]Usage:[/red] template-scan <path/to/template.yaml>")
        return
    if not session.target:
        console.print("[red]No target set.[/red] Use 'set target <URL>' first.")
        return

    template_path = Path(args[0])
    if not template_path.exists():
        console.print(f"[red]Template not found:[/red] {template_path}")
        return

    try:
        results = run_template(session.target, template_path)
    except (yaml.YAMLError, ValueError) as e:
        console.print(f"[red]Invalid template:[/red] {e}")
        return

    table = Table(title=f"Template Scan — {template_path.name}")
    table.add_column("Check", style="bold")
    table.add_column("Matched")
    table.add_column("Detail", style="dim")
    for r in results:
        matched_style = "red bold" if r.matched else "dim"
        table.add_row(r.name, f"[{matched_style}]{r.matched}[/{matched_style}]", r.detail)
    console.print(table)
