"""
TRAIN Framework - modules/nuclei_engine.py
Nuclei-style YAML template scanner (more capable than cve_lookup.py's
simple template-scan): supports multiple matcher types, AND/OR matcher
conditions, and multiple requests per template.

Registers: nuclei-scan <template.yaml> [target]

Template format (see templates/example-nuclei-template.yaml):

  id: exposed-git-config
  info:
    name: "Exposed .git/config"
    severity: medium
  requests:
    - method: GET
      path: "/.git/config"
      matchers-condition: and   # "and" (default) or "or"
      matchers:
        - type: status
          status: [200]
        - type: word
          part: body
          words: ["[core]"]

Supported matcher types:
  status  - HTTP status code is one of the listed values
  word    - any of the listed words/substrings appears in the response
            (part: body|header, default body)
  regex   - any of the listed regex patterns matches the response
            (part: body|header, default body)

This only sends plain GET/POST requests with the method/path/headers/body
declared in the YAML file itself - no arbitrary code execution, no shell
commands, nothing beyond what any HTTP client already does. It's a
detection tool (does this response match a known pattern?), not an
exploitation framework.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin

import requests
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.tui_engine import Session, register_command

console = Console()

REQUEST_TIMEOUT = 8
USER_AGENT = "TRAIN-Framework-NucleiEngine/0.1"


@dataclass
class RequestResult:
    method: str
    path: str
    matched: bool
    status_code: Optional[int]
    error: Optional[str] = None


@dataclass
class TemplateResult:
    template_id: str
    name: str
    severity: str
    target: str
    request_results: list[RequestResult] = field(default_factory=list)

    @property
    def matched(self) -> bool:
        return any(r.matched for r in self.request_results)


def _load_template(path: Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("Template root must be a YAML mapping.")
    if "requests" not in data:
        raise ValueError("Template must define a 'requests' list.")
    return data


def _eval_matcher(matcher: dict[str, Any], resp: requests.Response) -> bool:
    m_type = matcher.get("type", "word")
    part = matcher.get("part", "body")

    if m_type == "status":
        expected = matcher.get("status", [])
        return resp.status_code in expected

    if part == "header":
        haystack = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    else:
        haystack = resp.text

    if m_type == "word":
        words = matcher.get("words", [])
        return any(w in haystack for w in words)

    if m_type == "regex":
        patterns = matcher.get("regex", [])
        return any(re.search(p, haystack) for p in patterns)

    return False


def _run_request(target: str, req_spec: dict[str, Any], base_headers: dict) -> RequestResult:
    method = req_spec.get("method", "GET").upper()
    path = req_spec.get("path", "/")
    body = req_spec.get("body")
    extra_headers = req_spec.get("headers", {})

    url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    headers = {**base_headers, **extra_headers}

    try:
        resp = requests.request(method, url, headers=headers, data=body, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as e:
        return RequestResult(method=method, path=path, matched=False, status_code=None, error=str(e))

    matchers = req_spec.get("matchers", [])
    condition = req_spec.get("matchers-condition", "and").lower()

    if not matchers:
        matched = True  # no matchers defined -> treat a successful response as a match
    else:
        results = [_eval_matcher(m, resp) for m in matchers]
        matched = all(results) if condition == "and" else any(results)

    return RequestResult(method=method, path=path, matched=matched, status_code=resp.status_code)


def run_nuclei_template(target: str, template_path: Path) -> TemplateResult:
    template = _load_template(template_path)
    info = template.get("info", {})

    result = TemplateResult(
        template_id=template.get("id", template_path.stem),
        name=info.get("name", template_path.stem),
        severity=info.get("severity", "info"),
        target=target,
    )

    base_headers = {"User-Agent": USER_AGENT}
    for req_spec in template.get("requests", []):
        result.request_results.append(_run_request(target, req_spec, base_headers))

    return result


def _severity_style(severity: str) -> str:
    return {"critical": "red bold", "high": "red", "medium": "yellow",
            "low": "green", "info": "dim"}.get(severity.lower(), "white")


def _render_result(result: TemplateResult) -> None:
    style = _severity_style(result.severity)
    verdict = "[red bold]MATCHED[/red bold]" if result.matched else "[dim]no match[/dim]"

    console.print(Panel(
        f"[bold]{result.name}[/bold]  [{style}]({result.severity})[/{style}]\n"
        f"Template ID: {result.template_id}\n"
        f"Target: {result.target}\n"
        f"Verdict: {verdict}",
        title="Nuclei-Style Template Scan", border_style="cyan",
    ))

    table = Table(title="Requests")
    table.add_column("Method")
    table.add_column("Path")
    table.add_column("Status")
    table.add_column("Result")

    for r in result.request_results:
        if r.error:
            table.add_row(r.method, r.path, "-", f"[dim]unreachable: {r.error[:40]}[/dim]")
            continue
        result_style = "red bold" if r.matched else "dim"
        table.add_row(r.method, r.path, str(r.status_code),
                       f"[{result_style}]{'matched' if r.matched else 'no match'}[/{result_style}]")

    console.print(table)


@register_command("nuclei-scan")
def cmd_nuclei_scan(session: Session, args: list[str]) -> None:
    """
    Usage: nuclei-scan <template.yaml> [target]
    Runs a Nuclei-style YAML template against a target (session target if
    not given). Supports multiple requests per template, status/word/regex
    matchers, and and/or matcher conditions. See
    templates/example-nuclei-template.yaml for the format.
    """
    if not args:
        console.print("[red]Usage:[/red] nuclei-scan <template.yaml> [target]")
        return

    template_path = Path(args[0])
    target = args[1] if len(args) > 1 else session.target

    if not template_path.exists():
        console.print(f"[red]Template not found:[/red] {template_path}")
        return
    if not target:
        console.print("[red]No target set.[/red] Use 'set target <url>' first, or pass one directly.")
        return

    console.print(f"[cyan]Running template[/cyan] {template_path.name} [cyan]against[/cyan] {target}...")

    try:
        result = run_nuclei_template(target, template_path)
    except (yaml.YAMLError, ValueError) as e:
        console.print(f"[red]Invalid template:[/red] {e}")
        return

    _render_result(result)
    session.state["last_nuclei_result"] = result
