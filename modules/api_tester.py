"""
TRAIN Framework - modules/api_tester.py
REST API endpoint tester and lightweight discovery tool.

Registers:
  api-test <base_url>                -> checks common REST conventions on a base URL
  api-discover <base_url> [wordlist] -> checks a list of common endpoint names

Everything here is read-only HTTP requests (GET/OPTIONS) - no data is ever
written, updated, or deleted on the target. This mirrors what a developer's
own API client (Postman, curl) would do: ask "does this respond, and how?"
It does not attempt authentication bypass, injection, or fuzzing with
attack payloads - only checks whether a named, common endpoint exists and
what methods it advertises.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.tui_engine import Session, register_command

console = Console()

REQUEST_TIMEOUT = 6
USER_AGENT = "TRAIN-Framework-APITester/0.1"

# Common, well-known API path conventions - not a brute-force wordlist,
# just the handful of paths almost every REST API framework uses by default.
COMMON_ENDPOINTS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/health",
    "/healthz",
    "/status",
    "/version",
    "/openapi.json",
    "/swagger.json",
    "/swagger-ui.html",
    "/graphql",
    "/.well-known/openapi.json",
]

HTTP_METHODS_TO_PROBE = ["GET", "OPTIONS"]


@dataclass
class EndpointResult:
    path: str
    status_code: int | None
    allowed_methods: list[str] = field(default_factory=list)
    content_type: str | None = None
    error: str | None = None


def _probe_endpoint(base_url: str, path: str, session: requests.Session) -> EndpointResult:
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
    except requests.RequestException as e:
        return EndpointResult(path=path, status_code=None, error=str(e))

    allowed = []
    try:
        opt_resp = session.options(url, timeout=REQUEST_TIMEOUT)
        allow_header = opt_resp.headers.get("Allow", "")
        if allow_header:
            allowed = [m.strip() for m in allow_header.split(",")]
    except requests.RequestException:
        pass

    return EndpointResult(
        path=path,
        status_code=resp.status_code,
        allowed_methods=allowed,
        content_type=resp.headers.get("Content-Type"),
    )


def run_api_discover(base_url: str, endpoints: list[str] | None = None) -> list[EndpointResult]:
    endpoints = endpoints or COMMON_ENDPOINTS
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    return [_probe_endpoint(base_url, path, session) for path in endpoints]


def _render_discover_results(base_url: str, results: list[EndpointResult]) -> None:
    found = [r for r in results if r.status_code is not None and r.status_code != 404]

    table = Table(title=f"API Discovery — {base_url}")
    table.add_column("Path", style="bold")
    table.add_column("Status")
    table.add_column("Allowed Methods", style="cyan")
    table.add_column("Content-Type", style="dim")

    for r in results:
        if r.error:
            table.add_row(r.path, "[dim]unreachable[/dim]", "-", r.error[:40])
            continue
        status_style = "green" if r.status_code and r.status_code < 400 else "dim"
        table.add_row(
            r.path,
            f"[{status_style}]{r.status_code}[/{status_style}]",
            ", ".join(r.allowed_methods) or "-",
            r.content_type or "-",
        )
    console.print(table)

    if found:
        console.print(f"[green]{len(found)} endpoint(s) responded (non-404).[/green]")
    else:
        console.print("[dim]No common API endpoints responded.[/dim]")


@register_command("api-discover")
def cmd_api_discover(session: Session, args: list[str]) -> None:
    """Usage: api-discover <base_url>"""
    base_url = args[0] if args else session.target
    if not base_url:
        console.print("[red]No target set.[/red] Use 'set target <url>' first, or pass one directly.")
        return
    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url

    console.print(f"[cyan]Probing common API endpoints on[/cyan] {base_url}...")
    results = run_api_discover(base_url)
    _render_discover_results(base_url, results)
    session.state["last_api_discovery"] = results


@register_command("api-test")
def cmd_api_test(session: Session, args: list[str]) -> None:
    """
    Usage: api-test <url>
    Sends a single GET+OPTIONS probe to one specific endpoint and reports
    status code, allowed methods, content-type, and (if JSON) top-level
    response keys - useful for quickly inspecting one known endpoint.
    """
    if not args:
        console.print("[red]Usage:[/red] api-test <url>")
        return

    url = args[0]
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    req_session = requests.Session()
    req_session.headers.update({"User-Agent": USER_AGENT})

    console.print(f"[cyan]Testing[/cyan] {url}...")
    try:
        resp = req_session.get(url, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as e:
        console.print(f"[red]Request failed:[/red] {e}")
        return

    lines = [
        f"[bold]Status:[/bold] {resp.status_code}",
        f"[bold]Content-Type:[/bold] {resp.headers.get('Content-Type', '-')}",
        f"[bold]Response size:[/bold] {len(resp.content)} bytes",
    ]

    try:
        data = resp.json()
        if isinstance(data, dict):
            lines.append(f"[bold]Top-level keys:[/bold] {', '.join(data.keys())}")
        elif isinstance(data, list):
            lines.append(f"[bold]Response:[/bold] JSON array with {len(data)} item(s)")
    except ValueError:
        pass  # not JSON, that's fine

    console.print(Panel("\n".join(lines), title=f"API Test — {url}", border_style="cyan"))
