"""
TRAIN Framework - modules/web_auditor.py
Passive web server / web application configuration auditor.

Registers the "audit-web" command. This module ONLY sends plain, harmless
HTTP GET requests - the same kind any browser sends - and inspects:

  1. Security-relevant response headers (CSP, HSTS, X-Frame-Options, etc.)
  2. TLS certificate details, when the target is HTTPS
  3. Well-known paths that are commonly left exposed by misconfiguration
     (e.g. .git/config, backup files, phpinfo.php) - this is a read-only
     "does this URL respond with something other than 404?" check, not an
     exploitation attempt. It never sends injection payloads (no SQLi/XSS
     probing) - that is intentionally out of scope for this module.

This mirrors what widely-used open tools like Nikto do for the header/
misconfiguration side of an audit, kept here in a single readable module.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.tui_engine import Session, register_command

console = Console()

DEFAULT_TIMEOUT = 8
USER_AGENT = "TRAIN-Framework-WebAuditor/0.1 (+educational-purple-team-tool)"

# Headers we check for, with a short note on why each matters.
SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS; missing allows protocol downgrade attacks.",
    "Content-Security-Policy": "Restricts sources of scripts/styles; mitigates XSS impact.",
    "X-Frame-Options": "Prevents clickjacking via iframes.",
    "X-Content-Type-Options": "Prevents MIME-sniffing (should be 'nosniff').",
    "Referrer-Policy": "Controls how much referrer info leaks to other sites.",
    "Permissions-Policy": "Restricts access to browser features (camera, geo, etc.).",
}

# Well-known paths that are commonly left exposed by misconfiguration.
# Purely read-only GET requests - no parameters, no payloads.
WELL_KNOWN_PATHS = [
    ".git/config",
    ".env",
    "robots.txt",
    "phpinfo.php",
    "backup.zip",
    "backup.sql",
    ".DS_Store",
    "wp-config.php.bak",
    "server-status",
    ".well-known/security.txt",
]


@dataclass
class WebAuditResult:
    url: str
    status_code: Optional[int] = None
    headers_present: dict[str, str] = field(default_factory=dict)
    headers_missing: list[str] = field(default_factory=list)
    exposed_paths: list[tuple[str, int]] = field(default_factory=list)
    tls_info: Optional[dict] = None
    error: Optional[str] = None


def _normalize_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


def _check_headers(resp: requests.Response) -> tuple[dict[str, str], list[str]]:
    present, missing = {}, []
    for header, _hint in SECURITY_HEADERS.items():
        value = resp.headers.get(header)
        if value:
            present[header] = value
        else:
            missing.append(header)
    return present, missing


def _get_tls_info(hostname: str, port: int = 443) -> Optional[dict]:
    """Connects to the host and reads basic certificate metadata (no exploitation)."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=DEFAULT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                expires = None
                if not_after:
                    expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                        tzinfo=timezone.utc
                    )
                issuer = dict(x[0] for x in cert.get("issuer", []))
                return {
                    "issuer": issuer.get("organizationName", issuer.get("commonName", "unknown")),
                    "expires": expires.isoformat() if expires else "unknown",
                    "expired": (expires is not None and expires < datetime.now(timezone.utc)),
                    "tls_version": ssock.version(),
                }
    except (ssl.SSLError, socket.error, socket.timeout, ValueError):
        return None


def _check_well_known_paths(base_url: str, session: requests.Session) -> list[tuple[str, int]]:
    """
    Sends a plain GET to each well-known path and records ones that don't
    return 404 (i.e. something is actually there). Purely observational -
    no request bodies, no parameters, no attempt to read/exfiltrate content
    beyond the status code and a short content preview.
    """
    found = []
    for path in WELL_KNOWN_PATHS:
        url = urljoin(base_url if base_url.endswith("/") else base_url + "/", path)
        try:
            resp = session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
            if resp.status_code != 404:
                found.append((path, resp.status_code))
        except requests.RequestException:
            continue
    return found


def run_web_audit(target: str) -> WebAuditResult:
    url = _normalize_url(target)
    result = WebAuditResult(url=url)

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    try:
        resp = session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
    except requests.RequestException as e:
        result.error = str(e)
        return result

    result.status_code = resp.status_code
    result.headers_present, result.headers_missing = _check_headers(resp)

    parsed = urlparse(url)
    if parsed.scheme == "https":
        result.tls_info = _get_tls_info(parsed.hostname, parsed.port or 443)

    result.exposed_paths = _check_well_known_paths(url, session)
    return result


def _render_result(result: WebAuditResult) -> None:
    if result.error:
        console.print(Panel(f"[red]Could not reach {result.url}:[/red] {result.error}",
                             title="Web Audit", border_style="red"))
        return

    console.print(Panel(
        f"[bold]{result.url}[/bold]  ->  HTTP {result.status_code}",
        title="Web Audit", border_style="cyan"
    ))

    # Security headers table
    table = Table(title="Security Headers")
    table.add_column("Header", style="bold")
    table.add_column("Status")
    table.add_column("Value / Note", style="dim")

    for header, value in result.headers_present.items():
        display_value = value if len(value) < 60 else value[:57] + "..."
        table.add_row(header, "[green]present[/green]", display_value)
    for header in result.headers_missing:
        table.add_row(header, "[red]missing[/red]", SECURITY_HEADERS[header])

    console.print(table)

    # TLS info
    if result.tls_info:
        tls = result.tls_info
        expiry_style = "red" if tls["expired"] else "green"
        console.print(Panel(
            f"Issuer: {tls['issuer']}\n"
            f"TLS version: {tls['tls_version']}\n"
            f"Expires: [{expiry_style}]{tls['expires']}"
            f"{'  (EXPIRED)' if tls['expired'] else ''}[/{expiry_style}]",
            title="TLS Certificate", border_style="magenta"
        ))

    # Exposed paths
    if result.exposed_paths:
        exp_table = Table(title="Potentially Exposed Paths")
        exp_table.add_column("Path", style="bold yellow")
        exp_table.add_column("HTTP Status")
        for path, status in result.exposed_paths:
            exp_table.add_row(path, str(status))
        console.print(exp_table)
    else:
        console.print("[dim]No well-known sensitive paths responded (all 404 or unreachable).[/dim]")


@register_command("audit-web")
def cmd_audit_web(session: Session, args: list[str]) -> None:
    """
    Usage:
      audit-web              -> audit the session target
      audit-web <url/host>   -> audit an explicit target
    """
    target = args[0] if args else session.target
    if not target:
        console.print("[red]No target set.[/red] Use 'set target <URL>' first, or pass one directly.")
        return

    console.print(f"[cyan]Auditing[/cyan] {target}...")
    result = run_web_audit(target)
    _render_result(result)
    session.state["last_web_audit"] = result


# ---------------------------------------------------------------------------
# Lightweight local HTTP proxy
# ---------------------------------------------------------------------------
#
# A small forwarding proxy: point a browser or curl at it (e.g.
# `curl -x http://127.0.0.1:8899 http://example.com`), and every request/
# response passing through is logged live in the TUI. This is a passive
# observation tool - it forwards requests exactly as received and forwards
# responses exactly as received; it does not modify, inject into, or
# tamper with traffic. Useful for a quick look at what headers/cookies a
# tool or script sends without needing a full separate proxy application.

import http.server
import socketserver
import threading
import urllib.request
import urllib.error


class _ProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - stdlib signature
        pass  # suppress default stderr logging; we log via Rich instead

    def _forward(self, method: str) -> None:
        target_url = self.path  # BaseHTTPRequestHandler gives the full URL for proxy requests
        body = None
        content_length = self.headers.get("Content-Length")
        if content_length:
            body = self.rfile.read(int(content_length))

        headers = {k: v for k, v in self.headers.items() if k.lower() != "proxy-connection"}

        console.print(f"[cyan]{method}[/cyan] {target_url}")

        req = urllib.request.Request(target_url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                self.send_response(resp.status)
                for key, value in resp.getheaders():
                    if key.lower() not in ("transfer-encoding", "connection"):
                        self.send_header(key, value)
                self.end_headers()
                response_body = resp.read()
                self.wfile.write(response_body)
                console.print(f"  [green]{resp.status}[/green] {len(response_body)} bytes")
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            self.end_headers()
            console.print(f"  [yellow]{e.code}[/yellow] {e.reason}")
        except (urllib.error.URLError, OSError) as e:
            self.send_response(502)
            self.end_headers()
            console.print(f"  [red]Forwarding failed:[/red] {e}")

    def do_GET(self) -> None:
        self._forward("GET")

    def do_POST(self) -> None:
        self._forward("POST")

    def do_PUT(self) -> None:
        self._forward("PUT")

    def do_DELETE(self) -> None:
        self._forward("DELETE")

    def do_HEAD(self) -> None:
        self._forward("HEAD")


class _ProxyServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


@register_command("web-proxy")
def cmd_web_proxy(session: Session, args: list[str]) -> None:
    """
    Usage: web-proxy [port]   (default port 8899)
    Starts a lightweight local forwarding HTTP proxy and logs every
    request/response live. Point a client at it, e.g.:
      curl -x http://127.0.0.1:8899 http://example.com
    Press Ctrl+C to stop.
    """
    port = 8899
    if args:
        try:
            port = int(args[0])
        except ValueError:
            console.print("[red]Port must be a number.[/red]")
            return

    try:
        server = _ProxyServer(("127.0.0.1", port), _ProxyHandler)
    except OSError as e:
        console.print(f"[red]Could not start proxy on port {port}:[/red] {e}")
        return

    console.print(
        f"[cyan]Proxy listening on[/cyan] http://127.0.0.1:{port}  "
        f"[dim](e.g. curl -x http://127.0.0.1:{port} http://example.com)[/dim] "
        "— Ctrl+C to stop.\n"
    )

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        while server_thread.is_alive():
            server_thread.join(timeout=0.5)
    except KeyboardInterrupt:
        console.print("\n[dim]Stopping proxy...[/dim]")
    finally:
        server.shutdown()
        server.server_close()
