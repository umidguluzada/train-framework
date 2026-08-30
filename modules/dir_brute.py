"""
TRAIN Framework - modules/dir_brute.py
Web directory/file discovery (gobuster/dirb-style).

Registers: dir-brute <url> [wordlist] [--threads N] [--ext ext1,ext2]

Sends plain, harmless GET requests to a list of candidate paths (from a
wordlist file) and reports which ones respond with something other than
404. This is standard, widely-used reconnaissance in web application
security testing - the same approach as gobuster, dirb, or ffuf - and
sends no request bodies, no injection payloads, no authentication bypass
attempts. It's asking "does this URL exist?", nothing more.

A small built-in wordlist is used if the user doesn't supply one, so the
command works out of the box for a quick check.
"""

from __future__ import annotations

import concurrent.futures
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.tui_engine import Session, register_command

console = Console()

REQUEST_TIMEOUT = 6
USER_AGENT = "TRAIN-Framework-DirBrute/0.1"
DEFAULT_THREADS = 20

# Small built-in wordlist covering the most common directories/files -
# used when the person doesn't supply their own (e.g. SecLists).
BUILTIN_WORDLIST = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "backup", "backups", "config", "config.php", "config.yaml",
    ".env", ".git", ".git/config", ".htaccess", ".htpasswd",
    "api", "api/v1", "test", "dev", "staging", "old", "tmp", "temp",
    "uploads", "images", "assets", "static", "public", "private",
    "db", "database", "sql", "dump.sql", "backup.zip", "backup.tar.gz",
    "phpinfo.php", "info.php", "server-status", "server-info",
    "robots.txt", "sitemap.xml", ".well-known/security.txt",
    "readme.md", "README.md", "CHANGELOG.md", "LICENSE",
    "console", "debug", "phpmyadmin", "adminer.php",
    "swagger.json", "swagger-ui.html", "openapi.json", "graphql",
    "health", "healthz", "status", "metrics", "actuator",
    "docs", "documentation", "wp-content", "wp-includes",
]


@dataclass
class BruteResult:
    path: str
    status_code: int
    size_bytes: int


@dataclass
class BruteReport:
    base_url: str
    found: list[BruteResult] = field(default_factory=list)
    checked: int = 0


def _load_wordlist(path: str | None) -> list[str]:
    if not path:
        return BUILTIN_WORDLIST
    wl_path = Path(path)
    if not wl_path.exists():
        raise FileNotFoundError(f"Wordlist not found: {path}")
    lines = wl_path.read_text(encoding="utf-8", errors="replace").splitlines()
    return [l.strip() for l in lines if l.strip() and not l.startswith("#")]


def _check_path(base_url: str, path: str, session: requests.Session) -> BruteResult | None:
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
    except requests.RequestException:
        return None

    if resp.status_code == 404:
        return None
    return BruteResult(path=path, status_code=resp.status_code, size_bytes=len(resp.content))


def run_dir_brute(
    base_url: str,
    wordlist: list[str],
    extensions: list[str] | None = None,
    threads: int = DEFAULT_THREADS,
) -> BruteReport:
    candidates = list(wordlist)
    if extensions:
        for word in wordlist:
            if "." not in word:  # only extend bare words, not already-dotted ones
                candidates.extend(f"{word}.{ext.lstrip('.')}" for ext in extensions)

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    report = BruteReport(base_url=base_url, checked=len(candidates))

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(_check_path, base_url, path, session) for path in candidates]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                report.found.append(result)

    report.found.sort(key=lambda r: r.path)
    return report


def _status_style(status_code: int) -> str:
    if status_code < 300:
        return "green bold"
    if status_code < 400:
        return "cyan"
    if status_code == 401 or status_code == 403:
        return "yellow"
    return "dim"


def _render_report(report: BruteReport) -> None:
    if not report.found:
        console.print(Panel(
            f"No paths found ({report.checked} candidates checked, all returned 404).",
            title="Directory Brute-Force", border_style="yellow",
        ))
        return

    table = Table(title=f"Discovered Paths — {report.base_url}  ({report.checked} checked)")
    table.add_column("Path", style="bold")
    table.add_column("Status")
    table.add_column("Size (bytes)", justify="right")

    for r in report.found:
        style = _status_style(r.status_code)
        table.add_row(f"/{r.path}", f"[{style}]{r.status_code}[/{style}]", str(r.size_bytes))

    console.print(table)
    console.print(f"[green]{len(report.found)} path(s) found[/green] out of {report.checked} checked.")


@register_command("dir-brute")
def cmd_dir_brute(session: Session, args: list[str]) -> None:
    """
    Usage:
      dir-brute <url> [wordlist_file] [--threads N] [--ext php,html,txt]

    Examples:
      dir-brute http://127.0.0.1:8000
      dir-brute http://127.0.0.1:8000 /usr/share/wordlists/dirb/common.txt
      dir-brute http://127.0.0.1:8000 --ext php,bak --threads 30
    """
    if not args:
        console.print("[red]Usage:[/red] dir-brute <url> [wordlist_file] [--threads N] [--ext ext1,ext2]")
        return

    url = args[0]
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    rest = args[1:]
    threads = DEFAULT_THREADS
    extensions: list[str] | None = None
    wordlist_path: str | None = None

    i = 0
    while i < len(rest):
        if rest[i] == "--threads" and i + 1 < len(rest):
            try:
                threads = int(rest[i + 1])
            except ValueError:
                console.print("[red]--threads must be a number.[/red]")
                return
            i += 2
        elif rest[i] == "--ext" and i + 1 < len(rest):
            extensions = rest[i + 1].split(",")
            i += 2
        else:
            wordlist_path = rest[i]
            i += 1

    try:
        wordlist = _load_wordlist(wordlist_path)
    except FileNotFoundError as e:
        console.print(f"[red]{e}[/red]")
        return

    source = wordlist_path or f"built-in ({len(wordlist)} words)"
    console.print(f"[cyan]Brute-forcing paths on[/cyan] {url}  [dim](wordlist: {source})[/dim]...")

    report = run_dir_brute(url, wordlist, extensions, threads)
    _render_report(report)
    session.state["last_dir_brute"] = report
