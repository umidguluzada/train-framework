"""
TRAIN Framework - modules/offline_cve.py
Offline CVE database search (works with no internet access).

Registers:
  cve-db-build              -> builds/refreshes a local SQLite CVE database
                                 from a small bundled seed dataset
  cve-db-search <keywords>  -> searches the local database (no network calls)
  cve-db-import <file.json> -> imports a custom JSON CVE dataset (e.g. an
                                 NVD feed you downloaded ahead of time) into
                                 the local database

The local database lives at ~/.train_framework/cve.db (SQLite). This is
meant for air-gapped/offline engagements where 'audit-cve' (which hits
the live NVD API) isn't usable - the tradeoff is the local dataset is
only as current as whatever you last imported into it.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.tui_engine import Session, register_command

console = Console()

DB_PATH = Path.home() / ".train_framework" / "cve.db"

# A small bundled seed dataset covering commonly-taught, well-known CVEs -
# enough to demo/exercise the offline workflow without any network access.
# For real engagements, use 'cve-db-import' with a proper NVD data feed
# downloaded ahead of time.
SEED_CVES = [
    {"cve_id": "CVE-2021-44228", "product": "Apache Log4j", "version_range": "2.0-2.14.1",
     "severity": "CRITICAL", "score": 10.0,
     "description": "Log4Shell - JNDI lookup in Log4j allows remote code execution via crafted log messages."},
    {"cve_id": "CVE-2014-0160", "product": "OpenSSL", "version_range": "1.0.1-1.0.1f",
     "severity": "HIGH", "score": 7.5,
     "description": "Heartbleed - out-of-bounds read in the TLS heartbeat extension exposes process memory."},
    {"cve_id": "CVE-2017-0144", "product": "Windows SMBv1", "version_range": "N/A",
     "severity": "CRITICAL", "score": 8.1,
     "description": "EternalBlue - SMBv1 remote code execution, used by WannaCry ransomware."},
    {"cve_id": "CVE-2019-0708", "product": "Windows RDP", "version_range": "N/A",
     "severity": "CRITICAL", "score": 9.8,
     "description": "BlueKeep - pre-auth remote code execution in Remote Desktop Services."},
    {"cve_id": "CVE-2020-1472", "product": "Windows Netlogon", "version_range": "N/A",
     "severity": "CRITICAL", "score": 10.0,
     "description": "Zerologon - privilege escalation via a cryptographic flaw in Netlogon."},
    {"cve_id": "CVE-2021-34527", "product": "Windows Print Spooler", "version_range": "N/A",
     "severity": "CRITICAL", "score": 8.8,
     "description": "PrintNightmare - remote code execution via the Windows Print Spooler service."},
    {"cve_id": "CVE-2022-22965", "product": "Spring Framework", "version_range": "5.3.0-5.3.17",
     "severity": "CRITICAL", "score": 9.8,
     "description": "Spring4Shell - remote code execution via data binding in Spring MVC/WebFlux."},
    {"cve_id": "CVE-2023-4863", "product": "libwebp", "version_range": "<1.3.2",
     "severity": "CRITICAL", "score": 8.8,
     "description": "Heap buffer overflow in WebP image processing, exploitable via crafted images."},
    {"cve_id": "CVE-2010-2075", "product": "UnrealIRCd", "version_range": "3.2.8.1",
     "severity": "CRITICAL", "score": 10.0,
     "description": "Backdoor in UnrealIRCd tarball allows arbitrary command execution."},
    {"cve_id": "CVE-2011-2523", "product": "vsftpd", "version_range": "2.3.4",
     "severity": "CRITICAL", "score": 9.8,
     "description": "Backdoor in a compromised vsftpd 2.3.4 tarball allows a remote shell on connect."},
]


def _ensure_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            product TEXT,
            version_range TEXT,
            severity TEXT,
            score REAL,
            description TEXT
        )
    """)
    conn.commit()
    return conn


@register_command("cve-db-build")
def cmd_cve_db_build(session: Session, args: list[str]) -> None:
    """Usage: cve-db-build   (creates/refreshes the local offline CVE database with the bundled seed dataset)"""
    conn = _ensure_db()
    cur = conn.cursor()
    for entry in SEED_CVES:
        cur.execute(
            "INSERT OR REPLACE INTO cves (cve_id, product, version_range, severity, score, description) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (entry["cve_id"], entry["product"], entry["version_range"],
             entry["severity"], entry["score"], entry["description"]),
        )
    conn.commit()
    count = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    conn.close()

    console.print(Panel(
        f"Local CVE database built at [bold]{DB_PATH}[/bold]\n"
        f"{count} total entries ({len(SEED_CVES)} from the bundled seed dataset).\n"
        f"Use 'cve-db-import <file.json>' to add a larger dataset for offline use.",
        title="Offline CVE Database", border_style="green",
    ))


@register_command("cve-db-import")
def cmd_cve_db_import(session: Session, args: list[str]) -> None:
    """
    Usage: cve-db-import <file.json>
    Imports a custom JSON CVE dataset into the local database. Expected
    format: a JSON array of objects with keys cve_id, product,
    version_range, severity, score, description (same shape as the
    bundled seed dataset - see SEED_CVES in this module for an example).
    """
    if not args:
        console.print("[red]Usage:[/red] cve-db-import <file.json>")
        return

    path = Path(args[0])
    if not path.exists():
        console.print(f"[red]File not found:[/red] {path}")
        return

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        console.print(f"[red]Invalid JSON:[/red] {e}")
        return

    if not isinstance(data, list):
        console.print("[red]Expected a JSON array of CVE objects.[/red]")
        return

    conn = _ensure_db()
    cur = conn.cursor()
    imported = 0
    skipped = 0
    for entry in data:
        try:
            cur.execute(
                "INSERT OR REPLACE INTO cves (cve_id, product, version_range, severity, score, description) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (entry["cve_id"], entry.get("product", ""), entry.get("version_range", ""),
                 entry.get("severity", "UNKNOWN"), entry.get("score"), entry.get("description", "")),
            )
            imported += 1
        except (KeyError, sqlite3.Error):
            skipped += 1
    conn.commit()
    conn.close()

    console.print(f"[green]Imported {imported} entries[/green]"
                   f"{f', skipped {skipped} malformed entries' if skipped else ''}.")


@register_command("cve-db-search")
def cmd_cve_db_search(session: Session, args: list[str]) -> None:
    """
    Usage: cve-db-search <keywords...>
    Searches the local offline CVE database (no network access needed).
    Run 'cve-db-build' first if the database doesn't exist yet.
    """
    if not args:
        console.print("[red]Usage:[/red] cve-db-search <keywords...>")
        return

    if not DB_PATH.exists():
        console.print("[yellow]No local CVE database found.[/yellow] Run 'cve-db-build' first "
                       "(or 'cve-db-import <file.json>' with your own dataset).")
        return

    query = " ".join(args)
    conn = _ensure_db()
    like_pattern = f"%{query}%"
    rows = conn.execute(
        "SELECT cve_id, product, version_range, severity, score, description FROM cves "
        "WHERE product LIKE ? OR description LIKE ? OR cve_id LIKE ? "
        "ORDER BY score DESC",
        (like_pattern, like_pattern, like_pattern),
    ).fetchall()
    conn.close()

    if not rows:
        console.print(Panel(f"No local matches for '{query}'.", title="Offline CVE Search", border_style="yellow"))
        return

    table = Table(title=f"Offline CVE Search — '{query}' ({len(rows)} match(es))")
    table.add_column("CVE ID", style="bold cyan")
    table.add_column("Product")
    table.add_column("Version(s)")
    table.add_column("Severity")
    table.add_column("Score", justify="right")
    table.add_column("Description", style="dim")

    severity_style = {"CRITICAL": "red bold", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}
    for cve_id, product, version_range, severity, score, description in rows:
        style = severity_style.get(severity, "white")
        table.add_row(
            cve_id, product, version_range or "-",
            f"[{style}]{severity}[/{style}]",
            f"{score:.1f}" if score is not None else "-",
            (description or "")[:80],
        )
    console.print(table)
