"""
TRAIN Framework - modules/osint_auditor.py
OSINT, geolocation, ASN, and VirusTotal reputation lookups.

Registers:
  audit-osint <domain>     -> passive DNS record enumeration (A/AAAA/MX/TXT/NS)
  geo-track <ip/domain>    -> geolocation + ASN/ISP lookup (via ip-api.com, public/free)
  check-vt <hash|ip>       -> VirusTotal v3 reputation lookup (requires API key)

Everything here is passive, read-only intelligence gathering against public
data sources - standard DNS queries, a free public geolocation API, and
VirusTotal's own reputation API (which VT explicitly provides for this
purpose). No active exploitation, no brute-forcing of subdomains via
wordlists (that would need many more requests against the target's own
DNS infrastructure) - just the record types a domain's own nameservers
publish for anyone who asks.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.tui_engine import Session, register_command

console = Console()

IP_API_URL = "http://ip-api.com/json/{query}"
IP_API_TIMEOUT = 8

VT_API_BASE = "https://www.virustotal.com/api/v3"
VT_TIMEOUT = 10
VT_API_KEY_ENV = "VT_API_KEY"

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]


# ---------------------------------------------------------------------------
# Passive DNS enumeration
# ---------------------------------------------------------------------------

@dataclass
class DNSResult:
    domain: str
    records: dict[str, list[str]] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)


def run_dns_enum(domain: str) -> DNSResult:
    try:
        import dns.resolver  # local import: optional dependency (dnspython)
    except ImportError as e:
        raise RuntimeError(
            "dnspython is required for audit-osint. Install with: pip install dnspython"
        ) from e

    result = DNSResult(domain=domain)
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    for record_type in DNS_RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, record_type)
            result.records[record_type] = [str(r).strip() for r in answers]
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            result.errors["*"] = f"Domain does not exist: {domain}"
            break
        except Exception as e:  # noqa: BLE001 - dnspython raises several exception types
            result.errors[record_type] = str(e)

    return result


def _render_dns_result(result: DNSResult) -> None:
    if result.errors.get("*"):
        console.print(Panel(f"[red]{result.errors['*']}[/red]", title="OSINT / DNS", border_style="red"))
        return

    if not result.records:
        console.print(Panel(f"No DNS records found for {result.domain}.",
                             title="OSINT / DNS", border_style="yellow"))
        return

    table = Table(title=f"DNS Records — {result.domain}")
    table.add_column("Type", style="bold cyan")
    table.add_column("Value(s)")
    for record_type, values in result.records.items():
        table.add_row(record_type, "\n".join(values))
    console.print(table)


@register_command("audit-osint")
def cmd_audit_osint(session: Session, args: list[str]) -> None:
    """Usage: audit-osint <domain>"""
    domain = args[0] if args else session.target
    if not domain:
        console.print("[red]No target set.[/red] Use 'set target <domain>' first, or pass one directly.")
        return

    console.print(f"[cyan]Enumerating DNS records for[/cyan] {domain}...")
    try:
        result = run_dns_enum(domain)
    except RuntimeError as e:
        console.print(f"[red]{e}[/red]")
        return

    _render_dns_result(result)
    session.state["last_osint_result"] = result


# ---------------------------------------------------------------------------
# Geolocation / ASN lookup
# ---------------------------------------------------------------------------

@dataclass
class GeoResult:
    query: str
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    error: Optional[str] = None


def run_geo_lookup(query: str) -> GeoResult:
    try:
        resp = requests.get(
            IP_API_URL.format(query=query),
            params={"fields": "status,message,country,regionName,city,isp,org,as,lat,lon,query"},
            timeout=IP_API_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        return GeoResult(query=query, error=str(e))

    if data.get("status") != "success":
        return GeoResult(query=query, error=data.get("message", "lookup failed"))

    return GeoResult(
        query=data.get("query", query),
        country=data.get("country"),
        region=data.get("regionName"),
        city=data.get("city"),
        isp=data.get("isp"),
        org=data.get("org"),
        asn=data.get("as"),
        lat=data.get("lat"),
        lon=data.get("lon"),
    )


def _render_geo_result(result: GeoResult) -> None:
    if result.error:
        console.print(Panel(f"[red]{result.error}[/red]", title=f"Geolocation — {result.query}",
                             border_style="red"))
        return

    lines = [
        f"[bold]Country:[/bold] {result.country or '-'}",
        f"[bold]Region:[/bold] {result.region or '-'}",
        f"[bold]City:[/bold] {result.city or '-'}",
        f"[bold]ISP:[/bold] {result.isp or '-'}",
        f"[bold]Org:[/bold] {result.org or '-'}",
        f"[bold]ASN:[/bold] {result.asn or '-'}",
        f"[bold]Coordinates:[/bold] {result.lat}, {result.lon}" if result.lat else "",
    ]
    console.print(Panel("\n".join(l for l in lines if l), title=f"Geolocation — {result.query}",
                         border_style="magenta"))


@register_command("geo-track")
def cmd_geo_track(session: Session, args: list[str]) -> None:
    """Usage: geo-track <ip/domain>"""
    query = args[0] if args else session.target
    if not query:
        console.print("[red]No target set.[/red] Use 'set target <ip/domain>' first, or pass one directly.")
        return

    console.print(f"[cyan]Looking up geolocation for[/cyan] {query}...")
    result = run_geo_lookup(query)
    _render_geo_result(result)
    session.state["last_geo_result"] = result


# ---------------------------------------------------------------------------
# VirusTotal reputation lookup
# ---------------------------------------------------------------------------

@dataclass
class VTResult:
    query: str
    query_type: str  # "file" | "ip_address"
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: Optional[int] = None
    error: Optional[str] = None


def _looks_like_hash(value: str) -> bool:
    return all(c in "0123456789abcdefABCDEF" for c in value) and len(value) in (32, 40, 64)


def run_vt_lookup(query: str) -> VTResult:
    api_key = os.environ.get(VT_API_KEY_ENV)
    if not api_key:
        return VTResult(query=query, query_type="?",
                         error=f"No API key found. Set the {VT_API_KEY_ENV} environment variable.")

    query_type = "file" if _looks_like_hash(query) else "ip_address"
    endpoint = f"{VT_API_BASE}/{query_type}s/{query}"

    try:
        resp = requests.get(endpoint, headers={"x-apikey": api_key}, timeout=VT_TIMEOUT)
    except requests.RequestException as e:
        return VTResult(query=query, query_type=query_type, error=str(e))

    if resp.status_code == 404:
        return VTResult(query=query, query_type=query_type, error="Not found in VirusTotal.")
    if resp.status_code != 200:
        return VTResult(query=query, query_type=query_type,
                         error=f"VirusTotal API returned HTTP {resp.status_code}")

    data = resp.json().get("data", {}).get("attributes", {})
    stats = data.get("last_analysis_stats", {})

    return VTResult(
        query=query, query_type=query_type,
        malicious=stats.get("malicious", 0),
        suspicious=stats.get("suspicious", 0),
        harmless=stats.get("harmless", 0),
        undetected=stats.get("undetected", 0),
        reputation=data.get("reputation"),
    )


def _render_vt_result(result: VTResult) -> None:
    if result.error:
        console.print(Panel(f"[red]{result.error}[/red]", title=f"VirusTotal — {result.query}",
                             border_style="red"))
        return

    total_engines = result.malicious + result.suspicious + result.harmless + result.undetected
    verdict_style = "red bold" if result.malicious > 0 else "green"
    verdict = f"{result.malicious}/{total_engines} engines flagged as malicious" if total_engines else "no data"

    lines = [
        f"[{verdict_style}]{verdict}[/{verdict_style}]",
        f"Suspicious: {result.suspicious}  Harmless: {result.harmless}  Undetected: {result.undetected}",
    ]
    if result.reputation is not None:
        lines.append(f"Community reputation score: {result.reputation}")

    console.print(Panel("\n".join(lines), title=f"VirusTotal — {result.query} ({result.query_type})",
                         border_style="magenta"))


@register_command("check-vt")
def cmd_check_vt(session: Session, args: list[str]) -> None:
    """
    Usage: check-vt <hash|ip>
    Requires the VT_API_KEY environment variable (get a free key at virustotal.com).
    """
    if not args:
        console.print("[red]Usage:[/red] check-vt <hash|ip>")
        return

    query = args[0]
    console.print(f"[cyan]Checking VirusTotal for[/cyan] {query}...")
    result = run_vt_lookup(query)
    _render_vt_result(result)
    session.state["last_vt_result"] = result
