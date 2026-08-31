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

import base64
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
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
    query_type: str  # "file" | "ip_address" | "url"
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: Optional[int] = None
    error: Optional[str] = None
    # Extended detail fields (populated when the lookup succeeds)
    categories: dict[str, str] = field(default_factory=dict)
    engine_results: dict[str, str] = field(default_factory=dict)  # engine name -> verdict category
    first_submission: Optional[str] = None
    last_analysis: Optional[str] = None
    total_votes: dict[str, int] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)


def _build_vt_result(query: str, query_type: str, data: dict) -> VTResult:
    """
    Builds a fully-detailed VTResult from a VirusTotal 'attributes' object -
    shared by the file/IP and URL lookup paths so both surface the same
    level of detail (per-engine verdicts, categories, dates, votes).
    """
    stats = data.get("last_analysis_stats", {})
    engine_results = {
        engine: info.get("category", "unknown")
        for engine, info in data.get("last_analysis_results", {}).items()
    }

    def _fmt_ts(ts) -> Optional[str]:
        if not ts:
            return None
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        except (TypeError, ValueError, OSError):
            return None

    return VTResult(
        query=query, query_type=query_type,
        malicious=stats.get("malicious", 0),
        suspicious=stats.get("suspicious", 0),
        harmless=stats.get("harmless", 0),
        undetected=stats.get("undetected", 0),
        reputation=data.get("reputation"),
        categories=data.get("categories", {}),
        engine_results=engine_results,
        first_submission=_fmt_ts(data.get("first_submission_date")),
        last_analysis=_fmt_ts(data.get("last_analysis_date")),
        total_votes=data.get("total_votes", {}),
        tags=data.get("tags", []),
    )


def _looks_like_hash(value: str) -> bool:
    return all(c in "0123456789abcdefABCDEF" for c in value) and len(value) in (32, 40, 64)


def _looks_like_url(value: str) -> bool:
    return value.startswith(("http://", "https://")) or ("." in value and "/" in value)


def _vt_url_id(url: str) -> str:
    """VirusTotal identifies URLs by the base64 (no padding) of the URL itself."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def run_vt_url_lookup(url: str) -> VTResult:
    """
    Looks up a URL's reputation. If VirusTotal has no existing analysis for
    this URL, submits it for a fresh scan (a normal, documented part of
    VT's own API workflow - the same thing pasting a URL into virustotal.com
    does) and polls briefly for the result.
    """
    api_key = os.environ.get(VT_API_KEY_ENV)
    if not api_key:
        return VTResult(query=url, query_type="url",
                         error=f"No API key found. Set the {VT_API_KEY_ENV} environment variable.")

    headers = {"x-apikey": api_key}
    url_id = _vt_url_id(url)

    # First, try an existing analysis (fast path - no new scan needed).
    try:
        resp = requests.get(f"{VT_API_BASE}/urls/{url_id}", headers=headers, timeout=VT_TIMEOUT)
    except requests.RequestException as e:
        return VTResult(query=url, query_type="url", error=str(e))

    if resp.status_code == 200:
        data = resp.json().get("data", {}).get("attributes", {})
        return _build_vt_result(url, "url", data)

    if resp.status_code != 404:
        return VTResult(query=url, query_type="url",
                         error=f"VirusTotal API returned HTTP {resp.status_code}")

    # Not seen before - submit it for a new scan (standard VT workflow).
    try:
        submit_resp = requests.post(
            f"{VT_API_BASE}/urls", headers=headers, data={"url": url}, timeout=VT_TIMEOUT
        )
        submit_resp.raise_for_status()
        analysis_id = submit_resp.json()["data"]["id"]
    except (requests.RequestException, KeyError) as e:
        return VTResult(query=url, query_type="url", error=f"Failed to submit URL for scanning: {e}")

    # Poll briefly for the analysis to complete (VT scans typically take a
    # few seconds to a couple of minutes across all its engines).
    for _ in range(6):
        time.sleep(5)
        try:
            poll_resp = requests.get(
                f"{VT_API_BASE}/analyses/{analysis_id}", headers=headers, timeout=VT_TIMEOUT
            )
            poll_resp.raise_for_status()
            poll_data = poll_resp.json()["data"]["attributes"]
        except (requests.RequestException, KeyError):
            continue

        if poll_data.get("status") == "completed":
            # Re-fetch the URL object now that analysis is done, to get the
            # full set of details (categories, dates, votes) which the
            # /analyses/{id} endpoint itself doesn't include.
            try:
                final_resp = requests.get(f"{VT_API_BASE}/urls/{url_id}", headers=headers, timeout=VT_TIMEOUT)
                final_resp.raise_for_status()
                final_data = final_resp.json().get("data", {}).get("attributes", {})
                return _build_vt_result(url, "url", final_data)
            except requests.RequestException:
                # Fall back to the raw analysis stats if the re-fetch fails.
                stats = poll_data.get("stats", {})
                return VTResult(
                    query=url, query_type="url",
                    malicious=stats.get("malicious", 0),
                    suspicious=stats.get("suspicious", 0),
                    harmless=stats.get("harmless", 0),
                    undetected=stats.get("undetected", 0),
                )

    return VTResult(query=url, query_type="url",
                     error="Scan submitted but not completed yet - try again in a minute.")


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
    return _build_vt_result(query, query_type, data)


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
    if result.total_votes:
        harmless_votes = result.total_votes.get("harmless", 0)
        malicious_votes = result.total_votes.get("malicious", 0)
        lines.append(f"Community votes: {harmless_votes} harmless, {malicious_votes} malicious")
    if result.first_submission:
        lines.append(f"First seen: {result.first_submission}")
    if result.last_analysis:
        lines.append(f"Last analyzed: {result.last_analysis}")
    if result.categories:
        cat_summary = ", ".join(f"{engine}: {cat}" for engine, cat in list(result.categories.items())[:5])
        lines.append(f"Categories: {cat_summary}")
    if result.tags:
        lines.append(f"Tags: {', '.join(result.tags[:10])}")

    console.print(Panel("\n".join(lines), title=f"VirusTotal — {result.query} ({result.query_type})",
                         border_style="magenta"))

    # Per-engine verdicts, as a separate table (can be dozens of rows).
    if result.engine_results:
        table = Table(title=f"Engine Results ({len(result.engine_results)} engines)")
        table.add_column("Engine", style="bold")
        table.add_column("Verdict")

        # Sort so malicious/suspicious verdicts surface first.
        priority = {"malicious": 0, "suspicious": 1, "undetected": 2, "harmless": 3}
        sorted_engines = sorted(
            result.engine_results.items(),
            key=lambda kv: priority.get(kv[1], 4),
        )
        for engine, verdict_cat in sorted_engines:
            style = {
                "malicious": "red bold", "suspicious": "yellow",
                "harmless": "green", "undetected": "dim",
            }.get(verdict_cat, "white")
            table.add_row(engine, f"[{style}]{verdict_cat}[/{style}]")
        console.print(table)


@register_command("check-vt")
def cmd_check_vt(session: Session, args: list[str]) -> None:
    """
    Usage: check-vt <hash|ip|url>
    Requires the VT_API_KEY environment variable (get a free key at virustotal.com).
    For a URL not yet known to VirusTotal, this submits it for a fresh scan
    (the same thing pasting a link into virustotal.com does) and waits up
    to ~30s for the analysis to finish.
    """
    if not args:
        console.print("[red]Usage:[/red] check-vt <hash|ip|url>")
        return

    query = args[0]
    console.print(f"[cyan]Checking VirusTotal for[/cyan] {query}...")

    if _looks_like_url(query) and not _looks_like_hash(query):
        console.print("[dim]Detected as a URL - this may take up to ~30s if it needs a fresh scan.[/dim]")
        result = run_vt_url_lookup(query)
    else:
        result = run_vt_lookup(query)

    _render_vt_result(result)
    session.state["last_vt_result"] = result
