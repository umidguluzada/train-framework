"""
Normalize session results into one finding list for JSON, HTML, and PDF.

This module only reads objects other commands already stored on the
session. It does not open sockets or start scans.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.version import VERSION


@dataclass
class Finding:
    source: str
    title: str
    severity: str  # high | medium | low | info
    detail: str = ""


@dataclass
class ReportDocument:
    target: str | None
    generated_at: str
    findings: list[Finding] = field(default_factory=list)
    risk: dict[str, Any] = field(default_factory=dict)
    version: str = VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "TRAIN",
            "version": self.version,
            "generated_at": self.generated_at,
            "target": self.target,
            "risk": self.risk,
            "findings": [asdict(item) for item in self.findings],
        }


def _score(findings: list[Finding]) -> dict[str, Any]:
    high = sum(1 for item in findings if item.severity == "high")
    medium = sum(1 for item in findings if item.severity == "medium")
    low = sum(1 for item in findings if item.severity == "low")
    score = min(100, high * 10 + medium * 4 + low)
    if score >= 70 or high >= 5:
        level = "HIGH"
    elif score >= 30 or high >= 1 or medium >= 4:
        level = "MEDIUM"
    else:
        level = "LOW"
    return {"high": high, "medium": medium, "low": low, "score": score, "level": level}


def _add(findings: list[Finding], source: str, title: str, severity: str, detail: str) -> None:
    findings.append(Finding(
        source=source,
        title=str(title)[:160],
        severity=severity if severity in {"high", "medium", "low", "info"} else "info",
        detail=str(detail)[:500],
    ))


def collect_report(session: Any) -> ReportDocument:
    """Build a report document from session.state. Missing keys are skipped."""
    state = getattr(session, "state", {}) or {}
    findings: list[Finding] = []

    scan = state.get("last_scan") or {}
    if isinstance(scan, dict):
        for entry in scan.get("open_ports") or []:
            if not isinstance(entry, dict):
                continue
            banner = (entry.get("banner") or "").strip()
            _add(
                findings,
                "port-scan",
                f"Port {entry.get('port')} ({entry.get('service_guess', 'unknown')})",
                "info",
                banner or "open",
            )

    tse = state.get("last_tse_report")
    if tse is not None:
        for item in getattr(tse, "findings", []) or []:
            severity = {"finding": "high", "warning": "medium"}.get(getattr(item, "severity", ""), "info")
            _add(
                findings,
                "tse",
                f"{getattr(item, 'port', '?')} {getattr(item, 'check', '')}".strip(),
                severity,
                getattr(item, "detail", "") or getattr(item, "result", ""),
            )

    web = state.get("last_web_audit")
    if web is not None and not getattr(web, "error", None):
        url = getattr(web, "url", "")
        for header in getattr(web, "headers_missing", []) or []:
            _add(findings, "web-audit", f"Missing header {header}", "medium", url)
        for path, status in getattr(web, "exposed_paths", []) or []:
            _add(findings, "web-audit", f"Responding path {path}", "high", f"HTTP {status}")
        tls = getattr(web, "tls_info", None) or {}
        if tls.get("expired"):
            _add(findings, "web-audit", "TLS certificate expired", "high", str(tls.get("expires", "")))

    compliance = state.get("last_compliance_report")
    if compliance is not None:
        for check in getattr(compliance, "checks", []) or []:
            severity = {"fail": "high", "warn": "medium"}.get(getattr(check, "status", ""), "info")
            _add(
                findings,
                "compliance",
                getattr(check, "description", "compliance check"),
                severity,
                f"{getattr(check, 'check_id', '')}: {getattr(check, 'detail', '')}".strip(": "),
            )

    for cve in state.get("last_cve_results") or []:
        raw = (getattr(cve, "severity", "") or "").upper()
        if raw in {"CRITICAL", "HIGH"}:
            severity = "high"
        elif raw == "MEDIUM":
            severity = "medium"
        elif raw == "LOW":
            severity = "low"
        else:
            severity = "info"
        score = getattr(cve, "score", None)
        detail = getattr(cve, "description", "")
        if score is not None:
            detail = f"CVSS {score}. {detail}"
        _add(findings, "cve", getattr(cve, "cve_id", "?"), severity, detail)

    logs = state.get("last_log_report")
    if logs is not None:
        for ip, count in (getattr(logs, "brute_force_candidates", None) or {}).items():
            _add(findings, "logs", f"Repeated authentication failures from {ip}", "high", f"{count} failures")

    beacon = state.get("last_beacon_report")
    if beacon is not None:
        for candidate in getattr(beacon, "candidates", []) or []:
            _add(
                findings,
                "beacon",
                f"Regular callbacks from {getattr(candidate, 'source', '?')}",
                "high",
                f"{getattr(candidate, 'count', 0)} events, "
                f"avg {getattr(candidate, 'avg_interval_seconds', 0):.1f}s",
            )

    discovered = state.get("last_dir_brute")
    if discovered is not None:
        for item in getattr(discovered, "found", []) or []:
            _add(
                findings,
                "dir-brute",
                f"/{getattr(item, 'path', '')}",
                "low",
                f"HTTP {getattr(item, 'status_code', '')}",
            )

    mitre = state.get("last_mitre_report")
    if mitre is not None:
        for mapping in getattr(mitre, "mappings", []) or []:
            _add(
                findings,
                "mitre",
                f"{getattr(mapping, 'technique_id', '')} {getattr(mapping, 'technique_name', '')}".strip(),
                "info",
                getattr(mapping, "evidence", ""),
            )

    return ReportDocument(
        target=getattr(session, "target", None),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        findings=findings,
        risk=_score(findings),
    )
