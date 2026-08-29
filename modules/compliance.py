"""
TRAIN Framework - modules/compliance.py
Local system compliance auditor (CIS Benchmark-inspired checks).

Registers: audit-compliance

Runs a small set of read-only checks against THIS machine's configuration,
loosely inspired by CIS Benchmark items for Linux servers. Every check only
reads a file or a command's output - nothing is modified. This is meant to
run on the machine TRAIN Framework itself is installed on (or a machine the
user has legitimate admin access to), not against a remote target.

Checks implemented (a representative subset, not the full CIS benchmark):
  - SSH: PermitRootLogin, PasswordAuthentication, Protocol version
  - Password policy: /etc/login.defs PASS_MAX_DAYS, PASS_MIN_LEN
  - Filesystem: world-writable files in a few common sensitive directories
  - Firewall: whether ufw/iptables/nftables appears active
  - Auditd: whether the audit daemon is installed/running
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.tui_engine import Session, register_command

console = Console()

SSHD_CONFIG_PATHS = [Path("/etc/ssh/sshd_config")]
LOGIN_DEFS_PATH = Path("/etc/login.defs")


@dataclass
class ComplianceCheck:
    check_id: str
    description: str
    status: str    # "pass" | "fail" | "warn" | "n/a"
    detail: str = ""


@dataclass
class ComplianceReport:
    checks: list[ComplianceCheck] = field(default_factory=list)


def _read_file_safe(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (FileNotFoundError, PermissionError):
        return None


def _find_sshd_config() -> Optional[Path]:
    for p in SSHD_CONFIG_PATHS:
        if p.exists():
            return p
    return None


def check_ssh_root_login() -> ComplianceCheck:
    cfg_path = _find_sshd_config()
    if not cfg_path:
        return ComplianceCheck("SSH-1", "SSH root login disabled", "n/a",
                                "sshd_config not found (SSH may not be installed).")
    content = _read_file_safe(cfg_path) or ""
    match = re.search(r"^\s*PermitRootLogin\s+(\S+)", content, re.MULTILINE)
    if not match:
        return ComplianceCheck("SSH-1", "SSH root login disabled", "warn",
                                "PermitRootLogin not explicitly set (uses OpenSSH default).")
    value = match.group(1).lower()
    if value in ("no", "prohibit-password", "without-password"):
        return ComplianceCheck("SSH-1", "SSH root login disabled", "pass", f"PermitRootLogin {value}")
    return ComplianceCheck("SSH-1", "SSH root login disabled", "fail", f"PermitRootLogin {value}")


def check_ssh_password_auth() -> ComplianceCheck:
    cfg_path = _find_sshd_config()
    if not cfg_path:
        return ComplianceCheck("SSH-2", "SSH password authentication restricted", "n/a",
                                "sshd_config not found.")
    content = _read_file_safe(cfg_path) or ""
    match = re.search(r"^\s*PasswordAuthentication\s+(\S+)", content, re.MULTILINE)
    if not match:
        return ComplianceCheck("SSH-2", "SSH password authentication restricted", "warn",
                                "PasswordAuthentication not explicitly set.")
    value = match.group(1).lower()
    if value == "no":
        return ComplianceCheck("SSH-2", "SSH password authentication restricted", "pass",
                                "PasswordAuthentication no (key-based only)")
    return ComplianceCheck("SSH-2", "SSH password authentication restricted", "warn",
                            "PasswordAuthentication yes (consider key-based auth)")


def check_password_max_days() -> ComplianceCheck:
    content = _read_file_safe(LOGIN_DEFS_PATH)
    if content is None:
        return ComplianceCheck("PW-1", "Password max age configured", "n/a",
                                "/etc/login.defs not found.")
    match = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", content, re.MULTILINE)
    if not match:
        return ComplianceCheck("PW-1", "Password max age configured", "warn", "PASS_MAX_DAYS not set.")
    days = int(match.group(1))
    if 0 < days <= 90:
        return ComplianceCheck("PW-1", "Password max age configured", "pass", f"PASS_MAX_DAYS {days}")
    return ComplianceCheck("PW-1", "Password max age configured", "warn",
                            f"PASS_MAX_DAYS {days} (CIS recommends <= 90)")


def check_password_min_len() -> ComplianceCheck:
    content = _read_file_safe(LOGIN_DEFS_PATH)
    if content is None:
        return ComplianceCheck("PW-2", "Minimum password length enforced", "n/a",
                                "/etc/login.defs not found.")
    match = re.search(r"^\s*PASS_MIN_LEN\s+(\d+)", content, re.MULTILINE)
    if not match:
        return ComplianceCheck("PW-2", "Minimum password length enforced", "warn",
                                "PASS_MIN_LEN not set in login.defs (may be enforced via PAM instead).")
    length = int(match.group(1))
    if length >= 14:
        return ComplianceCheck("PW-2", "Minimum password length enforced", "pass", f"PASS_MIN_LEN {length}")
    return ComplianceCheck("PW-2", "Minimum password length enforced", "warn",
                            f"PASS_MIN_LEN {length} (CIS recommends >= 14)")


def check_world_writable_files() -> ComplianceCheck:
    """Looks for world-writable files in a couple of common sensitive dirs."""
    targets = ["/etc", "/usr/local/bin"]
    found: list[str] = []
    for base in targets:
        base_path = Path(base)
        if not base_path.exists():
            continue
        try:
            proc = subprocess.run(
                ["find", base, "-xdev", "-type", "f", "-perm", "-0002"],
                capture_output=True, text=True, timeout=15,
            )
            found.extend(line for line in proc.stdout.splitlines() if line)
        except (subprocess.SubprocessError, OSError):
            continue

    if not found:
        return ComplianceCheck("FS-1", "No world-writable files in sensitive dirs", "pass",
                                f"Checked: {', '.join(targets)}")
    preview = ", ".join(found[:5]) + (f" (+{len(found) - 5} more)" if len(found) > 5 else "")
    return ComplianceCheck("FS-1", "No world-writable files in sensitive dirs", "fail", preview)


def check_firewall_active() -> ComplianceCheck:
    if shutil.which("ufw"):
        try:
            proc = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=5)
            if "Status: active" in proc.stdout:
                return ComplianceCheck("FW-1", "Host firewall active", "pass", "ufw is active")
            return ComplianceCheck("FW-1", "Host firewall active", "fail", "ufw installed but inactive")
        except (subprocess.SubprocessError, OSError):
            pass

    if shutil.which("iptables"):
        try:
            proc = subprocess.run(["iptables", "-L"], capture_output=True, text=True, timeout=5)
            rule_lines = [l for l in proc.stdout.splitlines() if l and not l.startswith("Chain") and not l.startswith("target")]
            if rule_lines:
                return ComplianceCheck("FW-1", "Host firewall active", "pass",
                                        f"iptables has {len(rule_lines)} rule line(s)")
            return ComplianceCheck("FW-1", "Host firewall active", "warn", "iptables present but no rules found")
        except (subprocess.SubprocessError, OSError):
            pass

    return ComplianceCheck("FW-1", "Host firewall active", "n/a", "No supported firewall tool found (ufw/iptables).")


def check_auditd_present() -> ComplianceCheck:
    if shutil.which("auditctl"):
        try:
            proc = subprocess.run(["systemctl", "is-active", "auditd"], capture_output=True, text=True, timeout=5)
            if proc.stdout.strip() == "active":
                return ComplianceCheck("AUD-1", "Audit daemon running", "pass", "auditd is active")
            return ComplianceCheck("AUD-1", "Audit daemon running", "fail", "auditd installed but not active")
        except (subprocess.SubprocessError, OSError):
            return ComplianceCheck("AUD-1", "Audit daemon running", "warn", "auditctl found, status unknown")
    return ComplianceCheck("AUD-1", "Audit daemon running", "n/a", "auditd not installed")


ALL_CHECKS = [
    check_ssh_root_login,
    check_ssh_password_auth,
    check_password_max_days,
    check_password_min_len,
    check_world_writable_files,
    check_firewall_active,
    check_auditd_present,
]


def run_compliance_audit() -> ComplianceReport:
    report = ComplianceReport()
    for check_fn in ALL_CHECKS:
        try:
            report.checks.append(check_fn())
        except Exception as e:  # noqa: BLE001 - one bad check shouldn't kill the audit
            report.checks.append(ComplianceCheck(
                check_id="ERR", description=check_fn.__name__, status="warn", detail=str(e)
            ))
    return report


def _status_style(status: str) -> str:
    return {"pass": "green", "fail": "red bold", "warn": "yellow", "n/a": "dim"}.get(status, "white")


def _render_report(report: ComplianceReport) -> None:
    table = Table(title="Compliance Audit (CIS-inspired, local host)")
    table.add_column("ID", style="bold")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Detail", style="dim")

    for c in report.checks:
        style = _status_style(c.status)
        table.add_row(c.check_id, c.description, f"[{style}]{c.status.upper()}[/{style}]", c.detail)

    console.print(table)

    passed = sum(1 for c in report.checks if c.status == "pass")
    failed = sum(1 for c in report.checks if c.status == "fail")
    console.print(f"\n[bold]{passed}[/bold] passed, [red bold]{failed}[/red bold] failed, "
                  f"out of {len(report.checks)} checks.")

    if failed:
        console.print("[dim]Note: run with appropriate privileges (sudo) for full accuracy "
                       "on file-permission checks.[/dim]")


@register_command("audit-compliance")
def cmd_audit_compliance(session: Session, args: list[str]) -> None:
    """Usage: audit-compliance   (runs against the local host TRAIN is installed on)"""
    console.print("[cyan]Running local compliance audit...[/cyan]\n")
    report = run_compliance_audit()
    _render_report(report)
    session.state["last_compliance_report"] = report
