"""
TRAIN Framework - modules/pass_auditor.py
Password entropy and known-breach exposure auditor.

Registers: audit-pass <password>

Two checks, both defensive/educational in nature:
  1. Shannon-style entropy estimate (math.log2 of the character-set size)
     to give a quick sense of brute-force resistance.
  2. Optional breach check against the HaveIBeenPwned "Pwned Passwords"
     API using k-anonymity: only the first 5 characters of the SHA-1 hash
     are ever sent over the network, never the password itself and never
     the full hash. This is the same privacy-preserving method HIBP
     documents and password managers use.
"""

from __future__ import annotations

import hashlib
import math
import string
from dataclasses import dataclass
from typing import Optional

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.tui_engine import Session, register_command

console = Console()

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
HIBP_TIMEOUT = 6


@dataclass
class PasswordAuditResult:
    length: int
    charset_size: int
    entropy_bits: float
    strength_label: str
    breach_count: Optional[int] = None  # None = not checked / lookup failed
    breach_checked: bool = False


def _charset_size(password: str) -> int:
    size = 0
    if any(c in string.ascii_lowercase for c in password):
        size += 26
    if any(c in string.ascii_uppercase for c in password):
        size += 26
    if any(c in string.digits for c in password):
        size += 10
    if any(c in string.punctuation for c in password):
        size += len(string.punctuation)
    # Anything outside the above (unicode, spaces, etc.) - assume a
    # conservative extra 10 symbols worth of unpredictability.
    if any(c not in string.ascii_letters + string.digits + string.punctuation for c in password):
        size += 10
    return max(size, 1)


def _strength_label(entropy_bits: float) -> str:
    if entropy_bits < 28:
        return "very weak"
    if entropy_bits < 36:
        return "weak"
    if entropy_bits < 60:
        return "reasonable"
    if entropy_bits < 128:
        return "strong"
    return "very strong"


def estimate_entropy(password: str) -> tuple[int, float, str]:
    charset = _charset_size(password)
    bits = len(password) * math.log2(charset) if password else 0.0
    return charset, bits, _strength_label(bits)


def check_hibp_breach(password: str) -> Optional[int]:
    """
    Returns how many times this password has appeared in known breaches,
    or None if the lookup could not be completed (network error, etc.).
    Uses k-anonymity: only a 5-char SHA-1 prefix ever leaves the machine.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        resp = requests.get(
            HIBP_RANGE_URL.format(prefix=prefix),
            timeout=HIBP_TIMEOUT,
            headers={"User-Agent": "TRAIN-Framework-PassAuditor/0.1"},
        )
        resp.raise_for_status()
    except requests.RequestException:
        return None

    for line in resp.text.splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[0] == suffix:
            try:
                return int(parts[1])
            except ValueError:
                return None
    return 0  # not found in breach corpus


def run_password_audit(password: str, check_breach: bool = True) -> PasswordAuditResult:
    charset, bits, label = estimate_entropy(password)
    result = PasswordAuditResult(
        length=len(password), charset_size=charset, entropy_bits=bits, strength_label=label
    )

    if check_breach:
        count = check_hibp_breach(password)
        result.breach_checked = True
        result.breach_count = count

    return result


def _render_result(result: PasswordAuditResult) -> None:
    table = Table(title="Password Audit")
    table.add_column("Metric", style="bold")
    table.add_column("Value")

    table.add_row("Length", str(result.length))
    table.add_row("Estimated charset size", str(result.charset_size))
    table.add_row("Entropy", f"{result.entropy_bits:.1f} bits")

    strength_style = {
        "very weak": "red bold",
        "weak": "red",
        "reasonable": "yellow",
        "strong": "green",
        "very strong": "green bold",
    }.get(result.strength_label, "white")
    table.add_row("Strength", f"[{strength_style}]{result.strength_label}[/{strength_style}]")

    if result.breach_checked:
        if result.breach_count is None:
            table.add_row("Known breaches (HIBP)", "[dim]lookup failed / offline[/dim]")
        elif result.breach_count > 0:
            table.add_row(
                "Known breaches (HIBP)",
                f"[red bold]seen {result.breach_count:,} times - do not use[/red bold]",
            )
        else:
            table.add_row("Known breaches (HIBP)", "[green]not found in known breaches[/green]")

    console.print(table)


@register_command("audit-pass")
def cmd_audit_pass(session: Session, args: list[str]) -> None:
    """
    Usage:
      audit-pass <password>            -> entropy + breach check
      audit-pass <password> --offline  -> entropy only, skip network lookup
    """
    if not args:
        console.print("[red]Usage:[/red] audit-pass <password> [--offline]")
        return

    check_breach = "--offline" not in args
    password = " ".join(a for a in args if a != "--offline")

    if not password:
        console.print("[red]Usage:[/red] audit-pass <password> [--offline]")
        return

    console.print(
        "[dim]Note: only a 5-character hash prefix is sent to HIBP if breach checking "
        "is enabled - the password itself never leaves this machine.[/dim]"
    )
    result = run_password_audit(password, check_breach=check_breach)
    _render_result(result)
