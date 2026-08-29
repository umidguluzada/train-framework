"""
TRAIN Framework - core/bridge.py
Python <-> native (C++/Go) binary bridge.

Responsible for:
 - Locating compiled native binaries (train_scanner, train_sniffer, ...)
 - Running them as subprocesses with the right arguments
 - Parsing their JSON stdout output into Python objects
 - Registering the TUI commands that trigger them (e.g. "scan")

Keeping this in one place means every native module follows the same
"subprocess -> JSON on stdout -> parse" contract, so adding a new native
tool later (the Go IDS/IPS, etc.) is just a new thin wrapper function here.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core.tui_engine import Session, register_command

console = Console()

# Project root = parent of core/, so native_modules/ is a sibling directory.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
NATIVE_MODULES_DIR = PROJECT_ROOT / "native_modules"
SCANNER_BINARY = NATIVE_MODULES_DIR / "train_scanner"


class BridgeError(Exception):
    """Raised when a native binary is missing, fails, or returns bad output."""


def _run_native_binary(binary_path: Path, args: list[str], timeout_sec: int = 120) -> dict[str, Any]:
    """
    Runs a compiled native binary and parses its stdout as JSON.

    Raises BridgeError with a clear, user-facing message on any failure
    (binary missing, non-zero exit code, invalid JSON, timeout).
    """
    if not binary_path.exists():
        raise BridgeError(
            f"Binary not found: {binary_path}\n"
            f"Did you compile it? See the module's build instructions."
        )

    cmd = [str(binary_path)] + args
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
    except subprocess.TimeoutExpired as e:
        raise BridgeError(f"'{binary_path.name}' timed out after {timeout_sec}s") from e
    except OSError as e:
        raise BridgeError(f"Failed to execute '{binary_path.name}': {e}") from e

    if proc.returncode != 0:
        stderr = proc.stderr.strip() or "(no stderr output)"
        raise BridgeError(f"'{binary_path.name}' exited with code {proc.returncode}: {stderr}")

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise BridgeError(
            f"'{binary_path.name}' produced invalid JSON output: {e}\n"
            f"Raw output (first 300 chars): {proc.stdout[:300]!r}"
        ) from e


def run_port_scan(
    target: str,
    start_port: int = 1,
    end_port: int = 1024,
    threads: int = 200,
    timeout_ms: int = 500,
) -> dict[str, Any]:
    """Runs the C++ port scanner and returns its parsed JSON result."""
    args = [target, str(start_port), str(end_port), str(threads), str(timeout_ms)]
    return _run_native_binary(SCANNER_BINARY, args, timeout_sec=max(30, timeout_ms // 100))


def _print_scan_results(result: dict[str, Any]) -> None:
    target = result.get("target", "?")
    elapsed = result.get("elapsed_seconds", 0.0)
    open_ports = result.get("open_ports", [])

    if not open_ports:
        console.print(
            Panel(
                f"No open ports found on [bold]{target}[/bold] "
                f"(scanned in {elapsed:.2f}s).",
                title="Scan Result",
                border_style="yellow",
            )
        )
        return

    table = Table(title=f"Open Ports on {target}  ({elapsed:.2f}s)")
    table.add_column("Port", justify="right", style="bold cyan")
    table.add_column("Service (guess)", style="green")
    table.add_column("Banner", style="dim")

    for entry in open_ports:
        banner = entry.get("banner", "").strip() or "-"
        # Keep long banners readable in the table
        if len(banner) > 60:
            banner = banner[:57] + "..."
        table.add_row(str(entry.get("port", "?")), entry.get("service_guess", "unknown"), banner)

    console.print(table)


@register_command("scan")
def cmd_scan(session: Session, args: list[str]) -> None:
    """
    Usage:
      scan                          -> scan session target, ports 1-1024
      scan <start> <end>            -> scan session target, custom port range
      scan <target> <start> <end>   -> scan an explicit target, custom range
    """
    target: Optional[str] = None
    start_port, end_port = 1, 1024

    if len(args) == 0:
        target = session.target
    elif len(args) == 2:
        target = session.target
        start_port, end_port = int(args[0]), int(args[1])
    elif len(args) == 3:
        target, start_port, end_port = args[0], int(args[1]), int(args[2])
    else:
        console.print("[red]Usage:[/red] scan | scan <start> <end> | scan <target> <start> <end>")
        return

    if not target:
        console.print("[red]No target set.[/red] Use 'set target <IP/URL>' first, or pass one directly.")
        return

    console.print(f"[cyan]Scanning[/cyan] {target}  (ports {start_port}-{end_port})...")

    try:
        result = run_port_scan(target, start_port, end_port)
    except BridgeError as e:
        console.print(f"[red]Scan failed:[/red] {e}")
        return

    _print_scan_results(result)
    # Stash the last scan result in session state so other modules
    # (e.g. TSE, web_auditor) can reuse it without re-scanning.
    session.state["last_scan"] = result


def native_binary_status() -> dict[str, bool]:
    """Quick health check used by a future 'doctor'/'status' command."""
    return {
        "train_scanner": SCANNER_BINARY.exists(),
        "g++": shutil.which("g++") is not None,
    }


# ---------------------------------------------------------------------------
# IDS/IPS (Go sniffer) integration
# ---------------------------------------------------------------------------

import signal  # noqa: E402
import sys  # noqa: E402
import threading  # noqa: E402

SNIFFER_BINARY = NATIVE_MODULES_DIR / "train_sniffer"
DEFAULT_RULES_FILE = NATIVE_MODULES_DIR / "rules.conf"


def _sniffer_alert_style(action: str) -> str:
    return "red bold" if action == "drop" else "yellow"


def _stream_sniffer_output(proc: subprocess.Popen, stop_event: threading.Event) -> None:
    """
    Reads JSON-lines alerts from the sniffer process's stdout and prints
    each one as a formatted Rich line, until the process ends or the
    user asks us to stop (Ctrl+C).
    """
    assert proc.stdout is not None
    for raw_line in proc.stdout:
        if stop_event.is_set():
            break
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            alert = json.loads(raw_line)
        except json.JSONDecodeError:
            # The sniffer also writes plain-text status lines to stderr,
            # but just in case something non-JSON shows up on stdout,
            # don't crash the TUI over it.
            console.print(f"[dim]{raw_line}[/dim]")
            continue

        style = _sniffer_alert_style(alert.get("action", "alert"))
        blocked_tag = " [bold red][BLOCKED][/bold red]" if alert.get("blocked") else ""
        console.print(
            f"[{style}]ALERT[/{style}] sid={alert.get('sid')} "
            f"{alert.get('src_ip')}:{alert.get('src_port')} -> "
            f"{alert.get('dst_ip')}:{alert.get('dst_port')}/{alert.get('proto')}  "
            f"\"{alert.get('msg')}\"{blocked_tag}"
        )


@register_command("sniff")
@register_command("ids-run")
def cmd_sniff(session: Session, args: list[str]) -> None:
    """
    Usage:
      sniff <interface> [rules_file] [--ips]

    Runs the Go IDS/IPS engine on the given interface, streaming alerts
    live into the TUI. Requires root privileges to capture packets, so
    the TUI itself must be run with sudo (this command does not silently
    re-exec itself as root).

    Press Ctrl+C to stop capturing and return to the prompt.
    """
    if not SNIFFER_BINARY.exists():
        console.print(
            f"[red]'{SNIFFER_BINARY.name}' not found.[/red] "
            f"Build it first: cd native_modules && go build -o train_sniffer sniffer.go"
        )
        return

    if len(args) < 1:
        console.print("[red]Usage:[/red] sniff <interface> [rules_file] [--ips]")
        return

    iface = args[0]
    ips_mode = "--ips" in args
    rest = [a for a in args[1:] if a != "--ips"]
    rules_file = Path(rest[0]) if rest else DEFAULT_RULES_FILE

    if not rules_file.exists():
        console.print(f"[red]Rules file not found:[/red] {rules_file}")
        return

    cmd = [str(SNIFFER_BINARY), "-iface", iface, "-rules", str(rules_file)]
    if ips_mode:
        cmd.append("-ips")

    console.print(
        f"[cyan]Starting IDS{'/IPS' if ips_mode else ''} on[/cyan] {iface} "
        f"[dim](rules: {rules_file.name})[/dim] — Ctrl+C to stop.\n"
    )

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # line-buffered
        )
    except OSError as e:
        console.print(f"[red]Failed to start sniffer:[/red] {e}")
        return

    stop_event = threading.Event()
    reader_thread = threading.Thread(
        target=_stream_sniffer_output, args=(proc, stop_event), daemon=True
    )
    reader_thread.start()

    try:
        while reader_thread.is_alive():
            reader_thread.join(timeout=0.5)
            # If the process exited on its own (e.g. bad interface / permission
            # error), surface whatever it wrote to stderr and stop.
            if proc.poll() is not None:
                break
    except KeyboardInterrupt:
        console.print("\n[dim]Stopping capture...[/dim]")
    finally:
        stop_event.set()
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()

        # Surface any startup/parse errors the Go process reported.
        if proc.stderr is not None:
            leftover_err = proc.stderr.read()
            if leftover_err.strip():
                console.print(f"[dim]{leftover_err.strip()}[/dim]")

        returncode = proc.poll()
        if returncode not in (0, None, -signal.SIGINT):
            console.print(f"[red]Sniffer exited with code {returncode}.[/red]")
