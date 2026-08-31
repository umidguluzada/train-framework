"""
TRAIN Framework - TUI Engine
Threat Response & Automated Intelligence Network

This module drives the main interactive terminal interface:
 - ASCII banner
 - Colored panels (Rich)
 - `train-cli >` prompt (Prompt_Toolkit)
 - Command parsing and dispatch to the right module
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import Callable, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import InMemoryHistory

console = Console()

BANNER = r"""
[bold cyan] _____ ____      _    ___ _   _[/bold cyan]
[bold cyan]|_   _|  _ \    / \  |_ _| \ | |[/bold cyan]
[bold cyan]  | | | |_) |  / _ \  | ||  \| |[/bold cyan]
[bold cyan]  | | |  _ <  / ___ \ | || |\  |[/bold cyan]
[bold cyan]  |_| |_| \_\/_/   \_\___|_| \_|[/bold cyan]
[dim]Threat Response & Automated Intelligence Network[/dim]
[dim]Purple Team CLI  |  v0.1.0-dev[/dim]
"""

# Central registry for all commands. Each module registers itself here
# by calling @register_command(name) on its handler function.
COMMAND_REGISTRY: dict[str, Callable[["Session", list[str]], None]] = {}


def register_command(name: str):
    """Decorator used by modules to register a CLI command."""
    def wrapper(func: Callable[["Session", list[str]], None]):
        COMMAND_REGISTRY[name] = func
        return func
    return wrapper


@dataclass
class Session:
    """Current TUI session state (target, options, etc.)."""
    target: Optional[str] = None
    verbose: bool = False
    state: dict = field(default_factory=dict)


def print_banner() -> None:
    console.print(Panel(BANNER, border_style="cyan", expand=False))


def print_status(session: Session) -> None:
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_row("[bold]Target:[/bold]", session.target or "[dim]not set[/dim]")
    table.add_row("[bold]Verbose:[/bold]", "on" if session.verbose else "off")
    console.print(Panel(table, title="Session", border_style="grey50"))


HELP_TEXT = """
[bold]Core:[/bold]
  set target <IP/URL>              Set the current target
  status                            Show current session state
  help                               Show this list
  exit / quit                        Exit

[bold]Recon & IDS/IPS:[/bold]
  scan [start] [end]                Port scan (native_modules/scanner.cpp)
  sniff <iface> [rules] [--ips]      Start the Go IDS/IPS engine (alias: ids-run)

[bold]Web auditing:[/bold]
  audit-web [url]                    HTTP header/TLS/misconfig audit
  web-proxy [port]                   Local HTTP forwarding proxy (live traffic log)
  api-test <url>                     Probe a single API endpoint
  api-discover <base_url>            Probe common API path conventions
  dir-brute <url> [wordlist]         Web directory/file discovery (gobuster-style)

[bold]Vulnerability & compliance:[/bold]
  run-tse [ports]                    TRAIN Scripting Engine audit checks
  audit-cve <keywords>                NVD CVE lookup (or --from-tse)
  template-scan <file.yaml>           YAML template-based checks
  audit-compliance                    CIS Benchmark-inspired local audit

[bold]Log analysis & threat hunting:[/bold]
  audit-logs <file> --format <type>   Log correlation (auth/nginx/powershell/lsass/...)
  hunt-mitre                          Map findings to MITRE ATT&CK techniques
  hunt-beacon                         Detect C2 beaconing in timestamped logs

[bold]OSINT & reputation:[/bold]
  audit-osint <domain>                 Passive DNS enumeration
  geo-track <ip/domain>                 Geolocation/ASN lookup
  check-vt <hash/IP>                    VirusTotal reputation lookup

[bold]Binary forensics:[/bold]
  analyze-binary <file>                 Static PE/ELF analysis

[bold]Passwords & encryption:[/bold]
  audit-pass <password> [--offline]     Password entropy + breach check
  vault-init / vault-add / vault-get     AES-256 encrypted local secrets vault
  vault-list / vault-remove
  encode / decode <base64|hex|url>        Encode/decode text
  hash <md5|sha1|sha256|sha512>            Hash text

[bold]Phishing awareness:[/bold]
  phish-awareness [level]                Show a sample email + red flags
  phish-quiz [count] [level]              Interactive spot-the-phish quiz

[bold]Reporting:[/bold]
  generate-report [output.html]           Export all session findings to HTML
"""


@register_command("help")
def cmd_help(session: Session, args: list[str]) -> None:
    console.print(Panel(HELP_TEXT, title="TRAIN Framework - Commands", border_style="magenta"))


@register_command("status")
def cmd_status(session: Session, args: list[str]) -> None:
    print_status(session)


@register_command("set")
def cmd_set(session: Session, args: list[str]) -> None:
    if len(args) >= 2 and args[0] == "target":
        session.target = args[1]
        console.print(f"[green]OK[/green] Target set: [bold]{session.target}[/bold]")
    else:
        console.print("[red]Usage:[/red] set target <IP/URL>")


def _print_command_help(cmd: str, handler) -> None:
    """
    Prints a command's own docstring (the "Usage: ..." block every module
    writes on its handler function) when the user runs `<cmd> --help`.
    Falls back to a generic message if a handler has no docstring.
    """
    doc = (handler.__doc__ or "").strip()
    if not doc:
        doc = f"No detailed help available for '{cmd}'."
    console.print(Panel(doc, title=f"Help — {cmd}", border_style="cyan"))


def dispatch(session: Session, raw_line: str) -> bool:
    """Process a single command line. Returns False if the main loop should stop (exit)."""
    raw_line = raw_line.strip()
    if not raw_line:
        return True
    if raw_line in ("exit", "quit"):
        return False

    try:
        parts = shlex.split(raw_line)
    except ValueError as e:
        console.print(f"[red]Syntax error:[/red] {e}")
        return True

    cmd, args = parts[0], parts[1:]
    handler = COMMAND_REGISTRY.get(cmd)
    if handler is None:
        console.print(f"[red]Unknown command:[/red] {cmd}  ([dim]type 'help'[/dim])")
        return True

    # Any command supports `<cmd> --help` / `<cmd> -h` to show its own
    # usage docstring, without each module needing to implement this itself.
    if args and args[0] in ("--help", "-h"):
        _print_command_help(cmd, handler)
        return True

    try:
        handler(session, args)
    except Exception as e:  # noqa: BLE001 - surfaced to the user at TUI level
        console.print(f"[red]Error ({cmd}):[/red] {e}")
    return True


def run() -> None:
    session = Session()
    print_banner()
    console.print("[dim]Type 'help' to see available commands.[/dim]\n")

    completer = WordCompleter(list(COMMAND_REGISTRY.keys()) + ["target", "exit", "quit"])
    prompt_session = PromptSession(history=InMemoryHistory(), completer=completer)

    while True:
        try:
            line = prompt_session.prompt("train-cli > ")
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Exiting...[/dim]")
            break

        if not dispatch(session, line):
            console.print("[dim]Goodbye![/dim]")
            break
