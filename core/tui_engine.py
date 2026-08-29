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
[bold]Core commands:[/bold]
  set target <IP/URL>     Set the current target
  status                  Show current session state
  scan                    Port scan (via native_modules/scanner.cpp)
  run-tse                 Run TRAIN Scripting Engine audit scripts
  sniff / ids-run          Start the Go IDS/IPS engine
  audit-web                Web server header/misconfiguration audit
  audit-cve                YAML template-based CVE scan
  audit-compliance          CIS Benchmark compliance check
  audit-logs                Log correlation
  hunt-mitre                MITRE ATT&CK mapping
  audit-osint / geo-track    OSINT and geolocation recon
  check-vt <hash/IP>        VirusTotal reputation lookup
  audit-pass <password>      Password entropy audit
  encode / decode            Base64/Hex/URL encode-decode
  help                       Show this list
  exit / quit                Exit
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
