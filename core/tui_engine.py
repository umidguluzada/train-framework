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

from core.version import VERSION

console = Console()

BANNER = rf"""
[bold cyan] _____ ____      _    ___ _   _[/bold cyan]
[bold cyan]|_   _|  _ \    / \  |_ _| \ | |[/bold cyan]
[bold cyan]  | | | |_) |  / _ \  | ||  \| |[/bold cyan]
[bold cyan]  | | |  _ <  / ___ \ | || |\  |[/bold cyan]
[bold cyan]  |_| |_| \_\/_/   \_\___|_| \_|[/bold cyan]
[dim]Threat Response & Automated Intelligence Network[/dim]
[dim]Purple Team CLI  |  v{VERSION}[/dim]
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
    from core.bridge import native_binary_status
    from core.findings import collect_report

    report = collect_report(session)
    binaries = native_binary_status()
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_row("[bold]Target:[/bold]", session.target or "[dim]not set[/dim]")
    table.add_row("[bold]Verbose:[/bold]", "on" if session.verbose else "off")
    table.add_row("[bold]Commands:[/bold]", str(len(COMMAND_REGISTRY)))
    table.add_row(
        "[bold]Findings:[/bold]",
        f"{len(report.findings)} recorded  ·  risk {report.risk['level']} ({report.risk['score']})",
    )
    scanner = "built" if binaries["train_scanner"] else "not built"
    sniffer = "built" if binaries["train_sniffer"] else "not built"
    table.add_row("[bold]Native:[/bold]", f"scanner {scanner}, sniffer {sniffer}")
    console.print(Panel(table, title="Session", border_style="grey50"))


HELP_TEXT = """
[bold]Core:[/bold]
  menu                               Interactive command menu
  set target <IP/URL>              Set the current target
  status                            Show current session state
  doctor                             Check local install and native binaries
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
  generate-report [output.html]           Export JSON, interactive HTML, and PDF
  generate-pdf-report [output.pdf]         Export the PDF summary on its own

[bold]Wireless & router auditing:[/bold]
  wifi-scan                               List nearby Wi-Fi networks, flag weak encryption
  router-audit <router_ip>                 Check router/AP management ports for exposure
  net-discover <cidr>                      Find live LAN hosts, hostname/MAC lookup

[bold]Secure networking:[/bold]
  siem-dashboard <file> --format <type>     Live-updating SIEM-style log dashboard
  chat-listen / chat-connect <host> <port>  End-to-end encrypted terminal chat

[bold]Plugin system (TSE extensibility):[/bold]
  list-plugins                            List loaded plugins from plugins/ (Nmap-NSE-style)
"""


COMMAND_GROUPS: list[tuple[str, list[str]]] = [
    ("Core", ["menu", "set", "status", "doctor", "help"]),
    ("Recon & IDS/IPS", ["scan", "sniff", "ids-run"]),
    ("Web auditing", ["audit-web", "web-proxy", "api-test", "api-discover", "dir-brute"]),
    ("Vulnerability & compliance", ["run-tse", "audit-cve", "template-scan", "audit-compliance"]),
    ("Log analysis & threat hunting", ["audit-logs", "hunt-mitre", "hunt-beacon", "siem-dashboard"]),
    ("OSINT & reputation", ["audit-osint", "geo-track", "check-vt"]),
    ("Binary forensics", ["analyze-binary"]),
    ("Passwords & encryption", ["audit-pass", "vault-init", "vault-add", "vault-get", "vault-list", "vault-remove", "encode", "decode", "hash"]),
    ("Phishing awareness", ["phish-awareness", "phish-quiz"]),
    ("Reporting", ["generate-report", "generate-pdf-report"]),
    ("Wireless & router auditing", ["wifi-scan", "router-audit", "net-discover"]),
    ("Secure networking", ["chat-listen", "chat-connect"]),
    ("Plugins", ["list-plugins"]),
]


def _first_doc_line(handler) -> str:
    doc = (handler.__doc__ or "").strip()
    if not doc:
        return ""
    return doc.splitlines()[0].replace("Usage:", "").strip()


@register_command("help")
def cmd_help(session: Session, args: list[str]) -> None:
    console.print(Panel(HELP_TEXT, title="TRAIN Framework - Commands", border_style="magenta"))


@register_command("menu")
def cmd_menu(session: Session, args: list[str]) -> None:
    """Usage: menu    Show command groups, then optionally run one command."""
    for title, commands in COMMAND_GROUPS:
        table = Table(title=title, show_header=False, box=None, padding=(0, 1))
        for name in commands:
            handler = COMMAND_REGISTRY.get(name)
            summary = _first_doc_line(handler) if handler else "unavailable"
            table.add_row(f"[cyan]{name}[/cyan]", summary[:78])
        console.print(table)

    try:
        line = PromptSession().prompt("Command (blank cancels): ")
    except (EOFError, KeyboardInterrupt):
        console.print()
        return
    if line.strip():
        dispatch(session, line)


@register_command("doctor")
def cmd_doctor(session: Session, args: list[str]) -> None:
    """Usage: doctor    Check Python libraries, native binaries, and plugins."""
    import importlib
    import sys

    from core.bridge import native_binary_status

    table = Table(title=f"TRAIN {VERSION} doctor")
    table.add_column("Check")
    table.add_column("State")
    table.add_column("Detail")

    py_ok = sys.version_info >= (3, 10)
    table.add_row(
        "Python",
        "[green]ok[/green]" if py_ok else "[red]too old[/red]",
        f"{sys.version.split()[0]} (3.10+ required)",
    )

    for module_name, label in (
        ("aiohttp", "aiohttp"),
        ("rich", "rich"),
        ("prompt_toolkit", "prompt_toolkit"),
        ("yaml", "PyYAML"),
        ("requests", "requests"),
        ("cryptography", "cryptography"),
        ("reportlab", "reportlab"),
        ("dns.resolver", "dnspython"),
        ("psutil", "psutil"),
    ):
        try:
            importlib.import_module(module_name)
            table.add_row(label, "[green]ok[/green]", module_name)
        except ImportError as exc:
            table.add_row(label, "[yellow]missing[/yellow]", str(exc))

    for name, present in native_binary_status().items():
        table.add_row(name, "[green]ok[/green]" if present else "[yellow]missing[/yellow]", "")

    try:
        from modules.plugin_engine import discover_plugins
        plugins, errors = discover_plugins()
        table.add_row("plugins", "[green]ok[/green]", f"{len(plugins)} loaded, {len(errors)} errors")
    except Exception as exc:  # noqa: BLE001 - doctor should report, not crash
        table.add_row("plugins", "[red]error[/red]", str(exc))

    console.print(table)


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
