"""
TRAIN Framework - modules/plugin_engine.py
User-extensible plugin loader for the TRAIN Scripting Engine (TSE).

This is TRAIN's equivalent of Nmap's NSE (Nmap Scripting Engine): drop a
Python file into the plugins/ directory following the small convention
below, and it becomes a new port-triggered check that 'run-tse' picks up
automatically - no core code changes needed.

Plugin file convention (see plugins/example_http_title.py):
  PLUGIN_NAME = "My Check"                 # required: short display name
  PLUGIN_PORTS = [80, 443]                  # required: ports that trigger this,
                                              # or the string "all" to run on every port
  def run_check(target: str, port: int) -> dict | None:
      # required: return None for "nothing to report", or a dict:
      #   {"result": "...", "severity": "info"|"warning"|"finding", "detail": "..."}
      ...

SECURITY NOTE: plugins are arbitrary Python code that TRAIN executes
in-process. Only add plugins you wrote yourself or fully trust - this
loader does not sandbox or restrict what a plugin can do, exactly like
running any other local Python script. Never load a plugin file you
downloaded from an untrusted source without reading it first.
"""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.tui_engine import Session, register_command

console = Console()

PLUGINS_DIR = Path(__file__).resolve().parent.parent / "plugins"
REQUIRED_ATTRS = ("PLUGIN_NAME", "PLUGIN_PORTS", "run_check")


@dataclass
class LoadedPlugin:
    name: str
    ports: list[int]
    run_check: Callable[[str, int], Optional[dict]]
    source_file: str


@dataclass
class PluginLoadError:
    file: str
    error: str


def discover_plugins() -> tuple[list[LoadedPlugin], list[PluginLoadError]]:
    """
    Scans plugins/*.py, imports each as a standalone module, and validates
    it exposes the required convention. Files that fail to import or are
    missing required attributes are skipped with an error recorded (not
    raised) so one broken plugin never breaks the rest of TSE.
    """
    plugins: list[LoadedPlugin] = []
    errors: list[PluginLoadError] = []

    if not PLUGINS_DIR.exists():
        return plugins, errors

    for path in sorted(PLUGINS_DIR.glob("*.py")):
        if path.name.startswith("_"):
            continue  # allow underscore-prefixed helper files to be skipped

        try:
            spec = importlib.util.spec_from_file_location(f"train_plugin_{path.stem}", path)
            if spec is None or spec.loader is None:
                errors.append(PluginLoadError(file=path.name, error="Could not load module spec."))
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception as e:  # noqa: BLE001 - a broken plugin must not crash TSE
            errors.append(PluginLoadError(file=path.name, error=str(e)))
            continue

        missing = [attr for attr in REQUIRED_ATTRS if not hasattr(module, attr)]
        if missing:
            errors.append(PluginLoadError(
                file=path.name, error=f"Missing required attribute(s): {', '.join(missing)}"
            ))
            continue

        if not callable(getattr(module, "run_check")):
            errors.append(PluginLoadError(file=path.name, error="'run_check' is not callable."))
            continue

        plugins.append(LoadedPlugin(
            name=str(module.PLUGIN_NAME),
            ports=module.PLUGIN_PORTS if module.PLUGIN_PORTS == "all" else list(module.PLUGIN_PORTS),
            run_check=module.run_check,
            source_file=path.name,
        ))

    return plugins, errors


def run_plugins_for_port(target: str, port: int) -> list[dict]:
    """
    Runs every loaded plugin whose PLUGIN_PORTS includes this port (or is
    the special value "all", meaning the plugin runs for every port TSE
    checks - useful for checks that make sense regardless of protocol,
    or that simply fail gracefully on the wrong port).
    Returns a list of result dicts (as plugins define them); load/runtime
    errors are logged to the console but never raised, so a bad plugin
    can't take down a scan.
    """
    plugins, _ = discover_plugins()
    results = []

    for plugin in plugins:
        applies = plugin.ports == "all" or port in plugin.ports
        if not applies:
            continue
        try:
            outcome = plugin.run_check(target, port)
        except Exception as e:  # noqa: BLE001 - isolate plugin failures
            console.print(f"[red]Plugin '{plugin.name}' ({plugin.source_file}) raised an error:[/red] {e}")
            continue
        if outcome:
            outcome = dict(outcome)
            outcome["_plugin_name"] = plugin.name
            results.append(outcome)

    return results


@register_command("list-plugins")
def cmd_list_plugins(session: Session, args: list[str]) -> None:
    """Usage: list-plugins   (shows every plugin found in plugins/, and any load errors)"""
    plugins, errors = discover_plugins()

    if not plugins and not errors:
        console.print(Panel(
            f"No plugins found in {PLUGINS_DIR}.\n"
            f"Drop a .py file there following the convention in "
            f"plugins/example_http_title.py to add one.",
            title="TRAIN Plugins", border_style="yellow",
        ))
        return

    if plugins:
        table = Table(title=f"Loaded Plugins ({len(plugins)})")
        table.add_column("Name", style="bold")
        table.add_column("Ports")
        table.add_column("File", style="dim")
        for p in plugins:
            ports_display = "all" if p.ports == "all" else ", ".join(str(port) for port in p.ports)
            table.add_row(p.name, ports_display, p.source_file)
        console.print(table)

    if errors:
        err_table = Table(title=f"Plugin Load Errors ({len(errors)})")
        err_table.add_column("File", style="bold red")
        err_table.add_column("Error", style="red")
        for e in errors:
            err_table.add_row(e.file, e.error)
        console.print(err_table)
