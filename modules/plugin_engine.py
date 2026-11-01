"""
TRAIN Framework - modules/plugin_engine.py
User-extensible plugin loader for the TRAIN Scripting Engine (TSE).

Drop a Python file into plugins/ that follows core/plugin_contract.py.
`run-tse` and `list-plugins` pick it up without editing the core.

Plugins are arbitrary Python executed in-process. Only add plugins you
wrote or have fully read. Each plugin call is limited by PLUGIN_TIMEOUT,
which the loader caps.
"""

from __future__ import annotations

import importlib.util
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.plugin_contract import (
    ALLOWED_SEVERITIES,
    DEFAULT_TIMEOUT_SEC,
    MAX_DETAIL_LEN,
    MAX_NAME_LEN,
    MAX_RESULT_LEN,
    MAX_TIMEOUT_SEC,
)
from core.tui_engine import Session, register_command

console = Console()

PLUGINS_DIR = Path(__file__).resolve().parent.parent / "plugins"
REQUIRED_ATTRS = ("PLUGIN_NAME", "PLUGIN_PORTS", "run_check")

_CACHE: dict[str, tuple[tuple, list["LoadedPlugin"], list["PluginLoadError"]]] = {}


@dataclass
class LoadedPlugin:
    name: str
    description: str
    ports: list[int] | str
    run_check: Callable[[str, int], Optional[dict]]
    source_file: str
    timeout: float


@dataclass
class PluginLoadError:
    file: str
    error: str


def _directory_stamp(directory: Path) -> tuple:
    if not directory.exists():
        return ()
    files = sorted(path for path in directory.glob("*.py") if not path.name.startswith("_"))
    return tuple((path.name, path.stat().st_mtime_ns) for path in files)


def _validate_ports(value) -> list[int] | str:
    if value == "all":
        return "all"
    if not isinstance(value, list) or not value:
        raise ValueError("PLUGIN_PORTS must be 'all' or a non-empty list of ports.")
    ports: list[int] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int) or not 1 <= item <= 65535:
            raise ValueError(f"Invalid port in PLUGIN_PORTS: {item!r}")
        ports.append(item)
    return ports


def _validate_timeout(module) -> float:
    raw = getattr(module, "PLUGIN_TIMEOUT", DEFAULT_TIMEOUT_SEC)
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise ValueError("PLUGIN_TIMEOUT must be a number of seconds.")
    if raw <= 0:
        raise ValueError("PLUGIN_TIMEOUT must be greater than zero.")
    return min(float(raw), MAX_TIMEOUT_SEC)


def discover_plugins(
    directory: Path | None = None,
    *,
    use_cache: bool = True,
) -> tuple[list[LoadedPlugin], list[PluginLoadError]]:
    """
    Import plugins/*.py and validate the contract. A broken plugin is
    recorded and skipped so the rest of the set still loads.
    """
    directory = directory or PLUGINS_DIR
    cache_key = str(directory.resolve()) if directory.exists() else str(directory)
    stamp = _directory_stamp(directory)
    cached = _CACHE.get(cache_key)
    if use_cache and cached and cached[0] == stamp:
        return cached[1], cached[2]

    plugins: list[LoadedPlugin] = []
    errors: list[PluginLoadError] = []

    if not directory.exists():
        return plugins, errors

    for path in sorted(directory.glob("*.py")):
        if path.name.startswith("_"):
            continue
        try:
            spec = importlib.util.spec_from_file_location(f"train_plugin_{path.stem}", path)
            if spec is None or spec.loader is None:
                errors.append(PluginLoadError(file=path.name, error="Could not load module spec."))
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception as exc:  # noqa: BLE001 - one broken plugin must not abort discovery
            errors.append(PluginLoadError(file=path.name, error=str(exc)))
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

        name = getattr(module, "PLUGIN_NAME")
        if not isinstance(name, str) or not name.strip() or len(name) > MAX_NAME_LEN:
            errors.append(PluginLoadError(
                file=path.name, error=f"PLUGIN_NAME must be a string of 1-{MAX_NAME_LEN} characters."
            ))
            continue

        description = getattr(module, "PLUGIN_DESCRIPTION", "")
        if not isinstance(description, str):
            errors.append(PluginLoadError(file=path.name, error="PLUGIN_DESCRIPTION must be a string."))
            continue

        try:
            ports = _validate_ports(module.PLUGIN_PORTS)
            timeout = _validate_timeout(module)
        except ValueError as exc:
            errors.append(PluginLoadError(file=path.name, error=str(exc)))
            continue

        plugins.append(LoadedPlugin(
            name=name.strip(),
            description=description.strip(),
            ports=ports,
            run_check=module.run_check,
            source_file=path.name,
            timeout=timeout,
        ))

    if use_cache:
        _CACHE[cache_key] = (stamp, plugins, errors)
    return plugins, errors


def _normalize_outcome(plugin: LoadedPlugin, outcome: dict) -> dict:
    severity = str(outcome.get("severity", "info"))
    if severity not in ALLOWED_SEVERITIES:
        severity = "info"
    return {
        "result": str(outcome.get("result", ""))[:MAX_RESULT_LEN],
        "severity": severity,
        "detail": str(outcome.get("detail", ""))[:MAX_DETAIL_LEN],
        "_plugin_name": plugin.name,
    }


def _invoke(plugin: LoadedPlugin, target: str, port: int) -> Optional[dict]:
    pool = ThreadPoolExecutor(max_workers=1)
    future = pool.submit(plugin.run_check, target, port)
    try:
        return future.result(timeout=plugin.timeout)
    except FuturesTimeout:
        return {
            "result": "timeout",
            "severity": "info",
            "detail": f"Plugin exceeded the {plugin.timeout:.0f}s limit.",
        }
    finally:
        # Do not wait if the plugin is still running; waiting would ignore the timeout.
        pool.shutdown(wait=False, cancel_futures=True)


def run_plugins_for_port(
    target: str,
    port: int,
    directory: Path | None = None,
) -> list[dict]:
    """
    Run each plugin that applies to this port, one at a time.
    Load and runtime errors are reported and do not stop the others.
    """
    plugins, _errors = discover_plugins(directory)
    results: list[dict] = []

    for plugin in plugins:
        applies = plugin.ports == "all" or port in plugin.ports
        if not applies:
            continue
        try:
            outcome = _invoke(plugin, target, port)
        except Exception as exc:  # noqa: BLE001 - isolate plugin failures
            console.print(f"[red]Plugin '{plugin.name}' ({plugin.source_file}) raised an error:[/red] {exc}")
            continue
        if outcome:
            if not isinstance(outcome, dict):
                console.print(
                    f"[red]Plugin '{plugin.name}' returned {type(outcome).__name__}, expected a dict.[/red]"
                )
                continue
            results.append(_normalize_outcome(plugin, outcome))

    return results


@register_command("list-plugins")
def cmd_list_plugins(session: Session, args: list[str]) -> None:
    """Usage: list-plugins   (shows every plugin found in plugins/, and any load errors)"""
    plugins, errors = discover_plugins()

    if not plugins and not errors:
        console.print(Panel(
            f"No plugins found in {PLUGINS_DIR}.\n"
            "Drop a .py file there following core/plugin_contract.py "
            "and plugins/example_http_title.py.",
            title="TRAIN Plugins", border_style="yellow",
        ))
        return

    if plugins:
        table = Table(title=f"Loaded Plugins ({len(plugins)})")
        table.add_column("Name", style="bold")
        table.add_column("Ports")
        table.add_column("Limit", justify="right")
        table.add_column("Description")
        table.add_column("File", style="dim")
        for plugin in plugins:
            ports_display = "all" if plugin.ports == "all" else ", ".join(str(port) for port in plugin.ports)
            table.add_row(
                plugin.name,
                ports_display,
                f"{plugin.timeout:.0f}s",
                plugin.description or "-",
                plugin.source_file,
            )
        console.print(table)

    if errors:
        err_table = Table(title=f"Plugin Load Errors ({len(errors)})")
        err_table.add_column("File", style="bold red")
        err_table.add_column("Error", style="red")
        for error in errors:
            err_table.add_row(error.file, error.error)
        console.print(err_table)
