"""
TRAIN Framework - modules/binary_analyzer.py
Static binary forensics for PE (Windows) and ELF (Linux) files.

Registers: analyze-binary <path>

Pure static analysis: reads a file's headers, sections, and basic metadata
(entry point, architecture, linked libraries, section names/sizes) without
ever executing it. This is standard first-pass forensics/triage - the same
kind of information `file`, `readelf`, or PE-bear would show - useful for
quickly characterizing an unknown binary found during an investigation
(e.g. is this a 64-bit ELF? does it import network functions? does a
section have suspiciously high entropy suggesting packing?).

No disassembly, no unpacking, no sandboxing/execution - headers and
section metadata only.
"""

from __future__ import annotations

import math
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.tui_engine import Session, register_command

console = Console()

PE_MAGIC = b"MZ"
ELF_MAGIC = b"\x7fELF"


@dataclass
class SectionInfo:
    name: str
    size: int
    entropy: float


@dataclass
class BinaryReport:
    path: str
    file_type: str  # "PE" | "ELF" | "unknown"
    architecture: str = "unknown"
    entry_point: Optional[int] = None
    sections: list[SectionInfo] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _shannon_entropy(data: bytes) -> float:
    """Standard Shannon entropy (bits/byte) - high values (~7.5-8) often
    indicate compression/encryption/packing; typical code sits lower."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _analyze_elf(data: bytes, path: str) -> BinaryReport:
    report = BinaryReport(path=path, file_type="ELF")

    ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
    ei_data = data[5]   # 1 = little-endian, 2 = big-endian
    report.architecture = "64-bit" if ei_class == 2 else "32-bit"
    endianness = "little-endian" if ei_data == 1 else "big-endian"
    report.notes.append(f"Endianness: {endianness}")

    is_64 = ei_class == 2
    try:
        if is_64:
            e_entry = struct.unpack_from("<Q", data, 24)[0]
            e_shoff = struct.unpack_from("<Q", data, 40)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
        else:
            e_entry = struct.unpack_from("<I", data, 24)[0]
            e_shoff = struct.unpack_from("<I", data, 32)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 46)
        report.entry_point = e_entry
    except struct.error:
        report.notes.append("Could not parse ELF header fields (truncated/corrupt file?).")
        return report

    try:
        import elftools.elf.elffile as elffile
        import io
        ef = elffile.ELFFile(io.BytesIO(data))
        for section in ef.iter_sections():
            sec_data = section.data()
            report.sections.append(SectionInfo(
                name=section.name or "(unnamed)",
                size=len(sec_data),
                entropy=_shannon_entropy(sec_data),
            ))
        # Dynamic symbol table often reveals imported library functions.
        dynsym = ef.get_section_by_name(".dynsym")
        if dynsym:
            report.imports = sorted({
                sym.name for sym in dynsym.iter_symbols()
                if sym.name and sym["st_info"]["type"] == "STT_FUNC"
            })[:30]
    except ImportError:
        report.notes.append("pyelftools not installed - section-level detail unavailable "
                             "(pip install pyelftools).")
    except Exception as e:  # noqa: BLE001
        report.notes.append(f"Section parsing failed: {e}")

    return report


def _analyze_pe(data: bytes, path: str) -> BinaryReport:
    report = BinaryReport(path=path, file_type="PE")

    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        pe_sig = data[e_lfanew:e_lfanew + 4]
        if pe_sig != b"PE\x00\x00":
            report.notes.append("PE signature not found at expected offset (corrupt/unusual file).")
            return report

        coff_offset = e_lfanew + 4
        machine, num_sections = struct.unpack_from("<HH", data, coff_offset)
        machine_map = {0x8664: "x86-64", 0x14C: "x86 (32-bit)", 0xAA64: "ARM64"}
        report.architecture = machine_map.get(machine, f"unknown (0x{machine:04x})")

        opt_header_offset = coff_offset + 20
        magic = struct.unpack_from("<H", data, opt_header_offset)[0]
        is_pe32_plus = magic == 0x20B
        entry_offset = opt_header_offset + 16
        report.entry_point = struct.unpack_from("<I", data, entry_offset)[0]

        # Section table follows the optional header.
        opt_header_size = struct.unpack_from("<H", data, coff_offset + 16)[0]
        section_table_offset = opt_header_offset + opt_header_size

        for i in range(num_sections):
            entry = data[section_table_offset + i * 40: section_table_offset + (i + 1) * 40]
            if len(entry) < 40:
                break
            name = entry[:8].rstrip(b"\x00").decode("ascii", errors="replace")
            virtual_size = struct.unpack_from("<I", entry, 8)[0]
            raw_size = struct.unpack_from("<I", entry, 16)[0]
            raw_ptr = struct.unpack_from("<I", entry, 20)[0]
            section_bytes = data[raw_ptr:raw_ptr + raw_size] if raw_size else b""
            report.sections.append(SectionInfo(
                name=name or "(unnamed)",
                size=virtual_size or raw_size,
                entropy=_shannon_entropy(section_bytes),
            ))

        report.notes.append(f"PE format: {'PE32+' if is_pe32_plus else 'PE32'}")

    except (struct.error, IndexError) as e:
        report.notes.append(f"PE header parsing failed: {e}")

    return report


def analyze_binary(path: Path) -> BinaryReport:
    data = path.read_bytes()

    if data[:2] == PE_MAGIC and len(data) > 0x40:
        return _analyze_pe(data, str(path))
    if data[:4] == ELF_MAGIC:
        return _analyze_elf(data, str(path))

    return BinaryReport(path=str(path), file_type="unknown",
                         notes=["File does not start with a recognized PE or ELF magic number."])


def _render_report(report: BinaryReport) -> None:
    lines = [
        f"[bold]Type:[/bold] {report.file_type}",
        f"[bold]Architecture:[/bold] {report.architecture}",
    ]
    if report.entry_point is not None:
        lines.append(f"[bold]Entry point:[/bold] 0x{report.entry_point:x}")
    console.print(Panel("\n".join(lines), title=f"Binary Analysis — {report.path}", border_style="cyan"))

    if report.sections:
        table = Table(title="Sections")
        table.add_column("Name", style="bold")
        table.add_column("Size (bytes)", justify="right")
        table.add_column("Entropy", justify="right")
        for s in report.sections:
            entropy_style = "red bold" if s.entropy > 7.2 else "dim"
            table.add_row(s.name, str(s.size), f"[{entropy_style}]{s.entropy:.2f}[/{entropy_style}]")
        console.print(table)
        console.print("[dim]Entropy > ~7.2 bits/byte often indicates packing/compression/encryption.[/dim]")

    if report.imports:
        preview = ", ".join(report.imports[:20])
        console.print(Panel(preview, title=f"Imported functions ({len(report.imports)} shown, max 30)",
                             border_style="magenta"))

    for note in report.notes:
        console.print(f"[dim]Note: {note}[/dim]")


@register_command("analyze-binary")
def cmd_analyze_binary(session: Session, args: list[str]) -> None:
    """Usage: analyze-binary <path/to/file>"""
    if not args:
        console.print("[red]Usage:[/red] analyze-binary <path/to/file>")
        return

    path = Path(args[0])
    if not path.exists():
        console.print(f"[red]File not found:[/red] {path}")
        return
    if not path.is_file():
        console.print(f"[red]Not a file:[/red] {path}")
        return

    console.print(f"[cyan]Analyzing[/cyan] {path}...")
    try:
        report = analyze_binary(path)
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Analysis failed:[/red] {e}")
        return

    _render_report(report)
    session.state["last_binary_report"] = report
