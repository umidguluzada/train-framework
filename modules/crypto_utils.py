"""
TRAIN Framework - modules/crypto_utils.py
Data encoding/decoding and hashing utility.

Registers:
  encode <format> <text>   -> base64 | hex | url
  decode <format> <text>   -> base64 | hex | url
  hash <algo> <text>       -> md5 | sha1 | sha256 | sha512

Pure, local, offline string transforms - no network calls, no target
required. Useful for quickly encoding a payload/value found during other
audits (e.g. decoding a base64 string spotted in a log or banner).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from urllib.parse import quote, unquote

from rich.console import Console
from rich.panel import Panel

from core.tui_engine import Session, register_command

console = Console()

HASH_ALGOS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}


def encode_base64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def decode_base64(text: str) -> str:
    # Add missing padding defensively - a common source of decode failures
    # when a base64 string was copy-pasted without its trailing '='.
    padded = text + "=" * (-len(text) % 4)
    return base64.b64decode(padded).decode("utf-8", errors="replace")


def encode_hex(text: str) -> str:
    return text.encode("utf-8").hex()


def decode_hex(text: str) -> str:
    cleaned = text.replace(" ", "").replace("0x", "")
    return bytes.fromhex(cleaned).decode("utf-8", errors="replace")


def encode_url(text: str) -> str:
    return quote(text, safe="")


def decode_url(text: str) -> str:
    return unquote(text)


ENCODERS = {"base64": encode_base64, "hex": encode_hex, "url": encode_url}
DECODERS = {"base64": decode_base64, "hex": decode_hex, "url": decode_url}


@register_command("encode")
def cmd_encode(session: Session, args: list[str]) -> None:
    """Usage: encode <base64|hex|url> <text...>"""
    if len(args) < 2:
        console.print("[red]Usage:[/red] encode <base64|hex|url> <text...>")
        return

    fmt, text = args[0].lower(), " ".join(args[1:])
    encoder = ENCODERS.get(fmt)
    if not encoder:
        console.print(f"[red]Unknown format:[/red] {fmt}  (use: base64, hex, url)")
        return

    try:
        result = encoder(text)
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Encode failed:[/red] {e}")
        return

    console.print(Panel(result, title=f"Encoded ({fmt})", border_style="green"))


@register_command("decode")
def cmd_decode(session: Session, args: list[str]) -> None:
    """Usage: decode <base64|hex|url> <text...>"""
    if len(args) < 2:
        console.print("[red]Usage:[/red] decode <base64|hex|url> <text...>")
        return

    fmt, text = args[0].lower(), " ".join(args[1:])
    decoder = DECODERS.get(fmt)
    if not decoder:
        console.print(f"[red]Unknown format:[/red] {fmt}  (use: base64, hex, url)")
        return

    try:
        result = decoder(text)
    except (binascii.Error, ValueError) as e:
        console.print(f"[red]Decode failed:[/red] invalid {fmt} input ({e})")
        return

    console.print(Panel(result, title=f"Decoded ({fmt})", border_style="green"))


@register_command("hash")
def cmd_hash(session: Session, args: list[str]) -> None:
    """Usage: hash <md5|sha1|sha256|sha512> <text...>"""
    if len(args) < 2:
        console.print("[red]Usage:[/red] hash <md5|sha1|sha256|sha512> <text...>")
        return

    algo, text = args[0].lower(), " ".join(args[1:])
    hasher = HASH_ALGOS.get(algo)
    if not hasher:
        console.print(f"[red]Unknown algorithm:[/red] {algo}  (use: md5, sha1, sha256, sha512)")
        return

    digest = hasher(text.encode("utf-8")).hexdigest()
    console.print(Panel(digest, title=f"{algo.upper()} hash", border_style="blue"))
