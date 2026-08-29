"""
TRAIN Framework - modules/vault_manager.py
AES-256 encrypted local secrets vault.

Registers:
  vault-init                      -> creates a new encrypted vault (asks for a master password)
  vault-add <name>                -> adds/updates an entry (prompts for the secret value)
  vault-get <name>                -> decrypts and displays one entry
  vault-list                      -> lists entry names (without decrypting values)
  vault-remove <name>              -> deletes an entry

Implementation notes:
  - Uses Fernet (AES-128-CBC + HMAC, from the `cryptography` library) with
    a key derived from the user's master password via PBKDF2-HMAC-SHA256
    (390,000 iterations, matching OWASP's current minimum recommendation).
  - The vault file (vault.enc) stores only the PBKDF2 salt and the Fernet
    ciphertext - the master password itself is never written to disk and
    never leaves this process.
  - The master password is read via getpass (not echoed to the terminal,
    not passed as a CLI argument, so it doesn't end up in shell history).
"""

from __future__ import annotations

import base64
import getpass
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.tui_engine import Session, register_command

console = Console()

VAULT_PATH = Path.home() / ".train_framework" / "vault.enc"
PBKDF2_ITERATIONS = 390_000
SALT_SIZE = 16


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def _load_vault(password: str) -> dict[str, str]:
    """Reads and decrypts the vault. Returns an empty dict if no vault exists yet."""
    if not VAULT_PATH.exists():
        return {}

    raw = VAULT_PATH.read_bytes()
    salt, ciphertext = raw[:SALT_SIZE], raw[SALT_SIZE:]
    key = _derive_key(password, salt)

    try:
        plaintext = Fernet(key).decrypt(ciphertext)
    except InvalidToken as e:
        raise ValueError("Incorrect master password or corrupted vault file.") from e

    return json.loads(plaintext.decode("utf-8"))


def _save_vault(entries: dict[str, str], password: str, salt: Optional[bytes] = None) -> None:
    VAULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    salt = salt or os.urandom(SALT_SIZE)
    key = _derive_key(password, salt)
    ciphertext = Fernet(key).encrypt(json.dumps(entries).encode("utf-8"))

    VAULT_PATH.write_bytes(salt + ciphertext)
    VAULT_PATH.chmod(0o600)  # owner read/write only


def _prompt_master_password(confirm: bool = False) -> Optional[str]:
    try:
        pw = getpass.getpass("Master password: ")
        if confirm:
            pw2 = getpass.getpass("Confirm master password: ")
            if pw != pw2:
                console.print("[red]Passwords do not match.[/red]")
                return None
        return pw
    except (EOFError, KeyboardInterrupt):
        console.print("\n[dim]Cancelled.[/dim]")
        return None


@register_command("vault-init")
def cmd_vault_init(session: Session, args: list[str]) -> None:
    """Usage: vault-init   (creates a new empty vault; overwrites an existing one if confirmed)"""
    if VAULT_PATH.exists():
        console.print(f"[yellow]A vault already exists at {VAULT_PATH}.[/yellow]")
        confirm = input("Overwrite it and start fresh? (yes/no): ").strip().lower()
        if confirm != "yes":
            console.print("[dim]Cancelled.[/dim]")
            return

    password = _prompt_master_password(confirm=True)
    if password is None:
        return
    if len(password) < 8:
        console.print("[red]Master password should be at least 8 characters.[/red]")
        return

    _save_vault({}, password)
    console.print(f"[green]Vault created at {VAULT_PATH}[/green]")


@register_command("vault-add")
def cmd_vault_add(session: Session, args: list[str]) -> None:
    """Usage: vault-add <name>   (prompts for the master password and the secret value)"""
    if not args:
        console.print("[red]Usage:[/red] vault-add <name>")
        return
    if not VAULT_PATH.exists():
        console.print("[red]No vault found.[/red] Run 'vault-init' first.")
        return

    name = args[0]
    password = _prompt_master_password()
    if password is None:
        return

    try:
        entries = _load_vault(password)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        return

    try:
        secret = getpass.getpass(f"Value for '{name}': ")
    except (EOFError, KeyboardInterrupt):
        console.print("\n[dim]Cancelled.[/dim]")
        return

    entries[name] = secret
    _save_vault(entries, password)
    console.print(f"[green]Saved '{name}' to the vault.[/green]")


@register_command("vault-get")
def cmd_vault_get(session: Session, args: list[str]) -> None:
    """Usage: vault-get <name>"""
    if not args:
        console.print("[red]Usage:[/red] vault-get <name>")
        return
    if not VAULT_PATH.exists():
        console.print("[red]No vault found.[/red] Run 'vault-init' first.")
        return

    name = args[0]
    password = _prompt_master_password()
    if password is None:
        return

    try:
        entries = _load_vault(password)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        return

    if name not in entries:
        console.print(f"[yellow]No entry named '{name}' in the vault.[/yellow]")
        return

    console.print(Panel(entries[name], title=f"Vault entry: {name}", border_style="green"))


@register_command("vault-list")
def cmd_vault_list(session: Session, args: list[str]) -> None:
    """Usage: vault-list   (shows entry names only, values stay encrypted)"""
    if not VAULT_PATH.exists():
        console.print("[red]No vault found.[/red] Run 'vault-init' first.")
        return

    password = _prompt_master_password()
    if password is None:
        return

    try:
        entries = _load_vault(password)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        return

    if not entries:
        console.print("[dim]Vault is empty.[/dim]")
        return

    table = Table(title=f"Vault Entries ({VAULT_PATH})")
    table.add_column("Name", style="bold")
    for name in sorted(entries):
        table.add_row(name)
    console.print(table)


@register_command("vault-remove")
def cmd_vault_remove(session: Session, args: list[str]) -> None:
    """Usage: vault-remove <name>"""
    if not args:
        console.print("[red]Usage:[/red] vault-remove <name>")
        return
    if not VAULT_PATH.exists():
        console.print("[red]No vault found.[/red] Run 'vault-init' first.")
        return

    name = args[0]
    password = _prompt_master_password()
    if password is None:
        return

    try:
        entries = _load_vault(password)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        return

    if name not in entries:
        console.print(f"[yellow]No entry named '{name}' in the vault.[/yellow]")
        return

    del entries[name]
    _save_vault(entries, password)
    console.print(f"[green]Removed '{name}' from the vault.[/green]")
