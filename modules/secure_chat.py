"""
TRAIN Framework - modules/secure_chat.py
End-to-end encrypted local network chat (demo/educational).

Registers:
  chat-listen <port> [passphrase]         -> waits for one incoming connection
  chat-connect <host> <port> [passphrase] -> connects to a listening peer

Two TRAIN instances (or the same one run twice) can exchange encrypted
messages over a plain TCP socket. Both sides derive the same symmetric
key from a shared passphrase (PBKDF2-HMAC-SHA256, matching the same KDF
vault_manager.py uses), then encrypt every message with Fernet (AES-128
in CBC mode + HMAC for integrity) before sending. An eavesdropper on the
network sees only ciphertext.

This is a teaching example of end-to-end encryption over a socket, not a
production messenger: the passphrase must be shared with the other party
out-of-band beforehand (e.g. said aloud, or sent via an already-trusted
channel) - there is no key exchange protocol here (no Diffie-Hellman/
Signal-style ratcheting), so treat it as symmetric pre-shared-key chat,
not as forward-secure messaging.
"""

from __future__ import annotations

import base64
import socket
import threading

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rich.console import Console
from rich.panel import Panel

from core.tui_engine import Session, register_command

console = Console()

DEFAULT_PORT = 5566
# A fixed, non-secret salt is fine here since the passphrase itself is the
# shared secret (agreed out-of-band) - this mirrors how many PSK-based
# tools derive a session key from a shared passphrase.
FIXED_SALT = b"TRAIN-Framework-SecureChat-v1"
PBKDF2_ITERATIONS = 390_000
RECV_BUFFER = 4096


def _derive_key(passphrase: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=FIXED_SALT, iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def _recv_loop(sock: socket.socket, fernet: Fernet, stop_event: threading.Event) -> None:
    sock.settimeout(0.5)
    while not stop_event.is_set():
        try:
            data = sock.recv(RECV_BUFFER)
        except socket.timeout:
            continue
        except OSError:
            break

        if not data:
            console.print("\n[dim]Peer disconnected.[/dim]")
            stop_event.set()
            break

        try:
            plaintext = fernet.decrypt(data).decode("utf-8")
            console.print(f"\r[bold cyan]peer>[/bold cyan] {plaintext}\nyou> ", end="")
        except InvalidToken:
            console.print("\n[red]Received a message that failed to decrypt "
                           "(wrong passphrase on one side?).[/red]")
        except Exception:  # noqa: BLE001 - never let the background thread crash silently
            break


def _chat_loop(sock: socket.socket, passphrase: str) -> None:
    key = _derive_key(passphrase)
    fernet = Fernet(key)
    stop_event = threading.Event()

    receiver = threading.Thread(target=_recv_loop, args=(sock, fernet, stop_event), daemon=True)
    receiver.start()

    console.print(Panel(
        "Chat session started. Every message is encrypted before sending.\n"
        "Type a message and press Enter. Type /quit to leave.",
        title="Secure Chat", border_style="green",
    ))

    try:
        while not stop_event.is_set():
            try:
                message = input("you> ")
            except (EOFError, KeyboardInterrupt):
                break

            if message.strip() == "/quit":
                break
            if not message:
                continue

            try:
                sock.sendall(fernet.encrypt(message.encode("utf-8")))
            except OSError:
                console.print("[red]Connection lost.[/red]")
                break
    finally:
        stop_event.set()
        try:
            sock.close()
        except OSError:
            pass
        console.print("[dim]Chat session ended.[/dim]")


@register_command("chat-listen")
def cmd_chat_listen(session: Session, args: list[str]) -> None:
    """
    Usage: chat-listen [port] [passphrase]
    Waits for one incoming secure chat connection on the given port
    (default 5566). Both sides must use the same passphrase, agreed on
    beforehand through a separate trusted channel.
    """
    port = DEFAULT_PORT
    passphrase = None

    if args:
        try:
            port = int(args[0])
            passphrase = args[1] if len(args) > 1 else None
        except ValueError:
            passphrase = args[0]

    if not passphrase:
        console.print("[red]Usage:[/red] chat-listen [port] <passphrase>")
        return

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", port))
        server.listen(1)
    except OSError as e:
        console.print(f"[red]Could not listen on port {port}:[/red] {e}")
        return

    console.print(f"[cyan]Listening for a secure chat connection on port {port}...[/cyan] "
                   "[dim](Ctrl+C to cancel)[/dim]")
    try:
        conn, addr = server.accept()
    except KeyboardInterrupt:
        console.print("\n[dim]Cancelled.[/dim]")
        server.close()
        return

    console.print(f"[green]Connected from {addr[0]}:{addr[1]}[/green]")
    server.close()
    _chat_loop(conn, passphrase)


@register_command("chat-connect")
def cmd_chat_connect(session: Session, args: list[str]) -> None:
    """
    Usage: chat-connect <host> [port] <passphrase>
    Connects to a peer already running 'chat-listen'. Both sides must
    use the same passphrase.
    """
    if not args:
        console.print("[red]Usage:[/red] chat-connect <host> [port] <passphrase>")
        return

    host = args[0]
    rest = args[1:]
    port = DEFAULT_PORT
    passphrase = None

    if rest:
        try:
            port = int(rest[0])
            passphrase = rest[1] if len(rest) > 1 else None
        except ValueError:
            passphrase = rest[0]

    if not passphrase:
        console.print("[red]Usage:[/red] chat-connect <host> [port] <passphrase>")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    console.print(f"[cyan]Connecting to {host}:{port}...[/cyan]")
    try:
        sock.connect((host, port))
    except OSError as e:
        console.print(f"[red]Connection failed:[/red] {e}")
        return

    console.print("[green]Connected.[/green]")
    _chat_loop(sock, passphrase)
