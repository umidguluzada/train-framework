"""
TRAIN Framework - example plugin: custom SSH banner + weak-cipher hint.

Reads the SSH banner directly (a passive check - no login attempt) and
flags a couple of well-known legacy indicators that might warrant a
closer look. This overlaps a little with script_engine.py's built-in SSH
check, intentionally - it's meant to show how you'd extend/customize that
kind of check yourself without touching the core module.
"""

import socket

PLUGIN_NAME = "SSH Banner (custom)"
PLUGIN_PORTS = [22, 2222]


def run_check(target: str, port: int) -> dict | None:
    try:
        with socket.create_connection((target, port), timeout=3) as sock:
            banner = sock.recv(128).decode("utf-8", errors="replace").strip()
    except (socket.error, OSError) as e:
        return {"result": "unreachable", "severity": "info", "detail": str(e)}

    if not banner:
        return {"result": "empty response", "severity": "info", "detail": "No banner received."}

    lowered = banner.lower()
    legacy_markers = ["dropbear", "openssh_4", "openssh_5", "openssh_6.0", "openssh_6.1"]
    hit = next((m for m in legacy_markers if m in lowered), None)

    if hit:
        return {
            "result": banner,
            "severity": "warning",
            "detail": f"Banner suggests a possibly outdated SSH implementation ('{hit}') - "
                      f"worth checking it's still receiving security patches.",
        }

    return {
        "result": banner,
        "severity": "info",
        "detail": "No obviously outdated SSH implementation markers found in the banner.",
    }
