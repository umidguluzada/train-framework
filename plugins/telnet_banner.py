"""
TRAIN plugin: Telnet exposure + banner grab (port 23).

Telnet transmits everything - including login credentials - in plaintext.
Its mere presence on a reachable port is itself a finding worth flagging,
regardless of what the banner says. This plugin only connects and reads
whatever the service sends unprompted; it never attempts to log in.
"""

import socket

PLUGIN_NAME = "Telnet Exposure Check"
PLUGIN_PORTS = [23]


def run_check(target: str, port: int) -> dict | None:
    try:
        with socket.create_connection((target, port), timeout=3) as sock:
            banner = sock.recv(256).decode("utf-8", errors="replace").strip()
    except (socket.error, OSError) as e:
        return {"result": "unreachable", "severity": "info", "detail": str(e)}

    return {
        "result": "Telnet service reachable",
        "severity": "finding",
        "detail": f"Telnet transmits credentials in plaintext - migrate to SSH if possible. "
                   f"Banner: {banner[:100] or '(none)'}",
    }
