"""
TRAIN plugin: VNC exposure + protocol banner (port 5900).

VNC servers announce their protocol version unprompted on connect (e.g.
"RFB 003.008\\n") - this plugin only reads that greeting; it never
attempts authentication.
"""

import socket

PLUGIN_NAME = "VNC Exposure Check"
PLUGIN_PORTS = [5900]


def run_check(target: str, port: int) -> dict | None:
    try:
        with socket.create_connection((target, port), timeout=3) as sock:
            banner = sock.recv(32).decode("utf-8", errors="replace").strip()
    except (socket.error, OSError) as e:
        return {"result": "unreachable", "severity": "info", "detail": str(e)}

    if banner.startswith("RFB"):
        return {
            "result": banner, "severity": "warning",
            "detail": "VNC server reachable - ensure authentication and encryption are enabled, "
                       "or restrict access to a VPN.",
        }
    return {"result": banner or "unexpected response", "severity": "info", "detail": ""}
