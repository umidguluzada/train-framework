"""
TRAIN plugin: RDP exposure flag (port 3389).

RDP (Remote Desktop Protocol) is a frequent brute-force and ransomware
entry point when exposed to the internet. This plugin only checks
whether the port is reachable at all - no protocol handshake, no login
attempt - and flags it as a finding worth reviewing (VPN-only access is
the common recommendation).
"""

import socket

PLUGIN_NAME = "RDP Exposure Check"
PLUGIN_PORTS = [3389]


def run_check(target: str, port: int) -> dict | None:
    try:
        with socket.create_connection((target, port), timeout=3):
            pass
    except (socket.error, OSError) as e:
        return {"result": "unreachable", "severity": "info", "detail": str(e)}

    return {
        "result": "RDP port reachable",
        "severity": "finding",
        "detail": "RDP is a common ransomware/brute-force entry point when exposed. "
                   "Consider restricting to VPN-only access.",
    }
