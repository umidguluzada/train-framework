"""
TRAIN Framework plugin - SMTP banner grabber.

Connects to an SMTP port and passively reads the greeting banner the mail
server sends unprompted (the same first line any mail client sees on
connect). No commands are sent, no authentication attempted.
"""

import socket

PLUGIN_NAME = "SMTP Banner"
PLUGIN_PORTS = [25, 465, 587]


def run_check(target: str, port: int) -> dict | None:
    try:
        with socket.create_connection((target, port), timeout=4) as sock:
            banner = sock.recv(256).decode("utf-8", errors="replace").strip()
    except (socket.error, OSError) as e:
        return {"result": "unreachable", "severity": "info", "detail": str(e)}

    if not banner:
        return {"result": "no banner", "severity": "info", "detail": "Server accepted connection but sent nothing."}

    severity = "warning" if any(v in banner for v in ("Exim 4.9", "Postfix 2.", "Sendmail 8.1")) else "info"
    return {"result": banner[:100], "severity": severity,
            "detail": "SMTP greeting banner - check the software/version for known advisories."}
