"""
TRAIN plugin: TLS certificate expiry check (port 443/8443).

Connects and reads the certificate the server presents during the normal
TLS handshake (the same thing a browser does before showing the padlock
icon) - purely passive, no data is sent beyond the standard handshake.
"""

import socket
import ssl
from datetime import datetime, timezone

PLUGIN_NAME = "TLS Certificate Expiry Check"
PLUGIN_PORTS = [443, 8443]


def run_check(target: str, port: int) -> dict | None:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # we only want to READ the cert, not validate trust chain
        with socket.create_connection((target, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
    except (ssl.SSLError, socket.error, OSError) as e:
        return {"result": "unreachable/no TLS", "severity": "info", "detail": str(e)}

    not_after = cert.get("notAfter")
    if not not_after:
        return {"result": "no expiry field found", "severity": "info", "detail": ""}

    expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days_left = (expires - datetime.now(timezone.utc)).days

    if days_left < 0:
        return {"result": f"EXPIRED {abs(days_left)} days ago", "severity": "finding",
                 "detail": f"Certificate expired on {expires.date()}"}
    if days_left < 14:
        return {"result": f"expires in {days_left} days", "severity": "warning",
                 "detail": f"Certificate expires soon: {expires.date()}"}
    return {"result": f"valid, {days_left} days left", "severity": "info",
             "detail": f"Certificate expires {expires.date()}"}
