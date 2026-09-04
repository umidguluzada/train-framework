"""
TRAIN Framework plugin - DNS server version/banner check.

Sends a standard DNS CHAOS-class TXT query for "version.bind" - a normal,
documented part of the DNS protocol many resolvers respond to - which
often reveals the DNS server software and version. This is the same
technique `dig @server version.bind chaos txt` uses.
"""

import socket
import struct

PLUGIN_NAME = "DNS Version Query"
PLUGIN_PORTS = [53]


def _build_version_bind_query() -> bytes:
    # DNS header: ID, flags, 1 question, 0 answers/authority/additional.
    header = struct.pack(">HHHHHH", 0x1234, 0x0000, 1, 0, 0, 0)
    # QNAME for "version.bind": length-prefixed labels, terminated by 0x00.
    qname = b"\x07version\x04bind\x00"
    qtype_qclass = struct.pack(">HH", 16, 3)  # TYPE=TXT(16), CLASS=CHAOS(3)
    return header + qname + qtype_qclass


def run_check(target: str, port: int) -> dict | None:
    query = _build_version_bind_query()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(4)
        sock.sendto(query, (target, port))
        response, _ = sock.recvfrom(512)
        sock.close()
    except (socket.error, OSError) as e:
        return {"result": "unreachable", "severity": "info", "detail": str(e)}

    # Very small parser: look for a printable TXT payload in the response
    # tail rather than a full DNS decoder - good enough to surface version text.
    printable = "".join(chr(b) if 32 <= b < 127 else "" for b in response[-64:])
    if printable.strip():
        return {"result": printable.strip()[:80], "severity": "warning",
                 "detail": "DNS server answered a version.bind CHAOS query - version disclosure."}
    return {"result": "no version disclosed", "severity": "info",
             "detail": "Server did not respond to version.bind (good practice)."}
