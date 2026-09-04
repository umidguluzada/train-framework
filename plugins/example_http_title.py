"""
TRAIN Framework - example plugin: HTTP page title fetcher.

This is a template showing the plugin convention. Copy this file, rename
it, and change PLUGIN_NAME/PLUGIN_PORTS/run_check() to build your own
TSE check - it will be picked up automatically the next time 'run-tse'
or 'list-plugins' runs, no other code changes needed.

This example check sends a single, harmless GET request to the target
and reports the HTML <title> it finds - useful for quickly identifying
what web application/CMS is running on a port during recon.
"""

import re

import requests

PLUGIN_NAME = "HTTP Page Title"
PLUGIN_PORTS = "all"  # tries every port TSE checks; harmlessly reports
                       # "unreachable" on non-HTTP ports (e.g. SSH, FTP)


def run_check(target: str, port: int) -> dict | None:
    # Try HTTPS first for the common TLS ports, otherwise plain HTTP -
    # non-HTTP ports will simply fail to connect/respond and we report that.
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{target}:{port}/"

    try:
        resp = requests.get(url, timeout=5, headers={"User-Agent": "TRAIN-Framework-Plugin/0.1"})
    except requests.RequestException as e:
        return {"result": "unreachable", "severity": "info", "detail": str(e)}

    match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
    title = match.group(1).strip() if match else ""

    if not title:
        return {"result": "no title found", "severity": "info", "detail": f"HTTP {resp.status_code}"}

    return {
        "result": title[:80],
        "severity": "info",
        "detail": f"HTTP {resp.status_code} - page title captured for recon context.",
    }
