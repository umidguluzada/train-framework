"""
TRAIN Framework - example plugin: quick CORS misconfiguration check.

Sends a single GET request with an Origin header and checks whether the
server reflects back an overly permissive Access-Control-Allow-Origin
(e.g. '*' combined with credentials allowed) - a common web
misconfiguration distinct from the header checks in web_auditor.py.
"""

import requests

PLUGIN_NAME = "CORS Misconfiguration Check"
PLUGIN_PORTS = [80, 443, 8080, 8443]


def run_check(target: str, port: int) -> dict | None:
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{target}:{port}/"

    try:
        resp = requests.get(
            url, timeout=5,
            headers={
                "User-Agent": "TRAIN-Framework-Plugin/0.1",
                "Origin": "https://attacker-controlled.example",
            },
        )
    except requests.RequestException as e:
        return {"result": "unreachable", "severity": "info", "detail": str(e)}

    acao = resp.headers.get("Access-Control-Allow-Origin")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

    if not acao:
        return {"result": "no CORS headers", "severity": "info", "detail": "CORS not enabled on this response."}

    if acao == "https://attacker-controlled.example":
        return {
            "result": "reflects arbitrary Origin",
            "severity": "finding",
            "detail": "Server reflects any Origin back in Access-Control-Allow-Origin - "
                      "this allows any website to make authenticated cross-origin requests.",
        }

    if acao == "*" and acac == "true":
        return {
            "result": "wildcard + credentials",
            "severity": "finding",
            "detail": "Access-Control-Allow-Origin: * combined with credentials allowed is invalid/"
                      "dangerous per the CORS spec - browsers should reject it, but worth fixing.",
        }

    return {
        "result": acao,
        "severity": "info",
        "detail": "CORS is configured with a specific (non-wildcard) origin.",
    }
