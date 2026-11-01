"""
YAML template parser for defensive HTTP checks.

Allowed check types:
  http-path    GET one relative path and compare the status code
  http-header  GET one relative path and compare one response header

Templates cannot set a request body, custom request headers, or more than
20 checks. Unknown types are rejected.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from core.async_http import AsyncHttpClient

MAX_CHECKS = 20
USER_AGENT = "TRAIN-Framework-Templates/1.0"


class TemplateError(ValueError):
    """Raised when a template file does not match the allowed schema."""


@dataclass
class TemplateCheckResult:
    name: str
    flagged: bool
    severity: str
    detail: str = ""


def load_template(path: Path) -> dict[str, Any]:
    """Load and validate a template. Does not contact the network."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise TemplateError(f"Could not read template: {exc}") from exc
    except yaml.YAMLError as exc:
        raise TemplateError(f"Invalid YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise TemplateError("Template root must be a mapping with id, name, and checks.")
    if not isinstance(data.get("id"), str) or not data["id"].strip():
        raise TemplateError("Template 'id' must be a non-empty string.")
    if not isinstance(data.get("name"), str) or not data["name"].strip():
        raise TemplateError("Template 'name' must be a non-empty string.")

    checks = data.get("checks")
    if not isinstance(checks, list) or not checks:
        raise TemplateError("Template 'checks' must be a non-empty list.")
    if len(checks) > MAX_CHECKS:
        raise TemplateError(f"Templates are limited to {MAX_CHECKS} checks.")

    for index, check in enumerate(checks, start=1):
        _validate_check(check, index)
    return data


def _validate_check(check: Any, index: int) -> None:
    if not isinstance(check, dict):
        raise TemplateError(f"Check {index} must be a mapping.")
    name = check.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > 80:
        raise TemplateError(f"Check {index} needs a name of 1-80 characters.")
    severity = check.get("severity", "info")
    if severity not in {"info", "warning", "finding"}:
        raise TemplateError(f"Check {index} severity must be info, warning, or finding.")
    path = _require_path(check.get("path", "/"), index)
    check["path"] = path

    kind = check.get("type")
    if kind == "http-path":
        status = check.get("expect_status")
        if not isinstance(status, int) or not 100 <= status <= 599:
            raise TemplateError(f"Check {index} expect_status must be an HTTP status code.")
        return
    if kind == "http-header":
        header = check.get("header")
        if not isinstance(header, str) or not header.replace("-", "").isalnum():
            raise TemplateError(f"Check {index} header name is invalid.")
        if "expect_present" not in check and "expect_value" not in check:
            raise TemplateError(f"Check {index} needs expect_present or expect_value.")
        if "expect_value" in check and not isinstance(check["expect_value"], str):
            raise TemplateError(f"Check {index} expect_value must be a string.")
        return
    raise TemplateError(
        f"Check {index} type '{kind}' is not supported. Use http-path or http-header."
    )


def _require_path(path: Any, index: int) -> str:
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        raise TemplateError(f"Check {index} path must be a relative path starting with '/'.")
    if ".." in path or "\\" in path or "?" in path or " " in path:
        raise TemplateError(f"Check {index} path is not allowed.")
    if len(path) > 200:
        raise TemplateError(f"Check {index} path is too long.")
    return path


def _target_origin(target: str) -> str:
    base = target.strip()
    if not base.startswith(("http://", "https://")):
        base = "https://" + base
    parsed = urlparse(base)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise TemplateError("Target must be an http(s) host or URL.")
    if parsed.username or parsed.password:
        raise TemplateError("Target URL must not include credentials.")
    return f"{parsed.scheme}://{parsed.netloc}"


async def _run_check(client: AsyncHttpClient, origin: str, check: dict[str, Any]) -> TemplateCheckResult:
    name = check["name"]
    severity = check.get("severity", "info")
    url = origin + check["path"]
    page = await client.get(url, read_body=False)
    if not page.reached or page.status is None:
        return TemplateCheckResult(name=name, flagged=False, severity="info", detail=page.error or "unreachable")

    if check["type"] == "http-path":
        flagged = page.status == check["expect_status"]
        return TemplateCheckResult(
            name=name,
            flagged=flagged,
            severity=severity if flagged else "info",
            detail=f"HTTP {page.status} at {check['path']}",
        )

    headers = {key.lower(): value for key, value in page.headers.items()}
    actual = headers.get(str(check["header"]).lower())
    if "expect_value" in check:
        flagged = (actual or "").lower() != check["expect_value"].lower()
        shown = actual if actual is not None else "absent"
        detail = f"{check['header']} is {shown}"
    else:
        present = actual is not None
        expect_present = bool(check.get("expect_present", True))
        flagged = present != expect_present
        detail = f"{check['header']} is {'present' if present else 'absent'}"
    return TemplateCheckResult(
        name=name,
        flagged=flagged,
        severity=severity if flagged else "info",
        detail=detail,
    )


async def run_template_async(target: str, template: dict[str, Any]) -> list[TemplateCheckResult]:
    origin = _target_origin(target)
    async with AsyncHttpClient(concurrency=4, user_agent=USER_AGENT, timeout_total=10) as client:
        results = await asyncio.gather(*(
            _run_check(client, origin, check) for check in template["checks"]
        ))
    return list(results)


def run_template(target: str, template_path: Path) -> list[TemplateCheckResult]:
    template = load_template(template_path)
    return asyncio.run(run_template_async(target, template))
