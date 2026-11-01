"""
Bounded async HTTP client for defensive checks.

Used by security-header audits, NVD lookups, breach-range lookups, and
the YAML template runner. Concurrency, timeouts, redirects, and response
size are capped so callers cannot turn this into a high-rate fetcher.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Optional

import aiohttp

MAX_CONCURRENCY = 8
MAX_TIMEOUT_SEC = 30.0
MAX_RESPONSE_BYTES = 1_000_000
MAX_REDIRECTS = 3
DEFAULT_USER_AGENT = "TRAIN-Framework/1.0"


@dataclass
class HttpResponse:
    url: str
    reached: bool
    status: Optional[int] = None
    headers: dict[str, str] = field(default_factory=dict)
    text: str = ""
    error: Optional[str] = None


class AsyncHttpClient:
    """One shared session with a semaphore and a connector limit."""

    def __init__(
        self,
        concurrency: int = 4,
        timeout_total: float = 10.0,
        timeout_connect: float = 3.0,
        timeout_read: float = 8.0,
        user_agent: str = DEFAULT_USER_AGENT,
    ) -> None:
        self.concurrency = max(1, min(int(concurrency), MAX_CONCURRENCY))
        self.timeout_total = min(max(float(timeout_total), 1.0), MAX_TIMEOUT_SEC)
        self.timeout_connect = min(max(float(timeout_connect), 0.5), 10.0)
        self.timeout_read = min(max(float(timeout_read), 0.5), 20.0)
        self.user_agent = user_agent
        self._session: Optional[aiohttp.ClientSession] = None
        self._sem: Optional[asyncio.Semaphore] = None

    async def __aenter__(self) -> "AsyncHttpClient":
        timeout = aiohttp.ClientTimeout(
            total=self.timeout_total,
            connect=self.timeout_connect,
            sock_read=self.timeout_read,
        )
        connector = aiohttp.TCPConnector(
            limit=self.concurrency,
            limit_per_host=self.concurrency,
        )
        self._session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={"User-Agent": self.user_agent},
        )
        self._sem = asyncio.Semaphore(self.concurrency)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None
            self._sem = None

    async def get(
        self,
        url: str,
        *,
        params: Optional[dict[str, Any]] = None,
        read_body: bool = True,
        max_bytes: int = 65_536,
    ) -> HttpResponse:
        if self._session is None or self._sem is None:
            raise RuntimeError("AsyncHttpClient must be used as an async context manager.")

        max_bytes = max(0, min(int(max_bytes), MAX_RESPONSE_BYTES))
        async with self._sem:
            try:
                async with self._session.get(
                    url,
                    params=params,
                    allow_redirects=True,
                    max_redirects=MAX_REDIRECTS,
                ) as resp:
                    headers = {k: v for k, v in resp.headers.items()}
                    text = ""
                    if read_body and max_bytes:
                        raw = await resp.content.read(max_bytes + 1)
                        if len(raw) > max_bytes:
                            return HttpResponse(
                                url=str(resp.url),
                                reached=False,
                                status=resp.status,
                                headers=headers,
                                error="response exceeded size limit",
                            )
                        text = raw.decode("utf-8", errors="replace")
                    return HttpResponse(
                        url=str(resp.url),
                        reached=True,
                        status=resp.status,
                        headers=headers,
                        text=text,
                    )
            except asyncio.TimeoutError:
                return HttpResponse(url=url, reached=False, error="timed out")
            except aiohttp.ClientError as exc:
                return HttpResponse(url=url, reached=False, error=str(exc))
            except OSError as exc:
                return HttpResponse(url=url, reached=False, error=str(exc))


def fetch_sync(
    url: str,
    *,
    params: Optional[dict[str, Any]] = None,
    read_body: bool = True,
    max_bytes: int = 65_536,
    user_agent: str = DEFAULT_USER_AGENT,
    timeout_total: float = 10.0,
) -> HttpResponse:
    """Run a single capped GET from synchronous command handlers."""

    async def _once() -> HttpResponse:
        async with AsyncHttpClient(concurrency=1, timeout_total=timeout_total, user_agent=user_agent) as client:
            return await client.get(url, params=params, read_body=read_body, max_bytes=max_bytes)

    try:
        return asyncio.run(_once())
    except RuntimeError as exc:
        return HttpResponse(url=url, reached=False, error=str(exc))


async def fetch_all(
    urls: list[str],
    *,
    concurrency: int = 4,
    read_body: bool = False,
    max_bytes: int = 65_536,
    user_agent: str = DEFAULT_USER_AGENT,
    timeout_total: float = 10.0,
) -> list[HttpResponse]:
    """Fetch several URLs under the concurrency cap. Order matches urls."""

    async with AsyncHttpClient(
        concurrency=concurrency,
        timeout_total=timeout_total,
        user_agent=user_agent,
    ) as client:
        return list(await asyncio.gather(*(
            client.get(url, read_body=read_body, max_bytes=max_bytes) for url in urls
        )))
