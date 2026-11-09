"""Async HTTP client with timeout, retry with exponential backoff, and per-host rate limiting.

Every external feed is treated as untrusted input. No redirect chains across
schemes are followed blindly (httpx default), and responses are size-capped.
"""

import asyncio
import logging
import time
from collections import defaultdict

import httpx

from app.core.config import settings

logger = logging.getLogger("rtip.collectors.http")

MAX_RESPONSE_BYTES = 20 * 1024 * 1024  # 20 MB cap per response


class RateLimiter:
    """Per-host minimum-interval limiter; never polls faster than configured."""

    def __init__(self) -> None:
        self._min_intervals: dict[str, float] = defaultdict(float)
        self._last_request: dict[str, float] = {}
        self._lock = asyncio.Lock()

    def register(self, host: str, min_interval_seconds: float) -> None:
        if min_interval_seconds > 0:
            self._min_intervals[host] = min_interval_seconds

    async def acquire(self, host: str) -> None:
        async with self._lock:
            interval = self._min_intervals.get(host, 0.0)
            now = time.monotonic()
            elapsed = now - self._last_request.get(host, 0.0)
            if elapsed < interval:
                await asyncio.sleep(interval - elapsed)
            self._last_request[host] = time.monotonic()


class CollectorHTTPError(Exception):
    pass


class CollectorHTTP:
    def __init__(self) -> None:
        self._limiter = RateLimiter()
        self._client: httpx.AsyncClient | None = None

    async def client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=settings.COLLECTOR_TIMEOUT_SECONDS,
                follow_redirects=True,
                max_redirects=5,
                headers={"User-Agent": settings.COLLECTOR_USER_AGENT},
                limits=httpx.Limits(max_connections=10),
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict | None = None,
        params: dict | None = None,
        json_body: dict | None = None,
        rate_limit_interval: float = 0.0,
    ) -> httpx.Response:
        """Fetch with per-host rate limiting and exponential-backoff retries."""
        from urllib.parse import urlparse

        host = urlparse(url).hostname or "unknown"
        self._limiter.register(host, rate_limit_interval)

        client = await self.client()
        last_error: Exception | None = None
        for attempt in range(settings.COLLECTOR_MAX_RETRIES):
            await self._limiter.acquire(host)
            try:
                resp = await client.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    json=json_body,
                )
                if resp.status_code == 429:
                    retry_after = float(resp.headers.get("Retry-After", "5"))
                    logger.warning("rate limited by %s, backing off %.1fs", host, retry_after)
                    await asyncio.sleep(retry_after)
                    last_error = CollectorHTTPError(f"429 from {host}")
                    continue
                resp.raise_for_status()
                if len(resp.content) > MAX_RESPONSE_BYTES:
                    raise CollectorHTTPError(f"response from {host} exceeds size cap")
                return resp
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_error = exc
                backoff = settings.COLLECTOR_BACKOFF_BASE**attempt
                logger.warning("transient error from %s (attempt %d): %s", host, attempt + 1, exc)
                if attempt < settings.COLLECTOR_MAX_RETRIES - 1:
                    await asyncio.sleep(backoff)
            except httpx.HTTPStatusError as exc:
                # Non-retryable client/server error surface immediately
                raise CollectorHTTPError(f"HTTP {exc.response.status_code} from {host}: {exc}") from exc
        raise CollectorHTTPError(f"failed to fetch {url} after {settings.COLLECTOR_MAX_RETRIES} attempts: {last_error}")


shared_http = CollectorHTTP()
