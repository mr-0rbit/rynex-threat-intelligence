"""In-process sliding-window rate limiting.

Suitable for single-node deployments and as a stopgap; multi-node deployments
should front the app with a shared limiter (nginx/Envoy) or Redis-backed store.
"""

import asyncio
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request, status

from app.core.config import settings


class RateLimiter:
    def __init__(self) -> None:
        self.enabled = settings.RATE_LIMIT_ENABLED
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def check(self, key: str, max_attempts: int, window_seconds: int) -> None:
        if not self.enabled:
            return
        async with self._lock:
            now = time.monotonic()
            bucket = self._hits[key]
            while bucket and now - bucket[0] > window_seconds:
                bucket.popleft()
            if len(bucket) >= max_attempts:
                raise HTTPException(
                    status.HTTP_429_TOO_MANY_REQUESTS,
                    f"Rate limit exceeded: max {max_attempts} attempts per {window_seconds}s",
                )
            bucket.append(now)

    def reset(self) -> None:
        self._hits.clear()


limiter = RateLimiter()


def client_ip(request: Request) -> str:
    """Direct socket peer. Behind a trusted proxy, deploy with proxy header handling."""
    return request.client.host if request.client else "unknown"


async def login_rate_limit(request: Request) -> None:
    await limiter.check(
        f"login:{client_ip(request)}",
        max_attempts=settings.RATE_LIMIT_LOGIN_MAX_ATTEMPTS,
        window_seconds=settings.RATE_LIMIT_LOGIN_WINDOW_SECONDS,
    )
