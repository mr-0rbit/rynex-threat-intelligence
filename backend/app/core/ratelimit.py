"""Enterprise distributed sliding-window rate limiting.

Supports:
- Distributed sliding-window across multiple replicas backed by Redis.
- Fallback to in-process memory limiter when Redis is unreachable or disabled.
- Client IP extraction respecting reverse proxies (X-Forwarded-For / X-Real-IP).
"""

import asyncio
import ipaddress
import time
import uuid
from collections import defaultdict, deque

from fastapi import HTTPException, Request, status

from app.core.config import settings


class RateLimiter:
    def __init__(self) -> None:
        self.enabled = settings.RATE_LIMIT_ENABLED
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()
        self._redis_client = None

    async def _get_redis(self):
        if self._redis_client is None:
            try:
                import redis.asyncio as aioredis

                self._redis_client = aioredis.from_url(
                    settings.REDIS_URL,
                    decode_responses=True,
                    socket_connect_timeout=0.5,
                    socket_timeout=0.5,
                )
            except Exception:
                self._redis_client = False
        return self._redis_client if self._redis_client is not False else None

    async def check(self, key: str, max_attempts: int, window_seconds: int) -> None:
        if not self.enabled:
            return

        redis = await self._get_redis()
        if redis is not None:
            try:
                now = time.time()
                cutoff = now - window_seconds
                redis_key = f"rtip:ratelimit:{key}"
                member_id = f"{now}:{uuid.uuid4().hex[:8]}"

                pipe = redis.pipeline()
                pipe.zremrangebyscore(redis_key, 0, cutoff)
                pipe.zcard(redis_key)
                pipe.zadd(redis_key, {member_id: now})
                pipe.expire(redis_key, window_seconds + 5)
                results = await pipe.execute()

                current_count = results[1]
                if current_count >= max_attempts:
                    raise HTTPException(
                        status.HTTP_429_TOO_MANY_REQUESTS,
                        f"Rate limit exceeded: max {max_attempts} attempts per {window_seconds}s",
                    )
                return
            except HTTPException:
                raise
            except Exception:
                # If Redis times out or fails, fall back to in-memory check
                pass

        # In-memory sliding window fallback
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
    """Trust forwarded IP metadata only when the direct peer is a configured proxy."""
    peer = request.client.host if request.client else None
    if not peer:
        return "unknown"
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return peer

    proxy_networks = []
    for value in settings.TRUSTED_PROXY_CIDRS.split(","):
        value = value.strip()
        if not value:
            continue
        try:
            proxy_networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue

    def is_trusted(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return any(ip.version == network.version and ip in network for network in proxy_networks)

    if not is_trusted(peer_ip):
        return str(peer_ip)

    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        chain: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for item in forwarded.split(","):
            try:
                chain.append(ipaddress.ip_address(item.strip()))
            except ValueError:
                continue
        # Walk from the trusted edge toward the client. The first untrusted
        # address is the effective client; attacker-prepended XFF values are ignored.
        chain.append(peer_ip)
        for address in reversed(chain):
            if not is_trusted(address):
                return str(address)

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        try:
            return str(ipaddress.ip_address(real_ip.strip()))
        except ValueError:
            pass
    return str(peer_ip)


async def login_rate_limit(request: Request) -> None:
    await limiter.check(
        f"login:{client_ip(request)}",
        max_attempts=settings.RATE_LIMIT_LOGIN_MAX_ATTEMPTS,
        window_seconds=settings.RATE_LIMIT_LOGIN_WINDOW_SECONDS,
    )
