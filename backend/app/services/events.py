"""Enterprise distributed alert event bus with Redis Pub/Sub bridge.

Architecture:
- In-process subscribers: WebSockets connected to this local API worker.
- Distributed fan-out: When Redis is available, alerts published by any Celery task
  or API instance are broadcast to `settings.REDIS_ALERT_CHANNEL`.
- A background worker task on each API replica listens on the Redis channel
  and fans out incoming alerts to its local WebSockets.
- Graceful fallback: If Redis is unavailable or unconfigured (e.g. in single-node
  dev or tests), the bus falls back seamlessly to in-process memory.
"""

import asyncio
import json
import logging
import uuid
from typing import Any

from app.core.config import settings

logger = logging.getLogger("rtip.events")

_subscribers: list[asyncio.Queue] = []
_lock = asyncio.Lock()
_redis_listener_task: asyncio.Task | None = None
_instance_id: str = str(uuid.uuid4())


async def subscribe() -> asyncio.Queue:
    queue: asyncio.Queue = asyncio.Queue(maxsize=500)
    async with _lock:
        _subscribers.append(queue)
    return queue


async def unsubscribe(queue: asyncio.Queue) -> None:
    async with _lock:
        if queue in _subscribers:
            _subscribers.remove(queue)


def _deliver_local(payload: dict[str, Any]) -> None:
    """Deliver event to all local WebSocket subscriber queues on this process."""
    for queue in list(_subscribers):
        try:
            queue.put_nowait(payload)
        except asyncio.QueueFull:
            logger.warning("websocket subscriber queue overflow; dropping event")


def publish_alert(payload: dict[str, Any]) -> None:
    """Fan out a new-alert event.

    Delivers locally and, if an event loop is running, schedules an async
    publish to Redis Pub/Sub for cross-worker cluster fanout.
    """
    # 1. Deliver to local WebSockets immediately
    _deliver_local(payload)

    # 2. Fan out to cluster via Redis Pub/Sub
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_publish_to_redis(payload))
    except RuntimeError:
        # If called from a synchronous thread without an active event loop (e.g., Celery worker),
        # run a one-shot async publish or background task
        try:
            import redis

            r = redis.from_url(settings.REDIS_URL)
            envelope = json.dumps({"origin": _instance_id, "data": payload}, default=str)
            r.publish(settings.REDIS_ALERT_CHANNEL, envelope)
            r.close()
        except Exception as exc:  # noqa: BLE001
            logger.debug("synchronous redis pub/sub publish skipped: %s", exc)


async def _publish_to_redis(payload: dict[str, Any]) -> None:
    try:
        import redis.asyncio as aioredis

        client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        try:
            envelope = json.dumps({"origin": _instance_id, "data": payload}, default=str)
            await client.publish(settings.REDIS_ALERT_CHANNEL, envelope)
        finally:
            await client.aclose()
    except Exception as exc:  # noqa: BLE001
        logger.debug("redis pub/sub publish failed or not available: %s", exc)


async def _redis_pubsub_listener() -> None:
    """Listen for alerts published by other API replicas or Celery workers."""
    import redis.asyncio as aioredis

    while True:
        try:
            client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            pubsub = client.pubsub()
            await pubsub.subscribe(settings.REDIS_ALERT_CHANNEL)
            logger.info("connected to Redis Pub/Sub channel %s", settings.REDIS_ALERT_CHANNEL)

            async for message in pubsub.listen():
                if message["type"] == "message":
                    try:
                        envelope = json.loads(message["data"])
                        origin = envelope.get("origin")
                        # Skip if published by this exact process (already delivered locally)
                        if origin == _instance_id:
                            continue
                        data = envelope.get("data")
                        if data:
                            _deliver_local(data)
                    except Exception as parse_err:  # noqa: BLE001
                        logger.warning("invalid redis alert payload: %s", parse_err)
        except asyncio.CancelledError:
            break
        except Exception as exc:  # noqa: BLE001
            logger.debug("redis listener connection retry in 5s: %s", exc)
            await asyncio.sleep(5.0)


def start_redis_bridge() -> None:
    """Start background Redis subscriber task in the running loop."""
    global _redis_listener_task
    try:
        loop = asyncio.get_running_loop()
        if _redis_listener_task is None or _redis_listener_task.done():
            _redis_listener_task = loop.create_task(_redis_pubsub_listener())
    except RuntimeError:
        logger.debug("no running loop for redis bridge start")


def stop_redis_bridge() -> None:
    """Stop the background Redis listener task."""
    global _redis_listener_task
    if _redis_listener_task and not _redis_listener_task.done():
        _redis_listener_task.cancel()
        _redis_listener_task = None
