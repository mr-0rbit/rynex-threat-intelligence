"""In-process alert event bus for the live WebSocket feed.

Single-worker deployments (the default) get true push; multi-worker deployments
should add a Redis pub/sub bridge so every API replica receives all events.
"""

import asyncio
import logging
from typing import Any

logger = logging.getLogger("rtip.events")

_subscribers: list[asyncio.Queue] = []
_lock = asyncio.Lock()


async def subscribe() -> asyncio.Queue:
    queue: asyncio.Queue = asyncio.Queue(maxsize=200)
    async with _lock:
        _subscribers.append(queue)
    return queue


async def unsubscribe(queue: asyncio.Queue) -> None:
    async with _lock:
        if queue in _subscribers:
            _subscribers.remove(queue)


def publish_alert(payload: dict[str, Any]) -> None:
    """Fan out a new-alert event. Non-blocking; slow consumers drop overflow."""
    for queue in list(_subscribers):
        try:
            queue.put_nowait(payload)
        except asyncio.QueueFull:
            logger.warning("websocket subscriber queue overflow; dropping event")
