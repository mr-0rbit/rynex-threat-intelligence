"""Real-time alert feed over WebSocket.

Auth: `?token=<JWT access token>` query param (browsers cannot set headers on
WebSocket handshakes). Events fan out from the in-process event bus fed by the
ingestion pipeline. Multi-worker deployments need a Redis pub/sub bridge.
"""

import asyncio
import logging
import uuid

import jwt as pyjwt
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status

from app.core.config import settings
from app.services import events

logger = logging.getLogger("rtip.ws")

router = APIRouter(tags=["realtime"])


def _authenticate(token: str | None) -> uuid.UUID | None:
    """Validate a bearer JWT and return the user id, or None."""
    if not token:
        return None
    try:
        payload = pyjwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except pyjwt.PyJWTError:
        return None
    if payload.get("type") != "access":
        return None
    try:
        return uuid.UUID(payload["sub"])
    except (KeyError, ValueError):
        return None


@router.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket, token: str | None = Query(None)) -> None:
    user_id = _authenticate(token)
    if user_id is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    await websocket.accept()
    queue = await events.subscribe()
    try:
        await websocket.send_json({"type": "connected", "message": "Live alert feed active"})
        while True:
            # Waits on queue; a periodic ping keeps intermediaries from dropping the socket.
            try:
                payload = await asyncio.wait_for(queue.get(), timeout=30.0)
                await websocket.send_json({"type": "alert", **payload})
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001
        logger.exception("websocket alert stream error")
    finally:
        await events.unsubscribe(queue)
