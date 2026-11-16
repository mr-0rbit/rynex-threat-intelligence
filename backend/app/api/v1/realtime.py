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


def _authenticate(token: str | None) -> tuple[uuid.UUID, int] | None:
    """Validate a bearer JWT and return its user id and token version."""
    if not token:
        return None
    try:
        payload = pyjwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except pyjwt.PyJWTError as e:
        logger.warning("websocket jwt decode failed: %s", e)
        return None
    if payload.get("type") != "access":
        logger.warning("websocket token rejected: token type is %s (expected 'access')", payload.get("type"))
        return None
    try:
        return uuid.UUID(payload["sub"]), int(payload.get("ver", 0))
    except (KeyError, ValueError) as e:
        logger.warning("websocket token payload invalid: %s", e)
        return None


@router.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket, token: str | None = Query(None)) -> None:
    # Resolve token from query param, query string, cookie, or authorization header
    if not token:
        token = websocket.query_params.get("token") or websocket.cookies.get("access_token")
        if not token and "authorization" in websocket.headers:
            auth_hdr = websocket.headers.get("authorization", "")
            if auth_hdr.lower().startswith("bearer "):
                token = auth_hdr[7:].strip()

    principal = _authenticate(token)
    if principal is None:
        logger.warning("websocket alert connection rejected: missing or invalid authentication token")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    user_id, token_version = principal
    from app.core.database import AsyncSessionLocal
    from app.models import Organization, User

    try:
        async with AsyncSessionLocal() as db:
            user = await db.get(User, user_id)
            organization = await db.get(Organization, user.organization_id) if user else None
            if (
                user is None
                or not user.is_active
                or int(user.token_version or 0) != token_version
                or organization is None
                or not organization.enabled
            ):
                logger.warning(
                    "websocket alert connection rejected: user active=%s or org enabled=%s mismatch",
                    getattr(user, "is_active", None),
                    getattr(organization, "enabled", None),
                )
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return
            organization_id = str(user.organization_id)
    except Exception as e:  # noqa: BLE001
        logger.exception("websocket authentication session error: %s", e)
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
        return

    await websocket.accept()
    queue = await events.subscribe()
    try:
        await websocket.send_json({"type": "connected", "message": "Live alert feed active"})
        while True:
            # Waits on queue; a periodic ping keeps intermediaries from dropping the socket.
            try:
                payload = await asyncio.wait_for(queue.get(), timeout=30.0)
                if payload.get("organization_id") != organization_id:
                    continue
                await websocket.send_json({"type": "alert", **payload})
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001
        logger.exception("websocket alert stream error")
    finally:
        await events.unsubscribe(queue)
