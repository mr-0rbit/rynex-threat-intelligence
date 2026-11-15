"""Audit trail helper: one call, never breaks the request."""

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog

logger = logging.getLogger("rtip.audit")


async def record_audit(
    db: AsyncSession,
    *,
    action: str,
    actor_email: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    detail: dict[str, Any] | None = None,
    ip_address: str | None = None,
) -> None:
    """Append an audit record. Failures are logged, never raised."""
    try:
        db.add(
            AuditLog(
                actor_email=actor_email,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                detail=detail,
                ip_address=ip_address,
            )
        )
    except Exception:  # noqa: BLE001 — audit must never break the request path
        logger.exception("failed to record audit event %s", action)
