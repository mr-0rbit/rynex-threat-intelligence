"""Tamper-evident audit records and SIEM serialization."""

import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models import AuditChainHead, AuditLog, User

GENESIS_HMAC = "0" * 64


def _canonical_entry(
    *,
    sequence: int,
    previous_hmac: str,
    organization_id: UUID | None,
    actor_email: str | None,
    action: str,
    resource_type: str | None,
    resource_id: str | None,
    detail: dict[str, Any] | None,
    ip_address: str | None,
    created_at: datetime,
) -> bytes:
    """Serialize every security-relevant immutable field deterministically."""
    normalized_created_at = (
        created_at.replace(tzinfo=UTC)
        if created_at.tzinfo is None
        else created_at.astimezone(UTC)
    )
    payload = {
        "sequence": sequence,
        "previous_hmac": previous_hmac,
        "organization_id": str(organization_id) if organization_id else None,
        "actor_email": actor_email,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "detail": detail or {},
        "ip_address": ip_address,
        "created_at": normalized_created_at.isoformat(),
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def _calculate_entry_hmac(**entry: Any) -> str:
    return hmac.new(
        settings.AUDIT_HMAC_KEY.encode("utf-8"),
        _canonical_entry(**entry),
        hashlib.sha256,
    ).hexdigest()


async def record_audit(
    db: AsyncSession,
    *,
    action: str,
    actor_email: str | None = None,
    organization_id: UUID | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    detail: dict[str, Any] | None = None,
    ip_address: str | None = None,
) -> None:
    """Append one ordered, HMAC-chained audit record to the caller's transaction.

    The locked head row serializes writers on PostgreSQL. The transaction that
    inserts the record must also commit the updated head, so partial appends
    cannot silently fork the chain.
    """
    if organization_id is None and actor_email:
        organization_id = (
            await db.execute(
                select(User.organization_id).where(
                    User.email == actor_email.lower().strip()
                )
            )
        ).scalar_one_or_none()

    head = (
        await db.execute(
            select(AuditChainHead)
            .where(AuditChainHead.id == 1)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if head is None:
        head = AuditChainHead(id=1, last_sequence=0, last_hmac=GENESIS_HMAC)
        db.add(head)
        await db.flush()

    sequence = head.last_sequence + 1
    previous_hmac = head.last_hmac
    now = datetime.now(UTC)
    clean_detail = dict(detail or {})
    entry = {
        "sequence": sequence,
        "previous_hmac": previous_hmac,
        "organization_id": organization_id,
        "actor_email": actor_email,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "detail": clean_detail,
        "ip_address": ip_address,
        "created_at": now,
    }
    entry_hmac = _calculate_entry_hmac(**entry)

    db.add(
        AuditLog(
            organization_id=organization_id,
            actor_email=actor_email,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            detail=clean_detail,
            ip_address=ip_address,
            sequence=sequence,
            previous_hmac=previous_hmac,
            entry_hmac=entry_hmac,
            created_at=now,
            updated_at=now,
        )
    )
    head.last_sequence = sequence
    head.last_hmac = entry_hmac


async def verify_audit_log_chain(db: AsyncSession) -> dict[str, Any]:
    """Verify records, ordering, content HMACs, and the separately stored head."""
    rows = (
        await db.execute(
            select(AuditLog).where(AuditLog.sequence.is_not(None)).order_by(AuditLog.sequence)
        )
    ).scalars().all()
    legacy_count = (
        await db.execute(
            select(AuditLog.id).where(AuditLog.sequence.is_(None))
        )
    ).scalars().all()
    head = (
        await db.execute(select(AuditChainHead).where(AuditChainHead.id == 1))
    ).scalar_one_or_none()
    if head is None:
        return {
            "valid": False,
            "chain_valid": False,
            "status": "head_missing",
            "total_records": len(rows) + len(legacy_count),
            "legacy_records": len(legacy_count),
        }

    previous_hmac = GENESIS_HMAC
    expected_sequence = 1
    for row in rows:
        if row.sequence != expected_sequence:
            return {
                "valid": False,
                "chain_valid": False,
                "status": "sequence_gap",
                "record_id": str(row.id),
                "expected_sequence": expected_sequence,
                "actual_sequence": row.sequence,
                "legacy_records": len(legacy_count),
            }
        if row.previous_hmac != previous_hmac or not row.entry_hmac:
            return {
                "valid": False,
                "chain_valid": False,
                "status": "broken_link",
                "record_id": str(row.id),
                "legacy_records": len(legacy_count),
            }

        expected_hmac = _calculate_entry_hmac(
            sequence=row.sequence,
            previous_hmac=row.previous_hmac,
            organization_id=row.organization_id,
            actor_email=row.actor_email,
            action=row.action,
            resource_type=row.resource_type,
            resource_id=row.resource_id,
            detail=row.detail,
            ip_address=row.ip_address,
            created_at=row.created_at,
        )
        if not hmac.compare_digest(row.entry_hmac, expected_hmac):
            return {
                "valid": False,
                "chain_valid": False,
                "status": "content_tampered",
                "record_id": str(row.id),
                "legacy_records": len(legacy_count),
            }

        previous_hmac = row.entry_hmac
        expected_sequence += 1

    last_sequence = expected_sequence - 1
    head_sequence, head_hmac = head.last_sequence, head.last_hmac
    if head_sequence != last_sequence or head_hmac != previous_hmac:
        return {
            "valid": False,
            "chain_valid": False,
            "status": "head_mismatch",
            "total_records": len(rows),
            "legacy_records": len(legacy_count),
        }

    fully_verified = not legacy_count
    return {
        "valid": fully_verified,
        "chain_valid": True,
        "total_records": len(rows) + len(legacy_count),
        "verified_records": len(rows),
        "legacy_records": len(legacy_count),
        "status": "intact" if fully_verified else "legacy_unverified",
        "last_verified_hmac": previous_hmac,
    }


def _cef_header(value: str | None) -> str:
    return (value or "").replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _cef_extension(value: Any) -> str:
    text = str(value if value is not None else "none")
    return (
        text.replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


def format_cef_audit(log: AuditLog) -> str:
    """Format an audit event as CEF, escaping headers and extension values."""
    severity = 5
    if any(word in log.action for word in ("delete", "disable", "revoked")):
        severity = 7
    elif any(word in log.action for word in ("admin", "security")):
        severity = 6

    detail = json.dumps(log.detail, default=str, separators=(",", ":")) if log.detail else ""
    extension = " ".join(
        (
            f"src={_cef_extension(log.ip_address or 'unknown')}",
            f"suser={_cef_extension(log.actor_email or 'system')}",
            "cs1Label=ResourceType",
            f"cs1={_cef_extension(log.resource_type)}",
            "cs2Label=ResourceId",
            f"cs2={_cef_extension(log.resource_id)}",
            "cs3Label=OrganizationId",
            f"cs3={_cef_extension(log.organization_id)}",
            f"msg={_cef_extension(detail)}",
        )
    )
    return (
        "CEF:0|Rynex Technologies|RTIP|1.0|"
        f"{_cef_header(log.action)}|{_cef_header(log.action)}|{severity}|{extension}"
    )


def _syslog_sd(value: str | None) -> str:
    return (
        (str(value) if value is not None else "-")
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("]", "\\]")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def format_rfc5424_audit(log: AuditLog) -> str:
    """Format an audit event as an RFC 5424 message with escaped structured data."""
    ts = (
        log.created_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        if log.created_at
        else datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    )
    detail = json.dumps(log.detail, default=str, separators=(",", ":")) if log.detail else ""
    structured_data = (
        f'[audit@rynex action="{_syslog_sd(log.action)}" '
        f'actor="{_syslog_sd(log.actor_email)}" ip="{_syslog_sd(log.ip_address)}" '
        f'organization="{_syslog_sd(log.organization_id)}"]'
    )
    message = detail.replace("\r", "\\r").replace("\n", "\\n")
    return f"<134>1 {ts} rtip-server app - - {structured_data} {message}"
