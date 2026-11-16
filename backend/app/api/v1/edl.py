"""Enterprise Firewall External Dynamic Lists (EDL) endpoints.

Provides high-speed plain-text indicator feeds for next-generation firewalls:
- Palo Alto Networks (PAN-OS External Dynamic Lists)
- Fortinet FortiGate (Threat Feeds)
- Check Point (Custom Indicators Feed)
- pfSense / OPNsense (pfBlockerNG)
- Cisco Secure Firewall / Snort / Suricata
- DNS Sinkholes (Pi-hole, CoreDNS, Unbound)

Supports authentication via standard `X-API-Key` header or `?token=` parameter.
Includes HTTP ETag caching for minimal network/firewall overhead.
"""

import hashlib
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import _hash_api_key
from app.core.database import get_db
from app.core.security import Permission, has_permission
from app.core.timeutil import ensure_aware
from app.models import ApiToken, IOC, Organization, User

router = APIRouter(prefix="/edl", tags=["edl"])


async def authenticate_edl(
    request: Request,
    token: str | None = Query(None, description="API token as query parameter"),
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db),
) -> bool:
    """Validate EDL access via either X-API-Key header or ?token= parameter."""
    raw_key = x_api_key or token
    if not raw_key:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "EDL authentication required via X-API-Key header or ?token= parameter",
        )

    # Check API tokens table
    key_hash = _hash_api_key(raw_key)
    api_token = (
        await db.execute(select(ApiToken).where(ApiToken.key_hash == key_hash))
    ).scalar_one_or_none()

    if not api_token or api_token.revoked_at is not None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or revoked EDL API token")

    now = datetime.now(UTC)
    expires_at = ensure_aware(api_token.expires_at) if api_token.expires_at else None
    if expires_at and expires_at < now:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Expired EDL API token")

    api_token.last_used_at = now
    owner = await db.get(User, api_token.owner_user_id)
    if owner is None or not owner.is_active or not has_permission(owner.role, Permission.EDL_READ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "API key owner is not authorized for EDL access")
    organization = await db.get(Organization, owner.organization_id)
    if organization is None or not organization.enabled:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Organization is disabled")
    return True


def _make_edl_response(
    items: list[str],
    request: Request,
    content_type: str = "text/plain; charset=utf-8",
) -> Response:
    body = "\n".join(items) + ("\n" if items else "")
    etag = f'"{hashlib.sha256(body.encode()).hexdigest()[:16]}"'

    # Check If-None-Match for 304 Not Modified
    if_none_match = request.headers.get("If-None-Match")
    if if_none_match and if_none_match.strip() == etag:
        return Response(
            status_code=status.HTTP_304_NOT_MODIFIED,
            headers={
                "ETag": etag,
                "Cache-Control": "private, no-store",
                "Vary": "X-API-Key",
            },
        )

    return Response(
        content=body,
        media_type=content_type,
        headers={
            "ETag": etag,
            "Cache-Control": "private, no-store",
            "Vary": "X-API-Key",
            "X-Total-Count": str(len(items)),
        },
    )


@router.get("/ips")
async def edl_ips(
    request: Request,
    min_confidence: float = Query(0.60, ge=0.0, le=1.0, description="Minimum platform confidence threshold"),
    days: int = Query(30, ge=1, le=365, description="Only indicators seen within N days"),
    limit: int = Query(10000, ge=1, le=50000),
    auth: bool = Depends(authenticate_edl),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Plaintext newline-delimited IPv4 and IPv6 blocklist for firewalls."""
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=days)

    stmt = (
        select(IOC.value)
        .where(
            IOC.type.in_(["ipv4", "ipv6"]),
            IOC.confidence >= min_confidence,
            IOC.last_seen_at >= cutoff,
            (IOC.valid_until.is_(None) | (IOC.valid_until > now)),
        )
        .order_by(IOC.confidence.desc())
        .limit(limit)
    )
    ips = (await db.execute(stmt)).scalars().all()
    # Deduplicate while preserving order
    seen = set()
    deduped = [ip for ip in ips if not (ip in seen or seen.add(ip))]
    return _make_edl_response(deduped, request)


@router.get("/domains")
async def edl_domains(
    request: Request,
    min_confidence: float = Query(0.60, ge=0.0, le=1.0),
    days: int = Query(60, ge=1, le=365),
    limit: int = Query(10000, ge=1, le=50000),
    auth: bool = Depends(authenticate_edl),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Plaintext newline-delimited malicious domain list for DNS sinkholes and firewalls."""
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=days)

    stmt = (
        select(IOC.value)
        .where(
            IOC.type == "domain",
            IOC.confidence >= min_confidence,
            IOC.last_seen_at >= cutoff,
            (IOC.valid_until.is_(None) | (IOC.valid_until > now)),
        )
        .order_by(IOC.confidence.desc())
        .limit(limit)
    )
    domains = (await db.execute(stmt)).scalars().all()
    seen = set()
    deduped = [d for d in domains if not (d in seen or seen.add(d))]
    return _make_edl_response(deduped, request)


@router.get("/urls")
async def edl_urls(
    request: Request,
    min_confidence: float = Query(0.60, ge=0.0, le=1.0),
    days: int = Query(30, ge=1, le=365),
    limit: int = Query(10000, ge=1, le=50000),
    auth: bool = Depends(authenticate_edl),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Plaintext newline-delimited malicious URL list for web gateways and proxies."""
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=days)

    stmt = (
        select(IOC.value)
        .where(
            IOC.type == "url",
            IOC.confidence >= min_confidence,
            IOC.last_seen_at >= cutoff,
            (IOC.valid_until.is_(None) | (IOC.valid_until > now)),
        )
        .order_by(IOC.confidence.desc())
        .limit(limit)
    )
    urls = (await db.execute(stmt)).scalars().all()
    seen = set()
    deduped = [u for u in urls if not (u in seen or seen.add(u))]
    return _make_edl_response(deduped, request)


@router.get("/hashes")
async def edl_hashes(
    request: Request,
    min_confidence: float = Query(0.60, ge=0.0, le=1.0),
    hash_type: str = Query("sha256", description="md5, sha1, or sha256"),
    limit: int = Query(10000, ge=1, le=50000),
    auth: bool = Depends(authenticate_edl),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Plaintext newline-delimited malicious file hashes for EDR and anti-malware blocklists."""
    hash_type = hash_type.lower()
    if hash_type not in {"md5", "sha1", "sha256"}:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "hash_type must be md5, sha1, or sha256")
    now = datetime.now(UTC)
    stmt = (
        select(IOC.value)
        .where(
            IOC.type == hash_type.lower(),
            IOC.confidence >= min_confidence,
            (IOC.valid_until.is_(None) | (IOC.valid_until > now)),
        )
        .order_by(IOC.confidence.desc())
        .limit(limit)
    )
    hashes = (await db.execute(stmt)).scalars().all()
    seen = set()
    deduped = [h for h in hashes if not (h in seen or seen.add(h))]
    return _make_edl_response(deduped, request)
