"""Tenant-aware TAXII 2.1 endpoints with persisted STIX 2.1 writes."""

import base64
import json
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_permission
from app.core.config import settings
from app.core.database import get_db
from app.core.security import Permission
from app.models import (
    BreachIncident,
    IOC,
    TAXIIOperation,
    TAXIIObject,
    User,
    Vulnerability,
)

TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
UUID_PATTERN = re.compile(r"^[a-z][a-z0-9-]*--[0-9a-fA-F-]{36}$")
STIX_SDO_TYPES = {
    "attack-pattern",
    "campaign",
    "course-of-action",
    "identity",
    "indicator",
    "intrusion-set",
    "malware",
    "note",
    "observed-data",
    "report",
    "threat-actor",
    "tool",
    "vulnerability",
}

COLLECTIONS = {
    "high-confidence-iocs": {
        "id": "91a82f34-01fa-4f9e-87a1-8d4a4e1d0001",
        "alias": "high-confidence-iocs",
        "title": "High-Confidence IOC Feed",
        "description": "Indicators of compromise verified with platform confidence >= 70%.",
        "can_read": True,
        "can_write": True,
        "media_types": [TAXII_MEDIA_TYPE, "application/stix+json;version=2.1"],
    },
    "cisa-kev": {
        "id": "91a82f34-01fa-4f9e-87a1-8d4a4e1d0002",
        "alias": "cisa-kev",
        "title": "CISA KEV Catalog",
        "description": "All CVEs tracked in the CISA Known Exploited Vulnerabilities catalog.",
        "can_read": True,
        "can_write": False,
        "media_types": [TAXII_MEDIA_TYPE, "application/stix+json;version=2.1"],
    },
    "ransomware-breaches": {
        "id": "91a82f34-01fa-4f9e-87a1-8d4a4e1d0003",
        "alias": "ransomware-breaches",
        "title": "Ransomware Gang Incident Claims",
        "description": "Active ransomware gang leak site breach claims.",
        "can_read": True,
        "can_write": False,
        "media_types": [TAXII_MEDIA_TYPE, "application/stix+json;version=2.1"],
    },
    "all-intel": {
        "id": "91a82f34-01fa-4f9e-87a1-8d4a4e1d0004",
        "alias": "all-intel",
        "title": "Consolidated Threat Intelligence Feed",
        "description": "All active indicators, vulnerabilities, and breach intelligence.",
        "can_read": True,
        "can_write": False,
        "media_types": [TAXII_MEDIA_TYPE, "application/stix+json;version=2.1"],
    },
}


def _taxii_enabled() -> None:
    if not settings.TAXII_ENABLED:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "TAXII service is disabled")


router = APIRouter(
    prefix="/taxii2",
    tags=["taxii2"],
    dependencies=[Depends(_taxii_enabled)],
)


def _taxii_response(content: dict[str, Any], status_code: int = 200) -> Response:
    return Response(
        content=json.dumps(content, default=str, separators=(",", ":")),
        status_code=status_code,
        media_type=TAXII_MEDIA_TYPE,
        headers={"Cache-Control": "private, no-store"},
    )


def _find_collection(collection_id: str) -> dict | None:
    for collection in COLLECTIONS.values():
        if collection["id"] == collection_id or collection["alias"] == collection_id:
            return collection
    return None


def _stix_ts(value: datetime | None) -> str:
    value = value or datetime.now(UTC)
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _stix_pattern(ioc_type: str, value: str) -> str | None:
    safe = value.replace("\\", "\\\\").replace("'", "\\'")
    match ioc_type:
        case "ipv4":
            return f"[ipv4-addr:value = '{safe}']"
        case "ipv6":
            return f"[ipv6-addr:value = '{safe}']"
        case "domain":
            return f"[domain-name:value = '{safe}']"
        case "url":
            return f"[url:value = '{safe}']"
        case "md5":
            return f"[file:hashes.md5 = '{safe}']"
        case "sha1":
            return f"[file:hashes.sha1 = '{safe}']"
        case "sha256":
            return f"[file:hashes.sha256 = '{safe}']"
        case "email":
            return f"[email-addr:value = '{safe}']"
        case _:
            return None


def _page_offset(token: str | None) -> int:
    if not token:
        return 0
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode("ascii")
        if not raw.startswith("offset:"):
            raise ValueError
        offset = int(raw.split(":", 1)[1])
        if not 0 <= offset <= 1_000_000:
            raise ValueError
        return offset
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid TAXII pagination token")


def _page_token(offset: int) -> str:
    return base64.urlsafe_b64encode(f"offset:{offset}".encode("ascii")).decode("ascii").rstrip("=")


def _validate_stix_object(obj: dict[str, Any]) -> None:
    stix_type = obj.get("type")
    stix_id = obj.get("id")
    if stix_type not in STIX_SDO_TYPES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Unsupported STIX object type: {stix_type}")
    if obj.get("spec_version") != "2.1":
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "STIX objects must use spec_version 2.1")
    if not isinstance(stix_id, str) or not UUID_PATTERN.fullmatch(stix_id):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "STIX object id must be type--UUID")
    id_type, raw_uuid = stix_id.split("--", 1)
    try:
        uuid.UUID(raw_uuid)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "STIX object id must contain a UUID") from exc
    if id_type != stix_type:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "STIX object id type does not match its type")
    if stix_type == "indicator":
        required = ("created", "modified", "name", "pattern", "pattern_type", "valid_from")
        if any(not obj.get(key) for key in required) or obj.get("pattern_type") != "stix":
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "STIX indicators require created, modified, name, pattern, pattern_type=stix, and valid_from",
            )
    elif any(not obj.get(key) for key in ("created", "modified", "name")):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "STIX domain objects require created, modified, and name",
        )


def _indicator_object(ioc: IOC) -> dict[str, Any] | None:
    pattern = _stix_pattern(ioc.type, ioc.value)
    if not pattern:
        return None
    created = _stix_ts(ioc.created_at)
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{ioc.id}",
        "created": created,
        "modified": _stix_ts(ioc.updated_at),
        "name": f"{ioc.type.upper()}: {ioc.value}",
        "description": f"Source: {ioc.source_slug}. Platform confidence: {ioc.confidence:.0%}.",
        "indicator_types": ["malicious-activity"],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": _stix_ts(ioc.first_seen_at or ioc.created_at),
        "confidence": int(ioc.confidence * 100),
        "labels": ioc.tags or [],
    }


@router.get("/")
@router.get("")
async def taxii_discovery(request: Request) -> Response:
    """Public TAXII discovery; the advertised root remains authenticated."""
    api_root = f"{str(request.base_url).rstrip('/')}/taxii2/api1/"
    return _taxii_response(
        {
            "title": settings.TAXII_TITLE,
            "description": settings.TAXII_DESCRIPTION,
            "contact": "security@rynex.tech",
            "default": api_root,
            "api_roots": [api_root],
        }
    )


@router.get("/api1/")
@router.get("/api1")
async def taxii_api_root(
    user: User = Depends(require_permission(Permission.TAXII_READ)),
) -> Response:
    return _taxii_response(
        {
            "title": "RTIP TAXII API Root",
            "description": "Threat Intelligence Collection and Distribution Endpoint",
            "versions": ["taxii-2.1"],
            "max_content_length": settings.TAXII_MAX_CONTENT_LENGTH,
        }
    )


@router.get("/api1/collections/")
@router.get("/api1/collections")
async def taxii_collections(
    user: User = Depends(require_permission(Permission.TAXII_READ)),
) -> Response:
    collections = []
    for collection in COLLECTIONS.values():
        item = dict(collection)
        item["can_write"] = bool(
            item["can_write"] and user.role in ("admin", "soc_lead", "analyst")
        )
        collections.append(item)
    return _taxii_response({"collections": collections})


@router.get("/api1/collections/{collection_id}/")
@router.get("/api1/collections/{collection_id}")
async def taxii_collection_detail(
    collection_id: str,
    user: User = Depends(require_permission(Permission.TAXII_READ)),
) -> Response:
    collection = _find_collection(collection_id)
    if collection is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Collection not found")
    result = dict(collection)
    result["can_write"] = bool(
        result["can_write"] and user.role in ("admin", "soc_lead", "analyst")
    )
    return _taxii_response(result)


async def taxii_get_objects(
    collection_id: str,
    added_after: datetime | None = None,
    limit: int = 100,
    next: str | None = None,
    db: AsyncSession | None = None,
    user: User | None = None,
) -> Response:
    collection = _find_collection(collection_id)
    if collection is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Collection not found")
    if db is None or user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")

    alias = collection["alias"]
    offset = _page_offset(next)
    fetch_count = offset + limit + 1
    objects: list[dict[str, Any]] = []
    if alias in ("high-confidence-iocs", "all-intel"):
        stmt = select(IOC).where(
            IOC.confidence >= (0.70 if alias == "high-confidence-iocs" else 0.0),
            (IOC.valid_until.is_(None) | (IOC.valid_until > datetime.now(UTC))),
        )
        if added_after:
            stmt = stmt.where(IOC.created_at >= added_after)
        iocs = (
            await db.execute(stmt.order_by(IOC.created_at.desc()).limit(fetch_count))
        ).scalars().all()
        objects.extend(item for ioc in iocs if (item := _indicator_object(ioc)) is not None)

    if alias in ("cisa-kev", "all-intel"):
        stmt = select(Vulnerability)
        if alias == "cisa-kev":
            stmt = stmt.where(Vulnerability.in_kev.is_(True))
        if added_after:
            stmt = stmt.where(Vulnerability.created_at >= added_after)
        vulns = (
            await db.execute(stmt.order_by(Vulnerability.created_at.desc()).limit(fetch_count))
        ).scalars().all()
        for vulnerability in vulns:
            objects.append(
                {
                    "type": "vulnerability",
                    "spec_version": "2.1",
                    "id": f"vulnerability--{vulnerability.id}",
                    "created": _stix_ts(vulnerability.created_at),
                    "modified": _stix_ts(vulnerability.updated_at),
                    "name": vulnerability.cve_id,
                    "description": vulnerability.description or vulnerability.title or vulnerability.cve_id,
                    "external_references": [
                        {"source_name": "cve", "external_id": vulnerability.cve_id}
                    ],
                }
            )

    if alias in ("ransomware-breaches", "all-intel"):
        stmt = select(BreachIncident)
        if alias == "ransomware-breaches":
            stmt = stmt.where(BreachIncident.threat_actor_name.is_not(None))
        if added_after:
            stmt = stmt.where(BreachIncident.created_at >= added_after)
        breaches = (
            await db.execute(stmt.order_by(BreachIncident.created_at.desc()).limit(fetch_count))
        ).scalars().all()
        for breach in breaches:
            objects.append(
                {
                    "type": "x-rtip-breach",
                    "spec_version": "2.1",
                    "id": f"x-rtip-breach--{breach.id}",
                    "created": _stix_ts(breach.created_at),
                    "modified": _stix_ts(breach.updated_at),
                    "name": f"Breach claim: {breach.organization_name}",
                    "description": breach.summary or "",
                    "x_rtip_organization": breach.organization_name,
                    "x_rtip_organization_domain": breach.organization_domain,
                    "x_rtip_threat_actor": breach.threat_actor_name,
                    "x_rtip_verification_status": breach.verification_status,
                }
            )

    stored_stmt = select(TAXIIObject).where(
        TAXIIObject.organization_id == user.organization_id,
        TAXIIObject.collection_alias == alias,
    )
    if added_after:
        stored_stmt = stored_stmt.where(TAXIIObject.date_added >= added_after)
    stored = (
        await db.execute(
            stored_stmt.order_by(TAXIIObject.date_added.desc()).limit(fetch_count)
        )
    ).scalars().all()
    objects.extend(row.object_data for row in stored)

    objects.sort(key=lambda item: item.get("modified", item.get("created", "")), reverse=True)
    page = objects[offset : offset + limit]
    more = len(objects) > offset + limit
    return _taxii_response(
        {
            "more": more,
            "next": _page_token(offset + limit) if more else None,
            "objects": page,
        }
    )


@router.get("/api1/collections/{collection_id}/objects/")
@router.get("/api1/collections/{collection_id}/objects")
async def taxii_objects_endpoint(
    collection_id: str,
    added_after: datetime | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    next: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission(Permission.TAXII_READ)),
) -> Response:
    return await taxii_get_objects(collection_id, added_after, limit, next, db, user)


@router.get("/api1/collections/{collection_id}/manifest/")
@router.get("/api1/collections/{collection_id}/manifest")
async def taxii_manifest(
    collection_id: str,
    added_after: datetime | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    next: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission(Permission.TAXII_READ)),
) -> Response:
    objects_response = await taxii_get_objects(collection_id, added_after, limit, next, db, user)
    bundle = json.loads(objects_response.body)
    manifest = [
        {
            "id": obj["id"],
            "date_added": obj.get("created", obj.get("modified")),
            "version": obj.get("modified", obj.get("created")),
            "media_type": "application/stix+json;version=2.1",
        }
        for obj in bundle["objects"]
    ]
    return _taxii_response({"more": bundle["more"], "next": bundle["next"], "objects": manifest})


class TAXIIAddObjectsRequest(BaseModel):
    objects: list[dict[str, Any]] = Field(..., min_length=1, max_length=1000)


@router.post("/api1/collections/{collection_id}/objects/", status_code=202)
@router.post("/api1/collections/{collection_id}/objects", status_code=202)
async def taxii_add_objects(
    collection_id: str,
    body: TAXIIAddObjectsRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission(Permission.TAXII_WRITE)),
) -> Response:
    collection = _find_collection(collection_id)
    if collection is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Collection not found")
    if not collection["can_write"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Collection is read-only")

    payload_size = len(json.dumps(body.model_dump(), separators=(",", ":"), default=str).encode("utf-8"))
    if payload_size > settings.TAXII_MAX_CONTENT_LENGTH:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "TAXII request exceeds max_content_length")
    for obj in body.objects:
        _validate_stix_object(obj)

    now = datetime.now(UTC)
    success_count = 0
    for obj in body.objects:
        object_id = obj["id"]
        existing = (
            await db.execute(
                select(TAXIIObject).where(
                    TAXIIObject.organization_id == user.organization_id,
                    TAXIIObject.collection_alias == collection["alias"],
                    TAXIIObject.object_id == object_id,
                )
            )
        ).scalar_one_or_none()
        if existing:
            old_modified = existing.object_data.get("modified", "")
            new_modified = obj.get("modified", "")
            if new_modified < old_modified:
                continue
            existing.object_type = obj["type"]
            existing.object_data = obj
            existing.date_added = now
        else:
            db.add(
                TAXIIObject(
                    organization_id=user.organization_id,
                    created_by_user_id=user.id,
                    collection_alias=collection["alias"],
                    object_id=object_id,
                    object_type=obj["type"],
                    object_data=obj,
                    date_added=now,
                )
            )
        success_count += 1

    operation = TAXIIOperation(
        organization_id=user.organization_id,
        collection_alias=collection["alias"],
        status="complete",
        total_count=len(body.objects),
        success_count=success_count,
        failure_count=len(body.objects) - success_count,
        failure_detail=None,
        request_timestamp=now,
    )
    db.add(operation)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "Concurrent duplicate STIX object submission") from exc
    await db.refresh(operation)
    return _taxii_response(
        {
            "id": str(operation.id),
            "status": operation.status,
            "request_timestamp": _stix_ts(operation.request_timestamp),
            "total_count": operation.total_count,
            "success_count": operation.success_count,
            "failure_count": operation.failure_count,
            "pending_count": 0,
        },
        status_code=status.HTTP_202_ACCEPTED,
    )


@router.get("/api1/status/{status_id}/")
@router.get("/api1/status/{status_id}")
async def taxii_status(
    status_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission(Permission.TAXII_READ)),
) -> Response:
    operation = (
        await db.execute(
            select(TAXIIOperation).where(
                TAXIIOperation.id == status_id,
                TAXIIOperation.organization_id == user.organization_id,
            )
        )
    ).scalar_one_or_none()
    if operation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "TAXII operation not found")
    return _taxii_response(
        {
            "id": str(operation.id),
            "status": operation.status,
            "request_timestamp": _stix_ts(operation.request_timestamp),
            "total_count": operation.total_count,
            "success_count": operation.success_count,
            "failure_count": operation.failure_count,
            "pending_count": 0,
            "failure_detail": operation.failure_detail,
        }
    )
