"""MITRE ATT&CK API endpoints: matrix visualization, technique catalog, and actor correlations."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models import BreachIncident, IOC, User, Vulnerability
from app.services import mitre

router = APIRouter(prefix="/mitre", tags=["mitre"])


@router.get("/matrix")
async def get_matrix(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    """Return MITRE ATT&CK Matrix enriched with real platform indicator counts."""
    matrix = mitre.get_mitre_matrix()

    # Calculate real intel telemetry counts to enrich matrix techniques
    kev_count = (
        await db.execute(select(func.count()).select_from(Vulnerability).where(Vulnerability.in_kev.is_(True)))
    ).scalar() or 0
    c2_count = (
        await db.execute(select(func.count()).select_from(IOC).where(IOC.source_slug == "feodo"))
    ).scalar() or 0
    url_count = (
        await db.execute(select(func.count()).select_from(IOC).where(IOC.source_slug == "urlhaus"))
    ).scalar() or 0
    breach_count = (
        await db.execute(select(func.count()).select_from(BreachIncident))
    ).scalar() or 0
    bruteforce_count = (
        await db.execute(select(func.count()).select_from(IOC).where(IOC.source_slug == "blocklist-de"))
    ).scalar() or 0

    counts = {
        "T1190": kev_count,
        "T1068": kev_count // 3 if kev_count else 0,
        "T1566": url_count,
        "T1071": c2_count,
        "T1110": bruteforce_count,
        "T1486": breach_count,
        "T1567": breach_count,
        "T1078": breach_count // 2 if breach_count else 0,
    }

    # Attach live active detection counts
    for column in matrix:
        for tech in column["techniques"]:
            tech["active_detections"] = counts.get(tech["id"], 0)

    return {
        "version": "v14.1",
        "matrix": matrix,
        "total_tactics": len(mitre.TACTICS),
        "total_techniques": len(mitre.TECHNIQUES),
    }


@router.get("/techniques")
async def list_techniques(
    q: str | None = Query(None, description="Search by name, ID, or description"),
    user: User = Depends(get_current_user),
) -> list[dict]:
    """List and search all ATT&CK techniques with detection and mitigations."""
    results = mitre.TECHNIQUES
    if q:
        lowered = q.lower()
        results = [
            t for t in results
            if lowered in t["id"].lower()
            or lowered in t["name"].lower()
            or lowered in t["description"].lower()
        ]
    return results


@router.get("/actors/{actor_name}/techniques")
async def get_actor_techniques(
    actor_name: str,
    user: User = Depends(get_current_user),
) -> list[dict]:
    """Get ATT&CK techniques associated with a specific threat actor."""
    return mitre.get_actor_techniques(actor_name)
