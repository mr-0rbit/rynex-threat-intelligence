"""Dark web intelligence endpoints.

Scope: metadata about ransomware leak-site activity, aggregated from the
legitimate Ransomware.live research service. RTIP deliberately provides no
capability to access onion services, marketplaces, or stolen data.
"""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models import BreachIncident, ThreatActor, User

router = APIRouter(prefix="/darkweb", tags=["darkweb"])

POLICY_NOTICE = (
    "RTIP dark web monitoring consumes metadata from legitimate research "
    "intermediaries only. The platform does not connect to onion services or "
    "marketplaces, and never stores or redistributes stolen data. All threat "
    "actor activity is treated as unverified claims until independently corroborated."
)


@router.get("/overview")
async def darkweb_overview(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)) -> dict:
    now = datetime.now(UTC)
    day_ago = now - timedelta(hours=24)
    week_ago = now - timedelta(days=7)

    groups = (
        await db.execute(
            select(ThreatActor)
            .where(ThreatActor.source_slug == "darkweb-groups" or ThreatActor.source_slug == "ransomware-live")
            .order_by(ThreatActor.name)
        )
    ).scalars().all()

    posts_week = (
        await db.execute(
            select(func.count()).select_from(BreachIncident).where(
                BreachIncident.source_slug == "ransomware-live",
                BreachIncident.published_at >= week_ago,
            )
        )
    ).scalar() or 0
    posts_24h = (
        await db.execute(
            select(func.count()).select_from(BreachIncident).where(
                BreachIncident.source_slug == "ransomware-live",
                BreachIncident.published_at >= day_ago,
            )
        )
    ).scalar() or 0

    # Victim claims per actor (top 10)
    actor_rows = (
        await db.execute(
            select(BreachIncident.threat_actor_name, func.count())
            .where(BreachIncident.source_slug == "ransomware-live", BreachIncident.threat_actor_name.isnot(None))
            .group_by(BreachIncident.threat_actor_name)
            .order_by(func.count().desc())
            .limit(10)
        )
    ).all()

    # Victim claims per day (14d)
    day_rows = (
        await db.execute(
            select(func.date(BreachIncident.published_at), func.count())
            .where(
                BreachIncident.source_slug == "ransomware-live",
                BreachIncident.published_at >= now - timedelta(days=14),
            )
            .group_by(func.date(BreachIncident.published_at))
        )
    ).all()

    recent = (
        await db.execute(
            select(BreachIncident)
            .where(BreachIncident.source_slug == "ransomware-live")
            .order_by(BreachIncident.published_at.desc().nullslast())
            .limit(25)
        )
    ).scalars().all()

    return {
        "policy_notice": POLICY_NOTICE,
        "monitored_groups": len(groups),
        "claims_24h": posts_24h,
        "claims_7d": posts_week,
        "claims_by_actor": [{"label": r[0], "value": int(r[1])} for r in actor_rows if r[0]],
        "claims_over_time": [{"label": str(r[0]), "value": int(r[1])} for r in day_rows if r[0] is not None],
        "groups": [
            {
                "name": g.name,
                "aliases": g.aliases,
                "description": (g.description or "")[:280] or None,
                "first_observed": g.first_observed_at.isoformat() if g.first_observed_at else None,
                "last_observed": g.last_observed_at.isoformat() if g.last_observed_at else None,
                "attribution_status": g.attribution_status,
                "source_url": g.source_url,
            }
            for g in groups
        ],
        "recent_claims": [
            {
                "id": str(b.id),
                "organization": b.organization_name,
                "domain": b.organization_domain,
                "actor": b.threat_actor_name,
                "industry": b.industry,
                "country": b.country,
                "published_at": b.published_at.isoformat() if b.published_at else None,
                "verification_status": b.verification_status,
                "confidence": b.confidence,
                "source_url": b.source_url,
            }
            for b in recent
        ],
        "generated_at": now.isoformat(),
    }
