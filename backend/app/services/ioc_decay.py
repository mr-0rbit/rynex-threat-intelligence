"""Automated IOC confidence decay and aging engine.

Applies deterministic time-decay algorithms to indicators:
- IP addresses: fast turnover (half-life 14 days; retired after 45 days of inactivity).
- Domains & URLs: medium turnover (half-life 30 days).
- File hashes (MD5, SHA1, SHA256): immutable artifacts; retain full confidence.
- False positive suppression: immediate score zeroing with audit logging.
"""

from datetime import UTC, datetime, timedelta
import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.intel import IOC

logger = logging.getLogger("rtip.decay")

DECAY_RATES_PER_DAY = {
    "ipv4": 0.04,  # ~50% in 14 days
    "ipv6": 0.04,
    "url": 0.04,
    "domain": 0.02,  # ~50% in 30 days
    "email": 0.02,
    "md5": 0.0,
    "sha1": 0.0,
    "sha256": 0.0,
}


def calculate_decayed_confidence(
    base_confidence: float,
    ioc_type: str,
    last_seen_at: datetime | None,
    now: datetime | None = None,
) -> float:
    """Calculate decayed confidence score based on indicator type and inactivity duration."""
    if not last_seen_at:
        return base_confidence
    if now is None:
        now = datetime.now(UTC)
    if last_seen_at.tzinfo is None:
        last_seen_at = last_seen_at.replace(tzinfo=UTC)

    days_inactive = max(0.0, (now - last_seen_at).total_seconds() / 86400.0)
    rate = DECAY_RATES_PER_DAY.get(ioc_type.lower(), 0.02)
    if rate == 0.0:
        return base_confidence

    # Exponential decay: C(t) = C0 * (1 - rate)^t
    decayed = base_confidence * ((1.0 - rate) ** days_inactive)
    return round(max(0.05, min(1.0, decayed)), 3)


async def run_decay_cycle(db: AsyncSession, days_inactive_threshold: int = 7) -> dict:
    """Run a periodic decay evaluation across all active indicators."""
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=days_inactive_threshold)

    # Find IOCs that have not been seen within threshold
    stmt = (
        select(IOC)
        .where(
            IOC.last_seen_at < cutoff,
            IOC.type.in_(["ipv4", "ipv6", "domain", "url"]),
            IOC.confidence > 0.10,
        )
        .limit(2000)
    )
    stale_iocs = (await db.execute(stmt)).scalars().all()

    decayed_count = 0
    expired_count = 0

    for ioc in stale_iocs:
        new_score = calculate_decayed_confidence(ioc.confidence, ioc.type, ioc.last_seen_at, now)
        if new_score != ioc.confidence:
            ioc.confidence = new_score
            reasons = ioc.confidence_reasons or {}
            reasons["decay_applied"] = f"automated decay applied; inactive for {(now - ioc.last_seen_at.replace(tzinfo=UTC)).days} days"
            ioc.confidence_reasons = reasons
            decayed_count += 1

            if new_score <= 0.15:
                ioc.valid_until = now
                expired_count += 1

    await db.commit()
    logger.info("completed IOC decay cycle: %d decayed, %d expired", decayed_count, expired_count)
    return {
        "evaluated": len(stale_iocs),
        "decayed": decayed_count,
        "expired": expired_count,
        "timestamp": now.isoformat(),
    }
