"""Celery tasks — each runs its own DB session and closes connections cleanly."""

import asyncio
import logging

from app.workers.celery_app import celery_app

logger = logging.getLogger("rtip.tasks")


def _run_async(slug: str, trigger: str) -> dict:
    from app.core.database import AsyncSessionLocal
    from app.services.ingestion import run_collector

    async def _inner() -> dict:
        async with AsyncSessionLocal() as db:
            return await run_collector(slug, db, trigger=trigger)

    return asyncio.run(_inner())


@celery_app.task(name="rtip.collect_one", bind=True, max_retries=2)
def collect_one(self, slug: str, trigger: str = "scheduled") -> dict:
    try:
        return _run_async(slug, trigger)
    except Exception as exc:  # noqa: BLE001
        raise self.retry(exc=exc, countdown=60 * (2**self.request.retries)) from exc


def _collect_sequential(slugs: list[str]) -> list[dict]:
    """Run connectors one at a time, in-process, with per-slug error isolation.

    Deliberately NOT calling collect_one().delay().get() here: waiting on a
    subtask result from inside a worker deadlocks single-worker deployments
    and (with acks_late) can deadlock even multi-worker pools.
    """
    results = []
    for slug in slugs:
        try:
            results.append(_run_async(slug, trigger="scheduled"))
        except Exception as exc:  # noqa: BLE001 — one failing source never blocks the rest
            logger.error("scheduled collection of %s failed: %s", slug, exc)
            results.append({"source": slug, "received": 0, "stored": 0, "errors": [str(exc)]})
    return results


@celery_app.task(name="rtip.collect_multiple")
def collect_multiple(slugs: list[str]) -> list[dict]:
    return _collect_sequential(slugs)


@celery_app.task(name="rtip.collect_all")
def collect_all() -> list[dict]:
    from app.collectors.registry import COLLECTOR_CLASSES

    return _collect_sequential([cls.slug for cls in COLLECTOR_CLASSES])


@celery_app.task(name="rtip.retention_cleanup")
def retention_cleanup() -> dict:
    """Purge old collection jobs and expired password-reset tokens.

    Governed by RETENTION_COLLECTION_JOBS_DAYS (0 disables the collection-jobs
    purge). Never touches intelligence records — retention of intel is a
    deliberate operator decision, not an automatic one.
    """
    import asyncio

    return asyncio.run(_retention_purge())


async def _retention_purge() -> dict:
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import delete, select

    from app.core.config import settings
    from app.core.database import AsyncSessionLocal
    from app.models import CollectionJob, PasswordResetToken

    out = {"collection_jobs_deleted": 0, "reset_tokens_deleted": 0}
    async with AsyncSessionLocal() as db:
        if settings.RETENTION_COLLECTION_JOBS_DAYS > 0:
            cutoff = datetime.now(UTC) - timedelta(days=settings.RETENTION_COLLECTION_JOBS_DAYS)
            result = await db.execute(
                delete(CollectionJob).where(CollectionJob.started_at < cutoff)
            )
            out["collection_jobs_deleted"] = result.rowcount or 0
        # Expired, unconsumed reset tokens are always safe to drop
        now = datetime.now(UTC)
        stale = (
            await db.execute(
                select(PasswordResetToken.id).where(PasswordResetToken.expires_at < now)
            )
        ).scalars().all()
        if stale:
            result = await db.execute(
                delete(PasswordResetToken).where(PasswordResetToken.id.in_(stale))
            )
            out["reset_tokens_deleted"] = result.rowcount or 0
        await db.commit()
    return out
