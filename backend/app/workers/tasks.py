"""Celery tasks — each runs its own DB session and closes connections cleanly."""

import asyncio
import logging
import os
from collections.abc import Coroutine
from typing import Any, TypeVar

from celery.signals import worker_process_shutdown

from app.workers.celery_app import celery_app

logger = logging.getLogger("rtip.tasks")

_worker_event_loop: asyncio.AbstractEventLoop | None = None
_worker_event_loop_pid: int | None = None
_T = TypeVar("_T")


def _run_coroutine(coroutine: Coroutine[Any, Any, _T]) -> _T:
    """Run async work on a persistent loop owned by this Celery process.

    ``asyncio.run`` closes its loop after every task. Collectors share an
    async HTTP client, so the next scheduled task would otherwise reuse that
    client after its event loop had already closed.
    """
    global _worker_event_loop, _worker_event_loop_pid

    process_id = os.getpid()
    if (
        _worker_event_loop is None
        or _worker_event_loop.is_closed()
        or _worker_event_loop_pid != process_id
    ):
        _worker_event_loop = asyncio.new_event_loop()
        _worker_event_loop_pid = process_id

    asyncio.set_event_loop(_worker_event_loop)
    return _worker_event_loop.run_until_complete(coroutine)


def _close_worker_event_loop(**_kwargs: Any) -> None:
    """Release async resources when a prefork Celery child shuts down."""
    global _worker_event_loop, _worker_event_loop_pid

    loop = _worker_event_loop
    if loop is None or loop.is_closed() or _worker_event_loop_pid != os.getpid():
        return

    async def _close_resources() -> None:
        from app.collectors.http import shared_http
        from app.core.database import engine

        await shared_http.close()
        await engine.dispose()

    try:
        asyncio.set_event_loop(loop)
        loop.run_until_complete(_close_resources())
        loop.run_until_complete(loop.shutdown_asyncgens())
    except Exception:  # noqa: BLE001 — shutdown must not mask worker exit
        logger.exception("failed to close async worker resources")
    finally:
        loop.close()
        asyncio.set_event_loop(None)
        _worker_event_loop = None
        _worker_event_loop_pid = None


worker_process_shutdown.connect(_close_worker_event_loop, weak=False)


def _run_async(slug: str, trigger: str) -> dict:
    from app.core.database import AsyncSessionLocal
    from app.services.ingestion import run_collector

    async def _inner() -> dict:
        async with AsyncSessionLocal() as db:
            return await run_collector(slug, db, trigger=trigger)

    return _run_coroutine(_inner())

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
    return _run_coroutine(_retention_purge())


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


@celery_app.task(name="rtip.decay_indicators")
def decay_indicators() -> dict:
    """Enterprise IOC aging: recalculate confidence scores based on inactivity."""
    from app.core.database import AsyncSessionLocal
    from app.services.ioc_decay import run_decay_cycle

    async def _inner():
        async with AsyncSessionLocal() as db:
            return await run_decay_cycle(db)

    return _run_coroutine(_inner())
