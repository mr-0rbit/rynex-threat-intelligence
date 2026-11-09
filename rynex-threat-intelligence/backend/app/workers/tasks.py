"""Celery tasks — each runs its own DB session and closes connections cleanly."""

import asyncio

from app.workers.celery_app import celery_app


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
        raise self.retry(exc=exc, countdown=60 * (2**self.request.retries))


@celery_app.task(name="rtip.collect_multiple")
def collect_multiple(slugs: list[str]) -> list[dict]:
    return [collect_one.apply_async(args=[slug]).get() for slug in slugs]


@celery_app.task(name="rtip.collect_all")
def collect_all() -> list[dict]:
    from app.collectors.registry import COLLECTOR_CLASSES

    return [collect_one.apply_async(args=[cls.slug]).get() for cls in COLLECTOR_CLASSES]
