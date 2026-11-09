"""Celery application: scheduled collection with per-source intervals."""

from celery import Celery
from celery.schedules import crontab

from app.core.config import settings

celery_app = Celery(
    "rtip",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_time_limit=1800,
    task_soft_time_limit=1500,
)

# Beat schedule: per-source intervals from the connector registry.
# Celery beat uses static schedules; runtime per-source intervals are read
# from the intelligence_sources table by the tasks themselves.
celery_app.conf.beat_schedule = {
    "collect-ioc-feeds": {
        "task": "rtip.collect_multiple",
        "schedule": crontab(minute="*/15"),
        "args": (["urlhaus", "feodo-tracker"],),
    },
    "collect-threatfox": {
        "task": "rtip.collect_one",
        "schedule": crontab(minute="5 * * * *"),
        "args": ("threatfox",),
    },
    "collect-cisa-kev": {
        "task": "rtip.collect_one",
        "schedule": crontab(minute="10 * * * *"),
        "args": ("cisa-kev",),
    },
    "collect-ransomware-live": {
        "task": "rtip.collect_one",
        "schedule": crontab(minute="20 * * * *"),
        "args": ("ransomware-live",),
    },
    "collect-news": {
        "task": "rtip.collect_one",
        "schedule": crontab(minute="*/10"),
        "args": ("security-news-rss",),
    },
    "collect-darkweb-groups": {
        "task": "rtip.collect_one",
        "schedule": crontab(minute="40 */12 * * *"),
        "args": ("darkweb-groups",),
    },
}
