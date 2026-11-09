"""Connector registry — single source of truth for enabled collectors.

Adding a source = adding a connector module + one line here. Sources with
required keys are registered as soon as their connector exists; they report
as 'misconfigured' when the key is absent rather than crashing the pipeline.
"""

from app.collectors.base import BaseCollector
from app.collectors.connectors.cisa_kev import CisaKevCollector
from app.collectors.connectors.darkweb_groups import DarkWebGroupsCollector
from app.collectors.connectors.feodo import FeodoTrackerCollector
from app.collectors.connectors.news_rss import NewsRSSCollector
from app.collectors.connectors.ransomware_live import RansomwareLiveCollector
from app.collectors.connectors.threatfox import ThreatFoxCollector
from app.collectors.connectors.urlhaus import URLhausCollector
from app.core.config import settings
from app.core.logging import setup_logging

import os

COLLECTOR_CLASSES: list[type[BaseCollector]] = [
    CisaKevCollector,
    URLhausCollector,
    ThreatFoxCollector,
    FeodoTrackerCollector,
    RansomwareLiveCollector,
    DarkWebGroupsCollector,
    NewsRSSCollector,
]


def get_connector(slug: str) -> BaseCollector | None:
    for cls in COLLECTOR_CLASSES:
        if cls.slug == slug:
            api_key = None
            if cls.api_key_setting:
                api_key = os.getenv(cls.api_key_setting)
            return cls(api_key=api_key)
    return None


def all_connectors() -> list[BaseCollector]:
    out = []
    for cls in COLLECTOR_CLASSES:
        api_key = None
        if cls.api_key_setting:
            api_key = os.getenv(cls.api_key_setting)
        out.append(cls(api_key=api_key))
    return out
