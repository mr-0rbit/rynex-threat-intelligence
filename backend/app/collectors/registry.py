"""Connector registry — single source of truth for enabled collectors.

Adding a source = adding a connector module + one line here. Sources with
required keys are registered as soon as their connector exists; they report
as 'misconfigured' when the key is absent rather than crashing the pipeline.
"""

from app.collectors.base import BaseCollector
from app.collectors.connectors.blocklist_de import BlocklistDeCollector
from app.collectors.connectors.cisa_kev import CisaKevCollector
from app.collectors.connectors.darkweb_groups import DarkWebGroupsCollector
from app.collectors.connectors.epss import EPSSCollector
from app.collectors.connectors.feodo import FeodoTrackerCollector
from app.collectors.connectors.misp import MISPCollector
from app.collectors.connectors.news_rss import NewsRSSCollector
from app.collectors.connectors.nvd import NVDCollector
from app.collectors.connectors.ransomware_live import RansomwareLiveCollector
from app.collectors.connectors.threatfox import ThreatFoxCollector
from app.collectors.connectors.urlhaus import URLhausCollector
import os

# Connectors resolve their keys via os.getenv(API_KEY_SETTING); .env values are
# NOT in os.environ by default (pydantic-settings keeps them Settings-only), so
# load them explicitly or THREATFOX_AUTH_KEY etc. in .env would be silently
# ignored. Finds backend/.env (or any parent dir) and respects real env vars.
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover — python-dotenv ships with pydantic-settings
    pass

COLLECTOR_CLASSES: list[type[BaseCollector]] = [
    CisaKevCollector,
    NVDCollector,
    EPSSCollector,
    URLhausCollector,
    ThreatFoxCollector,
    FeodoTrackerCollector,
    BlocklistDeCollector,
    RansomwareLiveCollector,
    DarkWebGroupsCollector,
    NewsRSSCollector,
    MISPCollector,
]


def _connector_key(cls: type[BaseCollector]) -> str | None:
    return os.getenv(cls.api_key_setting) if cls.api_key_setting else None


def get_connector(slug: str) -> BaseCollector | None:
    for cls in COLLECTOR_CLASSES:
        if cls.slug == slug:
            return cls(api_key=_connector_key(cls))
    return None


def all_connectors() -> list[BaseCollector]:
    return [cls(api_key=_connector_key(cls)) for cls in COLLECTOR_CLASSES]
