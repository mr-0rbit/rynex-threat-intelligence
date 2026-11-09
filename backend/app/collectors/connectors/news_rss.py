"""Cybersecurity news via RSS/Atom feeds (Phase 5 first batch).

Publishers: The Hacker News, BleepingComputer, SecurityWeek, Dark Reading,
Krebs on Security, CISA Advisories. RSS is the publishers' intended
distribution channel for automated consumption.
"""

import hashlib
import logging
import re
import calendar
import time as _time
from collections.abc import AsyncIterator

import feedparser

logger = logging.getLogger("rtip.collectors.news")

from app.collectors.base import BaseCollector, CollectedRecord
from app.services.ioc_normalizer import IOCNormalizer

FEEDS: dict[str, str] = {
    "thehackernews": "https://feeds.feedburner.com/TheHackersNews",
    "bleepingcomputer": "https://www.bleepingcomputer.com/feed/",
    "securityweek": "https://www.securityweek.com/feed/",
    "darkreading": "https://www.darkreading.com/rss.xml",
    "krebsonsecurity": "https://krebsonsecurity.com/feed/",
    "cisa-advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
}


def parse_feed_entry(publisher: str, source_slug: str, entry: dict) -> dict | None:
    """Pure parser for one feed entry (feedparser entry dict)."""
    link = (entry.get("link") or "").strip()
    title = (entry.get("title") or "").strip()
    if not link or not title or not link.lower().startswith(("http://", "https://")):
        return None
    summary = entry.get("summary") or entry.get("description") or ""
    # strip HTML crudely; full sanitization happens before display storage
    summary = re.sub(r"<[^>]+>", " ", summary)
    summary = re.sub(r"\s+", " ", summary).strip()[:1000]

    published = None
    for field in ("published_parsed", "updated_parsed"):
        if entry.get(field):
            try:
                published = _time.strftime("%Y-%m-%dT%H:%M:%S%z", entry[field])
            except Exception:  # noqa: BLE001
                published = None
            break
    published_dt = IOCNormalizer.parse_date(published)

    url_hash = hashlib.sha256(link.encode()).hexdigest()
    return {
        "url_hash": url_hash,
        "url": link,
        "headline": title[:1024],
        "summary": summary or None,
        "publisher": publisher,
        "published_at": published_dt,
        "collected_at": None,  # set by ingestion service
        "source_slug": source_slug,
        "categories": [t.get("term") for t in entry.get("tags", []) if isinstance(t, dict)][:8] or None,
    }


class NewsRSSCollector(BaseCollector):
    """Multi-feed news collector; each publisher is one logical sub-source."""

    slug = "security-news-rss"
    name = "Cybersecurity News RSS Aggregator"
    category = "news"
    homepage_url = "https://www.cisa.gov/"
    description = "Aggregates headlines from reputable security publishers via their public RSS feeds."
    commercial_use_status = "attribution_required"
    terms_notes = (
        "Headlines/summaries are aggregated for internal intelligence use with attribution and "
        "original links. Do not republish full article text."
    )
    collection_interval_minutes = 10
    source_credibility = 0.8

    async def fetch_batch(self, checkpoint: str | None = None) -> AsyncIterator[CollectedRecord]:
        for slug, feed_url in FEEDS.items():
            try:
                resp = await self.http.fetch(feed_url, rate_limit_interval=2.0)
            except Exception as exc:  # noqa: BLE001 — one dead feed must not kill the rest
                logger.warning("feed %s unavailable: %s", slug, exc, extra={"source_id": slug})
                continue
            parsed_feed = feedparser.parse(resp.content)
            for entry in parsed_feed.entries:
                parsed = parse_feed_entry(slug, slug, entry)
                if parsed is None:
                    continue
                yield CollectedRecord(
                    kind="news", data=parsed, external_id=parsed["url_hash"], published_at=parsed.get("published_at")
                )
