"""Ransomware.live — ransomware victim disclosure monitor.

Source: https://api.ransomware.live/v2/ (public JSON API)
Policy: group victim claims are stored with verification_status='claimed' and
NEVER promoted to 'confirmed' without independent corroboration.
Optional free API key supported via RANSOMWARELIVE_API_KEY for partners.
"""

from collections.abc import AsyncIterator

from app.collectors.base import BaseCollector, CollectedRecord
from app.services.confidence import classify_breach, score_breach
from app.services.ioc_normalizer import IOCNormalizer

RANSOMWARELIVE_RECENT_URL = "https://api.ransomware.live/v2/recentcyberattacks"


def parse_ransomwarelive_record(item: dict) -> dict | None:
    """Pure parser — returns breach payload or None when invalid."""
    victim = (item.get("victim") or item.get("post_title") or "").strip()
    if not victim:
        return None
    domain = (item.get("website") or "").strip().removeprefix("http://").removeprefix("https://").rstrip("/")
    if domain and not IOCNormalizer.normalize(domain, "domain"):
        domain = None
    if domain and IOCNormalizer.is_benign_domain(domain):
        domain = None
    discovered = IOCNormalizer.parse_date(item.get("discovered") or item.get("published"))
    actor = item.get("group") or item.get("group_name") or None
    country = item.get("country") or None
    activity = item.get("activity") or item.get("sector") or None

    org_fp = IOCNormalizer.fingerprint("breach", victim, actor or "unknown-actor")
    confidence = score_breach(
        source_credibility=0.7,
        verification_status="claimed",
        corroborating_sources=1,
        record_count_sourced=False,
    )
    return {
        "fingerprint": org_fp,
        "organization_name": victim,
        "organization_domain": domain,
        "industry": activity,
        "country": country,
        "reported_date": discovered,
        "published_at": discovered,
        "threat_actor_name": actor,
        "claimed_data_types": [item.get("description")] if item.get("description") else [],
        "summary": item.get("description") or None,
        "source_slug": "ransomware-live",
        "source_url": item.get("post_url") or "https://www.ransomware.live/",
        "evidence_references": (
            [{"source_slug": "ransomware-live", "url": item.get("post_url")}] if item.get("post_url") else []
        ),
        "verification_status": classify_breach(has_actor_claim=True, has_org_disclosure=False, has_credible_media=False),
        "confidence": confidence.score,
        "confidence_reasons": {"reasons": confidence.reasons},
        "_external_id": org_fp,
    }


class RansomwareLiveCollector(BaseCollector):
    slug = "ransomware-live"
    name = "Ransomware.live"
    category = "breach"
    homepage_url = "https://www.ransomware.live/"
    description = "Tracks ransomware group victim disclosures published on leak sites (claims, unverified)."
    auth_method = "api_key_header"
    api_key_setting = "RANSOMWARELIVE_API_KEY"
    commercial_use_status = "unknown"
    terms_notes = (
        "Free public API for research/monitoring; verify commercial-use terms before any "
        "commercial redistribution. All victim entries are threat-actor claims, not confirmations."
    )
    collection_interval_minutes = 60
    source_credibility = 0.7

    async def fetch_batch(self, checkpoint: str | None = None) -> AsyncIterator[CollectedRecord]:
        headers = {"Auth-Key": self.api_key} if self.api_key else {}
        resp = await self.http.fetch(RANSOMWARELIVE_RECENT_URL, headers=headers, rate_limit_interval=2.0)
        for item in resp.json() or []:
            if not isinstance(item, dict):
                continue
            parsed = parse_ransomwarelive_record(item)
            if parsed is None:
                continue
            yield CollectedRecord(
                kind="breach", data=parsed, external_id=parsed["_external_id"], published_at=parsed.get("published_at")
            )
