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
    """Pure parser — returns breach payload or None when invalid.

    API v2 (recentcyberattacks) record keys:
      victim, domain, claim_gang (str|False), claim_url (str|False), date,
      added, country, summary, description, title, url (news source),
      link (ransomware.live victim page), has_infostealer_info.
    """
    victim = (item.get("victim") or item.get("post_title") or "").strip()
    if not victim:
        return None
    domain = (item.get("domain") or item.get("website") or "").strip().removeprefix("http://").removeprefix("https://").rstrip("/")
    if domain and not IOCNormalizer.normalize(domain, "domain"):
        domain = None
    if domain and IOCNormalizer.is_benign_domain(domain):
        domain = None
    # claim_gang/claim_url are booleans (False) when absent — only accept strings
    actor_raw = item.get("claim_gang")
    actor = actor_raw.strip() if isinstance(actor_raw, str) and actor_raw.strip() else None
    if not actor:  # v1 fallbacks
        actor = item.get("group") or item.get("group_name") or None
    # date = incident date; added = date ransomware.live published the entry
    incident_date = IOCNormalizer.parse_date(item.get("date") or item.get("discovered"))
    published = IOCNormalizer.parse_date(item.get("added") or item.get("published") or item.get("date"))
    claim_url = item.get("claim_url") if isinstance(item.get("claim_url"), str) and item.get("claim_url") else None
    page_url = claim_url or item.get("link") or item.get("post_url") or None
    summary = (item.get("summary") or item.get("description") or item.get("title") or "").strip() or None
    claimed_types: list[str] = []
    if item.get("description"):
        claimed_types.append(item["description"])
    if item.get("has_infostealer_info"):
        claimed_types.append("infostealer logs claimed")

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
        "industry": item.get("activity") or item.get("sector") or None,
        "country": item.get("country") or None,
        "reported_date": incident_date,
        "published_at": published,
        "threat_actor_name": actor,
        "claimed_data_types": claimed_types,
        "summary": summary,
        "source_slug": "ransomware-live",
        "source_url": page_url or "https://www.ransomware.live/",
        "evidence_references": (
            [{"source_slug": "ransomware-live", "url": page_url}] if page_url else []
        ),
        "verification_status": classify_breach(has_actor_claim=bool(actor), has_org_disclosure=False, has_credible_media=False),
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
        data = resp.json()
        # The API returns a JSON error body (e.g. {"message": "1 per 1 minute"})
        # with a non-200-shape payload when throttled — fail loudly, store nothing.
        if not isinstance(data, list):
            raise RuntimeError(f"ransomware.live API error: {data}")
        for item in data:
            if not isinstance(item, dict):
                continue
            parsed = parse_ransomwarelive_record(item)
            if parsed is None:
                continue
            yield CollectedRecord(
                kind="breach", data=parsed, external_id=parsed["_external_id"], published_at=parsed.get("published_at")
            )
