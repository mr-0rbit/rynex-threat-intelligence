"""abuse.ch ThreatFox — IOC sharing platform (malicious IPs, domains, URLs, hashes).

Source: https://threatfox.abuse.ch/api/
Access: free community API under abuse.ch Fair Use Principles, but an Auth-Key
(obtained free at https://auth.abuse.ch/) is REQUIRED. Commercial use may
require the paid commercial API — see terms_notes. The connector degrades
gracefully (source marked misconfigured) when no key is present.
"""

import os
from collections.abc import AsyncIterator

from app.collectors.base import BaseCollector, CollectedRecord
from app.services.ioc_normalizer import IOCNormalizer

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"

SUPPORTED_TYPES = {
    "ip:port": "ipv4",
    "ip": "ipv4",
    "domain": "domain",
    "url": "url",
    "md5_hash": "md5",
    "sha256_hash": "sha256",
}


def parse_threatfox_record(item: dict) -> dict | None:
    """Pure parser for one ThreatFox data record (API v1 schema)."""
    indicator = IOCNormalizer.refang(item.get("ioc") or "")
    ioc_type_raw = item.get("ioc_type") or ""
    mapped = SUPPORTED_TYPES.get(ioc_type_raw)
    if mapped is None:
        return None
    if ioc_type_raw == "ip:port":
        indicator = indicator.split(":")[0]
    normalized = IOCNormalizer.normalize(indicator, mapped)
    if normalized is None:
        return None
    value, vtype = normalized
    host = value.split("/")[2] if vtype == "url" else value
    if vtype in ("domain", "url") and IOCNormalizer.is_benign_domain(host):
        return None
    malware = item.get("malware_printable") or item.get("malware") or None
    confidence_pct = item.get("confidence_level")
    try:
        conf = float(confidence_pct) / 100 if confidence_pct is not None else 0.5
    except (TypeError, ValueError):
        conf = 0.5
    ts = IOCNormalizer.parse_date(item.get("last_seen") or item.get("first_seen"))
    return {
        "value": value,
        "type": vtype,
        "source_slug": "threatfox",
        "source_url": f"https://threatfox.abuse.ch/ioc/{item.get('id')}/" if item.get("id") else "https://threatfox.abuse.ch/browse/",
        "malware_family": malware,
        "tags": ["threatfox", *(item.get("tags") or [])],
        "confidence": conf,
        "source_reputation": f"threatfox confidence {confidence_pct}" if confidence_pct else None,
        "last_seen_at": ts,
        "first_seen_at": IOCNormalizer.parse_date(item.get("first_seen")),
        "description": item.get("threat_type_desc") or None,
        "external_id": str(item.get("id")) if item.get("id") else None,
    }


class ThreatFoxCollector(BaseCollector):
    slug = "threatfox"
    name = "abuse.ch ThreatFox"
    category = "ioc"
    homepage_url = "https://threatfox.abuse.ch/"
    description = "Platform for sharing IOCs of malware-associated infrastructure, run by abuse.ch."
    auth_method = "api_key_header"
    api_key_setting = "THREATFOX_AUTH_KEY"
    commercial_use_status = "fair_use"
    terms_notes = (
        "Free community API under abuse.ch Fair Use Principles; Auth-Key (free) REQUIRED. "
        "Commercial/for-profit use may require the paid commercial API — verify terms before "
        "commercial redistribution. IOCs expire after 6 months at source."
    )
    rate_limit_notes = "Fair use principles apply; do not poll more than once per hour."
    collection_interval_minutes = 60
    source_credibility = 0.85

    def __init__(self, api_key: str | None = None):
        super().__init__(api_key=api_key or os.getenv("THREATFOX_AUTH_KEY"))

    async def fetch_batch(self, checkpoint: str | None = None) -> AsyncIterator[CollectedRecord]:
        if not self.api_key:
            raise RuntimeError(
                "ThreatFox requires a free Auth-Key (https://auth.abuse.ch/) — set THREATFOX_AUTH_KEY"
            )
        headers = {"Auth-Key": self.api_key}
        body = {"query": "get_iocs", "days": "1"}
        resp = await self.http.fetch(
            THREATFOX_API_URL, method="POST", headers=headers, json_body=body, rate_limit_interval=2.0
        )
        payload = resp.json()
        if payload.get("query_status") != "ok":
            return
        for item in payload.get("data") or []:
            if not isinstance(item, dict):
                continue
            parsed = parse_threatfox_record(item)
            if parsed is None:
                continue
            ext = parsed.pop("external_id", None)
            yield CollectedRecord(
                kind="ioc", data=parsed, external_id=ext, published_at=parsed.get("last_seen_at")
            )
