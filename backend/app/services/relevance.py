"""Relevance engine: match intelligence against the organization's assets and
analyst watchlists. Pure matching functions (unit-testable); DB loading happens
in the ingestion service.

This is what turns a public intel firehose into actionable alerts: a KEV entry
for a product you run, or a breach claim naming your domain, escalates in
severity and names the affected asset in the alert payload.
"""

import ipaddress
import re
from typing import Any

_WORD = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> set[str]:
    return set(_WORD.findall(text.lower()))


def domain_matches(asset_value: str, candidate: str | None) -> bool:
    """Exact or subdomain match: assets 'example.com' matches 'www.example.com'."""
    if not candidate:
        return False
    a = asset_value.lower().removeprefix("*.").rstrip(".")
    c = candidate.lower().removeprefix("*.").rstrip(".")
    return c == a or c.endswith("." + a)


def ip_matches(asset_value: str, candidate: str | None) -> bool:
    """Exact IP match, or membership when the asset is a CIDR range."""
    if not candidate:
        return False
    if "/" in asset_value:
        try:
            return ipaddress.ip_address(candidate) in ipaddress.ip_network(asset_value, strict=False)
        except ValueError:
            return False
    return asset_value == candidate


def product_matches(asset_value: str, text: str | None) -> bool:
    """Asset product/vendor tokens appear in vulnerability title/products text."""
    if not text:
        return False
    asset_tokens = _tokens(asset_value)
    if not asset_tokens:
        return False
    haystack = _tokens(text)
    return asset_tokens.issubset(haystack)


def keyword_matches(asset_value: str, *texts: str | None) -> bool:
    joined = " ".join(t for t in texts if t).lower()
    return asset_value.lower() in joined


def match_assets(
    assets: list[Any],
    *,
    domains: list[str] | None = None,
    ips: list[str] | None = None,
    org_name: str | None = None,
    product_text: str | None = None,
) -> list[dict]:
    """Return matched assets as dicts {id, value, type, criticality, display_name}."""
    hits: list[dict] = []
    for asset in assets:
        if not getattr(asset, "enabled", True):
            continue
        value = getattr(asset, "value", "")
        atype = getattr(asset, "type", "")
        matched = False
        if atype in ("domain",):
            matched = any(domain_matches(value, d) for d in (domains or []))
            if not matched and org_name:
                matched = domain_matches(value, org_name)
        elif atype in ("ipv4", "ipv6"):
            matched = any(ip_matches(value, ip) for ip in (ips or []))
        elif atype == "cidr":
            matched = any(ip_matches(value, ip) for ip in (ips or []))
        elif atype in ("product", "vendor"):
            matched = product_matches(value, product_text) or product_matches(value, org_name)
        elif atype == "keyword":
            matched = keyword_matches(value, org_name, product_text)
        if matched:
            hits.append(
                {
                    "id": str(getattr(asset, "id", "")),
                    "organization_id": str(getattr(asset, "organization_id", "")),
                    "value": value,
                    "type": atype,
                    "criticality": getattr(asset, "criticality", "medium"),
                    "display_name": getattr(asset, "display_name", None) or value,
                }
            )
    return hits


def severity_for_asset_match(current: str, matches: list[dict]) -> str:
    """Escalate severity when the intel touches owned assets (highest wins)."""
    order = ["informational", "low", "medium", "high", "critical"]
    cur = order.index(current) if current in order else 0
    if not matches:
        return current
    worst = max((m.get("criticality") or "medium") for m in matches)
    floor = "critical" if worst == "critical" else "high"
    return floor if order.index(floor) > cur else current


def match_watchlists(
    items: list[Any],
    *,
    org_name: str | None = None,
    domain: str | None = None,
    actor: str | None = None,
    cves: list[str] | None = None,
    text: str | None = None,
) -> list[dict]:
    """Match breach/IOC/news content against enabled watchlist items.

    item_type: organization|domain|actor|cve|keyword.
    """
    hits: list[dict] = []
    for item in items:
        if not getattr(item, "value", None):
            continue
        itype = getattr(item, "item_type", "keyword")
        value = str(item["value"] if isinstance(item, dict) else item.value)
        enabled = getattr(item, "enabled", True) if not isinstance(item, dict) else item.get("enabled", True)
        if not enabled:
            continue
        v = value.lower()
        hit = False
        if itype == "organization" and org_name:
            hit = v == org_name.lower()
        elif itype == "domain":
            hit = domain_matches(v, domain)
        elif itype == "actor" and actor:
            hit = v == actor.lower()
        elif itype == "cve":
            hit = any(c.upper() == value.upper() for c in (cves or []))
        elif itype == "keyword":
            hit = keyword_matches(v, org_name, actor, text)
        if hit:
            hits.append(
                {
                    "watchlist_id": str(getattr(item, "watchlist_id", "") or ""),
                    "organization_id": str(getattr(item, "organization_id", "") or ""),
                    "item_type": itype,
                    "value": value,
                }
            )
    return hits
