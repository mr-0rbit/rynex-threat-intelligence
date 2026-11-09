"""Transparent, deterministic confidence scoring.

Platform confidence (0..1) is computed from explicit, auditable factors:
source credibility, corroboration across independent sources, primary vs
secondary reporting, freshness, and internal consistency. Every score ships
with human-readable reasons. No opaque AI percentage.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.services.ioc_normalizer import IOCNormalizer


@dataclass
class ConfidenceBreakdown:
    score: float
    reasons: list[str] = field(default_factory=list)

    def add(self, points: float, reason: str) -> None:
        self.score += points
        self.reasons.append(reason)

    def clamp(self) -> "ConfidenceBreakdown":
        self.score = round(max(0.0, min(1.0, self.score)), 3)
        return self


def score_ioc(
    *,
    source_credibility: float,
    corroborating_sources: int = 1,
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
    is_allowlisted: bool = False,
) -> ConfidenceBreakdown:
    cb = ConfidenceBreakdown(score=0.0)
    cb.add(0.5 * source_credibility, f"source credibility {source_credibility:.2f}")

    if corroborating_sources >= 3:
        cb.add(0.15, f"corroborated by {corroborating_sources} independent sources")
    elif corroborating_sources == 2:
        cb.add(0.08, "corroborated by 2 independent sources")
    elif corroborating_sources == 1:
        cb.add(0.0, "single source, uncorroborated")

    if is_allowlisted:
        cb.score *= 0.2
        cb.reasons.append("indicator matched benign-infrastructure allowlist; score heavily reduced")

    now = datetime.now(UTC)
    reference = last_seen or first_seen
    if reference:
        age_days = max(0.0, (now - reference.replace(tzinfo=UTC if reference.tzinfo is None else reference.tzinfo)).days)
        if age_days <= 7:
            cb.add(0.1, "fresh indicator (seen within 7 days)")
        elif age_days > 90:
            cb.score *= 0.8
            cb.reasons.append(f"stale indicator (last seen {int(age_days)} days ago); score reduced")
    else:
        cb.reasons.append("no first/last-seen timestamp available; freshness not credited")

    return cb.clamp()


def score_breach(
    *,
    verification_status: str,
    source_credibility: float,
    corroborating_sources: int = 1,
    has_primary_disclosure: bool = False,
    record_count_sourced: bool = False,
) -> ConfidenceBreakdown:
    """Breach confidence. A threat-actor claim alone never reaches 'confirmed' levels."""
    cb = ConfidenceBreakdown(score=0.0)

    if has_primary_disclosure:
        cb.add(0.35, "primary disclosure by affected organization")
    if verification_status == "confirmed":
        cb.add(0.3, "verified by reliable primary disclosure or strong corroboration")
    elif verification_status == "reported":
        cb.add(0.15, "reported by credible secondary source, not independently confirmed")
    elif verification_status == "claimed":
        cb.add(0.0, "threat-actor claim only; treated as unverified")

    cb.add(0.35 * source_credibility, f"source credibility {source_credibility:.2f}")

    if corroborating_sources >= 2:
        cb.add(min(0.2, 0.1 * corroborating_sources), f"{corroborating_sources} independent corroborating reports")
    if record_count_sourced:
        cb.add(0.05, "record count from a reliably sourced statement")

    return cb.clamp()


def classify_breach(
    *,
    has_actor_claim: bool,
    has_org_disclosure: bool,
    has_credible_media: bool,
    has_dispute: bool = False,
) -> str:
    """Deterministic verification classification per platform policy."""
    if has_dispute:
        return "disputed"
    if has_org_disclosure:
        return "confirmed"
    if has_credible_media:
        return "reported"
    if has_actor_claim:
        return "claimed"
    return "unverified"


def stable_fingerprint_ioc(value: str, ioc_type: str) -> str:
    return IOCNormalizer.fingerprint(ioc_type, value)
