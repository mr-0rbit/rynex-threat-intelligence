"""Confidence engine and breach classification tests."""

from app.services.confidence import classify_breach, score_breach, score_ioc


class TestBreachClassification:
    def test_actor_claim_is_never_confirmed(self):
        assert classify_breach(has_actor_claim=True, has_org_disclosure=False, has_credible_media=False) == "claimed"

    def test_org_disclosure_is_confirmed(self):
        assert classify_breach(has_actor_claim=True, has_org_disclosure=True, has_credible_media=False) == "confirmed"

    def test_credible_media_is_reported(self):
        assert classify_breach(has_actor_claim=False, has_org_disclosure=False, has_credible_media=True) == "reported"

    def test_dispute_wins(self):
        assert classify_breach(has_actor_claim=True, has_org_disclosure=True, has_credible_media=True, has_dispute=True) == "disputed"


class TestScoring:
    def test_score_range_and_reasons(self):
        cb = score_ioc(source_credibility=0.9, corroborating_sources=2)
        assert 0 <= cb.score <= 1
        assert len(cb.reasons) >= 2
        assert all(isinstance(r, str) for r in cb.reasons)

    def test_single_source_no_corroboration_bonus(self):
        cb = score_ioc(source_credibility=0.5, corroborating_sources=1)
        assert any("single source" in r for r in cb.reasons)

    def test_allowlist_reduces_score(self):
        normal = score_ioc(source_credibility=0.9, corroborating_sources=1)
        reduced = score_ioc(source_credibility=0.9, corroborating_sources=1, is_allowlisted=True)
        assert reduced.score < normal.score

    def test_actor_claim_alone_scores_low(self):
        cb = score_breach(
            verification_status="claimed", source_credibility=0.7, corroborating_sources=1
        )
        assert cb.score <= 0.6
        assert any("unverified" in r for r in cb.reasons)

    def test_primary_disclosure_scores_high(self):
        cb = score_breach(
            verification_status="confirmed",
            source_credibility=1.0,
            has_primary_disclosure=True,
            corroborating_sources=2,
        )
        assert cb.score >= 0.8
