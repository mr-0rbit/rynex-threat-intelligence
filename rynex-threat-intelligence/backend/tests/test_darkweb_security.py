"""Dark web module tests + security-focused regression tests (secure SDLC gates)."""

import pytest

from app.collectors.connectors.darkweb_groups import parse_group_record
from app.services.ioc_normalizer import IOCNormalizer


class TestDarkWebParsing:
    def test_group_profile(self):
        item = {"name": "LockBit3", "description": "Ransomware group", "url": "http://example.onion", "first_seen": "2023-01-01"}
        parsed = parse_group_record(item)
        assert parsed is not None
        assert parsed["name"] == "LockBit3"
        assert parsed["attribution_status"] == "claimed"
        assert parsed["source_slug"] == "ransomware-live"

    def test_empty_rejected(self):
        assert parse_group_record({"name": ""}) is None
        assert parse_group_record({}) is None


class TestDarkWebAPI:
    @pytest.mark.asyncio
    async def test_requires_auth(self, client):
        resp = await client.get("/api/v1/darkweb/overview")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_overview_shape(self, client, auth_headers):
        resp = await client.get("/api/v1/darkweb/overview", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "policy_notice" in body
        assert "monitored_groups" in body
        assert "claims_by_actor" in body
        assert "recent_claims" in body


class TestSecurityControls:
    """Secure SDLC: regression gates for injection, tampering, and sanitization."""

    @pytest.mark.asyncio
    async def test_sql_injection_in_search_param(self, client, auth_headers):
        # Parameterized queries must not error or leak rows
        resp = await client.get("/api/v1/search?q=%27%20OR%201%3D1%20--", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["query"] == "' OR 1=1 --"

    @pytest.mark.asyncio
    async def test_jwt_tampering_rejected(self, client):
        resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.tampered.payload"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_news_summary_html_stripped(self):
        from app.collectors.connectors.news_rss import parse_feed_entry

        entry = {
            "link": "https://example.com/article",
            "title": "Test",
            "summary": "<script>alert('xss')</script>Harmless text <b>bold</b>",
        }
        parsed = parse_feed_entry("test", "test", entry)
        assert parsed is not None
        assert "<script>" not in parsed["summary"]
        assert "<b>" not in parsed["summary"]
        # Residual text content is inert: stored as plain text and escaped by React at render
        assert "Harmless text" in parsed["summary"]

    @pytest.mark.asyncio
    async def test_report_type_whitelisted(self, client, auth_headers):
        resp = await client.get("/api/v1/reports/users?format=json", headers=auth_headers)
        assert resp.status_code == 404

    def test_no_secrets_in_source_settings(self):
        from app.core.config import settings

        assert settings.JWT_SECRET_KEY != ""  # configured, not blank
        # API key values are read at runtime via env names only
        from app.collectors.registry import COLLECTOR_CLASSES

        for cls in COLLECTOR_CLASSES:
            if cls.api_key_setting:
                assert cls.api_key_setting.isupper(), f"{cls.slug}: env var name, never a value"
