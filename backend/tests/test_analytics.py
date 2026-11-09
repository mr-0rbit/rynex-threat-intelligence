"""Tests for analytics: charts, global search, reports."""

import pytest


@pytest.mark.asyncio
async def test_charts_endpoint(client, auth_headers):
    resp = await client.get("/api/v1/dashboard/charts", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    for key in [
        "alerts_over_time", "alert_severity", "ioc_types", "source_contribution",
        "news_by_publisher", "breaches_by_verification", "cve_severity", "news_over_time",
    ]:
        assert key in body


@pytest.mark.asyncio
async def test_search_requires_auth(client):
    resp = await client.get("/api/v1/search?q=test")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_search_short_query_rejected(client, auth_headers):
    resp = await client.get("/api/v1/search?q=a", headers=auth_headers)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_report_json(client, auth_headers):
    resp = await client.get("/api/v1/reports/breaches?format=json", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["report"] == "breach_intelligence"
    assert "columns" in body and "rows" in body


@pytest.mark.asyncio
async def test_report_csv(client, auth_headers):
    resp = await client.get("/api/v1/reports/vulnerabilities?format=csv", headers=auth_headers)
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    first_line = resp.text.splitlines()[0]
    assert "cve_id" in first_line


@pytest.mark.asyncio
async def test_report_markdown(client, auth_headers):
    resp = await client.get("/api/v1/reports/iocs?format=md", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.text.startswith("# RTIP")


@pytest.mark.asyncio
async def test_report_invalid_type(client, auth_headers):
    resp = await client.get("/api/v1/reports/nonsense", headers=auth_headers)
    assert resp.status_code == 404
