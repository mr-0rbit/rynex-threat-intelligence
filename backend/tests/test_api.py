"""API integration tests: health, auth flow, RBAC, and alert listing."""

import uuid
from datetime import UTC, datetime

import pytest


@pytest.mark.asyncio
async def _seed_breach() -> uuid.UUID:
    from app.core.database import AsyncSessionLocal
    from app.models import BreachIncident

    async with AsyncSessionLocal() as db:
        breach = BreachIncident(
            fingerprint="fp-breach-detail-test",
            organization_name="Detail Test Corp",
            organization_domain="detailtest.example.com",
            industry="Manufacturing",
            country="US",
            threat_actor_name="LockBit",
            claimed_data_types=["financial data", "employee records"],
            published_at=datetime.now(UTC),
            verification_status="claimed",
            confidence=0.42,
            confidence_reasons={"reasons": ["actor claim only"]},
            summary="Seeded for detail-endpoint test",
            source_slug="ransomware-live",
            source_url="https://example.test/victim",
        )
        db.add(breach)
        await db.commit()
        return breach.id


@pytest.mark.asyncio
async def test_breach_detail_returns_seeded_record(client, auth_headers):
    breach_id = await _seed_breach()
    try:
        resp = await client.get(f"/api/v1/breaches/{breach_id}", headers=auth_headers)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["id"] == str(breach_id)
        assert body["organization_name"] == "Detail Test Corp"
        assert body["verification_status"] == "claimed"
        assert body["threat_actor_name"] == "LockBit"
        assert "financial data" in body["claimed_data_types"]
    finally:
        from app.core.database import AsyncSessionLocal
        from app.models import BreachIncident

        async with AsyncSessionLocal() as db:
            obj = await db.get(BreachIncident, breach_id)
            if obj:
                await db.delete(obj)
                await db.commit()


@pytest.mark.asyncio
async def test_breach_detail_404_for_unknown(client, auth_headers):
    resp = await client.get(
        f"/api/v1/breaches/{uuid.uuid4()}", headers=auth_headers
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_breach_detail_requires_auth(client):
    resp = await client.get(f"/api/v1/breaches/{uuid.uuid4()}")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def _seed_alert() -> uuid.UUID:
    from app.core.database import AsyncSessionLocal
    from app.models import Alert
    from app.models.organization import DEFAULT_ORGANIZATION_ID

    async with AsyncSessionLocal() as db:
        alert = Alert(
            organization_id=DEFAULT_ORGANIZATION_ID,
            fingerprint="fp-pdf-test",
            title="PDF report test alert",
            description="Seeded to exercise the PDF export path",
            category="critical_vulnerability",
            severity="high",
            confidence=0.9,
            evidence_sources=[{"source_slug": "cisa-kev", "url": "https://example.test/kev"}],
            detected_at=datetime.now(UTC),
            status="new",
            recommended_action="Review affected product usage.",
        )
        db.add(alert)
        await db.commit()
        return alert.id


@pytest.mark.asyncio
async def test_alert_report_pdf(client, auth_headers):
    pytest.importorskip("reportlab")
    alert_id = await _seed_alert()
    try:
        resp = await client.get(f"/api/v1/alerts/{alert_id}/report.pdf", headers=auth_headers)
        assert resp.status_code == 200, resp.text
        assert resp.headers["content-type"].startswith("application/pdf")
        assert resp.headers["content-disposition"].startswith("attachment")
        assert resp.content[:5] == b"%PDF-"
    finally:
        from app.core.database import AsyncSessionLocal
        from app.models import Alert

        async with AsyncSessionLocal() as db:
            obj = await db.get(Alert, alert_id)
            if obj:
                await db.delete(obj)
                await db.commit()


@pytest.mark.asyncio
async def test_alert_report_pdf_404(client, auth_headers):
    pytest.importorskip("reportlab")
    resp = await client.get(f"/api/v1/alerts/{uuid.uuid4()}/report.pdf", headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_alert_report_pdf_requires_auth(client):
    resp = await client.get(f"/api/v1/alerts/{uuid.uuid4()}/report.pdf")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_malformed_token_sub_rejected(client):
    # A syntactically valid JWT with a non-UUID sub must be 401, not a 500
    import jwt as pyjwt

    from app.core.config import settings

    token = pyjwt.encode({"sub": "not-a-uuid", "type": "access"}, settings.JWT_SECRET_KEY, algorithm="HS256")
    resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/api/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "rtip-backend"


@pytest.mark.asyncio
async def test_login_success_and_me(client, auth_headers):
    resp = await client.get("/api/v1/auth/me", headers=auth_headers)
    assert resp.status_code == 200
    me = resp.json()
    assert me["email"] == "admin@test.local"
    assert me["role"] == "admin"


@pytest.mark.asyncio
async def test_login_bad_credentials(client):
    resp = await client.post(
        "/api/v1/auth/login", json={"email": "admin@test.local", "password": "wrong"}
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_unauthenticated_access_denied(client):
    for path in ["/api/v1/alerts", "/api/v1/iocs", "/api/v1/sources", "/api/v1/news"]:
        resp = await client.get(path)
        assert resp.status_code == 401, path


@pytest.mark.asyncio
async def test_invalid_token_rejected(client):
    resp = await client.get("/api/v1/auth/me", headers={"Authorization": "Bearer garbage"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_admin_can_create_user(client, auth_headers):
    resp = await client.post(
        "/api/v1/auth/users",
        params={"email": "analyst@test.local", "password": "AnalystPass!123", "role": "analyst"},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    # New user can log in
    login = await client.post(
        "/api/v1/auth/login", json={"email": "analyst@test.local", "password": "AnalystPass!123"}
    )
    assert login.status_code == 200
    assert login.json()["role"] == "analyst"


@pytest.mark.asyncio
async def test_viewer_cannot_trigger_collection(client, auth_headers):
    # create a viewer
    await client.post(
        "/api/v1/auth/users",
        params={"email": "viewer@test.local", "password": "ViewerPass!123", "role": "viewer"},
        headers=auth_headers,
    )
    login = await client.post(
        "/api/v1/auth/login", json={"email": "viewer@test.local", "password": "ViewerPass!123"}
    )
    viewer_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    resp = await client.post("/api/v1/sources/cisa-kev/collect", headers=viewer_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_empty_intelligence_lists(client, auth_headers):
    for path in ["/api/v1/alerts", "/api/v1/iocs", "/api/v1/vulnerabilities", "/api/v1/breaches", "/api/v1/news", "/api/v1/sources"]:
        resp = await client.get(path, headers=auth_headers)
        assert resp.status_code == 200, path
        assert resp.json()["total"] == 0, path


@pytest.mark.asyncio
async def test_alert_status_update_requires_analyst(client, auth_headers):
    resp = await client.post(
        "/api/v1/alerts/00000000-0000-0000-0000-000000000000/status",
        json={"status": "acknowledged"},
        headers=auth_headers,
    )
    assert resp.status_code == 404  # admin passes RBAC, alert doesn't exist
