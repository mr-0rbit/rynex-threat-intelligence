"""API integration tests: health, auth flow, RBAC, and alert listing."""

import pytest


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
