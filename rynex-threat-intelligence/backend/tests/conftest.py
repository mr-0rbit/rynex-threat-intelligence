"""Test fixtures. Runs against a throwaway SQLite database, never real intelligence."""

import os
import pathlib
import sys

import pytest

# Configure environment BEFORE importing the application
TEST_DB = pathlib.Path("/tmp/opencode/rtip_test.db")
if TEST_DB.exists():
    TEST_DB.unlink()
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{TEST_DB}"
os.environ["DEBUG"] = "false"
os.environ["ENVIRONMENT"] = "development"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-not-for-production"
os.environ["ADMIN_EMAIL"] = "admin@test.local"
os.environ["ADMIN_PASSWORD"] = "TestAdminPass!123"

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))


class _LifespanClient:
    def __init__(self, app):
        self._ctx = app.router.lifespan_context(app)
        self._app = app
        self._ac = None

    async def __aenter__(self):
        await self._ctx.__aenter__()
        from httpx import ASGITransport, AsyncClient

        self._ac = AsyncClient(transport=ASGITransport(app=self._app), base_url="http://test")
        return self._ac

    async def __aexit__(self, *args):
        await self._ac.aclose()
        await self._ctx.__aexit__(*args)


@pytest.fixture
async def client():
    from app.main import app

    async with _LifespanClient(app) as ac:
        yield ac


@pytest.fixture
async def auth_headers(client):
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@test.local", "password": "TestAdminPass!123"},
    )
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
