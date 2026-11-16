"""Test fixtures. Runs against a throwaway SQLite database, never real intelligence."""

import asyncio
import inspect
import os
import pathlib
import sys
import tempfile

import pytest

# Configure environment BEFORE importing the application
TEST_DIR = pathlib.Path(tempfile.gettempdir()) / "rtip_test_data"
TEST_DIR.mkdir(parents=True, exist_ok=True)
TEST_DB = TEST_DIR / "rtip_test.db"
if TEST_DB.exists():
    TEST_DB.unlink()
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{TEST_DB}"
os.environ["DEBUG"] = "false"
os.environ["ENVIRONMENT"] = "development"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-not-for-production"
os.environ["ADMIN_EMAIL"] = "admin@test.local"
os.environ["ADMIN_PASSWORD"] = "TestAdminPass!123"
# Rate limiting is process-level state; tests would bleed 429s into each other
os.environ["RATE_LIMIT_ENABLED"] = "false"

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))


# Support running async tests when pytest-asyncio plugin is not installed system-wide
def pytest_pyfunc_call(pyfuncitem):
    if inspect.iscoroutinefunction(pyfuncitem.obj):
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            sig = inspect.signature(pyfuncitem.obj)
            call_args = {k: v for k, v in pyfuncitem.funcargs.items() if k in sig.parameters}
            loop.run_until_complete(pyfuncitem.obj(**call_args))
        finally:
            loop.close()
        return True


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
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def client():
    from app.main import app

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        ctx = _LifespanClient(app)
        ac = loop.run_until_complete(ctx.__aenter__())
        yield ac
        loop.run_until_complete(ctx.__aexit__(None, None, None))
    finally:
        loop.close()


@pytest.fixture
def auth_headers(client):
    loop = asyncio.get_event_loop() if asyncio.get_event_loop().is_running() else asyncio.new_event_loop()
    resp = loop.run_until_complete(
        client.post(
            "/api/v1/auth/login",
            json={"email": "admin@test.local", "password": "TestAdminPass!123"},
        )
    )
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
