"""Enterprise feature tests: security hardening, MFA, API keys, asset matching,
watchlist correlation, corroboration, new APIs, exports, ops endpoints."""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import uuid

import pyotp
import pytest


# ---------- helpers ----------

@dataclass
class _Rec:
    kind: str
    data: dict


@dataclass
class _Result:
    records: list = field(default_factory=list)
    source_slug: str = "test-source"


async def _cleanup(db, models_and_filters):
    for model, flt in models_and_filters:
        rows = (await db.execute(
            __import__("sqlalchemy").select(model).where(flt)
        )).scalars().all()
        for row in rows:
            await db.delete(row)
        await db.commit()


def _ingestion(db, alerting=True):
    from app.services.ingestion import IngestionService

    return IngestionService(db, alerting=alerting)


# ---------- password policy ----------

@pytest.mark.asyncio
async def test_password_policy_rejects_weak(client, auth_headers):
    for weak in ("short1A", "alllowercase12345", "ALLUPPERCASE12345", "NoDigitsHereAtAll"):
        resp = await client.post(
            "/api/v1/auth/users?email=policycheck@test.local&password=" + weak.replace(" ", "%20"),
            headers=auth_headers,
        )
        assert resp.status_code == 422, f"{weak} should be rejected: {resp.text}"


@pytest.mark.asyncio
async def test_password_policy_allows_strong_and_creates_user(client, auth_headers):
    resp = await client.post(
        "/api/v1/auth/users?email=policy-ok@test.local&password=StrongPassw0rd!2025&role=viewer",
        headers=auth_headers,
    )
    assert resp.status_code == 201, resp.text
    # cleanup
    from sqlalchemy import delete

    from app.core.database import AsyncSessionLocal
    from app.models import User

    async with AsyncSessionLocal() as db:
        await db.execute(delete(User).where(User.email == "policy-ok@test.local"))
        await db.commit()


@pytest.mark.asyncio
async def test_rate_limiter_unit():
    from fastapi import HTTPException

    from app.core.ratelimit import RateLimiter

    limiter = RateLimiter()
    limiter.enabled = True
    # Unique key per run: a shared Redis instance keeps the window across test
    # runs, which would make a fixed key order-dependent.
    key = f"unit:{uuid.uuid4().hex}"
    await limiter.check(key, max_attempts=2, window_seconds=60)
    await limiter.check(key, max_attempts=2, window_seconds=60)
    with pytest.raises(HTTPException) as exc:
        await limiter.check(key, max_attempts=2, window_seconds=60)
    assert exc.value.status_code == 429


# ---------- MFA flow ----------

@pytest.mark.asyncio
async def test_mfa_enrollment_and_login_flow(client, auth_headers):
    try:
        # setup
        resp = await client.post("/api/v1/auth/mfa/setup", headers=auth_headers)
        assert resp.status_code == 200, resp.text
        secret = resp.json()["secret"]
        assert resp.json()["otpauth_uri"].startswith("otpauth://totp/RTIP")

        # confirm with valid code
        code = pyotp.TOTP(secret).now()
        resp = await client.post("/api/v1/auth/mfa/confirm", headers=auth_headers, json={"code": code})
        assert resp.status_code == 200, resp.text

        # login now requires MFA
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "admin@test.local", "password": "TestAdminPass!123"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body.get("mfa_required") is True
        mfa_token = body["mfa_token"]

        # wrong code rejected
        resp = await client.post(
            "/api/v1/auth/mfa/verify", json={"mfa_token": mfa_token, "code": "000000"}
        )
        assert resp.status_code == 401

        # valid code completes login
        code = pyotp.TOTP(secret).now()
        resp = await client.post(
            "/api/v1/auth/mfa/verify", json={"mfa_token": mfa_token, "code": code}
        )
        assert resp.status_code == 200, resp.text
        assert "access_token" in resp.json()

        # preauth token cannot be used as an access token
        resp = await client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {mfa_token}"}
        )
        assert resp.status_code == 401
    finally:
        # disable MFA so other tests' logins keep working
        resp = await client.post("/api/v1/auth/mfa/setup", headers=auth_headers)
        if resp.status_code == 200:
            code = pyotp.TOTP(resp.json()["secret"]).now()
            await client.post("/api/v1/auth/mfa/confirm", headers=auth_headers, json={"code": code})
            await client.post("/api/v1/auth/mfa/disable", headers=auth_headers, json={"code": code})


# ---------- service API keys ----------

@pytest.mark.asyncio
async def test_api_key_auth_and_revocation(client, auth_headers):
    resp = await client.post(
        "/api/v1/admin/api-keys", headers=auth_headers, json={"name": "ci-test-key", "expires_in_days": 30}
    )
    assert resp.status_code == 201, resp.text
    raw_key = resp.json()["api_key"]
    assert raw_key.startswith("rtip_")
    assert "api_key" not in (await client.get("/api/v1/admin/api-keys", headers=auth_headers)).json()[0]

    # key authenticates without a JWT
    resp = await client.get("/api/v1/auth/me", headers={"X-API-Key": raw_key})
    assert resp.status_code == 200, resp.text
    assert resp.json()["email"] == "admin@test.local"

    # viewer cannot create keys
    resp = await client.get("/api/v1/admin/api-keys")
    assert resp.status_code == 401

    # revoke → key stops working
    keys = (await client.get("/api/v1/admin/api-keys", headers=auth_headers)).json()
    key_id = next(k["id"] for k in keys if k["name"] == "ci-test-key")
    resp = await client.delete(f"/api/v1/admin/api-keys/{key_id}", headers=auth_headers)
    assert resp.status_code == 200
    resp = await client.get("/api/v1/auth/me", headers={"X-API-Key": raw_key})
    assert resp.status_code == 401


# ---------- password reset + token revocation ----------

@pytest.mark.asyncio
async def test_password_reset_flow_revokes_old_tokens(client):
    # login
    resp = await client.post(
        "/api/v1/auth/login", json={"email": "admin@test.local", "password": "TestAdminPass!123"}
    )
    old_token = resp.json()["access_token"]
    old_auth = {"Authorization": f"Bearer {old_token}"}

    try:
        # forgot-password: dev-mode inline token (no SMTP configured)
        resp = await client.post("/api/v1/auth/forgot-password", json={"email": "admin@test.local"})
        assert resp.status_code == 202
        reset_token = resp.json().get("reset_token")
        assert reset_token, "dev mode should surface the reset token inline"

        # unknown email gets the same response shape (no enumeration)
        resp = await client.post("/api/v1/auth/forgot-password", json={"email": "nobody@test.local"})
        assert resp.status_code == 202
        assert "reset_token" not in resp.json()

        # weak password rejected
        resp = await client.post(
            "/api/v1/auth/reset-password", json={"token": reset_token, "new_password": "weak"}
        )
        assert resp.status_code == 422

        # strong password accepted
        resp = await client.post(
            "/api/v1/auth/reset-password",
            json={"token": reset_token, "new_password": "ResetPassw0rd!2025"},
        )
        assert resp.status_code == 200, resp.text

        # old access token is now revoked (token_version bumped)
        resp = await client.get("/api/v1/auth/me", headers=old_auth)
        assert resp.status_code == 401, "password reset must invalidate outstanding JWTs"

        # login works with the new password only
        resp = await client.post(
            "/api/v1/auth/login", json={"email": "admin@test.local", "password": "TestAdminPass!123"}
        )
        assert resp.status_code == 401
        resp = await client.post(
            "/api/v1/auth/login", json={"email": "admin@test.local", "password": "ResetPassw0rd!2025"}
        )
        assert resp.status_code == 200
    finally:
        # restore the default admin password for other tests
        resp = await client.post("/api/v1/auth/forgot-password", json={"email": "admin@test.local"})
        tok = resp.json()["reset_token"]
        resp = await client.post(
            "/api/v1/auth/reset-password", json={"token": tok, "new_password": "TestAdminPass!123"}
        )
        assert resp.status_code == 200


# ---------- corroboration re-scoring ----------

@pytest.mark.asyncio
async def test_ioc_corroboration_rescores_confidence(client):
    from sqlalchemy import select

    from app.core.database import AsyncSessionLocal
    from app.models import IOC

    value = "198.51.100.77"
    try:
        async with AsyncSessionLocal() as db:
            svc = _ingestion(db)
            await svc.store_result(
                _Result(records=[_Rec(kind="ioc", data={
                    "value": value, "type": "ipv4", "source_slug": "src-a",
                    "last_seen_at": datetime.now(UTC),
                })])
            )
            await db.commit()

            await svc.store_result(
                _Result(records=[_Rec(kind="ioc", data={
                    "value": value, "type": "ipv4", "source_slug": "src-b",
                    "last_seen_at": datetime.now(UTC),
                })])
            )
            await db.commit()

            ioc = (await db.execute(select(IOC).where(IOC.value == value))).scalar_one()
            assert sorted(ioc.corroborating_sources) == ["src-a", "src-b"]
            assert ioc.confidence_reasons["reasons"], "re-score must attach reasons"
            assert any("corroborat" in r for r in ioc.confidence_reasons["reasons"])
            assert ioc.confidence > 0.5, "corroborated IOC should score above single-source baseline"
            assert ioc.reports_count == 2
    finally:
        async with AsyncSessionLocal() as db:
            from sqlalchemy import delete

            await db.execute(delete(IOC).where(IOC.value == value))
            await db.commit()


# ---------- asset matching ----------

@pytest.mark.asyncio
async def test_asset_match_escalates_severity_and_bumps_counters(client):
    from sqlalchemy import delete, select

    from app.core.database import AsyncSessionLocal
    from app.models import Alert, Asset, IOC
    from app.models.organization import DEFAULT_ORGANIZATION_ID

    domain = "critical-asset-test.example.com"
    try:
        async with AsyncSessionLocal() as db:
            asset = Asset(
                organization_id=DEFAULT_ORGANIZATION_ID,
                type="domain",
                value=domain,
                criticality="critical",
                enabled=True,
            )
            db.add(asset)
            await db.commit()

            svc = _ingestion(db)
            await svc.store_result(
                _Result(records=[_Rec(kind="ioc", data={
                    "value": domain, "type": "domain", "source_slug": "src-a",
                    "last_seen_at": datetime.now(UTC), "confidence": 0.9,
                })])
            )
            await db.commit()

            alert = (
                await db.execute(select(Alert).where(Alert.fingerprint == f"mal:{domain}"))
            ).scalar_one_or_none()
            assert alert is not None, "asset-matched domain must raise an alert"
            assert alert.severity == "critical", "critical asset match escalates medium → critical"
            matched = alert.affected_entities.get("matched_assets") or []
            assert matched and matched[0]["value"] == domain

            await db.refresh(asset)
            assert asset.match_count >= 1
            assert asset.last_matched_at is not None
    finally:
        async with AsyncSessionLocal() as db:
            await db.execute(delete(Alert).where(Alert.fingerprint == f"mal:{domain}"))
            await db.execute(delete(IOC).where(IOC.value == domain))
            await db.execute(delete(Asset).where(Asset.value == domain))
            await db.commit()


# ---------- watchlist correlation ----------

@pytest.mark.asyncio
async def test_watchlist_mention_alert(client):
    from sqlalchemy import delete, select

    from app.core.database import AsyncSessionLocal
    from app.models import Alert, IOC, Watchlist, WatchlistItem
    from app.models.organization import DEFAULT_ORGANIZATION_ID

    org = "Watched Test Org"
    try:
        async with AsyncSessionLocal() as db:
            wl = Watchlist(
                organization_id=DEFAULT_ORGANIZATION_ID,
                name="test-watchlist",
                enabled=True,
            )
            db.add(wl)
            await db.flush()
            item = WatchlistItem(
                organization_id=DEFAULT_ORGANIZATION_ID,
                watchlist_id=wl.id,
                item_type="organization",
                value=org,
            )
            db.add(item)
            await db.commit()

            # a breach naming the watched org
            from app.services.ioc_normalizer import IOCNormalizer

            breach_rec = _Rec(kind="breach", data={
                "fingerprint": IOCNormalizer.fingerprint("breach", f"{org}|ActorX"),
                "organization_name": org,
                "organization_domain": "watchedtest.example.com",
                "threat_actor_name": "ActorX",
                "published_at": datetime.now(UTC),
                "source_slug": "src-a",
                "source_url": "https://example.test/watched-victim",
            })
            await _ingestion(db).store_result(_Result(records=[breach_rec]))
            await db.commit()

            alerts = (
                await db.execute(select(Alert).where(Alert.category == "watchlist_mention"))
            ).scalars().all()
            assert alerts, "watchlist match must raise a watchlist_mention alert"
            match_alert = next(a for a in alerts if a.fingerprint.startswith("watch:"))
            assert org.lower() in match_alert.fingerprint

            # also: an IOC whose domain is on the watchlist
            item2 = WatchlistItem(
                organization_id=DEFAULT_ORGANIZATION_ID,
                watchlist_id=wl.id,
                item_type="domain",
                value="watchedtest.example.com",
            )
            db.add(item2)
            await db.commit()
            await _ingestion(db).store_result(_Result(records=[_Rec(kind="ioc", data={
                "value": "watchedtest.example.com", "type": "domain", "source_slug": "src-a",
                "last_seen_at": datetime.now(UTC),
            })]))
            await db.commit()
            dom_alerts = (
                await db.execute(
                    select(Alert).where(
                        Alert.category == "watchlist_mention",
                        Alert.fingerprint == "watch:watchedtest.example.com",
                    )
                )
            ).scalars().all()
            assert dom_alerts, "domain watchlist item must fire on matching IOC"
    finally:
        async with AsyncSessionLocal() as db:
            await db.execute(delete(Alert).where(Alert.category == "watchlist_mention"))
            await db.execute(delete(Alert).where(Alert.fingerprint.in_([f"breach:{org.lower()}:actorx"])))
            await db.execute(delete(IOC).where(IOC.value == "watchedtest.example.com"))
            await db.execute(delete(WatchlistItem).where(WatchlistItem.value.in_([org, "watchedtest.example.com"])))
            await db.execute(delete(Watchlist).where(Watchlist.name == "test-watchlist"))
            await db.commit()


# ---------- enrichment_only (EPSS semantics) ----------

@pytest.mark.asyncio
async def test_enrichment_only_never_inserts_bare_rows(client):
    from sqlalchemy import select

    from app.core.database import AsyncSessionLocal
    from app.models import Vulnerability

    cve = "CVE-2999-90001"
    try:
        async with AsyncSessionLocal() as db:
            svc = _ingestion(db)
            received = await svc.store_result(_Result(records=[_Rec(kind="vulnerability", data={
                "cve_id": cve, "epss_score": 0.8, "enrichment_only": True, "source_slug": "epss",
            })]))
            await db.commit()
            assert received == 0, "enrichment-only record must not insert"

            count = (await db.execute(
                select(Vulnerability).where(Vulnerability.cve_id == cve)
            )).scalars().all()
            assert count == []

            # real vulnerability + EPSS enrichment updates it
            await svc.store_result(_Result(records=[_Rec(kind="vulnerability", data={
                "cve_id": cve, "title": "Test vuln", "cvss_base_score": 9.8,
                "source_slug": "nvd", "published_at": datetime.now(UTC),
            })]))
            await db.commit()
            await svc.store_result(_Result(records=[_Rec(kind="vulnerability", data={
                "cve_id": cve, "epss_score": 0.9, "enrichment_only": True, "source_slug": "epss",
            })]))
            await db.commit()
            vuln = (await db.execute(select(Vulnerability).where(Vulnerability.cve_id == cve))).scalar_one()
            assert vuln.epss_score == 0.9
    finally:
        async with AsyncSessionLocal() as db:
            from sqlalchemy import delete

            await db.execute(delete(Vulnerability).where(Vulnerability.cve_id == cve))
            await db.commit()


# ---------- new CRUD APIs ----------

@pytest.mark.asyncio
async def test_assets_crud(client, auth_headers):
    # create
    resp = await client.post(
        "/api/v1/assets", headers=auth_headers,
        json={"type": "domain", "value": "crud-asset.example.com", "criticality": "high"},
    )
    assert resp.status_code == 201, resp.text
    asset_id = resp.json()["id"]

    # duplicate rejected
    resp = await client.post(
        "/api/v1/assets", headers=auth_headers,
        json={"type": "domain", "value": "crud-asset.example.com"},
    )
    assert resp.status_code == 409

    # invalid type rejected
    resp = await client.post(
        "/api/v1/assets", headers=auth_headers, json={"type": "bananas", "value": "x"}
    )
    assert resp.status_code == 422

    # list + filter
    resp = await client.get("/api/v1/assets?q=crud-asset", headers=auth_headers)
    assert resp.status_code == 200
    assert any(a["id"] == asset_id for a in resp.json()["items"])

    # patch
    resp = await client.patch(
        f"/api/v1/assets/{asset_id}", headers=auth_headers, json={"criticality": "critical"}
    )
    assert resp.status_code == 200
    assert resp.json()["criticality"] == "critical"

    # delete
    resp = await client.delete(f"/api/v1/assets/{asset_id}", headers=auth_headers)
    assert resp.status_code == 200
    resp = await client.get(f"/api/v1/assets/{asset_id}", headers=auth_headers)
    assert resp.status_code in (404, 405)


@pytest.mark.asyncio
async def test_assets_require_analyst_role(client):
    # create viewer and use its token
    admin_headers = (await client.post(
        "/api/v1/auth/login", json={"email": "admin@test.local", "password": "TestAdminPass!123"}
    )).json()["access_token"]
    resp = await client.post(
        "/api/v1/auth/users?email=v-check@test.local&password=ViewerPassw0rd!2025&role=viewer",
        headers={"Authorization": f"Bearer {admin_headers}"},
    )
    if resp.status_code == 409:
        pass  # already exists from a previous run — but DB is fresh per run
    resp = await client.post(
        "/api/v1/auth/login", json={"email": "v-check@test.local", "password": "ViewerPassw0rd!2025"}
    )
    viewer_token = resp.json()["access_token"]
    resp = await client.post(
        "/api/v1/assets",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"type": "domain", "value": "nope.example.com"},
    )
    assert resp.status_code == 403

    from sqlalchemy import delete

    from app.core.database import AsyncSessionLocal
    from app.models import User

    async with AsyncSessionLocal() as db:
        await db.execute(delete(User).where(User.email == "v-check@test.local"))
        await db.commit()


@pytest.mark.asyncio
async def test_investigations_crud(client, auth_headers):
    resp = await client.post(
        "/api/v1/investigations", headers=auth_headers,
        json={"title": "Test case", "severity": "high", "entity_refs": {"cves": ["CVE-2025-0001"]}},
    )
    assert resp.status_code == 201, resp.text
    inv_id = resp.json()["id"]
    assert resp.json()["status"] == "open"

    resp = await client.patch(
        f"/api/v1/investigations/{inv_id}", headers=auth_headers, json={"status": "in_progress"}
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"

    resp = await client.post(
        f"/api/v1/investigations/{inv_id}/notes", headers=auth_headers,
        json={"note": "Checked with IT; no exposure."},
    )
    assert resp.status_code == 200
    notes = resp.json()["analyst_notes"]
    assert any("Checked with IT" in n["note"] for n in notes)

    resp = await client.get("/api/v1/investigations?status=in_progress", headers=auth_headers)
    assert any(i["id"] == inv_id for i in resp.json()["items"])

    resp = await client.delete(f"/api/v1/investigations/{inv_id}", headers=auth_headers)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_investigation_timeline_generation_persists(client, auth_headers):
    from app.core.database import AsyncSessionLocal
    from app.models import IOC

    entity = "timeline-evidence.example"
    created = await client.post(
        "/api/v1/investigations",
        headers=auth_headers,
        json={"title": "Timeline smoke test", "entity_refs": {"iocs": [entity]}},
    )
    assert created.status_code == 201, created.text
    investigation_id = created.json()["id"]

    async with AsyncSessionLocal() as db:
        db.add(
            IOC(
                value=entity,
                type="domain",
                source_slug="test-fixture",
                confidence=0.9,
            )
        )
        await db.commit()

    generated = await client.post(
        f"/api/v1/investigations/{investigation_id}/timeline",
        headers=auth_headers,
    )
    assert generated.status_code == 200, generated.text
    assert generated.json()["generated"] == 1

    # Re-running generation must not duplicate already-materialized events.
    repeated = await client.post(
        f"/api/v1/investigations/{investigation_id}/timeline",
        headers=auth_headers,
    )
    assert repeated.status_code == 200, repeated.text
    assert repeated.json()["generated"] == 0

    timeline = await client.get(
        f"/api/v1/investigations/{investigation_id}/timeline",
        headers=auth_headers,
    )
    assert timeline.status_code == 200, timeline.text
    assert len(timeline.json()["items"]) == 1
    assert timeline.json()["items"][0]["entity_key"] == entity

    correlations = await client.get(
        "/api/v1/correlations",
        headers=auth_headers,
        params={"entity_type": "iocs", "min_confidence": 0.1},
    )
    assert correlations.status_code == 200, correlations.text
    body = correlations.json()
    assert body["total"] >= 1
    matching = [item for item in body["items"] if item["entity_key"] == entity]
    assert matching and matching[0]["source_count"] == 1
    assert matching[0]["first_seen_at"] is not None


@pytest.mark.asyncio
async def test_service_api_key_authenticates_as_bearer(client, auth_headers):
    created = await client.post(
        "/api/v1/admin/api-keys",
        headers=auth_headers,
        json={"name": "prometheus-test-key"},
    )
    assert created.status_code == 201, created.text
    api_key = created.json()["api_key"]

    response = await client.get(
        "/api/v1/metrics",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert response.status_code == 200, response.text
    assert "rtip_records_total" in response.text
    assert "rtip_last_collection_timestamp_seconds" in response.text


@pytest.mark.asyncio
async def test_watchlist_api_crud(client, auth_headers):
    resp = await client.post(
        "/api/v1/watchlists", headers=auth_headers, json={"name": "api-test-watchlist"}
    )
    assert resp.status_code == 201, resp.text
    wl_id = resp.json()["id"]

    resp = await client.post(
        f"/api/v1/watchlists/{wl_id}/items", headers=auth_headers,
        json={"item_type": "domain", "value": "api-watch.example.com"},
    )
    assert resp.status_code == 201, resp.text
    item_id = resp.json()["id"]

    resp = await client.get(f"/api/v1/watchlists/{wl_id}/items", headers=auth_headers)
    assert resp.status_code == 200 and len(resp.json()) == 1

    resp = await client.delete(f"/api/v1/watchlists/{wl_id}/items/{item_id}", headers=auth_headers)
    assert resp.status_code == 200
    resp = await client.delete(f"/api/v1/watchlists/{wl_id}", headers=auth_headers)
    assert resp.status_code == 200


# ---------- exports & ops ----------

@pytest.mark.asyncio
async def test_stix_export_shape(client, auth_headers):
    resp = await client.get("/api/v1/export/stix?limit=50", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    bundle = resp.json()
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    for obj in bundle["objects"]:
        assert obj["spec_version"] == "2.1"
        assert "--" in obj["id"]
    types = {o["type"] for o in bundle["objects"]}
    assert types <= {"indicator", "vulnerability", "x-rtip-breach", "threat-actor"}
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    for ind in indicators:
        assert ind["pattern"].startswith("[")
        assert ind["pattern_type"] == "stix"


@pytest.mark.asyncio
async def test_executive_report(client, auth_headers):
    resp = await client.get("/api/v1/executive-report", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    text = resp.text
    assert "Posture snapshot" in text
    assert "Active alerts by severity" in text
    assert "Deterministic aggregation" in text


@pytest.mark.asyncio
async def test_metrics_endpoint(client, auth_headers):
    resp = await client.get("/api/v1/metrics", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    body = resp.text
    assert "rtip_records_total" in body
    assert "rtip_alerts_by_severity" in body
    assert "rtip_source_health" in body
    resp = await client.get("/api/v1/metrics")
    assert resp.status_code == 401, "metrics must require auth"


@pytest.mark.asyncio
async def test_retention_cleanup_task(client):
    from app.core.database import AsyncSessionLocal
    from app.models import CollectionJob
    from app.workers.tasks import _retention_purge

    old_job_id = None
    async with AsyncSessionLocal() as db:
        job = CollectionJob(
            source_slug="retention-test", status="success", trigger="scheduled",
            started_at=datetime.now(UTC) - timedelta(days=400),
            finished_at=datetime.now(UTC) - timedelta(days=400),
        )
        db.add(job)
        await db.commit()
        old_job_id = job.id

    result = await _retention_purge()
    assert result["collection_jobs_deleted"] >= 1

    async with AsyncSessionLocal() as db:
        gone = await db.get(CollectionJob, old_job_id)
        assert gone is None


@pytest.mark.asyncio
async def test_alert_engine_new_rules_and_fingerprints():
    from datetime import UTC, datetime

    from app.services.alert_engine import AlertEngine, IntelligenceEvent

    engine = AlertEngine()
    now = datetime.now(UTC)

    # malicious_ip now produces a candidate (previously silently dropped)
    cand = engine.evaluate(IntelligenceEvent(
        category="malicious_ip", title="Malicious IP observed: 203.0.113.9",
        description=None, severity="medium", confidence=0.6,
        source_slug="s", source_url=None, published_at=now,
        entities={"ips": ["203.0.113.9"]},
    ))
    assert cand is not None and cand.fingerprint == "mal:203.0.113.9"

    # watchlist fingerprint is value-based and stable
    cand = engine.evaluate(IntelligenceEvent(
        category="watchlist_mention", title="Watchlist match: acme",
        description=None, severity="informational", confidence=0.9,
        source_slug="s", source_url=None, published_at=now,
        entities={"watchlist_value": "acme"},
    ))
    assert cand.fingerprint == "watch:acme"

    # epss fingerprint per CVE
    cand = engine.evaluate(IntelligenceEvent(
        category="high_epss_vulnerability", title="High exploitation probability: CVE-2025-9999",
        description=None, severity="high", confidence=0.9,
        source_slug="s", source_url=None, published_at=now,
        entities={"cves": ["CVE-2025-9999"]},
    ))
    assert cand.fingerprint == "epss:cve-2025-9999"
