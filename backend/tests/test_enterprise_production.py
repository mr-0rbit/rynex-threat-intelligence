"""Comprehensive enterprise production feature tests:
- OASIS TAXII 2.1 Server & STIX 2.1 Objects
- Firewall External Dynamic Lists (EDL) with ETag caching
- MITRE ATT&CK Enterprise Matrix & adversary mapping
- Enterprise Liveness and Readiness Probes (/livez, /readyz)
- Cryptographic HMAC Hash-Chained Audit Trail & SIEM Export (CEF & Syslog)
- IOC Confidence Decay & False-Positive Revocation
- Enterprise Granular RBAC Permissions
"""

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.core.security import Permission, Role, has_permission
from app.models import AuditChainHead, AuditLog, IOC, User
from app.services.audit import record_audit
from app.services.ioc_decay import calculate_decayed_confidence


@pytest.mark.asyncio
async def test_taxii_discovery(client):
    """TAXII 2.1 Server Discovery."""
    resp = await client.get("/taxii2/")
    assert resp.status_code == 200, resp.text
    assert "application/taxii+json" in resp.headers["content-type"]
    data = resp.json()
    assert "title" in data
    assert "api_roots" in data
    assert len(data["api_roots"]) > 0


@pytest.mark.asyncio
async def test_taxii_api_root_and_collections(client, auth_headers):
    """TAXII 2.1 API Root and Collections list."""
    # API root requires auth
    resp = await client.get("/taxii2/api1/", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "taxii-2.1" in data["versions"]

    # Collections catalog
    resp = await client.get("/taxii2/api1/collections/", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    cols = resp.json()["collections"]
    aliases = [c["alias"] for c in cols]
    assert "high-confidence-iocs" in aliases
    assert "cisa-kev" in aliases

    # Single collection detail
    resp = await client.get("/taxii2/api1/collections/high-confidence-iocs/", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    col = resp.json()
    assert col["alias"] == "high-confidence-iocs"
    assert col["can_read"] is True


@pytest.mark.asyncio
async def test_taxii_objects_and_manifest(client, auth_headers):
    """TAXII 2.1 STIX objects retrieval and manifest."""
    resp = await client.get("/taxii2/api1/collections/high-confidence-iocs/objects/", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    bundle = resp.json()
    assert "objects" in bundle
    assert isinstance(bundle["objects"], list)

    resp = await client.get("/taxii2/api1/collections/high-confidence-iocs/manifest/", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    manifest = resp.json()
    assert "objects" in manifest


@pytest.mark.asyncio
async def test_taxii_add_objects(client, auth_headers):
    """TAXII 2.1 Ingest objects."""
    sample_stix = {
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": "2026-11-16T00:00:00.000Z",
                "modified": "2026-11-16T00:00:00.000Z",
                "name": "Test IPv4 indicator",
                "pattern": "[ipv4-addr:value = '198.51.100.1']",
                "pattern_type": "stix",
                "valid_from": "2026-11-16T00:00:00.000Z",
            }
        ]
    }
    resp = await client.post(
        "/taxii2/api1/collections/high-confidence-iocs/objects/",
        headers=auth_headers,
        json=sample_stix,
    )
    assert resp.status_code == 202, resp.text
    status_obj = resp.json()
    assert status_obj["status"] == "complete"
    assert status_obj["success_count"] == 1
    assert status_obj["id"]

    operation = await client.get(
        f"/taxii2/api1/status/{status_obj['id']}",
        headers=auth_headers,
    )
    assert operation.status_code == 200, operation.text
    assert operation.json()["success_count"] == 1


@pytest.mark.asyncio
async def test_taxii_objects_and_operations_are_tenant_scoped(client, auth_headers):
    from app.core.database import AsyncSessionLocal
    from app.core.security import hash_password
    from app.models import Organization, TAXIIOperation, TAXIIObject, User

    object_id = f"indicator--{uuid.uuid4()}"
    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    created = await client.post(
        "/taxii2/api1/collections/high-confidence-iocs/objects/",
        headers=auth_headers,
        json={
            "objects": [
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": object_id,
                    "created": timestamp,
                    "modified": timestamp,
                    "name": "Tenant scoped test indicator",
                    "pattern": "[ipv4-addr:value = '203.0.113.17']",
                    "pattern_type": "stix",
                    "valid_from": timestamp,
                }
            ]
        },
    )
    assert created.status_code == 202, created.text
    operation_id = created.json()["id"]

    org = Organization(name="TAXII Isolation Test", slug=f"taxii-{uuid.uuid4().hex[:12]}")
    async with AsyncSessionLocal() as db:
        db.add(org)
        await db.flush()
        user = User(
            email=f"taxii-user-{uuid.uuid4().hex[:12]}@test.local",
            organization_id=org.id,
            hashed_password=hash_password("StrongTestPass123!"),
            role="viewer",
            is_active=True,
        )
        db.add(user)
        await db.commit()
        email = user.email
        user_id = user.id
        organization_id = org.id

    login = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "StrongTestPass123!"},
    )
    assert login.status_code == 200, login.text
    other_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    other_collection = await client.get(
        "/taxii2/api1/collections/high-confidence-iocs/objects/",
        headers=other_headers,
    )
    assert other_collection.status_code == 200, other_collection.text
    assert object_id not in {obj["id"] for obj in other_collection.json()["objects"]}
    other_operation = await client.get(
        f"/taxii2/api1/status/{operation_id}",
        headers=other_headers,
    )
    assert other_operation.status_code == 404

    async with AsyncSessionLocal() as db:
        from sqlalchemy import delete

        await db.execute(delete(TAXIIObject).where(TAXIIObject.object_id == object_id))
        await db.execute(
            delete(TAXIIOperation).where(TAXIIOperation.id == uuid.UUID(operation_id))
        )
        tenant_user = await db.get(User, user_id)
        tenant_org = await db.get(Organization, organization_id)
        if tenant_user:
            await db.delete(tenant_user)
        if tenant_org:
            await db.delete(tenant_org)
        await db.commit()


@pytest.mark.asyncio
async def test_firewall_edl_auth_and_caching(client, auth_headers):
    """External Dynamic Lists (EDL) authentication, responses and ETag caching."""
    # 1. Unauthenticated request must fail
    resp = await client.get("/api/v1/edl/ips")
    assert resp.status_code == 401

    # 2. Create service API key for firewall
    key_resp = await client.post(
        "/api/v1/admin/api-keys",
        headers=auth_headers,
        json={"name": "palo-alto-firewall", "expires_in_days": 30},
    )
    assert key_resp.status_code == 201, key_resp.text
    raw_api_key = key_resp.json()["api_key"]

    # 3. Request with ?token= query parameter (PAN-OS / FortiGate compatible)
    edl_resp = await client.get(f"/api/v1/edl/ips?token={raw_api_key}")
    assert edl_resp.status_code == 200, edl_resp.text
    assert "text/plain" in edl_resp.headers["content-type"]
    assert "etag" in edl_resp.headers
    etag = edl_resp.headers["etag"]

    # 4. Request with If-None-Match should return 304 Not Modified
    cached_resp = await client.get(
        f"/api/v1/edl/ips?token={raw_api_key}",
        headers={"If-None-Match": etag},
    )
    assert cached_resp.status_code == 304

    # 5. Domains and Hashes EDLs
    resp_dom = await client.get(f"/api/v1/edl/domains?token={raw_api_key}")
    assert resp_dom.status_code == 200

    resp_hashes = await client.get(f"/api/v1/edl/hashes?token={raw_api_key}&hash_type=sha256")
    assert resp_hashes.status_code == 200


@pytest.mark.asyncio
async def test_mitre_attack_matrix(client, auth_headers):
    """MITRE ATT&CK Enterprise Matrix endpoints."""
    resp = await client.get("/api/v1/mitre/matrix", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["total_tactics"] == 14
    assert len(data["matrix"]) == 14
    # Initial Access should have T1190
    initial_access = next(c for c in data["matrix"] if c["tactic"]["id"] == "TA0001")
    tech_ids = [t["id"] for t in initial_access["techniques"]]
    assert "T1190" in tech_ids

    # Search techniques
    resp = await client.get("/api/v1/mitre/techniques?q=ransomware", headers=auth_headers)
    assert resp.status_code == 200

    # Actor techniques
    resp = await client.get("/api/v1/mitre/actors/lockbit/techniques", headers=auth_headers)
    assert resp.status_code == 200
    actor_techs = resp.json()
    actor_ids = [t["id"] for t in actor_techs]
    assert "T1486" in actor_ids


@pytest.mark.asyncio
async def test_enterprise_health_probes(client):
    """Kubernetes liveness and deep readiness probes."""
    # Liveness
    resp = await client.get("/livez")
    assert resp.status_code == 200
    assert resp.json()["alive"] is True

    # Readiness
    resp = await client.get("/readyz")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "checks" in data
    assert data["checks"]["database"]["status"] == "healthy"


@pytest.mark.asyncio
async def test_cryptographic_audit_trail_and_siem(client, auth_headers):
    """HMAC hash-chained audit logging and SIEM CEF/Syslog export."""
    from app.core.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        await record_audit(
            db,
            action="enterprise.security_check",
            actor_email="admin@test.local",
            resource_type="system",
            resource_id="soc-node-1",
            detail={"event": "initialization"},
            ip_address="192.0.2.1",
        )
        await db.commit()

    # Verify HMAC chain via endpoint
    verify_resp = await client.get("/api/v1/admin/audit-logs/verify", headers=auth_headers)
    assert verify_resp.status_code == 200, verify_resp.text
    verify_data = verify_resp.json()
    assert verify_data["valid"] is True
    assert verify_data["status"] == "intact"

    # Complete-record verification catches content edits even when the hash
    # links and separately persisted head have not been modified.
    from sqlalchemy import select

    from app.core.database import AsyncSessionLocal
    from app.services.audit import verify_audit_log_chain

    async with AsyncSessionLocal() as db:
        row = (
            await db.execute(
                select(AuditLog).where(AuditLog.action == "enterprise.security_check")
            )
        ).scalar_one()
        original_detail = row.detail
        row.detail = {"event": "tampered"}
        await db.commit()
        result = await verify_audit_log_chain(db)
        assert result["valid"] is False
        assert result["status"] == "content_tampered"

        row.detail = original_detail
        await db.commit()
        assert (await verify_audit_log_chain(db))["valid"] is True

        head = await db.get(AuditChainHead, 1)
        assert head is not None
        saved_sequence, saved_hmac = head.last_sequence, head.last_hmac
        await db.delete(head)
        await db.commit()
        assert (await verify_audit_log_chain(db))["status"] == "head_missing"
        db.add(AuditChainHead(id=1, last_sequence=saved_sequence, last_hmac=saved_hmac))
        await db.commit()
        assert (await verify_audit_log_chain(db))["valid"] is True

    # Export in ArcSight CEF format
    cef_resp = await client.get("/api/v1/admin/audit-logs/export?format=cef", headers=auth_headers)
    assert cef_resp.status_code == 200
    assert "CEF:0|Rynex" in cef_resp.text

    # Export in RFC 5424 Syslog format
    syslog_resp = await client.get("/api/v1/admin/audit-logs/export?format=syslog", headers=auth_headers)
    assert syslog_resp.status_code == 200
    assert "<134>1" in syslog_resp.text


@pytest.mark.asyncio
async def test_ioc_confidence_decay_and_revocation(client, auth_headers):
    """IOC time-decay calculation and analyst false-positive revocation."""
    from app.core.database import AsyncSessionLocal

    now = datetime.now(UTC)
    seen_20_days_ago = now - timedelta(days=20)

    # Unit check: IP decay vs Hash retention
    ip_decayed = calculate_decayed_confidence(0.80, "ipv4", seen_20_days_ago, now)
    assert ip_decayed < 0.80  # IP decayed significantly

    hash_retained = calculate_decayed_confidence(0.80, "sha256", seen_20_days_ago, now)
    assert hash_retained == 0.80  # Hash does not decay

    # Create test IOC in DB
    test_id = uuid.uuid4()
    async with AsyncSessionLocal() as db:
        test_ioc = IOC(
            id=test_id,
            value="198.51.100.99",
            type="ipv4",
            source_slug="test-feed",
            confidence=0.85,
            confidence_reasons={"source": "high"},
            last_seen_at=now,
        )
        db.add(test_ioc)
        await db.commit()

    # Mark as false positive via API
    fp_resp = await client.post(
        f"/api/v1/iocs/{test_id}/false-positive?reason=benign_corporate_cdn",
        headers=auth_headers,
    )
    assert fp_resp.status_code == 200, fp_resp.text

    # Verify score zeroed in DB
    async with AsyncSessionLocal() as db:
        updated = await db.get(IOC, test_id)
        assert updated.confidence == 0.0
        assert "false_positive_revoked" in updated.confidence_reasons
        await db.delete(updated)
        await db.commit()


def test_granular_rbac_matrix():
    """Verify granular enterprise permission matrix."""
    assert has_permission(Role.ADMIN, Permission.SETTINGS_MANAGE)
    assert has_permission(Role.SOC_LEAD, Permission.INTEL_WRITE)
    assert has_permission(Role.SOC_LEAD, Permission.EDL_READ)
    assert not has_permission(Role.VIEWER, Permission.INTEL_WRITE)
    assert has_permission(Role.VIEWER, Permission.EDL_READ)
    assert has_permission(Role.AUDITOR, Permission.AUDIT_READ)
    assert not has_permission(Role.AUDITOR, Permission.ASSETS_MANAGE)


def test_production_settings_reject_placeholders_and_accept_provisioned_secrets():
    from pydantic import ValidationError

    from app.core.config import Settings

    common = {
        "ENVIRONMENT": "production",
        "DEBUG": False,
        "DATABASE_URL": "postgresql+asyncpg://rtip:secret@db.example.test/rtip",
        "ADMIN_PASSWORD": "StrongProductionAdminPassword123!",
        "AUDIT_HMAC_KEY": "audit-hmac-key-with-sufficient-unique-length-123456",
    }
    with pytest.raises(ValidationError, match="JWT_SECRET_KEY"):
        Settings(**common, JWT_SECRET_KEY="CHANGE_ME_in_production")

    settings = Settings(
        **common,
        JWT_SECRET_KEY="a-unique-production-jwt-key-with-at-least-forty-eight-characters",
    )
    assert settings.ENVIRONMENT == "production"


def test_proxy_headers_are_trusted_only_from_configured_proxy_cidrs(monkeypatch):
    from starlette.requests import Request

    from app.core.config import settings
    from app.core.ratelimit import client_ip

    def request(peer: str, forwarded: str) -> Request:
        return Request(
            {
                "type": "http",
                "http_version": "1.1",
                "method": "GET",
                "scheme": "https",
                "path": "/",
                "raw_path": b"/",
                "query_string": b"",
                "headers": [(b"x-forwarded-for", forwarded.encode())],
                "client": (peer, 443),
                "server": ("rtip.test", 443),
            }
        )

    monkeypatch.setattr(settings, "TRUSTED_PROXY_CIDRS", "10.20.0.0/16")
    assert client_ip(request("198.51.100.8", "203.0.113.20")) == "198.51.100.8"
    # The client address closest to the trusted proxy wins; an attacker-
    # prepended XFF entry cannot spoof the rate-limit identity.
    assert (
        client_ip(request("10.20.0.5", "198.51.100.99, 203.0.113.20, 10.20.0.6"))
        == "203.0.113.20"
    )


@pytest.mark.asyncio
async def test_oidc_exchange_verifies_signature_and_verified_userinfo(monkeypatch):
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    import httpx
    from httpx import Response
    from jwt.algorithms import RSAAlgorithm

    from app.services.oidc import OIDCService

    issuer = "https://idp.validation.test"
    client_id = "rtip-test-client"
    nonce = "expected-nonce-value"
    now = datetime.now(UTC)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk.update({"kid": "key-1", "use": "sig", "alg": "RS256"})
    id_token = jwt.encode(
        {
            "iss": issuer,
            "sub": "idp-subject-1",
            "aud": client_id,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            "nonce": nonce,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "key-1"},
    )
    metadata = {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "userinfo_endpoint": f"{issuer}/userinfo",
        "jwks_uri": f"{issuer}/jwks",
    }
    service = OIDCService()
    service.enabled = True
    service.issuer_url = issuer
    service.client_id = client_id
    service.client_secret = "client-secret"
    service.redirect_uri = "https://rtip.test/oidc/callback"

    async def run_flow(email_verified: bool):
        service._provider_metadata = None
        async def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if url_str == f"{issuer}/.well-known/openid-configuration":
                return Response(200, json=metadata)
            elif url_str == f"{issuer}/token":
                return Response(
                    200,
                    json={"access_token": "access-token", "id_token": id_token},
                )
            elif url_str == f"{issuer}/jwks":
                return Response(200, json={"keys": [public_jwk]})
            elif url_str == f"{issuer}/userinfo":
                return Response(
                    200,
                    json={
                        "sub": "idp-subject-1",
                        "email": "oidc-verified@test.local",
                        "email_verified": email_verified,
                        "name": "OIDC Verified",
                    },
                )
            return Response(404)

        transport = httpx.MockTransport(handler)
        orig_client = httpx.AsyncClient

        class MockClient(orig_client):
            def __init__(self, *args, **kwargs):
                kwargs["transport"] = transport
                super().__init__(*args, **kwargs)

        with monkeypatch.context() as m:
            m.setattr(httpx, "AsyncClient", MockClient)
            return await service.exchange_code_for_user_info(
                "one-use-code",
                nonce=nonce,
                code_verifier="stored-pkce-verifier",
            )

    accepted = await run_flow(email_verified=True)
    assert accepted is not None
    assert accepted["email"] == "oidc-verified@test.local"
    assert accepted["sub"] == "idp-subject-1"
    assert await run_flow(email_verified=False) is None


@pytest.mark.asyncio
async def test_oidc_callback_state_is_browser_bound_single_use_and_provisions_identity(
    client,
    monkeypatch,
):
    from sqlalchemy import select

    from app.core.config import settings
    from app.core.database import AsyncSessionLocal
    from app.models import OIDCIdentity, OIDCLoginState, Organization
    from app.models.organization import DEFAULT_ORGANIZATION_ID
    from app.services.oidc import oidc_service

    monkeypatch.setattr(settings, "OIDC_ENABLED", True)
    state = "one-time-browser-state-" + uuid.uuid4().hex
    state_hash = hashlib.sha256(state.encode()).hexdigest()
    captured: dict[str, str] = {}
    subject = "oidc-subject-" + uuid.uuid4().hex

    async def exchange(code: str, *, nonce: str, code_verifier: str):
        captured.update(code=code, nonce=nonce, code_verifier=code_verifier)
        return {
            "email": f"oidc-{uuid.uuid4().hex[:12]}@test.local",
            "full_name": "OIDC Test User",
            "sub": subject,
            "issuer": "https://idp.test.example",
        }

    monkeypatch.setattr(oidc_service, "exchange_code_for_user_info", exchange)
    email = None
    async with AsyncSessionLocal() as db:
        organization = await db.get(Organization, DEFAULT_ORGANIZATION_ID)
        assert organization is not None
        nonce = "nonce-" + uuid.uuid4().hex
        verifier = "pkce-verifier-" + uuid.uuid4().hex
        db.add(
            OIDCLoginState(
                state_hash=state_hash,
                nonce=nonce,
                pkce_verifier=verifier,
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
            )
        )
        await db.commit()

    client.cookies.set(settings.OIDC_STATE_COOKIE_NAME, "wrong-browser-cookie", path="/")
    rejected = await client.post(
        "/api/v1/auth/oidc/callback",
        json={"code": "auth-code", "state": state},
    )
    assert rejected.status_code == 400

    client.cookies.set(settings.OIDC_STATE_COOKIE_NAME, state, path="/")
    response = await client.post(
        "/api/v1/auth/oidc/callback",
        json={"code": "auth-code", "state": state},
    )
    assert response.status_code == 200, response.text
    assert captured["code"] == "auth-code"
    assert captured["nonce"] == nonce
    assert captured["code_verifier"] == verifier
    access_token = response.json()["access_token"]
    me = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me.status_code == 200
    assert me.json()["role"] == "viewer"
    email = me.json()["email"]

    # The state is consumed before contacting the provider, so replay is denied.
    client.cookies.set(settings.OIDC_STATE_COOKIE_NAME, state, path="/")
    replay = await client.post(
        "/api/v1/auth/oidc/callback",
        json={"code": "auth-code", "state": state},
    )
    assert replay.status_code == 400
    async with AsyncSessionLocal() as db:
        identity = (
            await db.execute(
                select(OIDCIdentity).where(
                    OIDCIdentity.issuer == "https://idp.test.example",
                    OIDCIdentity.subject == subject,
                )
            )
        ).scalar_one()
        assert identity.user_id
        user = await db.get(User, identity.user_id)
        assert user.email == email
        await db.delete(identity)
        await db.delete(user)
        state_row = (
            await db.execute(
                select(OIDCLoginState).where(OIDCLoginState.state_hash == state_hash)
            )
        ).scalar_one_or_none()
        if state_row:
            await db.delete(state_row)
        await db.commit()


@pytest.mark.asyncio
async def test_alerts_are_isolated_between_organizations(client, auth_headers):
    from app.core.database import AsyncSessionLocal
    from app.core.security import hash_password
    from app.models import Alert, Organization, User

    org = Organization(name="Tenant Isolation Test", slug=f"tenant-{uuid.uuid4().hex[:12]}")
    second_user = None
    alert = None
    async with AsyncSessionLocal() as db:
        db.add(org)
        await db.flush()
        second_user = User(
            email=f"tenant-user-{uuid.uuid4().hex[:12]}@test.local",
            organization_id=org.id,
            hashed_password=hash_password("StrongTestPass123!"),
            role="viewer",
            is_active=True,
        )
        db.add(second_user)
        alert = Alert(
            organization_id=org.id,
            fingerprint=f"tenant-isolation-{uuid.uuid4().hex}",
            title="Private tenant alert",
            category="test",
            severity="high",
            confidence=0.9,
            detected_at=datetime.now(UTC),
            status="new",
        )
        db.add(alert)
        await db.commit()
        user_email = second_user.email
        user_password = "StrongTestPass123!"
        alert_id = alert.id

    login = await client.post(
        "/api/v1/auth/login",
        json={"email": user_email, "password": user_password},
    )
    assert login.status_code == 200, login.text
    second_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    default_tenant_alerts = await client.get("/api/v1/alerts", headers=auth_headers)
    assert default_tenant_alerts.status_code == 200
    assert all(row["id"] != str(alert_id) for row in default_tenant_alerts.json()["items"])

    second_tenant_alerts = await client.get("/api/v1/alerts", headers=second_headers)
    assert second_tenant_alerts.status_code == 200
    assert any(row["id"] == str(alert_id) for row in second_tenant_alerts.json()["items"])

    cross_tenant_detail = await client.get(
        f"/api/v1/alerts/{alert_id}/report.pdf",
        headers=auth_headers,
    )
    assert cross_tenant_detail.status_code == 404

    async with AsyncSessionLocal() as db:
        await db.delete(alert)
        await db.delete(second_user)
        await db.delete(org)
        await db.commit()
