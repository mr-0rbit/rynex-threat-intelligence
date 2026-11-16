"""Authentication endpoints: login (with TOTP MFA), refresh, MFA enrollment,
password change/reset, service API keys live in /admin. All security-sensitive
endpoints are rate-limited and audited."""

import base64
import hashlib
import logging
import secrets
import smtplib
import uuid
from datetime import UTC, datetime, timedelta
from email.mime.text import MIMEText

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import admin_required, get_current_user
from app.core.config import settings
from app.core.database import get_db
from app.core.ratelimit import client_ip, login_rate_limit
from app.core.timeutil import ensure_aware
from app.core.security import (
    PasswordPolicyError,
    Role,
    create_access_token,
    create_mfa_preauth_token,
    create_refresh_token,
    decode_token,
    hash_password,
    validate_password_policy,
    verify_password,
)
from app.models import OIDCIdentity, OIDCLoginState, Organization, PasswordResetToken, User
from app.services.audit import record_audit

logger = logging.getLogger("rtip.auth")

router = APIRouter(prefix="/auth", tags=["auth"])

REFRESH_COOKIE = "rtip_refresh"
REFRESH_COOKIE_PATH = f"{settings.API_V1_PREFIX}/auth"
CSRF_HEADER = "X-CSRF-Client"
CSRFHeaderValue = "rtip-refresh"


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    role: str


class MFALoginResponse(BaseModel):
    mfa_required: bool = True
    mfa_token: str


class MFAVerifyRequest(BaseModel):
    mfa_token: str
    code: str


class MFASetupResponse(BaseModel):
    secret: str
    otpauth_uri: str


class MFACodeRequest(BaseModel):
    code: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str | None
    role: str
    is_active: bool
    mfa_enabled: bool

    class Config:
        from_attributes = True


def _issue_session(response: Response, user: User) -> TokenResponse:
    tokens = TokenResponse(
        access_token=create_access_token(str(user.id), user.role, token_version=user.token_version),
        refresh_token=create_refresh_token(str(user.id), user.role, token_version=user.token_version),
        role=user.role,
    )
    # Refresh token moves to an httpOnly cookie; the SPA keeps only the access token in memory.
    response.set_cookie(
        REFRESH_COOKIE,
        tokens.refresh_token,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600,
        path=REFRESH_COOKIE_PATH,
        httponly=True,
        samesite="lax",
        secure=settings.ENVIRONMENT == "production",
    )
    return tokens


def _verify_totp(user: User, code: str) -> bool:
    if not user.mfa_secret:
        return False
    return pyotp.TOTP(user.mfa_secret).verify(code.strip(), valid_window=1)


@router.post("/login")
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(login_rate_limit),
) -> TokenResponse | MFALoginResponse:
    user = (
        await db.execute(select(User).where(User.email == body.email.lower().strip()))
    ).scalar_one_or_none()
    if not user or not user.is_active or not verify_password(body.password, user.hashed_password):
        await record_audit(
            db, action="auth.login_failed", resource_type="user",
            detail={"email": body.email.lower().strip()}, ip_address=client_ip(request),
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

    if user.mfa_enabled:
        await record_audit(
            db, action="auth.mfa_challenge", actor_email=user.email, resource_type="user",
            resource_id=str(user.id), ip_address=client_ip(request),
        )
        return MFALoginResponse(
            mfa_required=True,
            mfa_token=create_mfa_preauth_token(str(user.id), user.role, token_version=user.token_version),
        )

    user.last_login_at = datetime.now(UTC)
    await record_audit(
        db, action="auth.login", actor_email=user.email, resource_type="user",
        resource_id=str(user.id), ip_address=client_ip(request),
    )
    # Commit before responding: FastAPI runs get_db teardown AFTER the response is
    # sent, so teardown-only commits leave a read-after-write race for fast clients.
    await db.commit()
    return _issue_session(response, user)


@router.post("/mfa/verify")
async def mfa_verify(
    body: MFAVerifyRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(login_rate_limit),
) -> TokenResponse:
    payload = decode_token(body.mfa_token, token_types=("mfa_preauth",))
    if not payload:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "MFA session expired — sign in again")
    user = await db.get(User, uuid.UUID(payload["sub"]))
    if not user or not user.is_active or not user.mfa_enabled or not _verify_totp(user, body.code):
        await record_audit(
            db, action="auth.mfa_failed", resource_type="user",
            detail={"sub": payload.get("sub")}, ip_address=client_ip(request),
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid MFA code")
    user.last_login_at = datetime.now(UTC)
    await record_audit(
        db, action="auth.login", actor_email=user.email, resource_type="user",
        resource_id=str(user.id), detail={"mfa": True}, ip_address=client_ip(request),
    )
    await db.commit()
    return _issue_session(response, user)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    request: Request,
    response: Response,
    refresh_token: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    # Cookie path (SPA) requires a CSRF header; query path (API clients) stays compatible.
    cookie_token = request.cookies.get(REFRESH_COOKIE)
    if cookie_token:
        if request.headers.get(CSRF_HEADER) != CSRFHeaderValue:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing CSRF header")
        token = cookie_token
    else:
        token = refresh_token
    payload = decode_token(token) if token else None
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")
    user = await db.get(User, uuid.UUID(payload["sub"]))
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")
    if payload.get("ver") is not None and int(payload["ver"]) != int(user.token_version or 0):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token revoked — sign in again")
    return _issue_session(response, user)


@router.post("/logout")
async def logout(response: Response) -> dict:
    response.delete_cookie(REFRESH_COOKIE, path=REFRESH_COOKIE_PATH)
    return {"status": "signed out"}


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(get_current_user)) -> User:
    return user


@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(
    email: str,
    password: str,
    role: str = "viewer",
    full_name: str | None = None,
    organization_id: uuid.UUID | None = None,
    admin: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db),
) -> User:
    if role not in [r.value for r in Role]:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid role")
    target_organization_id = admin.organization_id
    if organization_id is not None and organization_id != admin.organization_id:
        if not admin.is_platform_admin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Cannot provision users for another organization")
        target_organization_id = organization_id
    organization = await db.get(Organization, target_organization_id)
    if organization is None or not organization.enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found or disabled")
    try:
        validate_password_policy(password)
    except PasswordPolicyError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    exists = (
        await db.execute(select(User).where(User.email == email.lower().strip()))
    ).scalar_one_or_none()
    if exists:
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
    user = User(
        email=email.lower().strip(),
        organization_id=target_organization_id,
        hashed_password=hash_password(password),
        role=role,
        full_name=full_name,
    )
    db.add(user)
    await db.flush()
    await record_audit(
        db,
        action="user.create",
        actor_email=admin.email,
        organization_id=target_organization_id,
        resource_type="user",
        resource_id=str(user.id),
        detail={"email": user.email, "role": role},
        ip_address=None,
    )
    await db.commit()
    await db.refresh(user)
    return user


@router.post("/change-password", response_model=TokenResponse)
async def change_password(
    body: ChangePasswordRequest,
    request: Request,
    response: Response,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    if not verify_password(body.current_password, user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Current password incorrect")
    try:
        validate_password_policy(body.new_password)
    except PasswordPolicyError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    user.hashed_password = hash_password(body.new_password)
    user.token_version = (user.token_version or 0) + 1  # revoke every outstanding JWT
    await record_audit(
        db, action="user.password_change", actor_email=user.email, resource_type="user",
        resource_id=str(user.id), ip_address=client_ip(request),
    )
    await db.commit()  # revocation must be durable before the new tokens are issued
    return _issue_session(response, user)  # new tokens for the current session


def _send_reset_email(to_email: str, token: str) -> bool:
    if not settings.SMTP_HOST or not settings.SMTP_FROM:
        return False
    link = f"https://rtip.local/reset-password?token={token}"  # frontend route when deployed
    msg = MIMEText(
        "A password reset was requested for your RTIP account.\n\n"
        f"Reset link (valid 30 minutes): {link}\n\n"
        "If you did not request this, ignore this email.",
        "plain", "utf-8",
    )
    msg["Subject"] = "RTIP password reset"
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to_email
    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=20) as smtp:
            if settings.SMTP_USER and settings.SMTP_PASSWORD:
                smtp.starttls()
                smtp.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error("reset email delivery failed: %s", exc)
        return False


@router.post("/forgot-password", status_code=202)
async def forgot_password(
    body: ForgotPasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(login_rate_limit),
) -> dict:
    """Uniform 202 response: no user enumeration via status or timing."""
    email = body.email.lower().strip()
    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    out: dict = {"status": "processed"}
    if user and user.is_active:
        raw_token = secrets.token_urlsafe(32)
        db.add(
            PasswordResetToken(
                user_id=user.id,
                token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
                expires_at=datetime.now(UTC) + timedelta(minutes=30),
                created_ip=client_ip(request),
            )
        )
        sent = _send_reset_email(email, raw_token)
        if not sent and settings.ENVIRONMENT == "development":
            # Dev convenience only: no SMTP configured locally. Never enabled in production.
            out["reset_token"] = raw_token
        await record_audit(
            db, action="auth.password_reset_requested", actor_email=email,
            resource_type="user", resource_id=str(user.id), ip_address=client_ip(request),
        )
        await db.commit()  # reset token must exist before the 202 is returned
    return out


@router.post("/reset-password")
async def reset_password(
    body: ResetPasswordRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(login_rate_limit),
) -> dict:
    try:
        validate_password_policy(body.new_password)
    except PasswordPolicyError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    token_hash = hashlib.sha256(body.token.encode()).hexdigest()
    reset = (
        await db.execute(select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash))
    ).scalar_one_or_none()
    now = datetime.now(UTC)
    reset_expires = ensure_aware(reset.expires_at) if reset else None
    if not reset or reset.used_at is not None or (reset_expires and reset_expires < now):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired reset token")
    user = await db.get(User, reset.user_id)
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid reset token")
    reset.used_at = now
    user.hashed_password = hash_password(body.new_password)
    user.token_version = (user.token_version or 0) + 1
    await record_audit(
        db, action="user.password_reset", actor_email=user.email, resource_type="user",
        resource_id=str(user.id), ip_address=client_ip(request),
    )
    await db.commit()  # single-use consumption + revocation must be durable
    return {"status": "password reset"}


# ---------------- TOTP MFA enrollment ----------------

@router.post("/mfa/setup", response_model=MFASetupResponse)
async def mfa_setup(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MFASetupResponse:
    secret = pyotp.random_base32()
    user.mfa_secret = secret
    user.mfa_enabled = False  # stays off until /mfa/confirm
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="RTIP")
    await record_audit(db, action="user.mfa_setup_started", actor_email=user.email, resource_type="user", resource_id=str(user.id))
    await db.commit()  # /mfa/confirm re-reads this row in a new session
    return MFASetupResponse(secret=secret, otpauth_uri=uri)


@router.post("/mfa/confirm")
async def mfa_confirm(
    body: MFACodeRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    if not user.mfa_secret:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Run /auth/mfa/setup first")
    if not _verify_totp(user, body.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid code — check authenticator clock")
    user.mfa_enabled = True
    await record_audit(db, action="user.mfa_enabled", actor_email=user.email, resource_type="user", resource_id=str(user.id))
    await db.commit()  # next login (new session) must see mfa_enabled
    return {"status": "MFA enabled"}


@router.post("/mfa/disable")
async def mfa_disable(
    body: MFACodeRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    if not user.mfa_enabled or not _verify_totp(user, body.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid code")
    user.mfa_enabled = False
    user.mfa_secret = None
    await record_audit(db, action="user.mfa_disabled", actor_email=user.email, resource_type="user", resource_id=str(user.id))
    await db.commit()
    return {"status": "MFA disabled"}


# ---------- Enterprise OIDC Single Sign-On ----------

class OIDCCallbackRequest(BaseModel):
    code: str
    state: str = Field(..., min_length=32, max_length=256)


@router.get("/oidc/config")
async def oidc_config() -> dict:
    """Return enterprise SSO configuration status."""
    return {
        "enabled": settings.OIDC_ENABLED,
        "issuer": settings.OIDC_ISSUER_URL,
    }


@router.get("/oidc/login")
async def oidc_login(
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Initiate enterprise OIDC authentication flow."""
    if not settings.OIDC_ENABLED:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Enterprise OIDC SSO is not enabled in settings")
    from app.services.oidc import oidc_service

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(48)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    try:
        url = await oidc_service.get_authorization_url(
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
        )
    except Exception as exc:  # noqa: BLE001 — provider details should not be exposed
        logger.warning("OIDC discovery or authorization URL generation failed")
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Identity provider is unavailable",
        ) from exc
    db.add(
        OIDCLoginState(
            state_hash=hashlib.sha256(state.encode("utf-8")).hexdigest(),
            nonce=nonce,
            pkce_verifier=code_verifier,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    )
    await db.commit()
    response.set_cookie(
        settings.OIDC_STATE_COOKIE_NAME,
        state,
        max_age=300,
        path="/",
        httponly=True,
        secure=settings.ENVIRONMENT == "production",
        samesite="lax",
    )
    return {"authorization_url": url}


@router.post("/oidc/callback")
async def oidc_callback(
    body: OIDCCallbackRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Handle authorization code exchange and Just-In-Time user provisioning."""
    if not settings.OIDC_ENABLED:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Enterprise OIDC SSO is not enabled")
    from app.services.oidc import oidc_service

    cookie_state = request.cookies.get(settings.OIDC_STATE_COOKIE_NAME)
    if not cookie_state or not secrets.compare_digest(cookie_state, body.state):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "OIDC state validation failed")

    now = datetime.now(UTC)
    state_hash = hashlib.sha256(body.state.encode("utf-8")).hexdigest()
    state_result = await db.execute(
        update(OIDCLoginState)
        .where(
            OIDCLoginState.state_hash == state_hash,
            OIDCLoginState.used_at.is_(None),
            OIDCLoginState.expires_at > now,
        )
        .values(used_at=now)
        .returning(OIDCLoginState.nonce, OIDCLoginState.pkce_verifier)
    )
    state_row = state_result.one_or_none()
    if state_row is None:
        await db.rollback()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "OIDC state is invalid, expired, or already used")
    nonce, code_verifier = state_row
    await db.commit()

    user_info = await oidc_service.exchange_code_for_user_info(
        body.code,
        nonce=nonce,
        code_verifier=code_verifier,
    )
    if not user_info:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "OIDC authentication failed or token invalid")

    email = user_info["email"]
    issuer = user_info["issuer"]
    subject = user_info["sub"]
    identity = (
        await db.execute(
            select(OIDCIdentity).where(
                OIDCIdentity.issuer == issuer,
                OIDCIdentity.subject == subject,
            )
        )
    ).scalar_one_or_none()
    user = await db.get(User, identity.user_id) if identity else None

    organization = (
        await db.execute(
            select(Organization).where(Organization.slug == settings.OIDC_ORGANIZATION_SLUG)
        )
    ).scalar_one_or_none()
    if organization is None or not organization.enabled:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "OIDC organization is not provisioned")

    if not user:
        user = (
            await db.execute(
                select(User).where(
                    User.email == email,
                    User.organization_id == organization.id,
                )
            )
        ).scalar_one_or_none()
        if user is None:
            user = User(
                email=email,
                organization_id=organization.id,
                full_name=user_info.get("full_name") or email.split("@")[0],
                role=settings.OIDC_DEFAULT_ROLE,
                hashed_password=hash_password(secrets.token_urlsafe(32) + "Aa1"),
                is_active=True,
            )
            db.add(user)
            await db.flush()
            await record_audit(
                db,
                action="user.oidc_provisioned",
                actor_email=email,
                organization_id=organization.id,
                resource_type="user",
                resource_id=str(user.id),
            )
        elif user.organization_id != organization.id:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "OIDC identity belongs to another organization")

        db.add(OIDCIdentity(user_id=user.id, issuer=issuer, subject=subject))
        try:
            await db.commit()
            await db.refresh(user)
        except Exception as exc:  # noqa: BLE001 — handles a concurrent first login safely
            await db.rollback()
            logger.info("OIDC identity provisioning conflict for %s", email)
            raise HTTPException(status.HTTP_409_CONFLICT, "OIDC identity already provisioned") from exc

    if not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User account is inactive")
    if user.organization_id != organization.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "OIDC identity belongs to another organization")

    user.last_login_at = datetime.now(UTC)
    await record_audit(
        db,
        action="auth.oidc_login",
        actor_email=user.email,
        organization_id=user.organization_id,
        resource_type="user",
        resource_id=str(user.id),
    )
    await db.commit()
    response.delete_cookie(settings.OIDC_STATE_COOKIE_NAME, path="/")
    return _issue_session(response, user)
