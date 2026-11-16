"""Enterprise security: password policies, JWT tokens, granular RBAC & permission matrices."""

import re
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum

import bcrypt
import jwt

from app.core.config import settings


class Role(StrEnum):
    ADMIN = "admin"
    SOC_LEAD = "soc_lead"
    ANALYST = "analyst"
    TRIAGE = "triage"
    AUDITOR = "auditor"
    VIEWER = "viewer"


class Permission(StrEnum):
    INTEL_READ = "intel:read"
    INTEL_WRITE = "intel:write"
    ALERTS_READ = "alerts:read"
    ALERTS_TRIAGE = "alerts:triage"
    SOURCES_MANAGE = "sources:manage"
    WATCHLISTS_MANAGE = "watchlists:manage"
    ASSETS_MANAGE = "assets:manage"
    INVESTIGATIONS_WRITE = "investigations:write"
    TAXII_READ = "taxii:read"
    TAXII_WRITE = "taxii:write"
    EDL_READ = "edl:read"
    AUDIT_READ = "audit:read"
    USERS_MANAGE = "users:manage"
    SETTINGS_MANAGE = "settings:manage"


# Role-to-Permissions Matrix
ROLE_PERMISSIONS: dict[str, set[Permission]] = {
    Role.ADMIN: set(Permission),
    Role.SOC_LEAD: {
        Permission.INTEL_READ,
        Permission.INTEL_WRITE,
        Permission.ALERTS_READ,
        Permission.ALERTS_TRIAGE,
        Permission.SOURCES_MANAGE,
        Permission.WATCHLISTS_MANAGE,
        Permission.ASSETS_MANAGE,
        Permission.INVESTIGATIONS_WRITE,
        Permission.TAXII_READ,
        Permission.TAXII_WRITE,
        Permission.EDL_READ,
        Permission.AUDIT_READ,
    },
    Role.ANALYST: {
        Permission.INTEL_READ,
        Permission.INTEL_WRITE,
        Permission.ALERTS_READ,
        Permission.ALERTS_TRIAGE,
        Permission.WATCHLISTS_MANAGE,
        Permission.ASSETS_MANAGE,
        Permission.INVESTIGATIONS_WRITE,
        Permission.TAXII_READ,
        Permission.TAXII_WRITE,
        Permission.EDL_READ,
    },
    Role.TRIAGE: {
        Permission.INTEL_READ,
        Permission.ALERTS_READ,
        Permission.ALERTS_TRIAGE,
        Permission.TAXII_READ,
        Permission.EDL_READ,
    },
    Role.AUDITOR: {
        Permission.INTEL_READ,
        Permission.ALERTS_READ,
        Permission.TAXII_READ,
        Permission.EDL_READ,
        Permission.AUDIT_READ,
    },
    Role.VIEWER: {
        Permission.INTEL_READ,
        Permission.ALERTS_READ,
        Permission.TAXII_READ,
        Permission.EDL_READ,
    },
}


def has_permission(role: str, permission: Permission) -> bool:
    """Evaluate if a role holds a specific enterprise permission."""
    perms = ROLE_PERMISSIONS.get(role, set())
    return permission in perms


PASSWORD_MIN_LENGTH = 12
_PASSWORD_COMPLEXITY = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$")


class PasswordPolicyError(ValueError):
    pass


def validate_password_policy(password: str) -> None:
    """Enterprise baseline: ≥12 chars with upper, lower and digit."""
    if len(password) < PASSWORD_MIN_LENGTH:
        raise PasswordPolicyError(f"Password must be at least {PASSWORD_MIN_LENGTH} characters")
    if not _PASSWORD_COMPLEXITY.match(password):
        raise PasswordPolicyError("Password must contain uppercase, lowercase and a digit")


def hash_password(password: str) -> str:
    validate_password_policy(password)
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except ValueError:
        return False


def _jwt_payload(subject: str, role: str, token_type: str, expire: datetime) -> dict:
    return {
        "sub": subject,
        "role": role,
        "jti": uuid.uuid4().hex,
        "type": token_type,
        "ver": 0,  # replaced by caller with the user's token_version
        "exp": expire,
    }


def create_access_token(subject: str, role: str, expires_minutes: int | None = None, token_version: int = 0) -> str:
    expire = datetime.now(UTC) + timedelta(
        minutes=expires_minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = _jwt_payload(subject, role, "access", expire)
    payload["ver"] = token_version
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(subject: str, role: str, token_version: int = 0) -> str:
    expire = datetime.now(UTC) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    payload = _jwt_payload(subject, role, "refresh", expire)
    payload["ver"] = token_version
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_mfa_preauth_token(subject: str, role: str, token_version: int = 0) -> str:
    """Short-lived bridge token issued after password+MFA-enabled check.

    Cannot be used as an access token; only /auth/mfa/verify accepts it.
    """
    expire = datetime.now(UTC) + timedelta(minutes=5)
    payload = _jwt_payload(subject, role, "mfa_preauth", expire)
    payload["ver"] = token_version
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str, token_types: tuple[str, ...] = ("access", "refresh")) -> dict | None:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload if payload.get("type") in token_types else None
    except jwt.PyJWTError:
        return None
