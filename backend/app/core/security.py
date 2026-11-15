"""Password hashing/policy, JWT creation/verification, RBAC helpers."""

import re
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum

import bcrypt
import jwt

from app.core.config import settings


class Role(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


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
