"""Organizations and enterprise identity/TAXII state."""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

DEFAULT_ORGANIZATION_ID = uuid.uuid5(
    uuid.NAMESPACE_URL, "https://rynex.tech/rtip/default-organization"
)


class Organization(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class OIDCIdentity(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Immutable mapping from a trusted OIDC issuer/subject to a local user."""

    __tablename__ = "oidc_identities"
    __table_args__ = (UniqueConstraint("issuer", "subject", name="uq_oidc_issuer_subject"),)

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    issuer: Mapped[str] = mapped_column(String(512), nullable=False)
    subject: Mapped[str] = mapped_column(String(512), nullable=False)


class OIDCLoginState(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Short-lived, one-use OIDC transaction bound to the initiating browser."""

    __tablename__ = "oidc_login_states"

    state_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    pkce_verifier: Mapped[str] = mapped_column(String(128), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuditChainHead(Base):
    """Serialized head of the tamper-evident audit log chain."""

    __tablename__ = "audit_chain_head"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    last_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_hmac: Mapped[str] = mapped_column(String(64), nullable=False)


class TAXIIObject(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Tenant-owned STIX objects received through TAXII."""

    __tablename__ = "taxii_objects"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "collection_alias",
            "object_id",
            name="uq_taxii_org_collection_object",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    collection_alias: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    object_id: Mapped[str] = mapped_column(String(255), nullable=False)
    object_type: Mapped[str] = mapped_column(String(64), nullable=False)
    object_data: Mapped[dict] = mapped_column(JSON, nullable=False)
    date_added: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class TAXIIOperation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Persisted status for TAXII asynchronous write operations."""

    __tablename__ = "taxii_operations"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    collection_alias: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    total_count: Mapped[int] = mapped_column(Integer, nullable=False)
    success_count: Mapped[int] = mapped_column(Integer, nullable=False)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False)
    failure_detail: Mapped[list | None] = mapped_column(JSON)
    request_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class OrganizationInvitation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One-use invitation for joining an organization."""

    __tablename__ = "organization_invitations"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    note: Mapped[str | None] = mapped_column(Text)
