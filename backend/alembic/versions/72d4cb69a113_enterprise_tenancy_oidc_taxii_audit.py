"""enterprise tenancy, OIDC transactions, TAXII persistence and audit integrity

Revision ID: 72d4cb69a113
Revises: 913c69783841
"""

from __future__ import annotations

import uuid

from alembic import op
import sqlalchemy as sa


revision = "72d4cb69a113"
down_revision = "913c69783841"
branch_labels = None
depends_on = None

DEFAULT_ORGANIZATION_ID = uuid.uuid5(
    uuid.NAMESPACE_URL, "https://rynex.tech/rtip/default-organization"
)
GENESIS_HMAC = "0" * 64


def _tenant_column(table: str, *, nullable: bool = False) -> None:
    op.add_column(table, sa.Column("organization_id", sa.Uuid(), nullable=True))
    op.execute(
        sa.text(f'UPDATE "{table}" SET organization_id = :org_id WHERE organization_id IS NULL')
        .bindparams(
            sa.bindparam("org_id", DEFAULT_ORGANIZATION_ID, type_=sa.Uuid())
        )
    )
    if not nullable:
        if op.get_bind().dialect.name == "sqlite":
            with op.batch_alter_table(table) as batch_op:
                batch_op.alter_column("organization_id", nullable=False)
        else:
            op.alter_column(table, "organization_id", nullable=False)
    constraint_name = f"fk_{table}_organization_id_organizations"
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table(table) as batch_op:
            batch_op.create_foreign_key(
                constraint_name,
                "organizations",
                ["organization_id"],
                ["id"],
                ondelete="SET NULL" if nullable else "CASCADE",
            )
    else:
        op.create_foreign_key(
            constraint_name,
            table,
            "organizations",
            ["organization_id"],
            ["id"],
            ondelete="SET NULL" if nullable else "CASCADE",
        )
    op.create_index(f"ix_{table}_organization_id", table, ["organization_id"])


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
    )
    op.create_index("ix_organizations_slug", "organizations", ["slug"], unique=True)
    op.bulk_insert(
        sa.table(
            "organizations",
            sa.column("id", sa.Uuid()),
            sa.column("name", sa.String()),
            sa.column("slug", sa.String()),
            sa.column("enabled", sa.Boolean()),
        ),
        [
            {
                "id": DEFAULT_ORGANIZATION_ID,
                "name": "Default Organization",
                "slug": "default",
                "enabled": True,
            }
        ],
    )

    op.add_column("users", sa.Column("organization_id", sa.Uuid(), nullable=True))
    op.add_column(
        "users",
        sa.Column("is_platform_admin", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.execute(
        sa.text("UPDATE users SET organization_id = :org_id WHERE organization_id IS NULL")
        .bindparams(
            sa.bindparam("org_id", DEFAULT_ORGANIZATION_ID, type_=sa.Uuid())
        )
    )
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("users") as batch_op:
            batch_op.alter_column("organization_id", nullable=False)
            batch_op.create_foreign_key(
                "fk_users_organization_id_organizations",
                "organizations",
                ["organization_id"],
                ["id"],
                ondelete="RESTRICT",
            )
    else:
        op.alter_column("users", "organization_id", nullable=False)
        op.create_foreign_key(
            "fk_users_organization_id_organizations",
            "users",
            "organizations",
            ["organization_id"],
            ["id"],
            ondelete="RESTRICT",
        )
    op.create_index("ix_users_organization_id", "users", ["organization_id"])
    op.execute(
        sa.text(
            "UPDATE users SET is_platform_admin = :platform_admin WHERE role = 'admin'"
        ).bindparams(platform_admin=True)
    )

    for table in (
        "assets",
        "alerts",
        "alert_rules",
        "watchlists",
        "watchlist_items",
        "investigations",
    ):
        _tenant_column(table)
    _tenant_column("audit_logs", nullable=True)

    op.drop_index("ix_assets_type_value", table_name="assets")
    op.create_index(
        "ix_assets_org_type_value",
        "assets",
        ["organization_id", "type", "value"],
    )
    op.create_index("ix_alerts_org_detected", "alerts", ["organization_id", "detected_at"])

    op.add_column("audit_logs", sa.Column("sequence", sa.Integer(), nullable=True))
    op.add_column("audit_logs", sa.Column("previous_hmac", sa.String(64), nullable=True))
    op.add_column("audit_logs", sa.Column("entry_hmac", sa.String(64), nullable=True))
    op.create_index("ix_audit_logs_sequence", "audit_logs", ["sequence"], unique=True)

    op.create_table(
        "audit_chain_head",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("last_sequence", sa.Integer(), nullable=False),
        sa.Column("last_hmac", sa.String(64), nullable=False),
    )
    op.bulk_insert(
        sa.table(
            "audit_chain_head",
            sa.column("id", sa.Integer()),
            sa.column("last_sequence", sa.Integer()),
            sa.column("last_hmac", sa.String()),
        ),
        [{"id": 1, "last_sequence": 0, "last_hmac": GENESIS_HMAC}],
    )

    op.create_table(
        "oidc_identities",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("issuer", sa.String(512), nullable=False),
        sa.Column("subject", sa.String(512), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("issuer", "subject", name="uq_oidc_issuer_subject"),
    )
    op.create_index("ix_oidc_identities_user_id", "oidc_identities", ["user_id"])
    op.create_table(
        "oidc_login_states",
        sa.Column("state_hash", sa.String(64), nullable=False),
        sa.Column("nonce", sa.String(128), nullable=False),
        sa.Column("pkce_verifier", sa.String(128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_oidc_login_states_state_hash", "oidc_login_states", ["state_hash"], unique=True)

    op.create_table(
        "taxii_objects",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid(), nullable=False),
        sa.Column("collection_alias", sa.String(100), nullable=False),
        sa.Column("object_id", sa.String(255), nullable=False),
        sa.Column("object_type", sa.String(64), nullable=False),
        sa.Column("object_data", sa.JSON(), nullable=False),
        sa.Column("date_added", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "collection_alias",
            "object_id",
            name="uq_taxii_org_collection_object",
        ),
    )
    op.create_index("ix_taxii_objects_organization_id", "taxii_objects", ["organization_id"])
    op.create_index("ix_taxii_objects_collection_alias", "taxii_objects", ["collection_alias"])

    op.create_table(
        "taxii_operations",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("collection_alias", sa.String(100), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("total_count", sa.Integer(), nullable=False),
        sa.Column("success_count", sa.Integer(), nullable=False),
        sa.Column("failure_count", sa.Integer(), nullable=False),
        sa.Column("failure_detail", sa.JSON(), nullable=True),
        sa.Column("request_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_taxii_operations_organization_id", "taxii_operations", ["organization_id"])

    op.create_table(
        "organization_invitations",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_user_id", sa.Uuid(), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(
        "ix_organization_invitations_organization_id",
        "organization_invitations",
        ["organization_id"],
    )
    op.create_index("ix_organization_invitations_email", "organization_invitations", ["email"])


def downgrade() -> None:
    op.drop_table("organization_invitations")
    op.drop_table("taxii_operations")
    op.drop_table("taxii_objects")
    op.drop_index("ix_oidc_login_states_state_hash", table_name="oidc_login_states")
    op.drop_table("oidc_login_states")
    op.drop_index("ix_oidc_identities_user_id", table_name="oidc_identities")
    op.drop_table("oidc_identities")
    op.drop_table("audit_chain_head")
    op.drop_index("ix_audit_logs_sequence", table_name="audit_logs")
    op.drop_column("audit_logs", "entry_hmac")
    op.drop_column("audit_logs", "previous_hmac")
    op.drop_column("audit_logs", "sequence")
    op.drop_index("ix_alerts_org_detected", table_name="alerts")
    op.drop_index("ix_assets_org_type_value", table_name="assets")
    op.create_index("ix_assets_type_value", "assets", ["type", "value"])

    for table in (
        "audit_logs",
        "investigations",
        "watchlist_items",
        "watchlists",
        "alert_rules",
        "alerts",
        "assets",
    ):
        op.drop_index(f"ix_{table}_organization_id", table_name=table)
        if op.get_bind().dialect.name == "sqlite":
            with op.batch_alter_table(table) as batch_op:
                batch_op.drop_constraint(
                    f"fk_{table}_organization_id_organizations",
                    type_="foreignkey",
                )
                batch_op.drop_column("organization_id")
        else:
            op.drop_constraint(
                f"fk_{table}_organization_id_organizations",
                table,
                type_="foreignkey",
            )
            op.drop_column(table, "organization_id")

    op.drop_index("ix_users_organization_id", table_name="users")
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("users") as batch_op:
            batch_op.drop_constraint(
                "fk_users_organization_id_organizations",
                type_="foreignkey",
            )
            batch_op.drop_column("is_platform_admin")
            batch_op.drop_column("organization_id")
    else:
        op.drop_constraint("fk_users_organization_id_organizations", "users", type_="foreignkey")
        op.drop_column("users", "is_platform_admin")
        op.drop_column("users", "organization_id")
    op.drop_index("ix_organizations_slug", table_name="organizations")
    op.drop_table("organizations")
