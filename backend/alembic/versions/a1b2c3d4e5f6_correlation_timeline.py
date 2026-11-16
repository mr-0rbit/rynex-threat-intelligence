"""correlation timeline: cross-source entity correlation + investigation timeline

Revision ID: a1b2c3d4e5f6
Revises: 72d4cb69a113
"""

from __future__ import annotations

import uuid

from alembic import op
import sqlalchemy as sa


revision = "a1b2c3d4e5f6"
down_revision = "72d4cb69a113"
branch_labels = None
depends_on = None

DEFAULT_ORGANIZATION_ID = uuid.uuid5(
    uuid.NAMESPACE_URL, "https://rynex.tech/rtip/default-organization"
)


def _tenant_column(table: str, *, nullable: bool = False) -> None:
    op.add_column(table, sa.Column("organization_id", sa.Uuid(), nullable=True))
    op.execute(
        sa.text(f'UPDATE "{table}" SET organization_id = :org_id WHERE organization_id IS NULL')
        .bindparams(
            sa.bindparam("org_id", uuid.UUID("00000000-0000-0000-0000-000000000000"), type_=sa.Uuid())
        )
    )
    if not nullable:
        if op.get_bind().dialect.name == "sqlite":
            with op.batch_alter_table(table) as batch_op:
                batch_op.alter_column("organization_id", nullable=False)
        else:
            op.alter_column("organization_id", nullable=False)
    constraint_name = f"fk_{table}_organization_id_organizations"
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table(table) as batch_op:
            batch_op.create_foreign_key(
                constraint_name,
                "organizations",
                ["organization_id"],
                ["id"],
                ondelete="CASCADE",
            )
    else:
        op.create_foreign_key(
            constraint_name,
            table,
            "organizations",
            ["organization_id"],
            ["id"],
            ondelete="CASCADE",
        )
    op.create_index(f"ix_{table}_organization_id", table, ["organization_id"])


def upgrade() -> None:
    op.create_table(
        "correlation_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("entity_key", sa.String(255), nullable=False, index=True),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("correlation_type", sa.String(32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("source_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("sources", sa.JSON(), nullable=True),
        sa.Column("related_alert_ids", sa.JSON(), nullable=True),
        sa.Column("related_breach_ids", sa.JSON(), nullable=True),
        sa.Column("related_cve_ids", sa.JSON(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("timeline", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_correlation_events_entity", "correlation_events", ["entity_key", "entity_type"]
    )
    op.create_index(
        "ix_correlation_events_type", "correlation_events", ["entity_type", "correlation_type"]
    )

    op.create_table(
        "investigation_timelines",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("investigation_id", sa.Uuid(), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("entity_key", sa.String(255), nullable=True),
        sa.Column("entity_type", sa.String(32), nullable=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("evidence_refs", sa.JSON(), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_investigation_timelines_inv",
        "investigation_timelines",
        ["investigation_id", "occurred_at"],
    )

    _tenant_column("correlation_events")
    _tenant_column("investigation_timelines")

    op.create_index(
        "ix_correlation_events_org_entity",
        "correlation_events",
        ["organization_id", "entity_key"],
    )
    op.create_index(
        "ix_correlation_events_org_type",
        "correlation_events",
        ["organization_id", "entity_type", "correlation_type"],
    )
    op.create_index(
        "ix_investigation_timelines_org",
        "investigation_timelines",
        ["organization_id", "occurred_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_investigation_timelines_org", table_name="investigation_timelines")
    op.drop_index("ix_correlation_events_org_type", table_name="correlation_events")
    op.drop_index("ix_correlation_events_org_entity", table_name="correlation_events")
    op.drop_index("ix_investigation_timelines_inv", table_name="investigation_timelines")
    op.drop_index("ix_correlation_events_type", table_name="correlation_events")
    op.drop_index("ix_correlation_events_entity", table_name="correlation_events")
    op.drop_table("investigation_timelines")
    op.drop_table("correlation_events")