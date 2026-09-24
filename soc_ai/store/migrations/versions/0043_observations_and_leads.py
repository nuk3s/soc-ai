"""Observations that decay, and the leads they form.

Phase 2 of the hunting release. Phase 1 could say "port 3389 is new on this
host"; it could not say that the same host also started talking to a new
destination an hour earlier, which is the difference between a fact and a lead.

``entity_observations`` is keyed on (entity, spec, content fingerprint) so a
repeat REFRESHES rather than accumulating a row. Without that key a beacon seen
every five minutes becomes three hundred observations and outweighs everything
else on the network by arithmetic alone.

There is no stored live weight and no decay column. Weight is computed on read
from ``born_at`` and ``occurrences``: a decay job that misses a night leaves
every weight in the system overstated and nothing anywhere says so.

``leads.entity_span`` is capped by the caller rather than the schema, and a
lead past the cap is stored with status ``fleet_condition``. Past the cap this
is not an intrusion, it is a software deployment, and reporting it as a lead
sends an analyst hunting for an attacker inside one.

Revision ID: 0043
Revises: 0042
Create Date: 2026-09-15
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0043"
down_revision = "0042"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "leads",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="open"),
        sa.Column("formed_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("entities_json", sa.JSON(none_as_null=True), nullable=True),
        sa.Column("kinds_json", sa.JSON(none_as_null=True), nullable=True),
        sa.Column("weight_at_formation", sa.Float(), nullable=False, server_default="0"),
        sa.Column("scope_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("hunt_id", sa.String(64), nullable=True),
        # Shadow by default. Nothing here triggers a playbook until a shadow
        # week has been read — a default of False would make the first sweep
        # after deploy the thing the design spent a paragraph forbidding.
        sa.Column("shadow", sa.Boolean(), nullable=False, server_default="1"),
    )
    op.create_index("ix_lead_status", "leads", ["status"])
    op.create_index("ix_lead_formed", "leads", ["formed_at"])

    op.create_table(
        "entity_observations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("entity_kind", sa.String(16), nullable=False),
        sa.Column("entity_key", sa.String(255), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("spec_id", sa.String(64), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("birth_weight", sa.Float(), nullable=False, server_default="0"),
        sa.Column("born_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("occurrences", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("evidence_json", sa.JSON(none_as_null=True), nullable=True),
        sa.Column(
            "lead_id",
            sa.Integer(),
            sa.ForeignKey("leads.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.UniqueConstraint(
            "entity_kind",
            "entity_key",
            "spec_id",
            "fingerprint",
            name="uq_entity_observation_content",
        ),
    )
    op.create_index(
        "ix_entity_observation_entity", "entity_observations", ["entity_kind", "entity_key"]
    )
    op.create_index("ix_entity_observation_born", "entity_observations", ["born_at"])
    op.create_index("ix_entity_observation_lead", "entity_observations", ["lead_id"])


def downgrade() -> None:
    op.drop_index("ix_entity_observation_lead", table_name="entity_observations")
    op.drop_index("ix_entity_observation_born", table_name="entity_observations")
    op.drop_index("ix_entity_observation_entity", table_name="entity_observations")
    op.drop_table("entity_observations")
    op.drop_index("ix_lead_formed", table_name="leads")
    op.drop_index("ix_lead_status", table_name="leads")
    op.drop_table("leads")
