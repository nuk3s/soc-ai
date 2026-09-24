"""What is normal for one entity on one dimension.

Phase 1 of the hunting release. Before this, soc-ai could say what a document
contained but not whether it was ordinary for the machine that produced it, so
every question about novelty was answered by the model from whatever the prompt
happened to carry — which is to say, guessed.

One row per (entity, dimension), because dimensions arrive from different
planes with different coverage and a single blob would force them to share one
answer to "was this measured?".

``coverage`` exists because an empty membership set and an unmeasured one
render identically and mean opposite things: a host that ships no process
telemetry has no unusual processes in exactly the way a quiet host does. Every
surface downstream has to be able to say "blind for process on this host"
rather than "nothing departed".

``identity_fingerprint`` is the rebind guard. The dossier already stamps
``identity_rebound_at`` when an address changes hands; a profile carrying the
previous occupant's fingerprint is stale by construction, and scoring a
departure against it charges one machine with its predecessor's history.

Revision ID: 0042
Revises: 0041
Create Date: 2026-09-15
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0042"
down_revision = "0041"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "entity_profiles",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("entity_kind", sa.String(16), nullable=False),
        sa.Column("entity_key", sa.String(255), nullable=False),
        sa.Column("dimension", sa.String(64), nullable=False),
        sa.Column("shape", sa.String(16), nullable=False),
        # none_as_null, per the note on NULLABLE_JSON in store/models.py: the
        # plain JSON type writes the two-byte text "null", which reads back as
        # None in Python while matching IS NOT NULL in SQL.
        sa.Column("vector_json", sa.JSON(none_as_null=True), nullable=True),
        sa.Column("coverage", sa.String(16), nullable=False, server_default="measured"),
        sa.Column("support_days", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("role", sa.String(32), nullable=True),
        sa.Column("role_confidence", sa.Float(), nullable=True),
        sa.Column("identity_fingerprint", sa.String(64), nullable=True),
        sa.Column("window_days", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("first_seen", sa.DateTime(), nullable=True),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.Column("built_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint(
            "entity_kind", "entity_key", "dimension", name="uq_entity_profile_dimension"
        ),
    )
    op.create_index("ix_entity_profile_entity", "entity_profiles", ["entity_kind", "entity_key"])
    op.create_index("ix_entity_profile_role", "entity_profiles", ["role"])


def downgrade() -> None:
    op.drop_index("ix_entity_profile_role", table_name="entity_profiles")
    op.drop_index("ix_entity_profile_entity", table_name="entity_profiles")
    op.drop_table("entity_profiles")
