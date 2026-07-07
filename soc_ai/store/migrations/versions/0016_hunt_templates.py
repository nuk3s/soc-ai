"""hunt_templates: curated, parameterized hunt objectives filtered by grid telemetry

A :class:`~soc_ai.store.models.HuntTemplate` row is a reusable hunt starter — a
named objective (the current "canned pill" text) plus the ``required_datasets``
it needs (``["zeek.rdp", …]``). ``GET /hunt-templates`` annotates each with
``available``/``missing_datasets`` against the LIVE grid inventory so a template
that needs telemetry the grid lacks renders FLAGGED, not hidden. ``builtin`` rows
are seeded idempotently at startup (upsert-by-name); operators can save custom
(``builtin=False``) templates too.

Revision ID: 0016
Revises: 0015
Create Date: 2026-07-07
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "hunt_templates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("objective_template", sa.Text(), nullable=False, server_default=""),
        sa.Column("required_datasets", sa.JSON(), nullable=False),
        sa.Column("default_window_minutes", sa.Integer(), nullable=False, server_default="1440"),
        sa.Column("builtin", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_by", sa.String(128), nullable=False, server_default="anonymous"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("hunt_templates")
