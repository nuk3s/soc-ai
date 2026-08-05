"""model_battery_results: cache the quick fitness check alongside the battery

The Config console auto-runs the 3-leg fitness check on every page load /
model change, which re-probed the live gateway each time ("Checking fitness…"
on every visit — dogfood 2026-08-05). The check's verdict only changes when
the backend behind the route changes, so the route now serves a cached result
inside a 24h TTL (`?force=true` bypasses). The cache rides the existing
per-model measurement row rather than a new table: same key, same lifecycle,
different cadence — hence separate columns, not a merged JSON blob.

Revision ID: 0023
Revises: 0022
Create Date: 2026-08-05
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("model_battery_results", sa.Column("fitness_result", sa.JSON(), nullable=True))
    op.add_column("model_battery_results", sa.Column("fitness_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("model_battery_results", "fitness_at")
    op.drop_column("model_battery_results", "fitness_result")
