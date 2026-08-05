"""model_battery_results: last fitness-battery run per analyst model

The Config console's fitness battery (design spec 2026-08-05) probes a model
under every structured-output configuration and recommends the winner. The
measurement is slow on lesser backends (minutes on a CPU tier), so the last
result persists per model: re-selecting a probed model renders its stored
result + age instantly, with a re-run button for when the backend behind the
route changes.

Design notes:

* ``model`` (the LiteLLM route name) is the natural primary key — one row per
  model, upsert-replaced per run. Run history lives in the ``model_battery``
  audit events, not here.
* ``result`` is the whole ``run_battery`` report as JSON: per-config probe
  outcomes, recommendation, timings. Schema-less on purpose — the report shape
  is owned by ``soc_ai.model_probe`` and rendered client-side.

Revision ID: 0022
Revises: 0021
Create Date: 2026-08-05
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "model_battery_results",
        sa.Column("model", sa.String(length=256), primary_key=True),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("model_battery_results")
