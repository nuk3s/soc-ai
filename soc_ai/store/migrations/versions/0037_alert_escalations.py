"""alert_escalations: which alerts soc-ai has already put on a case

Group escalate decided an alert was already on a case by reading
``event.acknowledged``/``event.escalated`` off the alert document. Security
Onion writes neither when soc-ai attaches an alert to a case: the attach route
``POST /api/case/events`` creates a related document on the case and touches
the alert not at all. On the Elastic Defend endpoint alert index, where the
console's own writes land in ``_source`` that no query can reach either, that
left the guard inert for the only case it existed to stop.

Measured on the range on 2026-09-06 against an 18-event group holding exactly
one unwritten alert: two presses, six seconds apart, both reported one
escalated and seventeen already escalated, and Security Onion ended with two
cases pointing at the same alert.

This table is the fact soc-ai records rather than infers. The unique index on
``alert_id`` is the guard itself: the row is claimed before the case is opened,
so concurrent presses collide on the insert instead of on the case.

Revision ID: 0037
Revises: 0036
Create Date: 2026-09-06
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0037"
down_revision = "0036"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "alert_escalations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("alert_id", sa.String(512), nullable=False),
        # NULL until Security Onion answers. A row that stays NULL is an
        # escalate whose outcome is unknown, not one that is known to have
        # failed, so it is reconciled against the grid rather than dropped.
        sa.Column("case_id", sa.String(128), nullable=True),
        sa.Column("escalated_by", sa.String(128), nullable=False, server_default="unknown"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_alert_escalations_alert_id", "alert_escalations", ["alert_id"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_alert_escalations_alert_id", table_name="alert_escalations")
    op.drop_table("alert_escalations")
