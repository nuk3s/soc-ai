"""rule decisions: the decisions on a rule, and the grid state of an alert

Two new tables, ``rule_decisions`` and ``rule_alert_states``. No existing
value changes.

Round 3 (2026-11-19): soc-ai gives a false positive verdict, and a guard of
the automatic acknowledge holds the write. The store cannot tell if the alert
is still open: an acknowledge from another investigation, from the inherited
fan-out or from Security Onion leaves no row. A background step asks the grid
for the alerts of the open false positives and stores the answer here
(:mod:`soc_ai.webui.rule_decisions`).

* ``alert_es_id`` names the alert. It has no foreign key: one alert can have
  many investigations.
* ``state`` is ``open``, ``acknowledged`` or ``gone``.
* ``read_at`` is the time of the read, naive UTC.

``rule_decisions`` holds one row for each decision of the analyst on the open
false positives of a rule. ``decision`` is ``acknowledge`` or ``standing``.
``state`` is ``acknowledging`` while the background work runs, then ``done``
or ``failed``. ``alerts``, ``failed`` and ``investigations`` count the
result. ``ends_at``, ``ended_at`` and ``end_cause`` hold the term and the end
of a standing decision. ``acknowledged`` counts the acknowledges under a
standing decision. The index serves the read of the decisions of one rule.

No fill here. The background step reads the grid.

Revision ID: 0075
Revises: 0074
Create Date: 2026-11-18
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0075"
down_revision = "0074"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rule_decisions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("rule_name", sa.String(length=512), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("include_weak", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.Column("decided_by", sa.String(length=64), nullable=False),
        sa.Column("decided_at", sa.DateTime(), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("alerts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("investigations", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("acknowledged", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("ends_at", sa.DateTime(), nullable=True),
        sa.Column("ended_at", sa.DateTime(), nullable=True),
        sa.Column("end_cause", sa.String(length=32), nullable=True),
        sa.Column("ended_by", sa.String(length=64), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=True),
    )
    op.create_index("ix_rule_decisions_rule", "rule_decisions", ["rule_name", "decided_at"])
    op.create_table(
        "rule_alert_states",
        sa.Column("alert_es_id", sa.String(length=128), primary_key=True),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("read_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("rule_alert_states")
    op.drop_index("ix_rule_decisions_rule", table_name="rule_decisions")
    op.drop_table("rule_decisions")
