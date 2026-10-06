"""A run records what it cost and its budget class. The rule prior records its decisions.

Every investigation and every hunt gains seven nullable columns, stamped at
finalize by the recorder from the run's own events: the budget class, the
model requests, the input and output tokens, the tool calls, the
Elasticsearch searches and the wall time in milliseconds. The store held the
model usage of a triage run as events only, and nothing for a hunt. No store
held a search count. The 2026-10-04 survey computed every cost table by hand
for that reason.

A row written before this upgrade keeps NULL in each column. Its cost is
unknown, and a reader says so. The usage report derives the tokens and the
tool calls of an older triage run from its stored events.

The ``rule_prior_decisions`` table records what the rule prior decided for
each scheduled alert, why it did or did not apply, and the real verdict
beside it. A disagreement with no clearance suspends the prior for its rule.

Revision ID: 0058
Revises: 0057
Create Date: 2026-10-04
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0058"
down_revision = "0057"
branch_labels = None
depends_on = None

_COUNTER_TABLES = ("investigations", "hunts")
_COUNTER_COLUMNS = (
    "model_requests",
    "input_tokens",
    "output_tokens",
    "tool_calls",
    "es_searches",
    "wall_ms",
)


def upgrade() -> None:
    for table in _COUNTER_TABLES:
        op.add_column(table, sa.Column("run_class", sa.String(length=16), nullable=True))
        for column in _COUNTER_COLUMNS:
            op.add_column(table, sa.Column(column, sa.Integer(), nullable=True))
    op.create_table(
        "rule_prior_decisions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("rule_name", sa.String(length=512), nullable=False),
        sa.Column("alert_es_id", sa.String(length=128), nullable=False),
        sa.Column("mode", sa.String(length=8), nullable=False),
        sa.Column("applies", sa.Boolean(), nullable=False),
        sa.Column("reason", sa.String(length=64), nullable=False),
        sa.Column("sampled", sa.Boolean(), nullable=False),
        sa.Column("source_investigation_id", sa.String(length=32), nullable=True),
        sa.Column("would_verdict", sa.String(length=32), nullable=True),
        sa.Column("would_confidence", sa.Float(), nullable=True),
        sa.Column("investigation_id", sa.String(length=32), nullable=True),
        sa.Column("real_verdict", sa.String(length=32), nullable=True),
        sa.Column("agree", sa.Boolean(), nullable=True),
        sa.Column("cleared_at", sa.DateTime(), nullable=True),
        sa.Column("cleared_by", sa.String(length=80), nullable=True),
    )
    op.create_index(
        "ix_rule_prior_decisions_rule",
        "rule_prior_decisions",
        ["rule_name", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_rule_prior_decisions_rule", table_name="rule_prior_decisions")
    op.drop_table("rule_prior_decisions")
    for table in _COUNTER_TABLES:
        with op.batch_alter_table(table) as batch:
            for column in reversed(_COUNTER_COLUMNS):
                batch.drop_column(column)
            batch.drop_column("run_class")
