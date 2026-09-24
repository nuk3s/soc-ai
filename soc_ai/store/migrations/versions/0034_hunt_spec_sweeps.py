"""The sweep trail for the declarative hunt catalog

A sweep computed everything worth knowing about each spec — blind or seeing,
how many documents the precondition and the detection matched, what the gate
held back, what was truncated — and persisted none of it. A clean sweep left no
trace at all, so "did spec X run and see nothing" was unanswerable, and a spec
that had quietly gone blind or stopped firing looked identical to one that had
never been swept. The network sweep hit the same hole and closed it with
``dossier_run``; this is the same shape for the catalog.

One row per spec per sweep, written on EVERY run including a clean one. Pruned
to the newest 2000 rows at each write, which at four specs on the default
hourly cadence is about twenty days — an operations trail, not an archive.

Every counter carries a database default of zero so a writer that predates a
column, or a raw insert naming only the identity columns, never trips a NOT
NULL. ``shadow`` is on the row rather than inferred from a missing ``hunt_id``
because a clean live sweep also has no hunt, and the two must never be
conflated: one spent the fire-once budget and the other did not.

Revision ID: 0034
Revises: 0033
Create Date: 2026-09-05
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0034"
down_revision = "0033"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "hunt_spec_sweeps",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("spec_id", sa.String(80), nullable=False),
        sa.Column("shadow", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("blind", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("precondition_docs", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("matched_docs", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("fresh_candidates", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("already_handled", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("over_budget", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("truncated_docs", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("unattributed_docs", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("hunt_id", sa.String(32), nullable=True),
        sa.Column("window_since", sa.String(64), nullable=False),
        sa.Column("window_until", sa.String(64), nullable=False),
    )
    # The per-spec history view and the "newest row for this spec" lookup the
    # catalog status is built from.
    op.create_index(
        "ix_hunt_spec_sweeps_spec_created", "hunt_spec_sweeps", ["spec_id", "created_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_hunt_spec_sweeps_spec_created", table_name="hunt_spec_sweeps")
    op.drop_table("hunt_spec_sweeps")
