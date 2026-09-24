"""Fire-once state for the declarative hunt catalog

A spec runs on a loop over a rolling window, so without memory a condition that
persists fires on every sweep. On a one-analyst SOC that is the whole
false-positive problem: not the first notification, the ninetieth. This table
gives a spec the memory to fire once per condition and then stay quiet.

Three columns in it are load-bearing and are here from the start rather than
retrofitted, because each is expensive to add to a live state table whose
primary key everything else joins on.

``scope_kind`` — a candidate's entity is not always a host. It is an account for
the identity specs, a source address for the decoy one, and would be an IAM
principal or a mailbox for the cloud planes the range already carries. Adding a
kind discriminator later would mean rewriting every row's identity.

``disposition`` — separates a condition SEEN during a historical backfill from
one that FIRED live. When a spec is first added, sweeping full retention marks
every historical occurrence as seen; if those rows were indistinguishable from
live firings, the operator who adds the DCSync spec on Monday would have the
one finding they care about permanently suppressed by the very mechanism meant
to protect them. A ``backfill_seed`` row still permits one live firing.

``fingerprint`` — what actually changed, not merely that the scope was seen
before. A spec that surfaces the same account for a NEW reason must be able to
fire again.

No unique constraint on (spec_id, scope_key): the disposition split means one
scope legitimately holds a backfill_seed row and a later fired row. Uniqueness
is on the full (spec_id, scope_key, fingerprint, disposition) tuple, which is
what the gate reads.

Revision ID: 0033
Revises: 0032
Create Date: 2026-09-04
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0033"
down_revision = "0032"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "hunt_spec_state",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("spec_id", sa.String(80), nullable=False),
        sa.Column("scope_key", sa.String(255), nullable=False),
        sa.Column("scope_kind", sa.String(24), nullable=False, server_default="host"),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        # fired | backfill_seed | suppressed | dismissed
        sa.Column("disposition", sa.String(16), nullable=False, server_default="fired"),
        sa.Column("doc_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("anchor_id", sa.String(64), nullable=True),
        sa.Column("anchor_index", sa.String(255), nullable=True),
        sa.Column("hunt_id", sa.String(32), nullable=True),
        sa.Column("first_seen", sa.DateTime(), nullable=True),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        # Declared INSIDE create_table, not via create_unique_constraint:
        # SQLite has no ALTER TABLE ADD CONSTRAINT, so the separate call raises
        # NotImplementedError and would only be reachable through batch mode's
        # copy-and-move. Inline costs nothing on a new table.
        sa.UniqueConstraint(
            "spec_id",
            "scope_key",
            "fingerprint",
            "disposition",
            name="uq_hunt_spec_state_condition",
        ),
    )
    # Sweep-time lookup and the per-spec history view.
    op.create_index("ix_hunt_spec_state_spec_scope", "hunt_spec_state", ["spec_id", "scope_key"])


def downgrade() -> None:
    op.drop_index("ix_hunt_spec_state_spec_scope", table_name="hunt_spec_state")
    # No drop_constraint: the unique constraint is part of the table definition
    # (SQLite cannot ALTER it in or out), so dropping the table takes it too.
    op.drop_table("hunt_spec_state")
