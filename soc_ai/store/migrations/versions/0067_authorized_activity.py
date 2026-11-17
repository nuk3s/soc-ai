"""authorized_activity table, and the link from a run to its authorization

One CREATE TABLE and one nullable column on ``investigations``. No existing
value changes.

The owner runs exploit tests on the production grid. From 2026-10-31 to
2026-11-13, 18 of 27 true positive verdicts and 41 of 51 recommended actions
came from one such test. Each run asked for a case, and no record could say
"this activity is authorized".

One row of ``authorized_activity`` is one decision of an analyst.

* ``label`` is the name the analyst gives the activity. ``note`` is free text.
* The scope has three parts, and a run must match all three.
  ``sources`` is a list of ``{"address", "machine_key", "name"}``: the exact
  source addresses, each with the agent machine that reported it.
  ``target_address`` and ``target_machine_key`` name the target.
  ``rule_names`` is the list of exact rule names, and ``rule_class`` is the
  alert class of those rules. No prefix and no pattern matches.
* ``starts_at`` and ``expires_at`` bound the alert time. The expiry is
  mandatory. The store allows 30 days at most.
* ``revoked_at``, ``revoked_by`` and ``revoke_reason`` record a revoke. A
  revoked row matches nothing, and its runs get normal handling again.
* ``expiry_recorded_at`` is the time the expiry got its audit record. NULL
  means the record is not written yet.
* ``source_investigation_id`` is the run the analyst made the decision on.

``investigations.authorization_id`` is the authorization a run matched. It is
a column because the bell and the lists read scalar columns only, never the
report JSON. It has no foreign key, like ``hunt_id``: an authorization is
never deleted, and a run must not depend on one.

Revision ID: 0067
Revises: 0066
Create Date: 2026-11-13
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0067"
down_revision = "0066"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "authorized_activity",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("label", sa.String(length=120), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("sources", sa.JSON(), nullable=False),
        sa.Column("target_address", sa.String(length=64), nullable=False),
        sa.Column("target_machine_key", sa.String(length=128), nullable=True),
        sa.Column("target_name", sa.String(length=255), nullable=True),
        sa.Column("rule_names", sa.JSON(), nullable=False),
        sa.Column("rule_class", sa.String(length=32), nullable=False),
        sa.Column("source_investigation_id", sa.String(length=32), nullable=True),
        sa.Column("starts_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_by", sa.String(length=128), nullable=True),
        sa.Column("revoke_reason", sa.String(length=512), nullable=True),
        sa.Column("expiry_recorded_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_authorized_activity_expires", "authorized_activity", ["expires_at"])
    with op.batch_alter_table("investigations") as batch:
        batch.add_column(sa.Column("authorization_id", sa.Integer(), nullable=True))
        batch.create_index("ix_investigations_authorization", ["authorization_id"])


def downgrade() -> None:
    with op.batch_alter_table("investigations") as batch:
        batch.drop_index("ix_investigations_authorization")
        batch.drop_column("authorization_id")
    op.drop_index("ix_authorized_activity_expires", table_name="authorized_activity")
    op.drop_table("authorized_activity")
