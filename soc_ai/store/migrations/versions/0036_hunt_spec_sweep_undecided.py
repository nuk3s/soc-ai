"""hunt_spec_sweeps.undecided_docs: documents the run could not decide

An exclusion is a statement about documents that carry the field it reads, so
the compiled detection requires the field present. That is correct and it is
also a deletion: every document without the field is dropped from the query
with nothing counting it. Where the field is missing because the event arrived
from a second dataset with a different schema, dropping it is what the rule is
for. Where the field is one Windows simply does not populate for that kind of
event, the same rule deletes the population the spec is about.

Measured on the development range over 2026-09-05, a 4624 network-logon spec
excluding machine accounts: 10,844 documents in the precondition and 5,240 in
the detection before the presence rule, 182 and 0 after. 182 is greater than
zero, so the run was not blind, and it reported clean over 5,240 documents.
Windows writes no SubjectUserName on a network logon at all; the subject there
is the null SID.

The run now counts those documents in their own query and reports them. This
column is where the sweep trail keeps the number, so a clean-looking row can be
told from one that discarded thousands. Separate from ``unattributed_docs``,
which counts documents that DID match and could not be grouped by scope: one
column for both would answer neither question.

Server default zero, like every other counter on this table, so a row written
by an older writer or a raw insert naming only the identity columns never trips
a NOT NULL.

Revision ID: 0036
Revises: 0035
Create Date: 2026-09-06
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0036"
down_revision = "0035"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "hunt_spec_sweeps",
        sa.Column("undecided_docs", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("hunt_spec_sweeps", "undecided_docs")
