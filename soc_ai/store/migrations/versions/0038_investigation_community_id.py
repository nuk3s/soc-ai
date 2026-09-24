"""investigations.community_id: which network session a run covered

Two alerts from one TCP session, twenty-eight minutes apart, reached opposite
verdicts on the range: one true positive recommending escalation, one false
positive recommending acknowledgement. Same source, same destination, same
port, same community id, same fifty-nine second window. An analyst working the
queue top down meets the false positive first, acknowledges on the product's
recommendation, and never reaches the row that says the same session was
lateral movement.

Nothing on the investigations row could see that. The finest key it carried was
``(rule_name, src_ip, dest_ip)``, which has no ports and no protocol in it, so
two different sessions between the same pair are indistinguishable and two
alerts on ONE session are only related if they also share a rule name. The
community id is the hashed five-tuple, which is exactly the identity that was
missing, and it is already on every network alert soc-ai reads.

Stamped the same way ``src_ip``/``dest_ip`` are: off the enriched alert as the
run records it, only if not already set. NULL on every legacy row and on every
alert with no network session behind it (endpoint alerts, promoted hunt
findings), and the lookup treats NULL as "no session", never as a match.

Revision ID: 0038
Revises: 0037
Create Date: 2026-09-07
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0038"
down_revision = "0037"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("investigations", sa.Column("community_id", sa.String(128), nullable=True))
    # The lookup is "completed verdicts on this session, newest first", so the
    # index carries created_at too and the window filter reads off the index
    # rather than the rows.
    op.create_index(
        "ix_investigations_session",
        "investigations",
        ["community_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_investigations_session", table_name="investigations")
    op.drop_column("investigations", "community_id")
