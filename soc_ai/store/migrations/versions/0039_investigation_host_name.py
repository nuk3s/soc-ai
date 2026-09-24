"""investigations.host_name: which machine a run's alert fired on

The inheritance key was ``(rule_name, src_ip, dest_ip)`` and a missing endpoint
coalesced to the empty string rather than being dropped, so every detection with
no network flow behind it keyed as ``(rule, "", "")``. That is not a cluster of
one subject. It is the whole rule, for all time, on every machine.

Measured on a live grid: 100 of 208 investigations carried that key, and one
Sigma rule held a false positive and a true positive under it at once, so
whichever landed last silenced the other everywhere. A separate rule verdicted
false positive was still firing at high severity on hosts it had never been
investigated on.

The addresses cannot fix this, because these detections have none. The host can:
Security Onion nests the originating endpoint document under ``event_data``, and
unwrapping it puts a real machine name on exactly the alerts that have no flow.

So the host joins the key, but ONLY when both endpoints are empty. On a
multi-sensor grid one flow is seen by two sensors under two ``host.name``
values, and keying a flow on the host would split one investigation in two. A
detection with no flow has no such collision to worry about.

NULL on every legacy row, which is the honest reading: those runs never recorded
which machine they were about, so they can only match a cluster that does not
know either, and that key carries no subject at all and is refused outright.

Revision ID: 0039
Revises: 0038
Create Date: 2026-09-07
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0039"
down_revision = "0038"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("investigations", sa.Column("host_name", sa.String(255), nullable=True))


def downgrade() -> None:
    op.drop_column("investigations", "host_name")
