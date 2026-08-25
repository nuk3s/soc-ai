"""Investigation kind + hunt promotion provenance

``investigations`` has always meant one thing: a Suricata alert under
analysis. Slice 1 of the hunting release promotes a cited hunt finding into
the same table (same list, same detail screen, same chat) instead of building
a parallel "finding" surface — but a promoted row has no alert in SO to ack,
so every SO-write surface needs a way to tell the two apart. ``kind``
carries that: ``'suricata'`` (the default, backfilled onto every existing
row via ``server_default``) for the alert-feed vocabulary, ``'hunt'`` for a
promotion.

``hunt_id`` + ``finding_ordinal`` are the promotion's provenance — which hunt,
and which zero-based index into that hunt's ``report["findings"]`` — so the
promoted investigation can always be traced back to the finding it came from.
Both are nullable because they're only set when ``kind == 'hunt'``.

Revision ID: 0031
Revises: 0030
Create Date: 2026-08-23
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0031"
down_revision = "0030"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "investigations",
        sa.Column("kind", sa.String(16), nullable=False, server_default="suricata"),
    )
    op.add_column("investigations", sa.Column("hunt_id", sa.String(32), nullable=True))
    op.add_column("investigations", sa.Column("finding_ordinal", sa.Integer(), nullable=True))
    op.create_index("ix_investigations_hunt_id", "investigations", ["hunt_id"])


def downgrade() -> None:
    op.drop_index("ix_investigations_hunt_id", table_name="investigations")
    op.drop_column("investigations", "finding_ordinal")
    op.drop_column("investigations", "hunt_id")
    op.drop_column("investigations", "kind")
