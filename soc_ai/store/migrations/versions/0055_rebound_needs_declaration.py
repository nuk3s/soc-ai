"""A rebound stamp stays only on an address that holds an operator declaration.

``host_dossier.identity_rebound_at`` exists to tell an operator "the machine
behind this address appears to have changed; your override may no longer
apply". The first machine sweep on production (2026-10-02T12:12:30Z) read
DHCP MACs that no build had read before. The fingerprint of every leased host
gained its MAC part, a whole-string compare stamped 41 machines "rebound", and
most of them held no declaration at all.

The builder now stamps only a part that moves to a different value, and only
on an address with a declaration. This upgrade clears the stamps that the old
rule left on the addresses with no declaration. The stamps on declared
addresses stay: the operator may still need to answer them. The fingerprints
stay too.

The downgrade does nothing. A cleared stamp held no information an operator
could act on, and there is no record of which rows held one.

Revision ID: 0055
Revises: 0054
Create Date: 2026-10-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0055"
down_revision = "0054"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.get_bind().execute(
        sa.text(
            "UPDATE host_dossier SET identity_rebound_at = NULL "
            "WHERE identity_rebound_at IS NOT NULL AND NOT EXISTS ("
            "SELECT 1 FROM host_dossier_field f WHERE f.dossier_id = host_dossier.id "
            "AND (f.operator_value IS NOT NULL OR f.operator_value_json IS NOT NULL))"
        )
    )


def downgrade() -> None:
    pass
