"""Host machines: one row per device above the per-address dossier.

The Hosts screen showed one row per IP address. A machine with several
addresses showed as several rows: fourteen for one proxy on production. The
``host_machine`` table holds the set of addresses that soc-ai holds to be one
device, and ``host_dossier`` gains the machine it belongs to and how the
address joined it.

``host_dossier.machine_id`` has no foreign key. The sweep rewrites the column
for every address at the end of each run, and a machine row that goes away
leaves the address to the next run. ``address_kind`` is one of ``agent``,
``dhcp``, ``name``, ``network`` and ``container``.

The upgrade writes no machine. The first sweep after it builds them.

Revision ID: 0054
Revises: 0053
Create Date: 2026-10-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0054"
down_revision = "0053"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "host_machine",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("machine_key", sa.String(128), nullable=False),
        sa.Column("name", sa.String(255), nullable=True),
        sa.Column("name_source", sa.String(16), nullable=True),
        sa.Column("names_json", sa.JSON(), nullable=True),
        sa.Column("primary_ip", sa.String(64), nullable=True),
        sa.Column("agent_id", sa.String(128), nullable=True),
        sa.Column("agent_name", sa.String(255), nullable=True),
        sa.Column("agent_last_report", sa.DateTime(), nullable=True),
        sa.Column("os", sa.String(255), nullable=True),
        sa.Column("macs_json", sa.JSON(), nullable=True),
        sa.Column("first_seen", sa.DateTime(), nullable=True),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.Column("event_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("address_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("container_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("merged_from_json", sa.JSON(), nullable=True),
        sa.Column("addresses_json", sa.JSON(), nullable=True),
        sa.Column("built_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("uq_host_machine_key", "host_machine", ["machine_key"], unique=True)
    op.create_index("ix_host_machine_agent_id", "host_machine", ["agent_id"])

    with op.batch_alter_table("host_dossier") as batch:
        batch.add_column(sa.Column("machine_id", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("address_kind", sa.String(16), nullable=True))
    op.create_index("ix_host_dossier_machine_id", "host_dossier", ["machine_id"])


def downgrade() -> None:
    op.drop_index("ix_host_dossier_machine_id", table_name="host_dossier")
    with op.batch_alter_table("host_dossier") as batch:
        batch.drop_column("address_kind")
        batch.drop_column("machine_id")
    op.drop_index("ix_host_machine_agent_id", table_name="host_machine")
    op.drop_index("uq_host_machine_key", table_name="host_machine")
    op.drop_table("host_machine")
