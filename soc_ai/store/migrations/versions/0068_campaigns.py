"""campaign tables: campaigns, members, parties and the facts of each run

Four CREATE TABLE statements. No existing table changes.

A campaign is one story of an attack. The campaign engine builds it from the
stored runs: a true positive run is a seed, and each linked run is a member.
The engine writes the four tables, and the campaign routes read them. The
engine writes no other table.

One row of ``campaigns`` is one campaign.

* ``status`` is ``active``, ``withdrawn`` or ``merged``. A rebuild keeps the
  id of a campaign stable. A campaign that loses all its members is
  ``withdrawn``. A campaign whose members join a different campaign is
  ``merged``, and ``merged_into_id`` names that campaign.
* ``earlier_campaign_id`` is the newest other campaign that shares an actor
  and target pair with this one and ends before this one starts. NULL means
  there is none.
* ``seed_run_id`` is the run that started the campaign.
* ``title`` and ``bottom_line`` are the words the console shows.
* ``stage`` is the highest stage the members reach. NULL means no member
  states a stage.
* ``first_event`` and ``last_event`` bound the event times of the members.
* ``detail`` holds the ladder, the waves, the sessions, the named hosts, the
  detection record and the pairs of the campaign.
* ``built_at`` is the time of the rebuild that wrote the row.

One row of ``campaign_members`` is one run in one campaign. A run is a member
of one campaign at most. The unique index on ``run_id`` holds this rule.

* ``link`` is the link type that joins the run to the campaign, and
  ``evidence`` is the proof of that link.
* ``direction`` is ``forward``, ``reverse`` or ``beyond``.
* ``verdict_differs`` is true when the verdict of the run is not a true
  positive.
* ``actor_key`` and ``target_key`` are the machine keys of the two ends.

One row of ``campaign_parties`` is one machine in one campaign. A machine is
a party of a campaign once, and the unique index holds this rule.

* ``role`` is ``actor`` or ``target``.
* ``addresses`` is the list of the addresses of the machine.
* ``join_kind`` is ``agent``, ``dhcp`` or ``network``. It tells how the
  store joined an address to the machine.
* ``member_runs`` is the count of the members that name the machine.
* ``beyond`` is true for a target that only ``beyond`` members name.

One row of ``campaign_run_facts`` is what the engine reads of one run. A
rebuild then does not query the grid. ``basis`` holds the verdict and the
times of the run and the version of the facts. When the basis changes, the
engine reads the facts again.

``campaign_members.campaign_id`` and ``campaign_parties.campaign_id`` have a
foreign key to ``campaigns.id``. ``run_id``, ``seed_run_id``,
``merged_into_id`` and ``earlier_campaign_id`` have no foreign key, like
``hunt_id``. The engine builds the campaign rows from the runs, and a
campaign row must not block a change to a run.

Revision ID: 0068
Revises: 0067
Create Date: 2026-11-13
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0068"
down_revision = "0067"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "campaigns",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="active"),
        sa.Column("merged_into_id", sa.Integer(), nullable=True),
        sa.Column("earlier_campaign_id", sa.Integer(), nullable=True),
        sa.Column("seed_run_id", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("bottom_line", sa.Text(), nullable=False),
        sa.Column("stage", sa.String(length=16), nullable=True),
        sa.Column("first_event", sa.DateTime(), nullable=False),
        sa.Column("last_event", sa.DateTime(), nullable=False),
        sa.Column("member_count", sa.Integer(), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("built_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_campaigns_last_event", "campaigns", ["last_event"])

    op.create_table(
        "campaign_members",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("campaign_id", sa.Integer(), sa.ForeignKey("campaigns.id"), nullable=False),
        sa.Column("run_id", sa.String(length=32), nullable=False),
        sa.Column("link", sa.String(length=16), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("direction", sa.String(length=8), nullable=False),
        sa.Column("stage", sa.String(length=16), nullable=True),
        sa.Column("verdict_differs", sa.Boolean(), nullable=False),
        sa.Column("event_time", sa.DateTime(), nullable=True),
        sa.Column("actor_key", sa.String(length=128), nullable=True),
        sa.Column("target_key", sa.String(length=128), nullable=True),
    )
    op.create_index("ux_campaign_members_run", "campaign_members", ["run_id"], unique=True)
    op.create_index("ix_campaign_members_campaign", "campaign_members", ["campaign_id"])

    op.create_table(
        "campaign_parties",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("campaign_id", sa.Integer(), sa.ForeignKey("campaigns.id"), nullable=False),
        sa.Column("machine_key", sa.String(length=128), nullable=False),
        sa.Column("role", sa.String(length=8), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=True),
        sa.Column("addresses", sa.JSON(), nullable=False),
        sa.Column("join_kind", sa.String(length=16), nullable=True),
        sa.Column("first_event", sa.DateTime(), nullable=True),
        sa.Column("last_event", sa.DateTime(), nullable=True),
        sa.Column("member_runs", sa.Integer(), nullable=False),
        sa.Column("beyond", sa.Boolean(), nullable=False),
    )
    op.create_index(
        "ux_campaign_parties_machine",
        "campaign_parties",
        ["campaign_id", "machine_key"],
        unique=True,
    )

    op.create_table(
        "campaign_run_facts",
        sa.Column("run_id", sa.String(length=32), primary_key=True),
        sa.Column("basis", sa.String(length=160), nullable=False),
        sa.Column("facts", sa.JSON(), nullable=False),
        sa.Column("built_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("campaign_run_facts")
    op.drop_index("ux_campaign_parties_machine", table_name="campaign_parties")
    op.drop_table("campaign_parties")
    op.drop_index("ix_campaign_members_campaign", table_name="campaign_members")
    op.drop_index("ux_campaign_members_run", table_name="campaign_members")
    op.drop_table("campaign_members")
    op.drop_index("ix_campaigns_last_event", table_name="campaigns")
    op.drop_table("campaigns")
