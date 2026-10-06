"""The estate model records its fits and the learned peer group of each host.

Tier 3 of the detection design fits a model of the whole estate once a day.
It groups hosts that act alike by clustering their behaviour vectors, and it
scores each host for how far it sits from the estate. Two tables hold what a
fit produced:

* ``estate_model_fits``: one row per fit. It records the sha256 of the model
  file the fit wrote under ``<data dir>/models/estate/``. soc-ai loads a model
  file only when the hash of its bytes matches the hash this table records for
  the file name. The row also holds the state of the model (measured,
  learning, drifted or held), the population stability index against the
  previous fit, the centroid of each group, and the counts of the fit.
* ``estate_peer_groups``: the learned group of each host, with its distance to
  the group centroid, its outlier score, the model hash and the fit time. A
  host with no declared role reads the hosts of its learned group as its peers.

Both tables start empty. The estate model is off by default
(``estate_model_enabled``), and it needs the ``ml`` extra.

Revision ID: 0059
Revises: 0058
Create Date: 2026-10-04
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0059"
down_revision = "0058"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "estate_model_fits",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("fitted_at", sa.DateTime(), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("model_sha256", sa.String(length=64), nullable=True),
        sa.Column("model_file", sa.String(length=255), nullable=True),
        sa.Column("hosts", sa.Integer(), nullable=False),
        sa.Column("features", sa.Integer(), nullable=False),
        sa.Column("groups", sa.Integer(), nullable=False),
        sa.Column("silhouette", sa.Float(), nullable=True),
        sa.Column("support_days", sa.Integer(), nullable=True),
        sa.Column("psi", sa.Float(), nullable=True),
        sa.Column("drifted_json", sa.JSON(none_as_null=True), nullable=True),
        sa.Column("groups_json", sa.JSON(none_as_null=True), nullable=True),
        sa.Column("outliers", sa.Integer(), nullable=False),
        sa.Column("unexplained", sa.Integer(), nullable=False),
        sa.Column("shared", sa.Integer(), nullable=False),
        sa.Column("no_documents", sa.Integer(), nullable=False),
        sa.Column("observations", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("challenger_until", sa.DateTime(), nullable=True),
        sa.Column("audited", sa.Boolean(), nullable=False, server_default="0"),
    )
    op.create_index("ix_estate_model_fit_at", "estate_model_fits", ["fitted_at"])
    op.create_index("ix_estate_model_fit_sha", "estate_model_fits", ["model_sha256"])
    op.create_table(
        "estate_peer_groups",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("entity_kind", sa.String(length=16), nullable=False),
        sa.Column("entity_key", sa.String(length=255), nullable=False),
        sa.Column("group_id", sa.Integer(), nullable=False),
        sa.Column("distance", sa.Float(), nullable=False),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("model_sha256", sa.String(length=64), nullable=False),
        sa.Column("fitted_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("entity_kind", "entity_key", name="uq_estate_peer_group_entity"),
    )
    op.create_index("ix_estate_peer_group_group", "estate_peer_groups", ["group_id"])


def downgrade() -> None:
    op.drop_index("ix_estate_peer_group_group", table_name="estate_peer_groups")
    op.drop_table("estate_peer_groups")
    op.drop_index("ix_estate_model_fit_sha", table_name="estate_model_fits")
    op.drop_index("ix_estate_model_fit_at", table_name="estate_model_fits")
    op.drop_table("estate_model_fits")
