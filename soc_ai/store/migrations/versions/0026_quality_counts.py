"""quality_snapshots: the grade counts behind agreement_rate

Four nullable INTEGER columns, no backfill and no default.

**Why counts, when the rate was already stored.** ``agreement_rate`` is a
point estimate over ``quality_nightly_n`` alerts — 5 by default — so it can
only take the values 0.0, 0.2, 0.4 … and the regression detector was comparing
one such value against the MEDIAN of seven others. At n=5 that rule reduces to
"alarm iff two of the five oracle grades flipped", which under the install's
own historical agreement (107 of 120 critiques = 0.892) happens with
probability 0.094 — roughly one false alarm every eleven nights. Rates cannot
be pooled or tested; counts can. With these columns the detector pools the
trailing history into one baseline and asks the exact binomial question
instead (:func:`soc_ai.eval.quality.detect_regression`).

**Why NULL and not 0.** Existing rows have no counts and never will — the
batch artifacts they were derived from are long pruned. NULL is the sentinel
that says "pre-0026 row"; the detector reads it and falls back to the median
rule those rows were written under, so the alarm keeps working through the
days it takes new history to accumulate. A 0 backfill would instead read as
"the oracle classified nothing", quietly poisoning the pooled baseline.

``n_partial``/``n_no`` are not needed by the detector: they exist so the
Quality card can say "3 agree, 2 partial" instead of a bare 0.60. A partial
critique ("right verdict, thin reasoning") counts in the rate's denominator
but not its numerator, so on an n=5 batch it costs the same 0.2 as a flat
disagreement — a distinction the stored rate erased.

SQLite ADD COLUMN is a metadata-only operation for nullable columns without a
default, so this is O(1) regardless of table size (capped at 90 rows anyway).

Revision ID: 0026
Revises: 0025
Create Date: 2026-08-07
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None

_COLUMNS = ("n_yes", "n_partial", "n_no", "n_classified")


def upgrade() -> None:
    for name in _COLUMNS:
        op.add_column("quality_snapshots", sa.Column(name, sa.Integer(), nullable=True))


def downgrade() -> None:
    for name in reversed(_COLUMNS):
        op.drop_column("quality_snapshots", name)
