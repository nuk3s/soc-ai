"""quality_snapshots: the alarm's identity (alarm_key) and its duration (alarm_since)

Two nullable columns, no backfill and no default.

**Why an identity column at all.** The regression detector re-decides from
scratch on every run and keeps no memory, so the caller could only ask "did
this run alarm?" — and fired an audit event plus a webhook every time the
answer was yes. A condition that PERSISTS answers yes every night it persists,
so one problem paged repeatedly: prod rows 9, 10 and 11 are the same
"agreement 0.80 against a median of 1.00" condition alarming three times in 27
hours, and 7 of the install's 28 snapshots are alarmed. Comparing the stored
``alarm_reasons`` instead cannot help — every reason string embeds the live
numbers behind it, so the same unchanged condition renders as a different
string each night. ``alarm_key`` is the sorted rule codes joined
(``"agreement_drop"``, ``"agreement_drop+error_ceiling"``, …), which is stable
across re-observations by construction, so the writer can fire side effects
only on a TRANSITION into a condition.

**Why ``alarm_since`` is stored and not derived.** The card needs "ongoing
since 08-06, 3 runs" — and the run that could derive it is the one being
written, against history that pruning (newest 90) is free to have removed.
Carrying the previous same-mode row's value forward while the key is unchanged
keeps the start date exact for as long as the condition lasts, and costs one
column instead of a scan.

**Why NULL and not a backfill.** A pre-0027 row's key is genuinely unknown: the
codes were never recorded and the reason strings cannot be parsed back into
them reliably (their text has changed twice). The writer treats NULL as
unknown-not-equal, so the first alarm after an upgrade fires — the safe
direction — and stamps a fresh ``alarm_since``. Inventing a key for old rows
would instead risk matching the new one and swallowing the first real page.

SQLite ADD COLUMN is metadata-only for nullable columns without a default, so
this is O(1) regardless of table size (capped at 90 rows anyway).

Revision ID: 0027
Revises: 0026
Create Date: 2026-08-07
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("quality_snapshots", sa.Column("alarm_key", sa.Text(), nullable=True))
    op.add_column("quality_snapshots", sa.Column("alarm_since", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("quality_snapshots", "alarm_since")
    op.drop_column("quality_snapshots", "alarm_key")
