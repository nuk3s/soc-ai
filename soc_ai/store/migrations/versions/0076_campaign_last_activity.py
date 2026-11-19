"""campaign last activity: two columns of ``campaigns`` hold what the end rule reads

Two ADD COLUMN on ``campaigns``, ``last_alert_at`` and ``events_to``. No
other value changes.

The owner, 2026-11-19: "A later alert of a confirmed rule keeps a campaign
open." An active campaign ended one horizon after its last investigation
event. A later alert of the same rule between the same machines takes its
verdict from the earlier investigation, so it moves no investigation event,
and the campaign ended while its alerts went on. The end rule now reads the
last activity: the later of ``last_event`` and the last alert event of a
confirmed rule that a grid read saw. A SQL selector needs both times, so
both live in columns.

* ``last_alert_at`` is the time of the last alert event of a confirmed rule
  between the machines of the campaign that a grid read saw. NULL with no
  grid read and with no such alert.
* ``events_to`` is the end of the window that the grid reads covered. NULL
  with no grid read and for a read of an earlier release.

The fill reads the stored grid read of each campaign (``events``, migration
0069) in pages of 500 by id. ``last_alert_at`` takes the value of
:func:`soc_ai.campaigns.events.last_alert_of`, so the value is the one that
the store writes. A read of an earlier release holds no last alert time, and
its pairs give it. ``events_to`` takes the field ``read_to`` of the read. A
row with no grid read keeps two NULL values. SQL alone cannot state the rule
on both dialects: the JSON paths and the parse of an ISO time differ.

Alembic runs the migration once. SQLite ADD COLUMN is metadata-only for a
nullable column with no default.

Revision ID: 0076
Revises: 0075
Create Date: 2026-11-19
"""

from __future__ import annotations

import json
from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "0076"
down_revision = "0075"
branch_labels = None
depends_on = None

# The rows that one page of the fill reads.
_PAGE = 500


def upgrade() -> None:
    op.add_column("campaigns", sa.Column("last_alert_at", sa.DateTime(), nullable=True))
    op.add_column("campaigns", sa.Column("events_to", sa.DateTime(), nullable=True))
    fill(op.get_bind())


def _stored(value: Any) -> Any:
    """A JSON value as the driver gives it: text on SQLite, a decoded value elsewhere."""
    if isinstance(value, str | bytes):
        try:
            return json.loads(value)
        except ValueError:
            return None
    return value


def fill(bind: sa.Connection, page: int = _PAGE) -> int:
    """Set the two columns from the stored grid read of each campaign. Returns the count."""
    # Lazy, as in 0072: the rule of the store fills the column.
    from soc_ai.campaigns import events as campaign_events  # noqa: PLC0415
    from soc_ai.campaigns.types import naive_utc  # noqa: PLC0415

    rows_sql = sa.text(
        "SELECT id, events FROM campaigns WHERE id > :last AND events IS NOT NULL "
        "ORDER BY id LIMIT :page"
    )
    # Typed, so each dialect stores the value as the column type stores it.
    update_sql = sa.text(
        "UPDATE campaigns SET last_alert_at = :alert, events_to = :to WHERE id = :id"
    ).bindparams(
        sa.bindparam("alert", type_=sa.DateTime()),
        sa.bindparam("to", type_=sa.DateTime()),
    )
    moved = 0
    last = 0
    while True:
        rows = bind.execute(rows_sql, {"last": last, "page": page}).all()
        if not rows:
            return moved
        last = int(rows[-1][0])
        values = []
        for campaign_id, raw in rows:
            held = _stored(raw)
            if not isinstance(held, dict) or held.get("source") != campaign_events.SOURCE_GRID:
                continue
            alert = campaign_events.last_alert_of(held)
            to = naive_utc(held.get("read_to"))
            if alert is not None or to is not None:
                values.append({"alert": alert, "to": to, "id": campaign_id})
        if values:
            bind.execute(update_sql, values)
        moved += len(values)


def downgrade() -> None:
    op.drop_column("campaigns", "events_to")
    op.drop_column("campaigns", "last_alert_at")
