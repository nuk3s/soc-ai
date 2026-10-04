"""Lead decisions as a history, and the time an analyst reopened a lead.

``leads.decisions_json`` holds every decision on a lead in order: a
dismissal, a reopen, a promotion, a close by the settle rule, and a hold
when a hunt could not settle the lead. The single set of dismissal columns
held one decision. A dismiss after a reopen wrote over the first one, and a
reopened or promoted lead kept the old dismissal as its current state.

``leads.reopened_at`` marks a lead an analyst reopened. The dismissal
columns used to carry that mark, so they could not be cleared on a reopen.
The loop and the settle rule read the new column to leave the lead to the
analyst.

The upgrade moves the old state into the history. A lead that is open,
hunting or promoted and still carries a dismissal was reopened: the
dismissal and the reopen go into the history, the reopen time is set, and
the dismissal columns are cleared.

Revision ID: 0053
Revises: 0052
Create Date: 2026-10-01
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "0053"
down_revision = "0052"
branch_labels = None
depends_on = None

# The settle rule's hand. A copy, because a migration must not import the app.
_AUTO_HUNT_ACTOR = "auto-hunt"


def _iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, str) and value:
        return value.replace(" ", "T")
    return None


def upgrade() -> None:
    with op.batch_alter_table("leads") as batch:
        batch.add_column(sa.Column("decisions_json", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("reopened_at", sa.DateTime(), nullable=True))

    bind = op.get_bind()
    rows = bind.execute(
        sa.text(
            "SELECT id, status, updated_at, dismissed_reason, dismissed_note, dismissed_by, "
            "dismissed_at, investigation_id FROM leads "
            "WHERE dismissed_at IS NOT NULL OR status = 'promoted'"
        )
    ).all()
    for row in rows:
        lead_id, status, updated_at, reason, note, by, at, inv = row
        history: list[dict[str, Any]] = []
        if at is not None:
            by_rule = by == _AUTO_HUNT_ACTOR
            history.append(
                {
                    "action": "closed_by_hunt" if by_rule else "dismissed",
                    "at": _iso(at),
                    "by": by,
                    "reason": reason,
                    "note": note,
                }
            )
        reopened = at is not None and status in ("open", "hunting", "promoted")
        if reopened:
            history.append({"action": "reopened", "at": _iso(updated_at), "by": None})
        if status == "promoted":
            history.append(
                {
                    "action": "promoted",
                    "at": _iso(updated_at),
                    "by": None,
                    "investigation_id": inv,
                }
            )
        params: dict[str, Any] = {"id": lead_id, "history": json.dumps(history)}
        if reopened:
            bind.execute(
                sa.text(
                    "UPDATE leads SET decisions_json = :history, reopened_at = :reopened, "
                    "dismissed_reason = NULL, dismissed_note = NULL, dismissed_by = NULL, "
                    "dismissed_at = NULL WHERE id = :id"
                ),
                {**params, "reopened": updated_at},
            )
        else:
            bind.execute(
                sa.text("UPDATE leads SET decisions_json = :history WHERE id = :id"), params
            )


def downgrade() -> None:
    with op.batch_alter_table("leads") as batch:
        batch.drop_column("reopened_at")
        batch.drop_column("decisions_json")
