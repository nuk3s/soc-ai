"""investigation event time: the time of the event that an investigation judges

One ADD COLUMN on ``investigations``, ``event_at``, and one index on it.

The owner, 2026-11-15: a hunt and a Re-run judged events of 3 and 17 days
ago, and the list dated them "1h ago". For the analyst, the time of an
investigation is the time of its event. The list, the confirmed threats and
their windows read ``event_at``. ``created_at`` stays the time when soc-ai
investigated.

The rule is :func:`soc_ai.store.event_at.decide`: the settled event time
(``report["event_time"]``), else the time of the stored alert (the
``alert.timestamp`` of the first context event), else ``created_at``.

The fill has two parts, both in this migration:

1. One plain UPDATE sets ``event_at = created_at`` on every row. No row
   holds a null, and a row with no better time keeps the windows that it
   was in before the upgrade.
2. A pass in Python reads the rows in pages of 500 by id and calls the
   rule itself, so the value is the one that the store writes. It reads
   one field of each report and of each context event, never the payload,
   and writes only the rows whose value moves. SQL alone cannot state the
   rule on both dialects: the parse of an ISO time with an offset differs.
   Migration 0044 fills a column in Python the same way.

Alembic runs the migration once. A start after it reads no row, so no
startup step and no marker exist.

SQLite ADD COLUMN is metadata-only for a nullable column with no default.

Revision ID: 0072
Revises: 0071
Create Date: 2026-11-16
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0072"
down_revision = "0071"
branch_labels = None
depends_on = None

# The event kinds that hold the alert of a run. The same tuple as
# ``soc_ai.store.investigations._CONTEXT_EVENT_KINDS``.
_CONTEXT_KINDS = ("alert_context", "enriched_alert_context")
# The rows that one page of the fill reads.
_PAGE = 500


def upgrade() -> None:
    op.add_column("investigations", sa.Column("event_at", sa.DateTime(), nullable=True))
    op.create_index("ix_investigations_event_at", "investigations", ["event_at"])
    bind = op.get_bind()
    bind.execute(sa.text("UPDATE investigations SET event_at = created_at"))
    fill(bind)


def fill(bind: sa.Connection, page: int = _PAGE) -> int:
    """Move ``event_at`` to the rule where a row states an earlier time. Returns the count."""
    from soc_ai.store import event_at as rule  # noqa: PLC0415 - lazy, as in 0044

    sqlite = bind.dialect.name == "sqlite"
    stored = "json_extract(report, '$.event_time')" if sqlite else "report #>> '{event_time}'"
    alert = (
        "json_extract(payload, '$.alert.timestamp')"
        if sqlite
        else "payload #>> '{alert,timestamp}'"
    )
    rows_sql = sa.text(
        f"SELECT id, created_at, {stored} FROM investigations "  # noqa: S608 - fixed text
        "WHERE id > :last ORDER BY id LIMIT :page"
    )
    alerts_sql = sa.text(
        f"SELECT investigation_id, {alert} FROM investigation_events "  # noqa: S608 - fixed text
        "WHERE investigation_id IN :ids AND kind IN :kinds "
        "ORDER BY investigation_id, sequence, id"
    ).bindparams(sa.bindparam("ids", expanding=True), sa.bindparam("kinds", expanding=True))
    # Typed, so each dialect stores the value as the column type stores it.
    update_sql = sa.text("UPDATE investigations SET event_at = :at WHERE id = :id").bindparams(
        sa.bindparam("at", type_=sa.DateTime())
    )
    moved = 0
    last = ""
    while True:
        rows = bind.execute(rows_sql, {"last": last, "page": page}).all()
        if not rows:
            return moved
        last = str(rows[-1][0])
        raws: dict[str, list[object]] = {}
        need = [str(r[0]) for r in rows if rule.parse_time(r[2]) is None]
        if need:
            for run_id, raw in bind.execute(
                alerts_sql, {"ids": need, "kinds": list(_CONTEXT_KINDS)}
            ).all():
                raws.setdefault(str(run_id), []).append(raw)
        values = []
        for run_id, created, raw in rows:
            created_at = rule.parse_time(created)
            if created_at is None:
                continue
            at = rule.decide(
                report={rule.EVENT_TIME_KEY: raw},
                alert_at=rule.first_time(raws.get(str(run_id), [])),
                created_at=created_at,
            )
            if at != created_at:
                values.append({"at": at, "id": run_id})
        if values:
            bind.execute(update_sql, values)
        moved += len(values)


def downgrade() -> None:
    op.drop_index("ix_investigations_event_at", table_name="investigations")
    op.drop_column("investigations", "event_at")
