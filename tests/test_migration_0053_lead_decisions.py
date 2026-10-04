"""Migration 0053: lead decisions become a history, and a reopen clears the dismissal.

Steps 0052 to 0053 by name, inserts pre-0053 lead rows through raw SQL, and
asserts the upgrade moves each old state into ``decisions_json``:

- a reopened lead (open with a dismissal) gets two entries, a reopen time,
  and no current dismissal (RA21: lead 9 open still read benign_repeat);
- a promoted lead with a dismissal (lead 13) gets three entries and no
  current dismissal;
- a dismissed lead keeps its dismissal and gets one entry;
- a lead the settle rule closed gets one ``closed_by_hunt`` entry;
- a lead with no decision gets no history.
"""

from __future__ import annotations

import json

from alembic import command
from soc_ai.config import Settings
from soc_ai.store.db import _migration_config, make_engine
from sqlalchemy import Connection, text


def _upgrade_to(connection: Connection, revision: str) -> None:
    cfg = _migration_config()
    cfg.attributes["connection"] = connection
    command.upgrade(cfg, revision)


def _seed(connection: Connection) -> None:
    rows = [
        (1, "open", "benign_repeat", "ann", "2026-09-30 10:00:00", None),
        (2, "promoted", "expected_for_role", "ann", "2026-09-30 10:00:00", "01INV"),
        (3, "dismissed", "known_change", "bob", "2026-09-30 11:00:00", None),
        (4, "dismissed", "hunt_clean", "auto-hunt", "2026-09-30 12:00:00", None),
        (5, "open", None, None, None, None),
    ]
    for lead_id, status, reason, by, at, inv in rows:
        connection.execute(
            text(
                "INSERT INTO leads (id, status, formed_at, updated_at, entities_json, "
                "kinds_json, weight_at_formation, scope_count, shadow, single_signal, "
                "dismissed_reason, dismissed_by, dismissed_at, investigation_id) VALUES "
                "(:id, :status, '2026-09-29 09:00:00', '2026-10-01 08:00:00', :ents, '[]', "
                "1.0, 0, 0, 0, :reason, :by, :at, :inv)"
            ),
            {
                "id": lead_id,
                "status": status,
                "ents": json.dumps([["host", "192.0.2.10"]]),
                "reason": reason,
                "by": by,
                "at": at,
                "inv": inv,
            },
        )


def _read(connection: Connection) -> dict[int, tuple[object, ...]]:
    rows = connection.execute(
        text(
            "SELECT id, decisions_json, reopened_at, dismissed_reason, dismissed_at FROM leads "
            "ORDER BY id"
        )
    ).all()
    return {int(r[0]): tuple(r[1:]) for r in rows}


async def test_0053_moves_the_dismissal_into_the_history(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    async with engine.begin() as conn:
        await conn.run_sync(_upgrade_to, "0052")
        await conn.run_sync(_seed)
        await conn.run_sync(_upgrade_to, "0053")
        rows = await conn.run_sync(_read)
    await engine.dispose()

    def actions(lead_id: int) -> list[str]:
        raw = rows[lead_id][0]
        history = json.loads(raw) if isinstance(raw, str) else raw
        return [d["action"] for d in (history or [])]

    assert actions(1) == ["dismissed", "reopened"]
    assert rows[1][1] is not None and rows[1][2] is None and rows[1][3] is None
    assert actions(2) == ["dismissed", "reopened", "promoted"]
    assert rows[2][2] is None and rows[2][3] is None
    assert actions(3) == ["dismissed"]
    assert rows[3][2] == "known_change" and rows[3][1] is None
    assert actions(4) == ["closed_by_hunt"]
    assert rows[4][2] == "hunt_clean"
    assert rows[5][0] is None and rows[5][1] is None
