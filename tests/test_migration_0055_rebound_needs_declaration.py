"""Migration 0055: a rebound stamp stays only on an address with a declaration.

Production 2026-10-02: 41 machines read "rebound" after the first machine
sweep, most with no operator declaration. The tripwire exists to say "your
override may no longer apply". Steps 0054 to 0055 by name, inserts address
rows through raw SQL, and asserts the upgrade clears the stamp on each address
with no declaration and keeps it on each address with one:

- a stamped address with an operator value keeps its stamp;
- a stamped address with only a JSON operator value keeps its stamp;
- a stamped address with inferred values only loses its stamp;
- a stamped address with no field rows loses its stamp;
- an unstamped address stays unstamped, and every fingerprint is kept.
"""

from __future__ import annotations

from alembic import command
from soc_ai.config import Settings
from soc_ai.store.db import _migration_config, make_engine
from sqlalchemy import Connection, text

_STAMP = "2026-10-02 12:12:30"


def _upgrade_to(connection: Connection, revision: str) -> None:
    cfg = _migration_config()
    cfg.attributes["connection"] = connection
    command.upgrade(cfg, revision)


def _seed(connection: Connection) -> None:
    hosts = [
        (1, "192.0.2.10", _STAMP),
        (2, "192.0.2.11", _STAMP),
        (3, "192.0.2.12", _STAMP),
        (4, "192.0.2.13", _STAMP),
        (5, "192.0.2.14", None),
    ]
    for host_id, ip, stamp in hosts:
        connection.execute(
            text(
                "INSERT INTO host_dossier (id, host_key, ip, event_count, identity_fingerprint, "
                "identity_rebound_at) VALUES (:id, :ip, :ip, 0, :fp, :stamp)"
            ),
            {"id": host_id, "ip": ip, "fp": f"h:{'a' * 16}|m:{'b' * 16}", "stamp": stamp},
        )
    fields = [
        (1, "criticality", "high", None, None),
        (2, "services_offered", None, '["ssh"]', None),
        (3, "role", None, None, "server"),
        (5, "role", "server", None, None),
    ]
    for dossier_id, name, value, value_json, inferred in fields:
        connection.execute(
            text(
                "INSERT INTO host_dossier_field (dossier_id, field, operator_value, "
                "operator_value_json, inferred_value, inferred_last_run_at, "
                "conflict_observations, conflict_prompt_count) VALUES "
                "(:dossier_id, :field, :value, :value_json, :inferred, :stamp, 0, 0)"
            ),
            {
                "dossier_id": dossier_id,
                "field": name,
                "value": value,
                "value_json": value_json,
                "inferred": inferred,
                "stamp": _STAMP,
            },
        )


def _read(connection: Connection) -> dict[int, tuple[object, ...]]:
    rows = connection.execute(
        text("SELECT id, identity_rebound_at, identity_fingerprint FROM host_dossier ORDER BY id")
    ).all()
    return {int(r[0]): tuple(r[1:]) for r in rows}


async def test_0055_clears_the_rebound_stamp_on_undeclared_addresses(
    settings_kratos: Settings,
) -> None:
    engine = make_engine(settings_kratos)
    async with engine.begin() as conn:
        await conn.run_sync(_upgrade_to, "0054")
        await conn.run_sync(_seed)
        await conn.run_sync(_upgrade_to, "0055")
        rows = await conn.run_sync(_read)
    await engine.dispose()

    stamped = {host_id for host_id, (stamp, _) in rows.items() if stamp is not None}
    assert stamped == {1, 2}
    assert all(fingerprint is not None for _, fingerprint in rows.values())
