"""Migration 0028: (status, created_at) indexes + denormalized columns.

Steps 0027 → 0028 by NAME (the repo keeps exactly one head canary, in
tests/test_hunts_store.py), inserts pre-0028 rows via raw SQL, and asserts:

- both composite indexes come into being,
- ``is_fallback`` / ``findings_count`` come into being, and
- the data-migration backfills them from the report JSON already on disk —
  the reason this is a backfill and not a lazy compute (the aggregate would
  otherwise miscount legacy fallbacks and the bell would show 0 findings for
  every hunt finalized before the upgrade).
"""

from __future__ import annotations

import json

from alembic import command
from soc_ai.config import Settings
from soc_ai.store.db import _migration_config, make_engine
from soc_ai.triage_models import PIPELINE_FALLBACK_PROVENANCE
from sqlalchemy import Connection, inspect, text

_FALLBACK_REPORT = {
    "verdict": "needs_more_info",
    "resolution": {"provenance": PIPELINE_FALLBACK_PROVENANCE, "phase": "synth_first_round1"},
}
_NORMAL_REPORT = {"verdict": "true_positive", "citations": ["ev-1"]}
_HUNT_REPORT_2 = {"findings": [{"title": "a"}, {"title": "b"}], "narrative": "n"}
_HUNT_REPORT_0 = {"findings": [], "narrative": "clean"}


def _upgrade_to(connection: Connection, revision: str) -> None:
    cfg = _migration_config()
    cfg.attributes["connection"] = connection
    command.upgrade(cfg, revision)


def _seed_pre_0028(connection: Connection) -> None:
    """Insert investigations + hunts at the 0027 schema (no new columns yet)."""
    connection.execute(
        text(
            "INSERT INTO investigations (id, alert_es_id, status, verdict, started_by, report) "
            "VALUES (:id, :aid, 'complete', :v, 't', :report)"
        ),
        [
            {
                "id": "i-fb",
                "aid": "ev-fb",
                "v": "needs_more_info",
                "report": json.dumps(_FALLBACK_REPORT),
            },
            {
                "id": "i-ok",
                "aid": "ev-ok",
                "v": "true_positive",
                "report": json.dumps(_NORMAL_REPORT),
            },
            {"id": "i-nul", "aid": "ev-nul", "v": "true_positive", "report": None},
        ],
    )
    connection.execute(
        text(
            "INSERT INTO hunts (id, objective, status, started_by, report) "
            "VALUES (:id, :obj, 'complete', 't', :report)"
        ),
        [
            {"id": "h-2", "obj": "two findings", "report": json.dumps(_HUNT_REPORT_2)},
            {"id": "h-0", "obj": "no findings", "report": json.dumps(_HUNT_REPORT_0)},
            {"id": "h-nul", "obj": "no report", "report": None},
        ],
    )


async def test_0028_creates_indexes_and_backfills_columns(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)

    async with engine.begin() as conn:
        await conn.run_sync(_upgrade_to, "0027")
        await conn.run_sync(_seed_pre_0028)
        # The columns do not exist yet at 0027.
        inv_cols = await conn.run_sync(
            lambda sc: {c["name"] for c in inspect(sc).get_columns("investigations")}
        )
        assert "is_fallback" not in inv_cols

    async with engine.begin() as conn:
        await conn.run_sync(_upgrade_to, "0028")

    async with engine.connect() as conn:
        inv_idx = await conn.run_sync(
            lambda sc: {ix["name"] for ix in inspect(sc).get_indexes("investigations")}
        )
        hunt_idx = await conn.run_sync(
            lambda sc: {ix["name"] for ix in inspect(sc).get_indexes("hunts")}
        )
        assert "ix_investigations_status_created" in inv_idx
        assert "ix_hunts_status_created" in hunt_idx

        # The composite index leads with status then created_at.
        inv_composite = await conn.run_sync(
            lambda sc: next(
                ix
                for ix in inspect(sc).get_indexes("investigations")
                if ix["name"] == "ix_investigations_status_created"
            )
        )
        assert inv_composite["column_names"] == ["status", "created_at"]

        # Backfill: fallback → 1, normal + NULL-report → 0.
        rows = (
            await conn.execute(text("SELECT id, is_fallback FROM investigations ORDER BY id"))
        ).all()
        by_id = {r[0]: r[1] for r in rows}
        assert by_id["i-fb"] == 1
        assert by_id["i-ok"] == 0
        assert by_id["i-nul"] == 0  # NULL report is not-a-fallback, not left NULL

        hrows = (await conn.execute(text("SELECT id, findings_count FROM hunts ORDER BY id"))).all()
        hby = {r[0]: r[1] for r in hrows}
        assert hby["h-2"] == 2
        assert hby["h-0"] == 0
        assert hby["h-nul"] == 0

    await engine.dispose()
