"""An observation carries its evidence: the statistic, the documents and a query.

A profile observation kept its numbers in the summary sentence and cited
three document ids. The lead hunt read the numbers as prose and searched the
grid for the departure again. These tests hold the columns, the query and the
subject block the hunt reads.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from soc_ai.config import Settings
from soc_ai.hunting.leads import MAX_DOCUMENT_IDS, content_fingerprint, record_observation
from soc_ai.hunting.prior_sweep import run_prior_sweep
from soc_ai.hunting.rerun import oql_value, rerun_query, window_minutes
from soc_ai.hunting.weight import Kind
from soc_ai.so_client.oql import parse_oql, validate_oql
from soc_ai.store.leads import evidence_block_for
from soc_ai.store.models import EntityObservation
from sqlalchemy import select

from tests.test_prior_sweep import _db, _FakeES, _prior, _settings_like
from tests.test_prior_sweep_tier2 import _declare, _set

_HOST = "192.0.2.20"
_START = datetime(2026, 9, 1, 8, tzinfo=UTC)
_END = datetime(2026, 9, 1, 12, tzinfo=UTC)


# ---------------------------------------------------------------------------
# The query
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("dimension", "entity", "member", "count_only"),
    [
        ("served_ports", _HOST, "4444", False),
        ("consumed_ports", _HOST, "8443", False),
        ("peers_out", _HOST, "203.0.113.9", False),
        ("dns_names", _HOST, "c2.example.test", False),
        ("process_names", "ws-01.example.test", "PSEXESVC.exe", False),
        ("process_parents", "ws-01.example.test", "cmd.exe", False),
        ("logon_users", "dc-01.example.test", "svc_backup", False),
        ("active_hours", _HOST, None, False),
        ("connection_rate", _HOST, None, False),
        ("connection_rate", _HOST, None, True),
        ("peers_out", "2001:db8::10", "2001:db8::99", False),
    ],
)
def test_every_query_shape_is_oql_the_agent_tool_accepts(
    dimension: str, entity: str, member: str | None, count_only: bool
) -> None:
    """The agent runs the query with the same parser and whitelist. A query
    the tool refuses is a citation the hunt cannot follow."""
    query = rerun_query(dimension, entity, member, start=_START, end=_END, count_only=count_only)
    assert query is not None
    validate_oql(parse_oql(query))
    assert '"2026-09-01T08:00:00Z" TO "2026-09-01T12:00:00Z"' in query


def test_a_value_with_a_quote_and_a_backslash_survives_the_parser() -> None:
    """A process path from a Windows host carries backslashes. Unescaped, the
    query either fails to parse or names another value."""
    member = 'C:\\Temp\\a"b.exe'
    query = rerun_query("process_names", "ws-01.example.test", member, start=_START, end=_END)
    assert query is not None
    ast = parse_oql(query)
    validate_oql(ast)
    terms = [c for c in ast.filter_.children if getattr(c, "field", "") == "process.name"]
    assert [t.value.text for t in terms] == [member]
    assert oql_value("445") == "445"
    assert oql_value("445a") == '"445a"'


def test_a_dimension_with_no_fields_states_no_query() -> None:
    assert rerun_query("no_such_dimension", _HOST, "x", start=_START, end=_END) is None
    assert rerun_query("served_ports", "", "445", start=_START, end=_END) is None


def test_the_window_reaches_back_to_the_start_of_the_query() -> None:
    now = _START + timedelta(days=2)
    assert window_minutes(_START, now=now) >= 2 * 24 * 60


# ---------------------------------------------------------------------------
# The columns
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_profile_departure_records_its_statistic_documents_and_query(
    settings_kratos: Settings,
) -> None:
    """The sweep writes the numbers in columns. They lived in the summary."""
    engine, maker = await _db(settings_kratos)
    await _declare(maker, _HOST, "network_device")
    await _set(maker, _HOST, {"22": 40, "443": 12})

    anchor = datetime(2026, 9, 1, 12, tzinfo=UTC)
    async with maker() as db:
        await run_prior_sweep(
            elastic=_FakeES(recent={_HOST: {"4444": 6}}),
            settings=_settings_like(settings_kratos),
            db=db,
            catalog=_prior(),
            record=True,
            now=anchor,
        )
        row = (await db.execute(select(EntityObservation))).scalars().one()

    # With the estate read, the statistic is the hosts that hold the member
    # against the hosts profiled: none of the one profiled host.
    assert row.statistic == "estate_hosts"
    assert row.statistic_value == 0.0
    assert row.baseline_value == 1.0
    assert row.document_ids == ["doc-4444-1", "doc-4444-2", "doc-4444-3"]
    assert row.rerun_query is not None
    assert f'destination.ip:"{_HOST}"' in row.rerun_query
    assert "destination.port:4444" in row.rerun_query
    assert row.rerun_query.endswith("| groupby source.ip")
    validate_oql(parse_oql(row.rerun_query))
    await engine.dispose()


@pytest.mark.asyncio
async def test_document_ids_keep_the_newest_first_and_stop_at_ten(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    first = [f"a-{n}" for n in range(6)]
    second = [f"b-{n}" for n in range(8)]
    async with maker() as db:
        for ids in (first, second):
            await record_observation(
                db,
                entity_kind="host",
                entity_key=_HOST,
                kind=Kind.NOVEL_SERVED_PORT,
                spec_id="s",
                fingerprint=content_fingerprint("served_ports", "4444"),
                evidence={"sample_ids": ids},
            )
        row = (await db.execute(select(EntityObservation))).scalars().one()
    assert row.document_ids == [*second, *first][:MAX_DOCUMENT_IDS]
    assert len(row.document_ids) == MAX_DOCUMENT_IDS
    await engine.dispose()


@pytest.mark.asyncio
async def test_an_alert_observation_cites_its_alert_and_states_no_query(
    settings_kratos: Settings,
) -> None:
    """Negative control: an alert verdict has no statistic and no query. It
    states none, and its document is the alert."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await record_observation(
            db,
            entity_kind="host",
            entity_key=_HOST,
            kind=Kind.ALERT,
            spec_id="alert",
            fingerprint="alert-1",
            evidence={"alert_id": "alert-1", "verdict": "needs_more_info"},
            source="alert",
        )
        row = (await db.execute(select(EntityObservation))).scalars().one()
    assert row.document_ids == ["alert-1"]
    assert row.statistic is None
    assert row.rerun_query is None
    await engine.dispose()


# ---------------------------------------------------------------------------
# The subject block the lead hunt reads
# ---------------------------------------------------------------------------


def _row(**fields: Any) -> EntityObservation:
    base: dict[str, Any] = {
        "entity_kind": "host",
        "entity_key": _HOST,
        "kind": "novel_served_port",
        "spec_id": "s",
        "fingerprint": "f",
        "summary": "New served port for this host: 4444",
        "born_at": datetime(2026, 9, 1, 12),
        "evidence_json": {"sample_ids": ["doc-1"]},
    }
    base.update(fields)
    return EntityObservation(**base)


def test_the_hunt_subject_states_the_statistic_and_the_query() -> None:
    """The hunt reads the departure. It searched the grid for it again."""
    query = rerun_query("served_ports", _HOST, "4444", start=_START, end=_END)
    block = evidence_block_for(
        [
            _row(
                statistic="documents",
                statistic_value=6.0,
                baseline_value=2.0,
                document_ids=["doc-1", "doc-2"],
                rerun_query=query,
            )
        ],
        now=datetime(2026, 9, 3, 12, tzinfo=UTC),
    )
    assert "document ids doc-1, doc-2" in block
    assert "Statistic: 6 documents in the recent window." in block
    assert f"Query: {query}" in block
    # The window reaches back past the start of the query: one day before the
    # record time, plus an hour of margin.
    assert f"time_range_minutes {3 * 24 * 60 + 60})" in block
    assert "Run the query of each observation" in block


def test_a_row_with_no_statistic_states_none() -> None:
    """Negative control: a row written before 0057 states no statistic line
    and no query line. It must not invent numbers."""
    block = evidence_block_for([_row()], now=datetime(2026, 9, 1, 13, tzinfo=UTC))
    assert "Statistic:" not in block
    assert "Query:" not in block
    assert "Run the query" not in block
    assert "document ids doc-1" in block
