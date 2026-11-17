"""The time of an investigation is the time of its event (migration 0072).

The owner, 2026-11-15: "The 'when' in investigations is causing events from
several days ago to show up as recent TPs." A hunt and a Re-run judged events
of 3 and 17 days ago, and the list, the Dashboard tile and the Confirmed
threats panel dated them by the time soc-ai investigated them.

``investigations.event_at`` holds the time of the event, by one rule: the
settled event time of the report, else the time of the stored alert, else
``created_at``. The windows that answer "what happened" read it. The windows
that answer "what did soc-ai do" keep ``created_at``. Needs you and the
campaign changes have no window, so a new verdict on an old event still
reaches the analyst.

The data is synthetic: placeholder addresses, host names and rule names.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.api.webui.routes_meta import _event_note
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import event_at as event_at_rule
from soc_ai.store import investigations as inv_svc
from soc_ai.store import rule_prior as rule_prior_store
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, run_migrations
from soc_ai.store.models import Investigation
from sqlalchemy import Connection, select, text

from tests.test_campaign_facts import seed_hosts
from tests.test_campaign_facts import seed_run as seed_campaign_run
from tests.test_campaign_store import _downgrade_to, _upgrade_to
from tests.test_threats_api import _ESCALATE, _seed_run

TEN_DAYS_MIN = 10 * 24 * 60
RULE_OLD = "ET EXPLOIT Example Old Event"


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            yield test_client


def _do(client: TestClient, work: Any) -> Any:
    async def go() -> Any:
        async with client.app.state.db_sessionmaker() as db:
            return await work(db)

    return asyncio.run(go())


def _ago(**delta: float) -> str:
    return (datetime.now(UTC) - timedelta(**delta)).isoformat()


def _list(client: TestClient, **params: Any) -> dict[str, Any]:
    res = client.get("/api/v1/investigations", params=params)
    assert res.status_code == 200, res.text
    body: dict[str, Any] = res.json()
    return body


def _ids(body: dict[str, Any]) -> list[str]:
    return [row["id"] for row in body["rows"]]


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _old_event_today(client: TestClient, alert_id: str = "old-1", **over: Any) -> str:
    """A true positive made 30 minutes ago on an event of 10 days ago."""
    return _seed_run(
        client,
        alert_id,
        rule=RULE_OLD,
        minutes_ago=30,
        event_minutes_ago=TEN_DAYS_MIN,
        **over,
    )


# ── The rule ─────────────────────────────────────────────────────────────


def test_the_rule_takes_the_report_then_the_alert_then_the_investigation() -> None:
    created = datetime(2026, 11, 15, 12, 0, 0)
    stored = {"event_time": "2026-11-05T08:00:00+02:00"}
    alert = datetime(2026, 11, 4, 9, 0, 0)

    assert event_at_rule.decide(report=stored, alert_at=alert, created_at=created) == datetime(
        2026, 11, 5, 6, 0, 0
    )
    assert event_at_rule.decide(report={}, alert_at=alert, created_at=created) == alert
    assert event_at_rule.decide(report=None, alert_at=None, created_at=created) == created
    # A malformed stored time is no time: the alert time decides.
    assert (
        event_at_rule.decide(
            report={"event_time": "not a time"}, alert_at=alert, created_at=created
        )
        == alert
    )
    # An event after the investigation is clamped to the investigation.
    later = {"event_time": "2026-11-16T00:00:00Z"}
    assert event_at_rule.decide(report=later, alert_at=None, created_at=created) == created
    # An aware time of the investigation is the same instant in UTC.
    aware = created.replace(tzinfo=UTC)
    assert event_at_rule.decide(report=None, alert_at=None, created_at=aware) == created


def test_finalize_settles_the_event_time_from_the_stored_alert(client: TestClient) -> None:
    run_id = _old_event_today(client)

    async def read(db: Any) -> Investigation | None:
        return await db.get(Investigation, run_id)

    inv = _do(client, read)
    assert inv is not None
    expected = utcnow() - timedelta(minutes=TEN_DAYS_MIN)
    assert abs((inv.event_at - expected).total_seconds()) < 5
    assert inv.created_at - inv.event_at > timedelta(days=9)


# ── Negative controls of the contract ────────────────────────────────────


def test_an_old_event_judged_today_is_no_row_of_24_hours_and_a_row_of_30_days(
    client: TestClient,
) -> None:
    old = _old_event_today(client)
    # Made 2 days ago, on an event of 2 days ago: a newer event, an older investigation.
    newer_event = _seed_run(client, "new-1", minutes_ago=2 * 24 * 60, event_minutes_ago=2 * 24 * 60)

    day = _list(client, since=_ago(hours=24))
    assert old not in _ids(day)
    assert day["total"] == 0
    assert day["truePositives"] == 0

    month = _list(client, since=_ago(days=30))
    # The newest event first: the investigation of today on the old event is last.
    assert _ids(month) == [newer_event, old]
    assert month["total"] == 2
    row = month["rows"][1]
    # The row states both times.
    assert row["eventWhen"] == "10d"
    assert row["when"] == "30m"
    assert _parse(row["ts"]) - _parse(row["eventAt"]) > timedelta(days=9)

    # A negative control: the time of the investigation still answers what soc-ai did.
    investigated = _list(client, since=_ago(hours=24), clock="investigated")
    assert _ids(investigated) == [old]


def test_an_unknown_clock_is_refused(client: TestClient) -> None:
    res = client.get("/api/v1/investigations", params={"clock": "wall"})
    assert res.status_code == 422
    assert "clock accepts one of these values: event, investigated." in res.text


def test_an_old_event_is_no_threat_of_24_hours(client: TestClient) -> None:
    old = _old_event_today(client)

    day = client.get("/api/v1/threats").json()
    assert day["total"] == 0
    assert day["rows"] == []

    month = client.get("/api/v1/threats", params={"since": _ago(days=30)}).json()
    assert month["total"] == 1
    (row,) = month["rows"]
    assert row["newestInvestigationId"] == old
    # The seen times are the time of the event, inside the window.
    assert datetime.now(UTC) - _parse(row["lastSeen"]) > timedelta(days=9)


def test_an_old_event_judged_today_is_still_a_needs_you_item(client: TestClient) -> None:
    waits = _old_event_today(client, "old-tp", actions=[_ESCALATE])
    asks = _old_event_today(client, "old-nmi", verdict="needs_more_info")

    needs = client.get("/api/v1/needs-you").json()
    assert needs["pending_actions"] == 1
    assert needs["needs_more_info"] == 1
    assert needs["investigations_waiting"] == 2
    listed = _list(client, needs_you="true")
    assert set(_ids(listed)) == {waits, asks}
    # A negative control: the list of 24 hours of events does not hold them.
    assert _list(client, needs_you="true", since=_ago(hours=24))["total"] == 0


def test_the_campaign_of_old_events_still_raises_its_change_row(client: TestClient) -> None:
    _do(client, seed_hosts)

    async def seed(db: Any, alert_id: str) -> str:
        return await seed_campaign_run(db, alert_id, event_hours_ago=240, created_minutes_ago=30)

    runs = [_do(client, lambda db, a=f"camp-{n}": seed(db, a)) for n in (1, 2)]
    (campaign,) = client.get("/api/v1/campaigns").json()["rows"]

    bell = client.get("/api/v1/notifications", params={"limit": 50}).json()
    assert [r["href"] for r in bell if r["id"].startswith("campaign:")] == [
        f"/campaigns/{campaign['id']}"
    ]
    # The threats of 24 hours hold no row and no campaign for events of 10 days ago.
    day = client.get("/api/v1/threats").json()
    assert day["campaigns"] == []
    assert day["total"] == 0
    month = client.get("/api/v1/threats", params={"since": _ago(days=30)}).json()
    assert [c["id"] for c in month["campaigns"]] == [campaign["id"]]
    assert month["campaigns"][0]["investigations"] == len(runs)


def test_an_investigation_in_progress_is_in_24_hours_by_its_start(client: TestClient) -> None:
    async def start(db: Any) -> str:
        inv = await inv_svc.create(db, alert_es_id="run-1", started_by="analyst", rule_name="X")
        # The alert of the run is 10 days old. The run has not ended.
        await inv_svc.append_events(
            db,
            inv.id,
            [
                {
                    "sequence": 1,
                    "kind": "alert_context",
                    "payload": {"alert": {"timestamp": _ago(days=10)}},
                }
            ],
        )
        return str(inv.id)

    run_id = _do(client, start)
    day = _list(client, since=_ago(hours=24))
    assert _ids(day) == [run_id]
    assert day["running"] == 1


def test_a_malformed_event_time_gets_the_investigation_time(client: TestClient) -> None:
    run_id = _seed_run(client, "bad-1", minutes_ago=45, report={"event_time": "yesterday-ish"})
    body = _list(client, since=_ago(hours=24))
    (row,) = body["rows"]
    assert row["id"] == run_id
    assert row["eventAt"] == row["ts"]
    assert row["eventWhen"] == row["when"] == "45m"


def test_the_inheritance_and_the_rule_prior_read_the_time_of_the_investigation(
    client: TestClient,
) -> None:
    run_id = _old_event_today(client)

    async def read(db: Any) -> tuple[dict[str, Investigation], list[Investigation]]:
        inherited = await inv_svc.latest_complete_for_rules(db, [RULE_OLD], window_days=7)
        prior = await rule_prior_store.model_backed_runs(
            db, RULE_OLD, since=utcnow() - timedelta(days=7)
        )
        return inherited, prior

    inherited, prior = _do(client, read)
    # The run is 30 minutes old and its event 10 days old: both windows of 7
    # days still hold it, as before the event time existed.
    assert inherited[RULE_OLD].id == run_id
    assert [inv.id for inv in prior] == [run_id]


# ── The bell ─────────────────────────────────────────────────────────────


def test_a_verdict_row_about_an_old_event_states_the_event_date(client: TestClient) -> None:
    old = _old_event_today(client)
    fresh = _seed_run(client, "fresh-1", rule="ET Fresh", minutes_ago=20, event_minutes_ago=25)

    rows = {r["id"]: r for r in client.get("/api/v1/notifications").json()}
    day = (utcnow() - timedelta(minutes=TEN_DAYS_MIN)).strftime("%Y-%m-%d")
    assert rows[f"inv-done:{old}"]["title"] == (
        f"Verdict true_positive: {RULE_OLD}. The event is from {day}."
    )
    # A negative control: a verdict on an event of today states no date.
    assert rows[f"inv-done:{fresh}"]["title"] == "Verdict true_positive: ET Fresh"


def test_the_event_note_reads_24_hours_as_the_limit() -> None:
    now = datetime(2026, 11, 16, 12, 0, 0)
    assert _event_note(None, now) == ""
    assert _event_note(now - timedelta(hours=23), now) == ""
    assert _event_note(now - timedelta(hours=25), now) == ". The event is from 2026-11-15."


# ── The page ─────────────────────────────────────────────────────────────


def test_the_investigation_page_states_the_event_time(client: TestClient) -> None:
    run_id = _old_event_today(client)
    meta = client.get(f"/api/v1/investigations/{run_id}").json()["meta"]
    assert _parse(meta["ranAt"]) - _parse(meta["eventAt"]) > timedelta(days=9)


# ── The upgrade ──────────────────────────────────────────────────────────


def _upgrade_again(settings: Settings) -> None:
    """Run migration 0072 again on the store of the app: down to 0071, up to head."""

    async def go() -> None:
        engine = make_engine(settings)
        async with engine.begin() as conn:
            await conn.run_sync(_downgrade_to, "0071")
            await conn.run_sync(_upgrade_to, "head")
        await engine.dispose()

    asyncio.run(go())


def _event_times(client: TestClient) -> dict[str, datetime | None]:
    async def read(db: Any) -> dict[str, datetime | None]:
        rows = await db.execute(select(Investigation.id, Investigation.event_at))
        return {str(rid): at for rid, at in rows.all()}

    out: dict[str, datetime | None] = _do(client, read)
    return out


def test_the_upgrade_gives_each_row_the_value_that_the_store_writes(
    client: TestClient, settings_kratos: Settings
) -> None:
    old = _old_event_today(client)
    recent = _seed_run(client, "new-1", minutes_ago=60, event_minutes_ago=90)
    malformed = _seed_run(client, "bad-1", minutes_ago=90, report={"event_time": "soon"})
    bare = _seed_run(client, "bare-1", minutes_ago=100)
    by_report = _seed_run(client, "rep-1", minutes_ago=120, report={"event_time": _ago(days=3)})
    # The values that finalize wrote, by the rule.
    written = _event_times(client)

    _upgrade_again(settings_kratos)

    # The migration alone: no null, and the value that finalize writes.
    times = _event_times(client)
    assert None not in times.values()
    assert times == written
    # A row with no better time keeps the time of its investigation, so it
    # is in the windows that it was in before the upgrade.
    by_created = set(_ids(_list(client, since=_ago(hours=24), clock="investigated")))
    assert by_created == {old, recent, malformed, bare, by_report}
    day = set(_ids(_list(client, since=_ago(hours=24))))
    assert day == {recent, malformed, bare}
    threats = client.get("/api/v1/threats").json()
    assert threats["total"] == 3
    assert {r["newestInvestigationId"] for r in threats["rows"]} <= day

    # A second start runs no migration and changes no row.
    asyncio.run(_migrate_again(settings_kratos))
    assert _event_times(client) == times


async def _migrate_again(settings: Settings) -> None:
    engine = make_engine(settings)
    await run_migrations(engine)
    await engine.dispose()


@pytest.mark.asyncio
async def test_0072_fills_each_row_by_the_rule_on_upgrade(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    created = (utcnow() - timedelta(days=1)).replace(microsecond=0)

    def seed_at_0071(sc: Connection) -> None:
        _downgrade_to(sc, "0071")
        for run_id, report in (
            ("m-bare", None),
            ("m-report", '{"event_time": "2026-11-01T02:00:00+02:00"}'),
            ("m-alert", None),
            ("m-bad", '{"event_time": "soon"}'),
            ("m-edge", '{"event_time": "0001-01-01T00:00:00+01:00"}'),
            ("m-later", '{"event_time": "2999-01-01T00:00:00Z"}'),
        ):
            sc.execute(
                text(
                    "INSERT INTO investigations (id, alert_es_id, kind, status, started_by,"
                    " created_at, report) VALUES (:id, :id, 'suricata', 'complete', 'x', :at, :r)"
                ),
                {"id": run_id, "at": created.strftime("%Y-%m-%d %H:%M:%S.%f"), "r": report},
            )
        for run_id, seq, stamp in (
            ("m-alert", 1, "2026-11-02T00:00:00.250000Z"),
            # The first time that parses decides: the bad one is skipped.
            ("m-bad", 1, "not a time"),
            ("m-bad", 2, "2026-11-03T00:00:00Z"),
        ):
            sc.execute(
                text(
                    "INSERT INTO investigation_events (investigation_id, sequence, kind, payload)"
                    " VALUES (:id, :seq, 'alert_context', :p)"
                ),
                {"id": run_id, "seq": seq, "p": json.dumps({"alert": {"timestamp": stamp}})},
            )
        _upgrade_to(sc, "head")

    async with engine.begin() as conn:
        await conn.run_sync(seed_at_0071)
        rows = dict(
            (await conn.execute(text("SELECT id, event_at FROM investigations"))).tuples().all()
        )
    await engine.dispose()
    assert {run_id: event_at_rule.parse_time(at) for run_id, at in rows.items()} == {
        "m-bare": created,
        "m-report": datetime(2026, 11, 1, 0, 0, 0),
        "m-alert": datetime(2026, 11, 2, 0, 0, 0, 250000),
        "m-bad": datetime(2026, 11, 3, 0, 0, 0),
        # No UTC value at the edge of the calendar: no time.
        "m-edge": created,
        # An event after the investigation is clamped.
        "m-later": created,
    }


# ── No null ──────────────────────────────────────────────────────────────


def test_no_orm_write_stores_a_null_event_time(client: TestClient) -> None:
    async def write(db: Any) -> tuple[datetime | None, datetime | None]:
        bare = Investigation(id="null-1", alert_es_id="a")
        db.add(bare)
        await db.commit()
        first = (await db.get(Investigation, "null-1")).event_at
        row = await db.get(Investigation, "null-1")
        row.event_at = None
        await db.commit()
        db.expire_all()
        second = (await db.get(Investigation, "null-1")).event_at
        return first, second

    first, second = _do(client, write)
    assert first is not None
    assert second is not None


def test_no_code_writes_investigations_around_the_orm_hooks() -> None:
    """A core INSERT or UPDATE skips the hooks of the model, and could store a null.

    The startup step is the one bulk write, and it writes values of the rule.
    """
    root = Path(__file__).resolve().parents[1] / "soc_ai"
    patterns = (
        re.compile(r"insert\(\s*Investigation\s*\)"),
        re.compile(r"Investigation\.__table__"),
        re.compile(r"(?i)insert\s+into\s+investigations\b"),
        re.compile(r"(?i)update\s+investigations\s+set"),
        re.compile(r"event_at\s*=\s*None"),
        re.compile(r"[\"']event_at[\"']\s*:\s*None"),
    )
    found = []
    for path in root.rglob("*.py"):
        if "migrations" in path.parts:
            continue
        text_ = path.read_text(encoding="utf-8")
        found.extend(f"{path.name}: {p.pattern}" for p in patterns if p.search(text_))
    assert found == []
