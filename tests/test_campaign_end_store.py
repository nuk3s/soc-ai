"""Migration 0076: the two columns of the end rule of a campaign, and their fill (round 4, E1).

The fill reads the stored grid read of each campaign. A read of this release
holds the last alert time and the end of its window. A read of an earlier
release holds neither, and its pairs give the last alert time. The module
runs on PostgreSQL too (``tests/conftest.py``, ``POSTGRES_MODULES``).

The data is synthetic: placeholder machine keys and rule names.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import pytest
import sqlalchemy as sa
from soc_ai.campaigns import service
from soc_ai.config import Settings
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Campaign
from sqlalchemy import Connection, inspect, select, text

from tests.test_campaign_store import _downgrade_to, _upgrade_to

pytestmark = pytest.mark.asyncio

T0 = datetime(2026, 11, 7, 2, 20, 52)
LAST_ALERT = datetime(2026, 11, 18, 15, 8, 41)
READ_TO = datetime(2026, 11, 19, 11, 11, 17)

_CAMPAIGNS = sa.table(
    "campaigns",
    sa.column("id", sa.Integer),
    sa.column("seed_run_id", sa.String),
    sa.column("title", sa.String),
    sa.column("bottom_line", sa.Text),
    sa.column("first_event", sa.DateTime),
    sa.column("last_event", sa.DateTime),
    sa.column("member_count", sa.Integer),
    sa.column("detail", sa.JSON),
    sa.column("built_at", sa.DateTime),
    sa.column("events", sa.JSON),
)


def _pair(last_at: datetime | None, alerts: int) -> dict[str, Any]:
    return {
        "source": "agent:a1",
        "target": "ip:t1",
        "alerts": alerts,
        "last_at": last_at.isoformat() if last_at else None,
    }


# id -> the stored ``events`` of the row.
STORED: dict[int, Any] = {
    # This release: the read states both facts.
    1: {
        "source": "grid",
        "last_alert_at": LAST_ALERT.isoformat(),
        "read_to": READ_TO.isoformat(),
        "pairs": [_pair(LAST_ALERT, 12)],
    },
    # An earlier release: no last alert time and no end of the window.
    2: {"source": "grid", "pairs": [_pair(T0 - timedelta(minutes=28), 28), _pair(None, 0)]},
    # The events that the investigations hold are no grid read.
    3: {"source": "stored", "last_alert_at": LAST_ALERT.isoformat(), "pairs": []},
    # No read at all.
    4: None,
}


def _seed(connection: Connection) -> None:
    for campaign_id, events in STORED.items():
        connection.execute(
            _CAMPAIGNS.insert().values(
                id=campaign_id,
                seed_run_id=f"run-{campaign_id}",
                title="Example campaign",
                bottom_line="Example bottom line.",
                first_event=T0 - timedelta(hours=1),
                last_event=T0,
                member_count=1,
                detail={},
                built_at=T0,
                events=events,
            )
        )


def _columns(connection: Connection) -> dict[int, tuple[Any, Any]]:
    rows = connection.execute(
        text("SELECT id, last_alert_at, events_to FROM campaigns ORDER BY id")
    ).all()
    return {int(r[0]): (r[1], r[2]) for r in rows}


def _naive(value: Any) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value))


async def test_the_fill_sets_the_two_columns_from_the_stored_read(
    settings_kratos: Settings,
) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    async with engine.begin() as conn:
        await conn.run_sync(_downgrade_to, "0075")
        before = await conn.run_sync(
            lambda sc: {c["name"] for c in inspect(sc).get_columns("campaigns")}
        )
        await conn.run_sync(_seed)
        await conn.run_sync(_upgrade_to, "head")
        held = await conn.run_sync(_columns)
        head = await conn.execute(text("SELECT version_num FROM alembic_version"))
        assert head.scalar_one() == "0076"
    await engine.dispose()
    assert {"last_alert_at", "events_to"}.isdisjoint(before)
    filled = {cid: (_naive(a), _naive(b)) for cid, (a, b) in held.items()}
    assert filled[1] == (LAST_ALERT, READ_TO)
    # A read of an earlier release: its pairs give the last alert time.
    assert filled[2] == (T0 - timedelta(minutes=28), None)
    # NEGATIVE CONTROLS: no grid read fills nothing.
    assert filled[3] == (None, None)
    assert filled[4] == (None, None)


async def test_the_open_rule_reads_both_columns_in_sql(settings_kratos: Settings) -> None:
    """The SQL of the status (``open_sql``, ``ended_sql``) on the store dialect, with a NULL."""
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    horizon = timedelta(hours=service.decay_horizon_hours())
    now = T0 + horizon + timedelta(days=1)
    async with maker() as db:
        for campaign_id, alert in ((1, now - timedelta(hours=2)), (2, None), (3, T0)):
            db.add(
                Campaign(
                    id=campaign_id,
                    seed_run_id=f"run-{campaign_id}",
                    title="Example campaign",
                    bottom_line="Example bottom line.",
                    first_event=T0 - timedelta(hours=1),
                    last_event=T0,
                    member_count=1,
                    detail={},
                    built_at=T0,
                    last_alert_at=alert,
                )
            )
        # A campaign with a recent investigation event and no alert.
        db.add(
            Campaign(
                id=4,
                seed_run_id="run-4",
                title="Example campaign",
                bottom_line="Example bottom line.",
                first_event=now - timedelta(hours=3),
                last_event=now - timedelta(hours=1),
                member_count=1,
                detail={},
                built_at=now,
            )
        )
        await db.commit()
        opened = set((await db.scalars(select(Campaign.id).where(service.open_sql(now)))).all())
        # The end check selects the rest, with a NULL last alert too (E2).
        ended = set((await db.scalars(select(Campaign.id).where(service.ended_sql(now)))).all())
        rows = (await db.scalars(select(Campaign).order_by(Campaign.id))).all()
        statuses = {row.id: service.api_status(row, now) for row in rows}
    await engine.dispose()
    assert opened == {1, 4}
    assert ended == {2, 3}
    assert statuses == {1: "open", 2: "ended", 3: "ended", 4: "open"}
