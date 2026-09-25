"""The profile store: what is normal for one entity on one dimension.

The behaviour worth testing here is not the round trip. It is the rebind
guard — a profile whose identity fingerprint no longer matches the dossier's
must not be returned, because a departure scored against it charges one
machine with its predecessor's history.
"""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime, timedelta

import pytest
from soc_ai.config import Settings
from soc_ai.store import entity_profiles as ep
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from sqlalchemy import inspect, text

pytestmark = pytest.mark.asyncio


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def test_migration_creates_the_table(settings_kratos: Settings) -> None:
    engine, _maker = await _db(settings_kratos)
    async with engine.connect() as conn:
        tables = await conn.run_sync(lambda sc: inspect(sc).get_table_names())
        assert "entity_profiles" in tables
        row = await conn.execute(text("SELECT version_num FROM alembic_version"))
        assert row.scalar_one() == "0050"
    await engine.dispose()


async def test_a_profile_round_trips(settings_kratos: Settings) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await ep.upsert_profile(
            db,
            entity_kind="host",
            entity_key="10.1.10.21",
            dimension="served_ports",
            shape="categorical",
            vector={"445": {"count": 12, "first_seen": "2026-09-01", "last_seen": "2026-09-14"}},
            support_days=13,
            role="workstation",
            role_confidence=0.9,
            identity_fingerprint="fp-a",
        )
        loaded = await ep.load_profiles(db, entity_kind="host", entity_key="10.1.10.21")
    assert set(loaded) == {"served_ports"}
    assert loaded["served_ports"].vector["445"]["count"] == 12
    assert loaded["served_ports"].support_days == 13
    assert loaded["served_ports"].coverage == "measured"


async def test_upserting_twice_updates_rather_than_duplicating(
    settings_kratos: Settings,
) -> None:
    # The unique constraint is on (entity_kind, entity_key, dimension). A sweep
    # runs repeatedly; without an upsert the table grows a row per sweep and
    # every read has to guess which row is current.
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for count in (1, 2, 3):
            await ep.upsert_profile(
                db,
                entity_kind="host",
                entity_key="10.1.10.21",
                dimension="served_ports",
                shape="categorical",
                vector={"445": {"count": count}},
                support_days=count,
            )
        loaded = await ep.load_profiles(db, entity_kind="host", entity_key="10.1.10.21")
        rows = await db.execute(text("SELECT COUNT(*) FROM entity_profiles"))
        assert rows.scalar_one() == 1
    assert loaded["served_ports"].vector["445"]["count"] == 3
    assert loaded["served_ports"].support_days == 3


async def test_rewriting_a_profile_stamps_built_at_in_utc_not_local_time(
    settings_kratos: Settings,
) -> None:
    # The insert path leaves built_at to the database default, which is UTC,
    # and every other timestamp in the store is naive UTC. A rewrite that
    # stamps the local clock instead would put the second sweep's row hours
    # away from the first on any host whose TZ is not UTC, and a "built N
    # ago" reading over it would be off by the whole offset. Pin the process
    # to a fixed-offset zone (no tzdata needed) so the bug is visible on a
    # UTC build box too.
    _engine, maker = await _db(settings_kratos)
    previous_tz = os.environ.get("TZ")
    os.environ["TZ"] = "XXX-7"
    time.tzset()
    try:
        async with maker() as db:
            for count in (1, 2):
                await ep.upsert_profile(
                    db,
                    entity_kind="host",
                    entity_key="10.1.10.21",
                    dimension="served_ports",
                    shape="categorical",
                    vector={"445": {"count": count}},
                    support_days=count,
                )
            loaded = await ep.load_profiles(db, entity_kind="host", entity_key="10.1.10.21")
    finally:
        if previous_tz is None:
            del os.environ["TZ"]
        else:
            os.environ["TZ"] = previous_tz
        time.tzset()
    built_at = loaded["served_ports"].built_at
    assert built_at is not None
    assert built_at.tzinfo is None
    assert abs(built_at - datetime.now(UTC).replace(tzinfo=None)) < timedelta(seconds=5)


async def test_a_stale_fingerprint_yields_nothing_not_a_stale_profile(
    settings_kratos: Settings,
) -> None:
    # THE test. The address changed hands; the profile describes whoever held
    # it before. Returning it would let the new occupant inherit the old one's
    # permissions, which is the precise failure the dossier's rebind stamp
    # exists to prevent.
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await ep.upsert_profile(
            db,
            entity_kind="host",
            entity_key="10.1.10.21",
            dimension="served_ports",
            shape="categorical",
            vector={"445": {"count": 12}},
            identity_fingerprint="fp-old",
        )
        same = await ep.load_profiles(
            db, entity_kind="host", entity_key="10.1.10.21", identity_fingerprint="fp-old"
        )
        rebound = await ep.load_profiles(
            db, entity_kind="host", entity_key="10.1.10.21", identity_fingerprint="fp-new"
        )
    assert set(same) == {"served_ports"}
    assert rebound == {}, "a rebound address must not inherit its predecessor's profile"


async def test_no_fingerprint_asked_for_returns_everything(
    settings_kratos: Settings,
) -> None:
    # The operator surfaces read profiles to render them, not to score against
    # them. They pass no fingerprint and must still see the row.
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await ep.upsert_profile(
            db,
            entity_kind="host",
            entity_key="10.1.10.21",
            dimension="served_ports",
            shape="categorical",
            vector={},
            identity_fingerprint="fp-old",
        )
        loaded = await ep.load_profiles(db, entity_kind="host", entity_key="10.1.10.21")
    assert set(loaded) == {"served_ports"}


async def test_a_profile_with_no_fingerprint_is_returned_for_any_fingerprint(
    settings_kratos: Settings,
) -> None:
    # A host the dossier has never fingerprinted (no hostname, no MAC) still
    # gets profiles. Withholding them would make every un-fingerprinted host
    # permanently blind, which is most of a network-only grid.
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await ep.upsert_profile(
            db,
            entity_kind="host",
            entity_key="10.1.10.99",
            dimension="peers_out",
            shape="categorical",
            vector={},
            identity_fingerprint=None,
        )
        loaded = await ep.load_profiles(
            db, entity_kind="host", entity_key="10.1.10.99", identity_fingerprint="fp-any"
        )
    assert set(loaded) == {"peers_out"}


async def test_blind_coverage_round_trips_and_is_not_an_empty_measurement(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await ep.upsert_profile(
            db,
            entity_kind="host",
            entity_key="10.1.10.40",
            dimension="process_names",
            shape="categorical",
            vector=None,
            coverage="blind",
        )
        loaded = await ep.load_profiles(db, entity_kind="host", entity_key="10.1.10.40")
    row = loaded["process_names"]
    assert row.coverage == "blind"
    assert row.vector is None, "blind must not be stored as an empty set"
    assert not row.is_scorable, "a blind dimension cannot produce a departure"


async def test_a_measured_but_empty_dimension_is_scorable(settings_kratos: Settings) -> None:
    # The mirror image of the test above, and the reason coverage is a column:
    # a host that genuinely served no ports has an empty set that MEANS
    # something, and a new port on it is a real departure.
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await ep.upsert_profile(
            db,
            entity_kind="host",
            entity_key="10.1.10.41",
            dimension="served_ports",
            shape="categorical",
            vector={},
            coverage="measured",
            support_days=30,
        )
        loaded = await ep.load_profiles(db, entity_kind="host", entity_key="10.1.10.41")
    row = loaded["served_ports"]
    assert row.vector == {}
    assert row.is_scorable


async def test_learning_below_the_support_floor_is_not_scorable(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await ep.upsert_profile(
            db,
            entity_kind="host",
            entity_key="10.1.10.42",
            dimension="peers_out",
            shape="categorical",
            vector={"1.1.1.1": {"count": 2}},
            coverage="learning",
            support_days=3,
        )
        loaded = await ep.load_profiles(db, entity_kind="host", entity_key="10.1.10.42")
    assert loaded["peers_out"].coverage == "learning"
    assert not loaded["peers_out"].is_scorable


async def test_profiles_for_role_finds_the_peer_group(settings_kratos: Settings) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for key in ("10.1.10.21", "10.1.10.22", "10.1.10.23"):
            await ep.upsert_profile(
                db,
                entity_kind="host",
                entity_key=key,
                dimension="process_names",
                shape="categorical",
                vector={"chrome.exe": {"count": 5}},
                role="workstation",
                support_days=30,
            )
        await ep.upsert_profile(
            db,
            entity_kind="host",
            entity_key="10.1.10.11",
            dimension="process_names",
            shape="categorical",
            vector={"lsass.exe": {"count": 5}},
            role="domain_controller",
            support_days=30,
        )
        peers = await ep.profiles_for_role(db, role="workstation", dimension="process_names")
    assert {p.entity_key for p in peers} == {"10.1.10.21", "10.1.10.22", "10.1.10.23"}


async def test_peer_group_excludes_unscorable_members(settings_kratos: Settings) -> None:
    # A blind peer contributes no evidence about what is normal for the role.
    # Counting it in the denominator makes a membership look rarer than it is.
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await ep.upsert_profile(
            db,
            entity_kind="host",
            entity_key="10.1.10.21",
            dimension="process_names",
            shape="categorical",
            vector={"chrome.exe": {"count": 5}},
            role="workstation",
            support_days=30,
        )
        await ep.upsert_profile(
            db,
            entity_kind="host",
            entity_key="10.1.10.22",
            dimension="process_names",
            shape="categorical",
            vector=None,
            coverage="blind",
            role="workstation",
        )
        peers = await ep.profiles_for_role(db, role="workstation", dimension="process_names")
    assert {p.entity_key for p in peers} == {"10.1.10.21"}


async def test_purge_entity_removes_every_dimension(settings_kratos: Settings) -> None:
    # Used by the rebind guard: when an address changes hands the old profile
    # is not merely hidden, it is deleted, so it cannot come back if the
    # fingerprint is later lost.
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for dim in ("served_ports", "peers_out", "process_names"):
            await ep.upsert_profile(
                db,
                entity_kind="host",
                entity_key="10.1.10.21",
                dimension=dim,
                shape="categorical",
                vector={},
            )
        removed = await ep.purge_entity(db, entity_kind="host", entity_key="10.1.10.21")
        loaded = await ep.load_profiles(db, entity_kind="host", entity_key="10.1.10.21")
    assert removed == 3
    assert loaded == {}


async def test_a_user_entity_and_a_host_entity_do_not_collide(
    settings_kratos: Settings,
) -> None:
    # entity_key alone is not unique across kinds: a host could be keyed by a
    # name that is also a principal. The constraint includes entity_kind.
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await ep.upsert_profile(
            db,
            entity_kind="host",
            entity_key="alice",
            dimension="peers_out",
            shape="categorical",
            vector={"a": {"count": 1}},
        )
        await ep.upsert_profile(
            db,
            entity_kind="user",
            entity_key="alice",
            dimension="peers_out",
            shape="categorical",
            vector={"b": {"count": 2}},
        )
        host = await ep.load_profiles(db, entity_kind="host", entity_key="alice")
        user = await ep.load_profiles(db, entity_kind="user", entity_key="alice")
    assert host["peers_out"].vector == {"a": {"count": 1}}
    assert user["peers_out"].vector == {"b": {"count": 2}}


async def test_first_and_last_seen_survive_the_round_trip(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    first = datetime(2026, 9, 1, 12, tzinfo=UTC).replace(tzinfo=None)
    last = datetime(2026, 9, 14, 12, tzinfo=UTC).replace(tzinfo=None)
    async with maker() as db:
        await ep.upsert_profile(
            db,
            entity_kind="host",
            entity_key="10.1.10.21",
            dimension="peers_out",
            shape="categorical",
            vector={},
            first_seen=first,
            last_seen=last,
        )
        loaded = await ep.load_profiles(db, entity_kind="host", entity_key="10.1.10.21")
    assert loaded["peers_out"].first_seen == first
    assert loaded["peers_out"].last_seen == last


async def test_out_of_scope_profiles_are_purged(settings_kratos: Settings) -> None:
    """A scoping change must remove what it now excludes.

    upsert_profile writes and never deletes, so when host entities were scoped
    to the estate's own CIDRs the previously-built profiles for a Microsoft
    server, the loopback address and an upstream gateway simply stayed in the
    table -- and the prior sweep kept reporting findings about them. The
    building side was fixed and the stored side was not, which is the same
    surface reading healthy while holding stale state.
    """
    import ipaddress

    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for key in ("10.1.10.21", "52.123.129.14", "127.0.0.1", "192.0.2.254"):
            await ep.upsert_profile(
                db,
                entity_kind="host",
                entity_key=key,
                dimension="peers_out",
                shape="categorical",
                vector={},
            )
        removed = await ep.purge_out_of_scope(db, cidrs=[ipaddress.ip_network("10.1.0.0/16")])
        kept = await ep.load_profiles(db, entity_kind="host", entity_key="10.1.10.21")
        gone = await ep.load_profiles(db, entity_kind="host", entity_key="52.123.129.14")

    assert removed == 3
    assert set(kept) == {"peers_out"}
    assert gone == {}


async def test_purging_with_no_cidrs_removes_nothing(settings_kratos: Settings) -> None:
    """Fail OPEN, matching the lane.

    An empty CIDR list means nobody has told this deployment what its own
    network is. Purging everything on that basis would delete every baseline
    on an unconfigured estate.
    """
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await ep.upsert_profile(
            db,
            entity_kind="host",
            entity_key="52.123.129.14",
            dimension="peers_out",
            shape="categorical",
            vector={},
        )
        removed = await ep.purge_out_of_scope(db, cidrs=[])
        kept = await ep.load_profiles(db, entity_kind="host", entity_key="52.123.129.14")
    assert removed == 0
    assert set(kept) == {"peers_out"}


async def test_purging_never_touches_user_entities(settings_kratos: Settings) -> None:
    # A principal has no address. Running one through an address test would
    # delete every user profile on the grid.
    import ipaddress

    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await ep.upsert_profile(
            db,
            entity_kind="user",
            entity_key="alice",
            dimension="logon_users",
            shape="categorical",
            vector={},
        )
        removed = await ep.purge_out_of_scope(db, cidrs=[ipaddress.ip_network("10.1.0.0/16")])
        kept = await ep.load_profiles(db, entity_kind="user", entity_key="alice")
    assert removed == 0
    assert set(kept) == {"logon_users"}
