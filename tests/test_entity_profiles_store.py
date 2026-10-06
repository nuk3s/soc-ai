"""The profile store: what is normal for one entity on one dimension.

The behaviour worth testing here is not the round trip. It is the rebind
guard — a profile whose identity fingerprint no longer matches the dossier's
must not be returned, because a departure scored against it charges one
machine with its predecessor's history.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from soc_ai.config import Settings
from soc_ai.store import entity_profiles as ep
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import EntityProfile
from sqlalchemy import event, func, inspect, select, text, update

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
        profile_cols = await conn.run_sync(
            lambda sc: {c["name"] for c in inspect(sc).get_columns("entity_profiles")}
        )
        run_cols = await conn.run_sync(
            lambda sc: {c["name"] for c in inspect(sc).get_columns("prior_spec_runs")}
        )
        row = await conn.execute(text("SELECT version_num FROM alembic_version"))
        assert row.scalar_one() == "0060"
    # Why a dimension could not be measured, and what the sweep knew about
    # its baselines. Without the first, a refused query wrote no row and read
    # as blind; without the second, coverage counts implied "now".
    assert "coverage_reason" in profile_cols
    assert {"profiles_built_at", "profiles_stale", "profiles_reason"} <= run_cols
    await engine.dispose()


async def test_one_dimension_loads_for_many_entities_in_one_read(
    settings_kratos: Settings,
) -> None:
    """The scoring loop reads one dimension for a slice of entities at a time.

    Only the asked dimension and the asked keys come back. A key with no row
    on the dimension is absent, the same answer one load per entity gave.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for key in ("198.51.100.1", "198.51.100.2", "198.51.100.3"):
            for dimension in ("served_ports", "peers_out"):
                await ep.upsert_profile(
                    db,
                    entity_kind="host",
                    entity_key=key,
                    dimension=dimension,
                    shape="categorical",
                    vector={"445": {"count": 3}},
                    support_days=10,
                )
        loaded = await ep.load_dimension(
            db,
            entity_kind="host",
            dimension="served_ports",
            entity_keys=["198.51.100.1", "198.51.100.3", "198.51.100.9"],
        )
        empty = await ep.load_dimension(
            db, entity_kind="host", dimension="served_ports", entity_keys=[]
        )
    assert empty == {}
    assert set(loaded) == {"198.51.100.1", "198.51.100.3"}
    assert {row.dimension for row in loaded.values()} == {"served_ports"}
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


async def test_built_at_is_utc_on_insert_and_on_update_whatever_the_host_zone(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The range host runs in America/New_York. The update path stamped local
    time and the insert path stamped UTC, so one table held two clocks and a
    rebuilt row read four hours older than it was."""
    import time

    monkeypatch.setenv("TZ", "Pacific/Kiritimati")  # UTC+14, the widest offset there is
    time.tzset()
    try:
        _engine, maker = await _db(settings_kratos)
        async with maker() as db:
            for count in (1, 2):
                await ep.upsert_profile(
                    db,
                    entity_kind="host",
                    entity_key="198.51.100.21",
                    dimension="served_ports",
                    shape="categorical",
                    vector={"445": {"count": count}},
                    support_days=count,
                )
                loaded = await ep.load_profiles(db, entity_kind="host", entity_key="198.51.100.21")
                stamp = loaded["served_ports"].built_at
                assert stamp is not None and stamp.tzinfo is None
                skew = abs(datetime.now(UTC).replace(tzinfo=None) - stamp)
                assert skew < timedelta(minutes=5), f"write {count}: built_at is {skew} from UTC"
    finally:
        monkeypatch.delenv("TZ", raising=False)
        time.tzset()


async def test_freshness_reports_the_newest_stamp_and_every_unmeasurable_reason(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        empty = await ep.freshness(db)
        assert empty.newest_built_at is None
        assert empty.unmeasurable == {}
        await ep.upsert_profile(
            db,
            entity_kind="host",
            entity_key="198.51.100.5",
            dimension="peers_out",
            shape="categorical",
            vector={},
            support_days=9,
        )
        for key in ("198.51.100.5", "198.51.100.6"):
            await ep.upsert_profile(
                db,
                entity_kind="host",
                entity_key=key,
                dimension="active_hours",
                shape="active_hours",
                vector=None,
                coverage=ep.COVERAGE_UNMEASURABLE,
                coverage_reason="Trying to create too many buckets",
            )
        state = await ep.freshness(db)
    assert state.newest_built_at is not None
    assert abs(datetime.now(UTC).replace(tzinfo=None) - state.newest_built_at) < timedelta(
        minutes=5
    )
    # One reason per dimension, however many hosts carry it.
    assert state.unmeasurable == {"active_hours": "Trying to create too many buckets"}


async def test_purge_older_than_removes_only_rows_built_before_the_mark(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for key in ("198.51.100.7", "198.51.100.8"):
            await ep.upsert_profile(
                db,
                entity_kind="host",
                entity_key=key,
                dimension="served_ports",
                shape="categorical",
                vector={},
                support_days=9,
            )
        two_days_ago = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=2)
        await db.execute(
            update(EntityProfile)
            .where(EntityProfile.entity_key == "198.51.100.7")
            .values(built_at=two_days_ago)
        )
        await db.commit()
        mark = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=1)
        gone = await ep.purge_older_than(db, built_before=mark)
        assert gone == 1
        assert await ep.load_profiles(db, entity_kind="host", entity_key="198.51.100.7") == {}
        kept = await ep.load_profiles(db, entity_kind="host", entity_key="198.51.100.8")
    assert set(kept) == {"served_ports"}


async def test_unmeasurable_keeps_its_reason_and_is_not_scorable(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await ep.upsert_profile(
            db,
            entity_kind="host",
            entity_key="198.51.100.9",
            dimension="connection_rate",
            shape="numeric",
            vector=None,
            coverage=ep.COVERAGE_UNMEASURABLE,
            coverage_reason="Trying to create too many buckets",
        )
        loaded = await ep.load_profiles(db, entity_kind="host", entity_key="198.51.100.9")
    row = loaded["connection_rate"]
    assert row.coverage == "unmeasurable"
    assert row.coverage_reason == "Trying to create too many buckets"
    assert row.vector is None
    assert not row.is_scorable, "a refused measurement must not score a departure"


async def test_purging_keeps_host_rows_keyed_on_a_hostname(settings_kratos: Settings) -> None:
    """A hostname is not an address, and failing the address test is not proof
    of being foreign.

    The process and logon dimensions key their host rows on ``host.name``.
    Purging those as out of scope would delete every agent-plane baseline on
    any estate that had configured its CIDRs, on every sweep.
    """
    import ipaddress

    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for key, dim in (
            ("dc01", "logon_users"),
            ("WS01.corp.example", "process_names"),
            ("52.123.129.14", "peers_out"),
        ):
            await ep.upsert_profile(
                db,
                entity_kind="host",
                entity_key=key,
                dimension=dim,
                shape="categorical",
                vector={},
            )
        removed = await ep.purge_out_of_scope(db, cidrs=[ipaddress.ip_network("10.1.0.0/16")])
        dc = await ep.load_profiles(db, entity_kind="host", entity_key="dc01")
        ws = await ep.load_profiles(db, entity_kind="host", entity_key="WS01.corp.example")
        gone = await ep.load_profiles(db, entity_kind="host", entity_key="52.123.129.14")

    assert removed == 1
    assert set(dc) == {"logon_users"}
    assert set(ws) == {"process_names"}
    assert gone == {}


# ---------------------------------------------------------------------------
# The role stamp
# ---------------------------------------------------------------------------


def _built_at() -> datetime:
    """A build three days ago. Relative to now, so the seed does not age out."""
    return datetime.now(UTC).replace(tzinfo=None, microsecond=0) - timedelta(days=3)


def _stamp_row(
    key: str,
    *,
    built_at: datetime,
    dimension: str = "served_ports",
    role: str | None = None,
    confidence: float | None = None,
    kind: str = "host",
) -> EntityProfile:
    return EntityProfile(
        entity_kind=kind,
        entity_key=key,
        dimension=dimension,
        shape="categorical",
        vector_json={},
        role=role,
        role_confidence=confidence,
        built_at=built_at,
    )


# 501 workstations fill one IN list and spill one row into a second. Three
# servers are a second group. Two hosts already hold their role.
_WORKSTATIONS = [f"ws{n:04d}.example.test" for n in range(501)]
_SERVERS = ["srv1.example.test", "srv2.example.test", "srv3.example.test"]
_SETTLED = {
    "ws-settled.example.test": ("workstation", 0.9),
    "srv-settled.example.test": ("server", 0.8),
}


def _estate_role(key: str) -> tuple[str | None, float]:
    if key in _SETTLED:
        return _SETTLED[key]
    if key.startswith("ws"):
        return ("workstation", 0.9)
    if key.startswith("srv"):
        return ("server", 0.8)
    return (None, 0.0)


async def _seed_stamp_estate(maker: Any) -> dict[str, datetime]:
    """Write the estate above with no role on the moving rows. Returns built_at per key.

    Every row has its own built_at, so a stamp that writes any one value is seen.
    """
    base = _built_at()
    seeded: dict[str, datetime] = {}
    rows: list[EntityProfile] = []
    for n, key in enumerate([*_WORKSTATIONS, *_SERVERS]):
        seeded[key] = base - timedelta(minutes=n)
        rows.append(_stamp_row(key, built_at=seeded[key]))
    for n, (key, (role, confidence)) in enumerate(_SETTLED.items()):
        seeded[key] = base - timedelta(days=1, minutes=n)
        rows.append(_stamp_row(key, built_at=seeded[key], role=role, confidence=confidence))
    async with maker() as db:
        db.add_all(rows)
        await db.commit()
    return seeded


async def test_stamp_roles_writes_new_changed_and_cleared_roles_and_skips_the_rest(
    settings_kratos: Settings,
) -> None:
    """New, changed and cleared roles move. A settled row and a user row stay."""
    roles: dict[str, tuple[str | None, float]] = {
        "192.0.2.1": ("workstation", 0.9),
        "192.0.2.2": ("server", 0.8),
        "192.0.2.3": ("server", 0.7),
        "192.0.2.4": ("printer", 0.95),
        # A principal never takes a host role, whatever the map says.
        "analyst@example.test": ("server", 0.9),
    }
    built = _built_at()
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        db.add_all(
            [
                _stamp_row("192.0.2.1", built_at=built, role="workstation", confidence=0.9),
                _stamp_row("192.0.2.2", built_at=built),
                _stamp_row("192.0.2.2", built_at=built, dimension="peers_out"),
                _stamp_row("192.0.2.3", built_at=built, role="workstation", confidence=0.9),
                _stamp_row("192.0.2.4", built_at=built, role="printer", confidence=0.6),
                _stamp_row("192.0.2.5", built_at=built, role="server", confidence=0.8),
                _stamp_row("192.0.2.6", built_at=built),
                _stamp_row("analyst@example.test", built_at=built, kind="user"),
            ]
        )
        await db.commit()
        changed = await ep.stamp_roles(db, lambda key: roles.get(key, (None, 0.0)))
    # 192.0.2.2 on two dimensions, then .3, .4 and the cleared .5.
    assert changed == 5

    async with maker() as db:
        got = {
            (row.entity_kind, row.entity_key, row.dimension): (row.role, row.role_confidence)
            for row in (await db.scalars(select(EntityProfile))).all()
        }
        again = await ep.stamp_roles(db, lambda key: roles.get(key, (None, 0.0)))
    assert got == {
        ("host", "192.0.2.1", "served_ports"): ("workstation", 0.9),
        ("host", "192.0.2.2", "served_ports"): ("server", 0.8),
        ("host", "192.0.2.2", "peers_out"): ("server", 0.8),
        ("host", "192.0.2.3", "served_ports"): ("server", 0.7),
        ("host", "192.0.2.4", "served_ports"): ("printer", 0.95),
        ("host", "192.0.2.5", "served_ports"): (None, None),
        ("host", "192.0.2.6", "served_ports"): (None, None),
        ("user", "analyst@example.test", "served_ports"): (None, None),
    }
    assert again == 0


async def test_stamp_roles_updates_501_rows_in_bounded_statements(
    settings_kratos: Settings,
) -> None:
    """504 changed rows in two groups cost three UPDATEs, never one per row.

    The 501st workstation sits in the second IN list of its group, so a stamp
    that dropped the tail leaves it with no role.
    """
    engine, maker = await _db(settings_kratos)
    await _seed_stamp_estate(maker)
    updates: list[int] = []

    def _record(conn: Any, cursor: Any, statement: str, parameters: Any, *args: Any) -> None:
        if statement.lstrip().upper().startswith("UPDATE"):
            updates.append(len(parameters or ()))

    event.listen(engine.sync_engine, "before_cursor_execute", _record)
    try:
        async with maker() as db:
            changed = await ep.stamp_roles(db, _estate_role)
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", _record)

    assert changed == 504
    assert len(updates) == 3, updates
    assert all(params <= 502 for params in updates), updates
    async with maker() as db:
        tail = await db.scalar(
            select(EntityProfile).where(EntityProfile.entity_key == _WORKSTATIONS[-1])
        )
        unstamped = await db.scalar(
            select(func.count(EntityProfile.id)).where(EntityProfile.role.is_(None))
        )
    assert tail is not None
    assert (tail.role, tail.role_confidence) == ("workstation", 0.9)
    assert unstamped == 0
    await engine.dispose()


async def test_stamp_roles_leaves_built_at_where_the_build_put_it(
    settings_kratos: Settings,
) -> None:
    """The stamp moves the role and its confidence. ``built_at`` stays on every row.

    The rows sit in both IN lists of the first group, in the second group and
    among the rows that do not change. A stamp that wrote ``built_at`` would
    make the rows look newer than the build that wrote them.
    """
    engine, maker = await _db(settings_kratos)
    seeded = await _seed_stamp_estate(maker)
    async with maker() as db:
        assert await ep.stamp_roles(db, _estate_role) == 504
    async with maker() as db:
        rows = (await db.scalars(select(EntityProfile))).all()
    assert len(rows) == len(seeded)
    for row in rows:
        assert row.built_at == seeded[row.entity_key], row.entity_key
        # The stamp did write the row, so an unchanged built_at means something.
        assert (row.role, row.role_confidence) == _estate_role(row.entity_key), row.entity_key
    await engine.dispose()
