"""Tests for the host-dossier store: the two-lane invariant and the prod machine.

The spine of this file is the invariant that makes the feature trustworthy: an
operator override survives every subsequent inference run *structurally*, not by
convention —

* a rebuild preserves ``operator_*`` verbatim;
* a rebuild still refreshes ``inferred_*`` ON an overridden row (the
  anti-``InternalIdentifier.dismissed`` test — the builder must keep observing a
  field it is not allowed to decide, or persistent disagreement can never
  accumulate);
* an override committed mid-build is not answered with a verdict argued against
  the claim it replaced, whether it lands before the build's read or after it;
* ``clear_override`` clears the conflict state, and clears it to SQL NULL —
  the JSON literal ``'null'`` would leave the field reading as held forever;
* ``set_override`` does not touch the inference lane;
* ``first_seen`` is monotone and never widens backwards;
* ``prune`` spares any host carrying an operator override.

The rest exercise the persistent-disagreement state machine: three disagreeing
builds earn exactly one prod, a fourth inside the interval stays quiet,
agreement resets the observation counter but keeps the prompt history, a build
with no usable signal HOLDS the counter rather than resetting it, a JSON-only
override earns its prod like any other, and "keep mine" snoozes with a doubling
backoff capped at 90 days.

Scratch-DB recipe copied from tests/test_hunts_store.py: a real SQLite file
migrated to head, isolated per test by the autouse ``clean_env`` fixture.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from soc_ai.config import Settings
from soc_ai.dossier.resolve import resolve_dossier
from soc_ai.dossier.types import DOSSIER_FIELDS, Fact
from soc_ai.store import host_dossier as store
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import HostDossier, HostDossierField
from sqlalchemy import event, select, text, update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

# A fixed build clock. Every timestamp in this file is derived from it so a
# failure reads as "build N" rather than as an opaque datetime.
T0 = datetime(2026, 8, 1, 12, 0, 0)
HOUR = timedelta(hours=1)


async def _db(settings: Settings) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


def _fact(
    field: str,
    value: str | None,
    *,
    confidence: float = 0.9,
    strength: str = "strong",
    source: str = "banner",
    evidence: list[str] | None = None,
    observed_at: datetime | None = T0,
    value_json: object | None = None,
    conflict: str | None = None,
) -> Fact:
    return Fact(
        field=field,
        value=value,
        value_json=value_json,
        confidence=confidence,
        strength=strength,  # type: ignore[arg-type]
        source=source,  # type: ignore[arg-type]
        evidence=evidence if evidence is not None else [f"{value} (from {source})"],
        observed_at=observed_at,
        conflict=conflict,
    )


# ---------------------------------------------------------------------------
# upsert_host — monotone lifetime, identity rebinding, build bookkeeping
# ---------------------------------------------------------------------------


async def test_upsert_host_inserts_then_updates_one_row(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        row = await store.upsert_host(
            db, "192.168.10.202", first_seen=T0, last_seen=T0 + HOUR, event_count=41
        )
        assert row.id is not None
        assert row.host_key == "192.168.10.202"
        assert row.ip == "192.168.10.202"
        assert row.event_count == 41

        again = await store.upsert_host(
            db, "192.168.10.202", last_seen=T0 + 2 * HOUR, event_count=7
        )
        await db.commit()
        assert again.id == row.id  # keyed, not appended
        assert again.event_count == 7  # window count REPLACES, never accumulates
        assert len((await db.scalars(select(HostDossier))).all()) == 1
    await engine.dispose()


async def test_first_seen_is_monotone_and_never_widens_backwards(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await store.upsert_host(db, "192.168.10.202", first_seen=T0, last_seen=T0)
        # A later sweep over a NARROWER window sees the host for the first time
        # inside that window. first_seen must not follow it forward, or the
        # dossier would keep claiming the host is newly arrived.
        row = await store.upsert_host(
            db, "192.168.10.202", first_seen=T0 + 100 * HOUR, last_seen=T0 + 100 * HOUR
        )
        assert row.first_seen == T0
        assert row.last_seen == T0 + 100 * HOUR

        # An earlier observation DOES widen it backwards.
        row = await store.upsert_host(db, "192.168.10.202", first_seen=T0 - 500 * HOUR)
        await db.commit()
        assert row.first_seen == T0 - 500 * HOUR
        assert row.last_seen == T0 + 100 * HOUR  # last_seen is monotone the other way
    await engine.dispose()


async def test_aware_timestamps_are_stored_as_naive_utc(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        aware = datetime(2026, 8, 1, 12, 0, 0, tzinfo=UTC)
        row = await store.upsert_host(db, "192.168.10.202", first_seen=aware, last_seen=aware)
        await db.commit()
        # Mixing aware and naive datetimes raises at comparison time; the store
        # is the boundary that normalizes ES timestamps to the naive-UTC the
        # rest of the schema uses.
        assert row.first_seen == T0
        assert row.first_seen is not None and row.first_seen.tzinfo is None
    await engine.dispose()


async def test_identity_rebound_stamped_only_on_a_different_non_null_fingerprint(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        row = await store.upsert_host(db, "192.168.10.202", identity_fingerprint="aaa", now=T0)
        assert row.identity_rebound_at is None  # first sighting is not a rebind

        row = await store.upsert_host(
            db, "192.168.10.202", identity_fingerprint=None, now=T0 + HOUR
        )
        assert row.identity_fingerprint == "aaa"  # silence is not a change
        assert row.identity_rebound_at is None

        row = await store.upsert_host(
            db, "192.168.10.202", identity_fingerprint="bbb", now=T0 + 2 * HOUR
        )
        await db.commit()
        assert row.identity_fingerprint == "bbb"
        assert row.identity_rebound_at == T0 + 2 * HOUR
    await engine.dispose()


async def test_build_outcome_is_recorded_with_the_build_stamp(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await store.upsert_host(db, "192.168.10.202", last_built_at=T0, build_error="es timeout")
        row = await store.upsert_host(db, "192.168.10.202", event_count=9)
        assert row.build_error == "es timeout"  # a non-build upsert leaves it alone
        row = await store.upsert_host(db, "192.168.10.202", last_built_at=T0 + HOUR)
        await db.commit()
        assert row.build_error is None  # a clean build clears it
        assert row.last_built_at == T0 + HOUR
    await engine.dispose()


async def test_upsert_host_rejects_a_non_ip_key(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        with pytest.raises(ValueError):
            await store.upsert_host(db, "not-an-ip")
    await engine.dispose()


# ---------------------------------------------------------------------------
# THE TWO-LANE INVARIANT
# ---------------------------------------------------------------------------


async def test_rebuild_preserves_operator_value(settings_kratos: Settings) -> None:
    """An inference run must not be able to touch the operator lane. At all."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await store.upsert_host(db, "192.168.10.202", first_seen=T0, last_seen=T0)
        await store.upsert_inferred(db, host, _fact("role", "workstation", source="behaviour"))
        await store.set_override(
            db, "192.168.10.202", "role", "hypervisor", actor="analyst", note="Proxmox node", now=T0
        )

        # Three more builds, all of them still concluding "workstation".
        for i in range(3):
            await store.upsert_inferred(
                db, host, _fact("role", "workstation", source="behaviour"), now=T0 + i * HOUR
            )
        await db.commit()

        row = await store.get_field(db, "192.168.10.202", "role")
        assert row is not None
        assert row.operator_value == "hypervisor"
        assert row.operator_actor == "analyst"
        assert row.operator_note == "Proxmox node"
        assert row.operator_set_at == T0
        assert row.operator_value_json is None
    await engine.dispose()


async def test_rebuild_refreshes_inferred_on_an_overridden_row(settings_kratos: Settings) -> None:
    """The anti-``dismissed`` test: an override suppresses EFFECT, not OBSERVATION.

    ``internal_identifiers.upsert_detected`` returns a dismissed row untouched,
    which stops the system recording what it currently believes — and that is
    exactly what makes a "the evidence keeps disagreeing" prod impossible to
    build. Here the builder keeps writing into the inference lane forever.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await store.upsert_host(db, "192.168.10.202")
        await store.set_override(
            db, "192.168.10.202", "os_family", "linux", actor="analyst", now=T0
        )

        await store.upsert_inferred(
            db,
            host,
            _fact("os_family", "windows", confidence=0.9, evidence=["windows (from user-agent)"]),
            now=T0 + HOUR,
        )
        await db.commit()

        row = await store.get_field(db, "192.168.10.202", "os_family")
        assert row is not None
        assert row.operator_value == "linux"  # still authoritative
        assert row.inferred_value == "windows"  # ... and still observing
        assert row.inferred_confidence == 0.9
        assert row.inferred_source == "banner"
        assert row.inferred_last_run_at == T0 + HOUR
        assert row.inferred_evidence == {
            "banner": {
                "strings": ["windows (from user-agent)"],
                "value": "windows",
                "strength": "strong",
                "confidence": 0.9,
                "last_seen": T0.isoformat(),
            }
        }
    await engine.dispose()


async def test_set_override_does_not_touch_the_inference_lane(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await store.upsert_host(db, "192.168.10.202")
        await store.upsert_inferred(db, host, _fact("hostname", "pve01", source="banner"), now=T0)
        before = await store.get_field(db, "192.168.10.202", "hostname")
        assert before is not None
        snapshot = {
            column.name: getattr(before, column.name)
            for column in HostDossierField.__table__.columns
            if column.name.startswith("inferred_")
        }

        await store.set_override(db, "192.168.10.202", "hostname", "pve-lab-01", now=T0 + HOUR)
        await db.commit()

        after = await store.get_field(db, "192.168.10.202", "hostname")
        assert after is not None
        assert {
            column.name: getattr(after, column.name)
            for column in HostDossierField.__table__.columns
            if column.name.startswith("inferred_")
        } == snapshot
        assert after.operator_value == "pve-lab-01"
        assert after.operator_set_at == T0 + HOUR
    await engine.dispose()


async def test_an_override_landing_mid_build_is_not_clobbered(settings_kratos: Settings) -> None:
    """The sweep reads a field row, a route's ``set_override`` commits, the sweep
    writes: the conflict verdict in that write was argued against a claim that no
    longer stands.

    A blind UPDATE re-installs the disagreement the operator just settled — and
    prods them about their own brand-new value. The observation itself must still
    land (dropping it would be the ``dismissed`` trap); only the verdict is void.

    Two sessions on purpose: the identity map hands the builder the row as it
    read it, which is exactly what the real sweep holds while a route commits
    underneath it.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as build, maker() as route:
        host = await store.upsert_host(build, "192.168.10.202")
        await build.commit()
        await store.set_override(
            route, "192.168.10.202", "role", "workstation", actor="analyst", now=T0
        )
        for i in range(2):
            await store.upsert_inferred(
                build, host, _fact("role", "hypervisor", source="behaviour"), now=T0 + i * HOUR
            )
        await build.commit()

        # The build reads the row it is about to write...
        stale = await store.get_field(build, "192.168.10.202", "role")
        assert stale is not None and stale.operator_value == "workstation"
        await build.commit()

        # ...the operator changes their mind, from the route, and commits...
        await store.set_override(
            route, "192.168.10.202", "role", "hypervisor", actor="analyst", now=T0 + 2 * HOUR
        )

        # ...and only now does the build write what it saw.
        result = await store.upsert_inferred(
            build, host, _fact("role", "hypervisor", source="behaviour"), now=T0 + 2 * HOUR
        )
        await build.commit()
        assert result.prompted is False
        assert result.conflict_kind is None

    async with maker() as reader:
        row = await store.get_field(reader, "192.168.10.202", "role")
        assert row is not None
        assert row.operator_value == "hypervisor"  # the new claim stands
        assert row.conflict_kind is None  # and its clean slate stands with it
        assert row.conflict_first_seen_at is None
        assert row.conflict_observations == 0
        assert row.conflict_prompt_count == 0  # never prodded about their own value
        assert row.inferred_value == "hypervisor"  # the observation still landed
        assert row.inferred_last_run_at == T0 + 2 * HOUR
    await engine.dispose()


async def test_the_build_write_is_conditional_on_the_operator_lane(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The narrower half of the same race: the override commits AFTER the read.

    Re-reading closes the window the identity map opens, but not the one between
    the SELECT and the UPDATE — and the UPDATE is what installs the verdict. So
    it is conditional on the operator lane still being the one the verdict was
    argued from, and when that has moved the build recomputes instead of writing
    a judgement about a claim that is gone.

    The interleave is forced by handing ``upsert_inferred`` the row it had
    already loaded before the operator's commit; a real sweep gets there by
    taking longer over one host than an operator takes to click.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as build, maker() as route:
        host = await store.upsert_host(build, "192.168.10.202")
        await build.commit()
        await store.set_override(route, "192.168.10.202", "role", "workstation", now=T0)
        for i in range(2):
            await store.upsert_inferred(
                build, host, _fact("role", "hypervisor", source="behaviour"), now=T0 + i * HOUR
            )
        await build.commit()

        # Two disagreeing observations against "workstation": one more fires the prod.
        snapshot = await store.get_field(build, "192.168.10.202", "role")
        assert snapshot is not None and snapshot.conflict_observations == 2
        await build.commit()

        # The operator settles it — inside the build's read/write window.
        await store.set_override(route, "192.168.10.202", "role", "hypervisor", now=T0 + 2 * HOUR)

        reads = 0
        real_get = store._get_field_row

        async def stale_first(db: Any, dossier_id: int, field: str) -> Any:
            nonlocal reads
            reads += 1
            return snapshot if reads == 1 else await real_get(db, dossier_id, field)

        monkeypatch.setattr(store, "_get_field_row", stale_first)
        result = await store.upsert_inferred(
            build, host, _fact("role", "hypervisor", source="behaviour"), now=T0 + 2 * HOUR
        )
        monkeypatch.undo()  # the window is closed; the reads below are the test's own
        await build.commit()

    assert result.prompted is False  # never prodded about the operator's own value
    assert result.conflict_kind is None
    async with maker() as reader:
        row = await store.get_field(reader, "192.168.10.202", "role")
        assert row is not None
        assert row.operator_value == "hypervisor"
        assert row.conflict_observations == 0  # the stale count did not land
        assert row.conflict_first_seen_at is None
        assert row.conflict_prompt_count == 0
        assert row.inferred_value == "hypervisor"  # but the observation did
        assert row.inferred_last_run_at == T0 + 2 * HOUR
    assert reads == 2  # the guarded UPDATE matched nothing, so it read again
    await engine.dispose()


def test_inferred_write_never_names_an_operator_column() -> None:
    """Structural guard: the inference UPDATE cannot spell an operator column.

    The behavioural tests above prove today's code preserves the operator lane.
    This one stops a future edit from smuggling ``operator_set_at=now`` into the
    build path, which would silently re-date every override on every sweep.
    """
    operator_columns = {
        column.name
        for column in HostDossierField.__table__.columns
        if column.name.startswith("operator_")
    }
    for fact in (
        _fact("role", "hypervisor"),
        _fact("role", None, confidence=0.0, strength="none"),
        _fact("hostname", "pve01", source="telemetry", observed_at=None),
    ):
        values, _kind, _prompted = store._inferred_values(
            None,
            fact,
            now=T0,
            identity_rebound_at=None,
            min_confidence=0.6,
            min_observations=3,
            prompt_interval_hours=336,
        )
        assert operator_columns.isdisjoint(values)


async def test_clear_override_clears_conflict_state_but_keeps_prompt_history(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await store.upsert_host(db, "192.168.10.202")
        await store.set_override(
            db, "192.168.10.202", "role", "workstation", actor="analyst", now=T0
        )
        for i in range(3):
            await store.upsert_inferred(
                db, host, _fact("role", "hypervisor", source="behaviour"), now=T0 + i * HOUR
            )
        await db.commit()
        conflicted = await store.get_field(db, "192.168.10.202", "role")
        assert conflicted is not None and conflicted.conflict_prompt_count == 1

        row = await store.clear_override(db, "192.168.10.202", "role")
        assert row is not None
        assert row.operator_value is None
        assert row.operator_set_at is None
        assert row.operator_actor is None
        assert row.conflict_kind is None
        assert row.conflict_first_seen_at is None
        assert row.conflict_observations == 0
        assert row.conflict_snoozed_until is None
        # History is NOT reset: the backoff must keep growing if the operator
        # overrides again and the evidence disagrees again.
        assert row.conflict_prompt_count == 1
        assert row.conflict_last_prompted_at == T0 + 2 * HOUR
        assert row.inferred_value == "hypervisor"  # inference lane untouched
    await engine.dispose()


async def test_clear_override_writes_sql_null_not_the_json_string_null(
    settings_kratos: Settings,
) -> None:
    """A cleared override has to be SQL NULL, or it never really cleared.

    SQLAlchemy's JSON type defaults to ``none_as_null=False``, so a plain Python
    ``None`` is stored as the JSON literal ``'null'`` — which is NOT SQL NULL.
    Every predicate that asks whether a lane holds anything (``prune``'s override
    protection, the ``source=`` filter) tests ``IS NULL``, so a field cleared
    this way would keep reading as held forever.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await store.upsert_host(db, "192.168.10.202", last_seen=T0)
        await store.set_override(
            db,
            "192.168.10.202",
            "services_offered",
            None,
            value_json=[{"port": 8006, "proto": "tcp"}],
            actor="analyst",
            now=T0,
        )
        await store.clear_override(db, "192.168.10.202", "services_offered")

        raw = await db.scalar(text("SELECT operator_value_json FROM host_dossier_field"))
        assert raw is None  # the string 'null' would be a value, not an absence

        # The two SQL-level consumers of "does this lane hold anything".
        assert await store.list_dossiers(db, source="operator") == ([], 0)
        _rows, total = await store.list_dossiers(db, source="inferred")
        assert total == 1
        # An override the operator dropped must stop protecting the host.
        assert await store.prune(db, max_hosts=0) == 1
    await engine.dispose()


async def test_a_scalar_override_leaves_the_json_lane_sql_null(settings_kratos: Settings) -> None:
    """The same trap on the way in: a scalar override writes no structured value.

    ``set_override`` names ``operator_value_json`` on every call, so a scalar
    override would otherwise stamp the JSON literal 'null' into the structured
    column and make ``operator_value_json IS NOT NULL`` true for a field that
    holds nothing structured at all.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await store.upsert_host(db, "192.168.10.202")
        # Both write paths: an insert (no field row yet) and an update.
        await store.set_override(db, "192.168.10.202", "criticality", "high", now=T0)
        await store.upsert_inferred(db, host, _fact("role", "server", source="behaviour"), now=T0)
        await store.set_override(db, "192.168.10.202", "role", "hypervisor", now=T0)

        held = (
            await db.execute(
                text("SELECT field FROM host_dossier_field WHERE operator_value_json IS NOT NULL")
            )
        ).all()
        assert held == []
    await engine.dispose()


async def test_clear_override_returns_none_without_an_override(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await store.upsert_host(db, "192.168.10.202")
        await store.upsert_inferred(db, host, _fact("role", "server", source="behaviour"))
        await db.commit()
        # No override on this field, and no such host — both return None; the
        # route disambiguates 404 from 409 with get_field().
        assert await store.clear_override(db, "192.168.10.202", "role") is None
        assert await store.clear_override(db, "192.168.10.9", "role") is None
        assert await store.get_field(db, "192.168.10.202", "role") is not None
        assert await store.get_field(db, "192.168.10.9", "role") is None
    await engine.dispose()


async def test_set_override_creates_an_operator_only_field_row(settings_kratos: Settings) -> None:
    """``criticality`` and ``policy_notes`` are never inferred — no row exists yet."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await store.upsert_host(db, "192.168.10.202")
        row = await store.set_override(
            db,
            "192.168.10.202",
            "policy_notes",
            "no interactive SSH; API-token access only",
            actor="analyst",
            now=T0,
        )
        await db.commit()
        assert row is not None
        assert row.operator_value == "no interactive SSH; API-token access only"
        assert row.inferred_value is None
        assert row.inferred_confidence is None
    await engine.dispose()


async def test_set_override_on_an_unknown_host_returns_none(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        assert await store.set_override(db, "192.168.10.9", "criticality", "high") is None
        assert await store.set_override(db, "not-an-ip", "criticality", "high") is None
    await engine.dispose()


@pytest.mark.parametrize("field", ["bogus", "", "operator_value"])
async def test_unknown_fields_are_rejected(settings_kratos: Settings, field: str) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await store.upsert_host(db, "192.168.10.202")
        with pytest.raises(ValueError):
            await store.upsert_inferred(db, host, _fact(field, "x"))
        with pytest.raises(ValueError):
            await store.set_override(db, "192.168.10.202", field, "x")
    await engine.dispose()


# ---------------------------------------------------------------------------
# The persistent-disagreement state machine
# ---------------------------------------------------------------------------


async def _conflicting_host(db: AsyncSession) -> HostDossier:
    """A host whose operator says "workstation" and whose evidence says otherwise."""
    host = await store.upsert_host(db, "192.168.10.202")
    await store.set_override(db, "192.168.10.202", "role", "workstation", actor="analyst", now=T0)
    return host


async def test_three_disagreeing_builds_fire_exactly_one_prompt(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await _conflicting_host(db)
        prompts = []
        for i in range(3):
            result = await store.upsert_inferred(
                db, host, _fact("role", "hypervisor", source="behaviour"), now=T0 + i * HOUR
            )
            prompts.append(result.prompted)
            assert result.conflict_kind == "mismatch"
        await db.commit()

        # One anomalous sweep must not nag; three consecutive ones earn one prod.
        assert prompts == [False, False, True]
        row = await store.get_field(db, "192.168.10.202", "role")
        assert row is not None
        assert row.conflict_observations == 3
        assert row.conflict_kind == "mismatch"
        assert row.conflict_first_seen_at == T0  # the disagreement started at build 1
        assert row.conflict_prompt_count == 1
        assert row.conflict_last_prompted_at == T0 + 2 * HOUR
    await engine.dispose()


async def test_fourth_build_inside_the_interval_does_not_reprompt(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await _conflicting_host(db)
        for i in range(4):
            result = await store.upsert_inferred(
                db, host, _fact("role", "hypervisor", source="behaviour"), now=T0 + i * HOUR
            )
        await db.commit()
        assert result.prompted is False
        row = await store.get_field(db, "192.168.10.202", "role")
        assert row is not None
        assert row.conflict_observations == 4  # still counting
        assert row.conflict_prompt_count == 1  # but silent
        assert row.conflict_last_prompted_at == T0 + 2 * HOUR

        # Past the interval, the same standing disagreement prods again.
        late = await store.upsert_inferred(
            db, host, _fact("role", "hypervisor", source="behaviour"), now=T0 + 400 * HOUR
        )
        await db.commit()
        assert late.prompted is True
        assert late.row.conflict_prompt_count == 2
    await engine.dispose()


async def test_agreement_resets_observations_but_keeps_prompt_count(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await _conflicting_host(db)
        for i in range(3):
            await store.upsert_inferred(
                db, host, _fact("role", "hypervisor", source="behaviour"), now=T0 + i * HOUR
            )
        # The network changes and the builder now agrees with the operator.
        result = await store.upsert_inferred(
            db, host, _fact("role", "workstation", source="behaviour"), now=T0 + 3 * HOUR
        )
        await db.commit()
        assert result.conflict_kind is None
        assert result.prompted is False
        row = result.row
        assert row.conflict_first_seen_at is None
        assert row.conflict_observations == 0
        assert row.conflict_snoozed_until is None
        assert row.conflict_kind is None
        # Kept as history — a second disagreement backs off from where the
        # first one left it rather than starting the nag from scratch.
        assert row.conflict_prompt_count == 1
        assert row.conflict_last_prompted_at == T0 + 2 * HOUR
    await engine.dispose()


async def test_a_low_confidence_inference_never_conflicts(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await _conflicting_host(db)
        for i in range(4):
            result = await store.upsert_inferred(
                db,
                host,
                _fact("role", "hypervisor", confidence=0.5, strength="weak", source="behaviour"),
                now=T0 + i * HOUR,
            )
        await db.commit()
        # A weak guess is not "continued evidence" — it must never earn a prod.
        assert result.conflict_kind is None
        assert result.row.conflict_observations == 0
        assert result.row.conflict_prompt_count == 0
    await engine.dispose()


async def test_a_json_only_override_still_earns_its_prod(settings_kratos: Settings) -> None:
    """``services_offered`` / ``activity_profile`` / ``management_plane`` are
    overridden through ``value_json`` with ``operator_value`` left NULL — that is
    what ``DossierOverrideIn.value_json`` exists to supply. A disagreement check
    that only compared the scalar lane could never see one of those disagree, so
    the three structured fields silently lost the cyclic prod altogether.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await store.upsert_host(db, "192.168.10.202")
        await store.set_override(
            db,
            "192.168.10.202",
            "services_offered",
            None,
            value_json=[{"port": 8006, "proto": "tcp"}],
            actor="analyst",
            now=T0,
        )
        for i in range(3):
            result = await store.upsert_inferred(
                db,
                host,
                _fact(
                    "services_offered",
                    None,
                    value_json=[{"port": 22, "proto": "tcp"}],
                    source="behaviour",
                    evidence=["responds on tcp/22 (from behaviour)"],
                ),
                now=T0 + i * HOUR,
            )
            assert result.conflict_kind == "mismatch"
        await db.commit()

        assert result.prompted is True
        assert result.row.conflict_observations == 3
        assert result.row.operator_value is None  # the override lives in the JSON lane
        assert result.row.operator_value_json == [{"port": 8006, "proto": "tcp"}]
    await engine.dispose()


async def test_a_reordered_json_lane_is_not_a_disagreement(settings_kratos: Settings) -> None:
    """Key order and list order are not news.

    A ``services_offered`` list the next sweep happens to bucket in a different
    order is the same fact, and prodding an operator about it would be exactly
    the noise the min-observations gate exists to suppress.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await store.upsert_host(db, "192.168.10.202")
        await store.set_override(
            db,
            "192.168.10.202",
            "services_offered",
            None,
            value_json=[{"port": 22, "proto": "tcp"}, {"port": 8006, "proto": "tcp"}],
            now=T0,
        )
        result = await store.upsert_inferred(
            db,
            host,
            _fact(
                "services_offered",
                None,
                value_json=[{"proto": "tcp", "port": 8006}, {"proto": "tcp", "port": 22}],
                source="behaviour",
                evidence=["responds on tcp/22, tcp/8006 (from behaviour)"],
            ),
            now=T0 + HOUR,
        )
        await db.commit()
        assert result.conflict_kind is None
        assert result.row.conflict_first_seen_at is None
    await engine.dispose()


async def test_the_builders_own_bookkeeping_is_not_a_disagreement(
    settings_kratos: Settings,
) -> None:
    """The structured lanes carry counters no operator ever writes.

    ``services_offered`` entries come with a per-port connection count and a
    ``service`` slot; ``activity_profile`` is mostly an hour-of-day histogram and
    byte percentiles. Compared for deep equality, every build would "disagree"
    with a services list the operator got exactly right, and the prod would fire
    forever. The operator's claim is contradicted only on what they actually
    stated — but a port they did NOT state still contradicts the enumeration.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await store.upsert_host(db, "192.168.10.202")
        await store.set_override(
            db, "192.168.10.202", "services_offered", None, value_json=[{"port": 8006}], now=T0
        )

        def _seen(*ports: int) -> Fact:
            return _fact(
                "services_offered",
                ", ".join(f"tcp/{port}" for port in ports),
                value_json=[
                    {"port": port, "proto": "tcp", "count": 40 + port, "service": None}
                    for port in ports
                ],
                source="behaviour",
                evidence=["responder connections (from behaviour)"],
            )

        agreed = await store.upsert_inferred(db, host, _seen(8006), now=T0 + HOUR)
        assert agreed.conflict_kind is None  # counts are detail, not news
        assert agreed.row.conflict_first_seen_at is None

        # A second port the operator did not declare IS news: the list is an
        # enumeration, and the builder is now seeing a service they left out.
        widened = await store.upsert_inferred(db, host, _seen(22, 8006), now=T0 + 2 * HOUR)
        await db.commit()
        assert widened.conflict_kind == "mismatch"
    await engine.dispose()


async def test_a_weak_build_holds_the_conflict_instead_of_resetting_it(
    settings_kratos: Settings,
) -> None:
    """ "No usable signal" is not "the operator was right".

    A build whose inference lands below the confidence floor has nothing to say
    about the override either way. Treating that silence as AGREEMENT wiped
    ``conflict_first_seen_at`` and the observation counter, so a host that
    alternates strong and weak across builds could never reach the
    three-consecutive threshold and the prod would never fire.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await _conflicting_host(db)
        strong = _fact("role", "hypervisor", source="behaviour")
        weak = _fact("role", "hypervisor", confidence=0.5, strength="weak", source="behaviour")

        first = await store.upsert_inferred(db, host, strong, now=T0)
        assert first.row.conflict_observations == 1

        quiet = await store.upsert_inferred(db, host, weak, now=T0 + HOUR)
        assert quiet.conflict_kind is None  # a weak guess never argues...
        assert quiet.row.conflict_first_seen_at == T0  # ...and never settles it either
        assert quiet.row.conflict_observations == 1
        assert quiet.row.conflict_kind == "mismatch"

        await store.upsert_inferred(db, host, strong, now=T0 + 2 * HOUR)
        third = await store.upsert_inferred(db, host, strong, now=T0 + 3 * HOUR)
        await db.commit()

        # Three disagreeing builds, one interrupted by a weak one: still a prod.
        assert third.row.conflict_observations == 3
        assert third.prompted is True
        assert third.row.conflict_prompt_count == 1
    await engine.dispose()


async def test_prompt_interval_zero_never_prompts(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await _conflicting_host(db)
        for i in range(6):
            result = await store.upsert_inferred(
                db,
                host,
                _fact("role", "hypervisor", source="behaviour"),
                now=T0 + i * HOUR,
                prompt_interval_hours=0,
            )
        await db.commit()
        assert result.row.conflict_observations == 6  # still tracked
        assert result.row.conflict_prompt_count == 0  # never prodded
    await engine.dispose()


async def test_a_family_disagreement_is_kept_in_the_evidence(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await store.upsert_host(db, "192.168.10.202", last_observed_at=T0 + HOUR)
        assert host.last_observed_at == T0 + HOUR
        conflict = "OS family disagreement: banner=linux vs user-agent=windows"
        result = await store.upsert_inferred(
            db, host, _fact("os_family", "linux", conflict=conflict), now=T0
        )
        await db.commit()
        # The classifier's own two-sources-disagree string survives into the
        # row: a dossier that dropped the loser would hide the case most worth
        # reading.
        assert result.row.inferred_evidence is not None
        assert result.row.inferred_evidence["banner"]["conflict"] == conflict
    await engine.dispose()


async def test_retraction_nulls_the_value_and_conflicts_with_an_override(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await store.upsert_host(db, "192.168.10.202")
        await store.upsert_inferred(db, host, _fact("hostname", "pve01"), now=T0)
        await store.set_override(db, "192.168.10.202", "hostname", "pve-lab-01", now=T0)

        result = await store.upsert_inferred(
            db,
            host,
            _fact("hostname", None, confidence=0.0, strength="none", evidence=[]),
            now=T0 + HOUR,
        )
        await db.commit()
        assert result.row.inferred_value is None
        assert result.row.inferred_retracted_at == T0 + HOUR
        assert result.row.inferred_source is None
        assert result.conflict_kind == "retracted"
        # The evidence that supported the retracted belief is kept: it explains
        # what the dossier used to think and why.
        assert result.row.inferred_evidence is not None
        assert "banner" in result.row.inferred_evidence

        # The value comes back → the retraction stamp is cleared.
        back = await store.upsert_inferred(db, host, _fact("hostname", "pve01"), now=T0 + 2 * HOUR)
        await db.commit()
        assert back.row.inferred_retracted_at is None
    await engine.dispose()


async def test_identity_rebound_after_an_override_is_a_conflict(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await store.upsert_host(db, "192.168.10.202", identity_fingerprint="aaa", now=T0)
        await store.set_override(
            db, "192.168.10.202", "criticality", "high", actor="analyst", now=T0
        )
        # A different machine now answers on this address.
        host = await store.upsert_host(
            db, "192.168.10.202", identity_fingerprint="bbb", now=T0 + 10 * HOUR
        )
        result = await store.upsert_inferred(
            db,
            host,
            _fact("criticality", None, confidence=0.0, strength="none", evidence=[]),
            now=T0 + 10 * HOUR,
        )
        await db.commit()
        assert result.conflict_kind == "rebound"

        # Re-affirming the override after the rebind settles it.
        await store.set_override(
            db, "192.168.10.202", "criticality", "high", actor="analyst", now=T0 + 11 * HOUR
        )
        settled = await store.upsert_inferred(
            db,
            host,
            _fact("criticality", None, confidence=0.0, strength="none", evidence=[]),
            now=T0 + 12 * HOUR,
        )
        await db.commit()
        assert settled.conflict_kind is None
    await engine.dispose()


async def test_evidence_is_merged_by_source(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await store.upsert_host(db, "192.168.10.202")
        await store.upsert_inferred(
            db,
            host,
            _fact("os_family", "linux", source="telemetry", evidence=["linux (from user-agent)"]),
            now=T0,
        )
        result = await store.upsert_inferred(
            db,
            host,
            _fact(
                "os_family",
                "linux",
                source="banner",
                evidence=["linux (from OpenSSH_9.6p1 Debian-3)"],
            ),
            now=T0 + HOUR,
        )
        await db.commit()
        evidence = result.row.inferred_evidence
        assert evidence is not None
        # A stronger source arriving later refines the value without erasing the
        # weaker belief that supported it.
        assert set(evidence) == {"telemetry", "banner"}
        assert evidence["telemetry"]["strings"] == ["linux (from user-agent)"]
    await engine.dispose()


# ---------------------------------------------------------------------------
# snooze_conflict — "keep mine", with a decaying nag
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("prompt_count", "expected_hours"),
    [
        (0, 336),  # 14d
        (1, 672),  # 28d
        (2, 1344),  # 56d
        (3, 2160),  # 112d → capped at 90d
        (9, 2160),  # cap holds however many times it has fired
    ],
)
async def test_snooze_doubles_per_prompt_and_caps_at_90_days(
    settings_kratos: Settings, prompt_count: int, expected_hours: int
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await _conflicting_host(db)
        await store.upsert_inferred(db, host, _fact("role", "hypervisor", source="behaviour"))
        await db.execute(
            update(HostDossierField).values(
                conflict_prompt_count=prompt_count, conflict_observations=4
            )
        )
        row = await store.snooze_conflict(db, "192.168.10.202", "role", now=T0)
        await db.commit()
        assert row is not None
        assert row.conflict_snoozed_until == T0 + timedelta(hours=expected_hours)
        assert row.conflict_observations == 0  # the counter restarts after the cycle
        assert row.operator_value == "workstation"  # "keep mine" keeps mine
    await engine.dispose()


async def test_a_snoozed_conflict_stays_quiet_until_the_snooze_expires(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await _conflicting_host(db)
        for i in range(3):
            await store.upsert_inferred(
                db, host, _fact("role", "hypervisor", source="behaviour"), now=T0 + i * HOUR
            )
        await store.snooze_conflict(db, "192.168.10.202", "role", now=T0 + 3 * HOUR)

        # Builds keep disagreeing, well past the prompt interval, but the
        # operator said "keep mine" — silence until the snooze (336h × 2 after
        # one prod) expires.
        for i in range(4, 7):
            result = await store.upsert_inferred(
                db, host, _fact("role", "hypervisor", source="behaviour"), now=T0 + i * 100 * HOUR
            )
            assert result.prompted is False
        await db.commit()
        assert result.row.conflict_prompt_count == 1

        after = await store.upsert_inferred(
            db, host, _fact("role", "hypervisor", source="behaviour"), now=T0 + 1000 * HOUR
        )
        await db.commit()
        assert after.prompted is True
        assert after.row.conflict_prompt_count == 2
    await engine.dispose()


async def test_snooze_on_an_unknown_row_returns_none(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        assert await store.snooze_conflict(db, "192.168.10.9", "role") is None
    await engine.dispose()


# ---------------------------------------------------------------------------
# Reads: get_dossier / list_dossiers / conflicts_due
# ---------------------------------------------------------------------------


async def test_get_dossier_returns_fields_in_render_order(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await store.upsert_host(db, "192.168.10.202", first_seen=T0, last_seen=T0)
        for field in ("role", "hostname", "os_family"):
            await store.upsert_inferred(db, host, _fact(field, "x"), now=T0)
        await db.commit()

        got = await store.get_dossier(db, "192.168.10.202")
        assert got is not None
        row, fields = got
        assert row.host_key == "192.168.10.202"
        names = [f.field for f in fields]
        assert names == [f for f in DOSSIER_FIELDS if f in set(names)]
        assert await store.get_dossier(db, "192.168.10.9") is None
        # A path segment that is not an address cannot name a host — 404, not 500.
        assert await store.get_dossier(db, "not-an-ip") is None
        assert await store.get_field(db, "not-an-ip", "role") is None
        assert await store.snooze_conflict(db, "  ", "role") is None
    await engine.dispose()


async def test_list_dossiers_pages_filters_and_counts(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for i, role in enumerate(("hypervisor", "workstation", "server", "workstation")):
            ip = f"192.168.10.{10 + i}"
            host = await store.upsert_host(db, ip, first_seen=T0, last_seen=T0 + i * HOUR)
            await store.upsert_inferred(db, host, _fact("role", role, source="behaviour"), now=T0)
        # The operator disagrees about one of them; the resolved role follows
        # the operator lane, so the filter must too.
        await store.set_override(db, "192.168.10.11", "role", "hypervisor", now=T0)
        await store.upsert_inferred(
            db,
            await store.upsert_host(db, "192.168.10.10"),
            _fact("hostname", "pve01", source="banner"),
            now=T0,
        )
        await db.commit()

        # Paging is what this test pins, so the order is pinned explicitly —
        # the DEFAULT is attention, which the attention tests own.
        rows, total = await store.list_dossiers(db, sort="last_seen")
        assert total == 4
        assert [r.ip for r, _fields in rows] == [
            "192.168.10.13",
            "192.168.10.12",
            "192.168.10.11",
            "192.168.10.10",
        ]

        rows, total = await store.list_dossiers(db, sort="last_seen", limit=2, offset=2)
        assert total == 4
        assert [r.ip for r, _fields in rows] == ["192.168.10.11", "192.168.10.10"]

        rows, total = await store.list_dossiers(db, role="hypervisor")
        assert total == 2
        assert {r.ip for r, _fields in rows} == {"192.168.10.10", "192.168.10.11"}

        rows, total = await store.list_dossiers(db, source="operator")
        assert [r.ip for r, _fields in rows] == ["192.168.10.11"]

        rows, _total = await store.list_dossiers(db, q="pve")
        assert [r.ip for r, _fields in rows] == ["192.168.10.10"]
        rows, _total = await store.list_dossiers(db, q="10.13")
        assert [r.ip for r, _fields in rows] == ["192.168.10.13"]

        rows, total = await store.list_dossiers(db, source="inferred")
        assert total == 3

        # Staleness-first is the sweep's own ordering; never-built sorts first.
        rows, _total = await store.list_dossiers(db, sort="stale")
        assert rows[0][0].last_built_at is None
    await engine.dispose()


async def test_list_dossiers_sorts_are_an_allowlist(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for i in range(3):
            await store.upsert_host(
                db,
                f"192.168.10.{12 - i}",
                first_seen=T0 - i * HOUR,
                last_seen=T0 + i * HOUR,
                event_count=i,
            )
        await db.commit()

        async def _ips(**kwargs: Any) -> list[str]:
            rows, _total = await store.list_dossiers(db, **kwargs)
            return [row.ip for row, _fields in rows]

        assert await _ips(sort="ip") == ["192.168.10.10", "192.168.10.11", "192.168.10.12"]
        assert await _ips(sort="first_seen") == ["192.168.10.12", "192.168.10.11", "192.168.10.10"]
        assert await _ips(sort="event_count") == ["192.168.10.10", "192.168.10.11", "192.168.10.12"]
        # An unknown sort is a client typo, not a 500: fall back to last_seen.
        assert await _ips(sort="'; DROP TABLE") == await _ips()
        assert await _ips(q="   ") == await _ips()
    await engine.dispose()


async def test_list_dossiers_clamps_the_page_size(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await store.upsert_host(db, "192.168.10.202")
        await db.commit()
        rows, _total = await store.list_dossiers(db, limit=10_000, offset=-5)
        assert len(rows) == 1
    await engine.dispose()


async def test_health_broken_selects_exactly_the_kpi_no_clean_build_set(
    settings_kratos: Settings,
) -> None:
    """``health="broken"`` = never built OR last build errored — the KPI's set.

    The strip's "never built or errored" count must click through to the rows it
    counted; a filter matching a different set is the untriaged-tile defect
    (a number that points at nothing) rebuilt on this screen.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await store.upsert_host(db, "192.168.10.10", last_seen=T0, last_built_at=T0)
        # Seen on the wire, never built: the census reached it, the sweep did not.
        await store.upsert_host(db, "192.168.10.11", last_seen=T0)
        # Built, and the build failed.
        await store.upsert_host(
            db, "192.168.10.12", last_seen=T0, last_built_at=T0, build_error="grid timeout"
        )
        await db.commit()

        rows, total = await store.list_dossiers(db, health="broken")
        assert total == 2
        assert {r.ip for r, _f in rows} == {"192.168.10.11", "192.168.10.12"}
        # The filter and the KPI are the same predicate, or they will drift.
        summary = await store.summarize_dossiers(db, now=T0 + HOUR)
        assert total == summary.never_built

        # Composes with the other filters.
        rows, total = await store.list_dossiers(db, health="broken", q="10.12")
        assert total == 1
        assert [r.ip for r, _f in rows] == ["192.168.10.12"]

        # An unknown value is ignored, matching the source filter's convention —
        # the route's Literal is what turns a typo into a 422.
        _rows, total = await store.list_dossiers(db, health="bogus")
        assert total == 3
    await engine.dispose()


# ---------------------------------------------------------------------------
# sort=attention — the DEFAULT list order, and why it exists
#
# The dogfood seed that motivated this: 41 hosts sorted by last_seen, and the
# ONE that mattered — named, critical, operator note, open conflict — was the
# last row. The default order must rank what needs the operator, not what
# happened to talk most recently.
# ---------------------------------------------------------------------------


async def test_attention_sort_surfaces_what_needs_the_operator(
    settings_kratos: Settings,
) -> None:
    """No clean build > open conflict > declared (critical first) > named > the rest.

    ``last_seen`` is deliberately INVERTED against the expected order — the
    host that talked most recently is the least interesting one — so a fall
    back to the old default cannot accidentally pass this test.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # Tier 5 (the anonymous tail): newest last_seen, nothing else.
        await store.upsert_host(db, "192.168.20.50", last_seen=T0 + 5 * HOUR, last_built_at=T0)
        # Tier 4: a resolver-assertable name.
        named = await store.upsert_host(
            db, "192.168.20.40", last_seen=T0 + 4 * HOUR, last_built_at=T0
        )
        await store.upsert_inferred(db, named, _fact("hostname", "nas-1", source="banner"), now=T0)
        # Tier 3: declared. Mixed-case "Critical" must still outrank "low".
        await store.upsert_host(db, "192.168.20.32", last_seen=T0 + 3 * HOUR, last_built_at=T0)
        await store.set_override(db, "192.168.20.32", "criticality", "low", now=T0)
        await store.upsert_host(db, "192.168.20.31", last_seen=T0 + 2 * HOUR, last_built_at=T0)
        await store.set_override(db, "192.168.20.31", "criticality", "Critical", now=T0)
        # Tier 2: an open conflict past the observation gate. This host is ALSO
        # declared — the conflict must outrank its own declaration.
        conflicted = await store.upsert_host(
            db, "192.168.20.20", last_seen=T0 + HOUR, last_built_at=T0
        )
        await store.set_override(db, "192.168.20.20", "role", "workstation", now=T0)
        for i in range(3):
            await store.upsert_inferred(
                db, conflicted, _fact("role", "hypervisor", source="behaviour"), now=T0 + i * HOUR
            )
        # Tier 1: no clean build — here, a build that FAILED. (The never-built
        # half of that tier is pinned by the health-broken relation test.)
        await store.upsert_host(
            db, "192.168.20.10", last_seen=T0, last_built_at=T0, build_error="grid timeout"
        )
        await db.commit()

        now = T0 + 6 * HOUR
        rows, total = await store.list_dossiers(db, sort="attention", now=now)
        assert total == 6
        assert [r.ip for r, _fields in rows] == [
            "192.168.20.10",  # no clean build (errored)
            "192.168.20.20",  # open conflict
            "192.168.20.31",  # declared, critical
            "192.168.20.32",  # declared, low
            "192.168.20.40",  # named
            "192.168.20.50",  # everything else
        ]

        # Attention is the DEFAULT: the landing screen gets this order without
        # asking for it.
        default_rows, _total = await store.list_dossiers(db, now=now)
        assert [r.ip for r, _f in default_rows] == [r.ip for r, _f in rows]

        # The old default is still available, and still means what it meant.
        recent, _total = await store.list_dossiers(db, sort="last_seen", now=now)
        assert [r.ip for r, _f in recent] == [
            "192.168.20.50",
            "192.168.20.40",
            "192.168.20.32",
            "192.168.20.31",
            "192.168.20.20",
            "192.168.20.10",
        ]
    await engine.dispose()


async def test_importance_sort_leads_with_the_named_and_the_graded(
    settings_kratos: Settings,
) -> None:
    """The LANDING order: critical/high, then named, then the rest of the grading.

    The dogfood finding this pins (B2a, 2026-08-11): on a real estate almost
    every host has never been built, so ``attention``'s tier 0 — no clean build
    — was the whole first screen, and the handful of named, operator-graded
    machines sat below the fold. This order asks the opposite question: which
    hosts does the operator already care about.

    And it must not answer that question the way it broke the last one. Only
    ``critical`` and ``high`` lead the named predicate; ``medium`` and ``low``
    rank BELOW it. Leading with every grade would mean one bulk "declare
    criticality" pass over a subnet of printers as ``low`` puts 200 dash-under-
    HOST rows in front of the domain controller — the first-screen-of-nothing
    this order exists to prevent, arriving by way of the order itself.

    ``last_seen`` is inverted against the expected order so a fall back to the
    old default cannot accidentally pass.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # The anonymous tail: never built, nothing declared, talked most
        # recently. Under `attention` these lead; here they sink.
        for n in range(3):
            await store.upsert_host(db, f"192.168.60.{50 + n}", last_seen=T0 + (9 - n) * HOUR)
        # Named only — no operator has graded it.
        named = await store.upsert_host(
            db, "192.168.60.40", last_seen=T0 + 4 * HOUR, last_built_at=T0
        )
        await store.upsert_inferred(db, named, _fact("hostname", "nas-1", source="banner"), now=T0)
        # Declared, but not on criticality and not named: still ahead of the tail.
        await store.upsert_host(db, "192.168.60.30", last_seen=T0 + 3 * HOUR, last_built_at=T0)
        await store.set_override(db, "192.168.60.30", "role", "workstation", now=T0)
        # The bulk-tagged printers, unnamed. Graded, and MORE recently seen than
        # the named host — neither buys them a place above it.
        await store.upsert_host(db, "192.168.60.10", last_seen=T0 + 6 * HOUR, last_built_at=T0)
        await store.set_override(db, "192.168.60.10", "criticality", "low", now=T0)
        await store.upsert_host(db, "192.168.60.11", last_seen=T0 + 5 * HOUR, last_built_at=T0)
        await store.set_override(db, "192.168.60.11", "criticality", "medium", now=T0)
        # Graded as mattering. Mixed-case "Critical" must still outrank "high",
        # and a graded host that has NEVER been built still leads — the
        # operator's word about what matters outranks the sweep's reach.
        await store.upsert_host(db, "192.168.60.21", last_seen=T0 + 2 * HOUR, last_built_at=T0)
        await store.set_override(db, "192.168.60.21", "criticality", "high", now=T0)
        await store.upsert_host(db, "192.168.60.20", last_seen=T0 + HOUR)
        await store.set_override(db, "192.168.60.20", "criticality", "Critical", now=T0)
        await db.commit()

        now = T0 + 10 * HOUR
        rows, total = await store.list_dossiers(db, sort="importance", now=now)
        assert total == 9
        assert [r.ip for r, _f in rows] == [
            "192.168.60.20",  # declared critical (never built — still first)
            "192.168.60.21",  # declared high
            "192.168.60.40",  # named — AHEAD of every medium and low
            "192.168.60.11",  # graded medium, unnamed
            "192.168.60.10",  # graded low, unnamed (and the more recent of the two)
            "192.168.60.30",  # declared something ungraded, unnamed
            "192.168.60.50",  # the anonymous tail, newest first
            "192.168.60.51",
            "192.168.60.52",
        ]

        # Said plainly, because this is the rule and not an artefact of the
        # fixture's timestamps: a low-graded host never outranks a named one; a
        # critical-graded one always does.
        order = [r.ip for r, _f in rows]
        assert order.index("192.168.60.40") < order.index("192.168.60.10")
        assert order.index("192.168.60.20") < order.index("192.168.60.40")

        # Page of one at each offset reassembles the same order: ranked in SQL,
        # before the page was cut.
        paged = []
        for offset in range(total):
            page, _t = await store.list_dossiers(
                db, sort="importance", now=now, limit=1, offset=offset
            )
            paged.extend(r.ip for r, _f in page)
        assert paged == [r.ip for r, _f in rows]

        # Needs-attention stays reachable, and still leads with the unreached
        # hosts — this order is an addition, not a replacement.
        attention, _t = await store.list_dossiers(db, sort="attention", now=now)
        assert [r.ip for r, _f in attention][:4] == [
            "192.168.60.20",  # never built AND critical
            "192.168.60.50",  # never built, anonymous tail
            "192.168.60.51",
            "192.168.60.52",
        ]
    await engine.dispose()


async def test_attention_tier_zero_is_exactly_the_health_broken_set(
    settings_kratos: Settings,
) -> None:
    """Never-built and errored hosts BOTH lead the order — the filter's own set.

    The dogfood catch this pins: tier 0 was drawn as ``build_error`` only, so a
    never-built host was "broken" to the KPI and to ``health=broken`` but
    "nothing special" to the sort — three surfaces, two definitions. All three
    must read :func:`_no_clean_build`; the top of the attention order IS the
    click-through set.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # A conflicted host: the strongest NON-broken tier, so ranking below it
        # is exactly the defect.
        conflicted = await store.upsert_host(
            db, "192.168.50.30", last_seen=T0 + 3 * HOUR, last_built_at=T0
        )
        await store.set_override(db, "192.168.50.30", "role", "workstation", now=T0)
        for i in range(3):
            await store.upsert_inferred(
                db, conflicted, _fact("role", "hypervisor", source="behaviour"), now=T0 + i * HOUR
            )
        # Built, and the build failed.
        await store.upsert_host(
            db,
            "192.168.50.10",
            last_seen=T0 + 2 * HOUR,
            last_built_at=T0,
            build_error="es timeout",
        )
        # Seen by the census, never built at all.
        await store.upsert_host(db, "192.168.50.20", last_seen=T0 + HOUR)
        await db.commit()

        now = T0 + 4 * HOUR
        rows, _total = await store.list_dossiers(db, sort="attention", now=now)
        ordered = [r.ip for r, _f in rows]
        assert ordered == [
            "192.168.50.10",  # errored (newer last_seen breaks the tier-0 tie)
            "192.168.50.20",  # never built — ahead of the conflict, not below the tail
            "192.168.50.30",  # open conflict
        ]

        # The relation itself: the head of the order is the filter's whole set.
        broken_rows, broken_total = await store.list_dossiers(db, health="broken", now=now)
        assert {r.ip for r, _f in broken_rows} == set(ordered[:broken_total])
        # ...and the filter still is the KPI's set, so all three surfaces agree.
        assert broken_total == (await store.summarize_dossiers(db, now=now)).never_built == 2
    await engine.dispose()


async def test_upsert_host_rejects_an_error_without_its_build_stamp(
    settings_kratos: Settings,
) -> None:
    """``build_error`` without ``last_built_at`` raises instead of vanishing.

    A build outcome is one atomic fact, and the builder always passes the pair
    — but this helper used to DISCARD a lone ``build_error`` silently, so a
    caller's error string read back as null and looked like a column that does
    not persist. An argument accepted and ignored is worse than a refusal.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await store.upsert_host(db, "192.168.50.40", last_seen=T0)
        with pytest.raises(ValueError, match="last_built_at"):
            await store.upsert_host(db, "192.168.50.40", build_error="es timeout")
        # And the paired form still round-trips verbatim.
        row = await store.upsert_host(
            db, "192.168.50.40", last_built_at=T0, build_error="es timeout"
        )
        await db.commit()
        assert row.build_error == "es timeout"
    await engine.dispose()


async def test_attention_order_is_stable_and_cut_in_sql(settings_kratos: Settings) -> None:
    """Ties break on the host key, and the ORDER BY runs before the LIMIT.

    Two loads of the same data must never swap rows under the operator's
    cursor, and page 1 must hold the top of the WHOLE order — ordering the page
    after cutting it is the defect class this project keeps re-shipping.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # Inserted .9 BEFORE .10 so an id-ordered tie-break would give [.9, .10]
        # while the host-key tie-break gives [.10, .9] (string order).
        await store.upsert_host(db, "192.168.30.9", last_seen=T0 + 2 * HOUR, last_built_at=T0)
        await store.upsert_host(db, "192.168.30.10", last_seen=T0 + 2 * HOUR, last_built_at=T0)
        # Declared, and the OLDEST — a last_seen page-cut would drop it.
        await store.upsert_host(db, "192.168.30.20", last_seen=T0, last_built_at=T0)
        await store.set_override(db, "192.168.30.20", "criticality", "high", now=T0)
        await db.commit()

        now = T0 + 3 * HOUR
        expected = ["192.168.30.20", "192.168.30.10", "192.168.30.9"]

        first, _total = await store.list_dossiers(db, sort="attention", now=now)
        second, _total = await store.list_dossiers(db, sort="attention", now=now)
        assert [r.ip for r, _f in first] == expected
        assert [r.ip for r, _f in second] == expected  # stable across loads

        # Page of one at each offset reassembles the same order: the sort
        # happened in SQL, before the page was cut.
        paged = []
        for offset in range(3):
            page, _total = await store.list_dossiers(
                db, sort="attention", now=now, limit=1, offset=offset
            )
            paged.extend(r.ip for r, _f in page)
        assert paged == expected
    await engine.dispose()


async def test_attention_tiers_agree_with_the_resolver_and_the_conflict_gate(
    settings_kratos: Settings,
) -> None:
    """ "Named" means the resolver would assert the name; "conflict" means due.

    A stored hostname the resolver withholds (weak, or stale) must not rank the
    host as named — the row underneath renders a dash for it. A disagreement
    below the observation gate, or snoozed, is not yet asking the operator
    anything, so it ranks as its declaration, not as a conflict.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # Every host here has a CLEAN build stamp: the tiers under test are the
        # resolver's and the conflict gate's, not the no-clean-build tier.
        # Weak name: stored, withheld by the confidence floor.
        weak = await store.upsert_host(
            db, "192.168.40.40", last_seen=T0 + 3 * HOUR, last_built_at=T0
        )
        await store.upsert_inferred(
            db, weak, _fact("hostname", "guess", confidence=0.5, strength="weak"), now=T0
        )
        # Stale name: confident when written, past the staleness window now.
        stale = await store.upsert_host(
            db, "192.168.40.41", last_seen=T0 + 2 * HOUR, last_built_at=T0
        )
        await store.upsert_inferred(
            db, stale, _fact("hostname", "forgotten"), now=T0 - timedelta(hours=100)
        )
        # Assertable name, and the OLDEST last_seen of the three.
        strong = await store.upsert_host(db, "192.168.40.42", last_seen=T0 + HOUR, last_built_at=T0)
        await store.upsert_inferred(db, strong, _fact("hostname", "known"), now=T0)
        # Two disagreeing builds: below the observation gate, so declared-only.
        gated = await store.upsert_host(
            db, "192.168.40.43", last_seen=T0 + 4 * HOUR, last_built_at=T0
        )
        await store.set_override(db, "192.168.40.43", "role", "workstation", now=T0)
        for i in range(2):
            await store.upsert_inferred(
                db, gated, _fact("role", "hypervisor", source="behaviour"), now=T0 + i * HOUR
            )
        # Past the gate but snoozed: "keep mine" bought its way off this tier.
        snoozed = await store.upsert_host(
            db, "192.168.40.44", last_seen=T0 + 5 * HOUR, last_built_at=T0
        )
        await store.set_override(db, "192.168.40.44", "role", "workstation", now=T0)
        for i in range(3):
            await store.upsert_inferred(
                db, snoozed, _fact("role", "hypervisor", source="behaviour"), now=T0 + i * HOUR
            )
        await store.snooze_conflict(db, "192.168.40.44", "role", now=T0 + 3 * HOUR)
        await db.commit()

        now = T0 + 6 * HOUR

        async def _order(**kwargs: Any) -> list[str]:
            rows, _total = await store.list_dossiers(db, sort="attention", now=now, **kwargs)
            return [r.ip for r, _f in rows]

        assert await _order() == [
            "192.168.40.44",  # declared (snoozed conflict is NOT due)
            "192.168.40.43",  # declared (two observations is not continued evidence)
            "192.168.40.42",  # named — despite the oldest last_seen
            "192.168.40.40",  # weak name withheld: the anonymous tail
            "192.168.40.41",  # stale name withheld: the anonymous tail
        ]

        # The tiers track the same knobs the resolver and the conflict queue
        # read, rather than hardcoding their defaults.
        assert (await _order(min_observations=2))[0] == "192.168.40.43"
        assert "192.168.40.40" in (await _order(min_confidence=0.4))[2:3]
        assert "192.168.40.41" in (await _order(staleness_hours=200))[2:4]
    await engine.dispose()


async def test_conflicts_due_returns_rows_past_the_gate(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await _conflicting_host(db)
        for i in range(2):
            await store.upsert_inferred(
                db, host, _fact("role", "hypervisor", source="behaviour"), now=T0 + i * HOUR
            )
        await db.commit()
        rows, total = await store.conflicts_due(db, now=T0 + 2 * HOUR)
        assert (rows, total) == ([], 0)  # two observations is not "continued evidence"

        await store.upsert_inferred(
            db, host, _fact("role", "hypervisor", source="behaviour"), now=T0 + 2 * HOUR
        )
        await db.commit()
        rows, total = await store.conflicts_due(db, now=T0 + 3 * HOUR)
        assert total == 1
        dossier, field = rows[0]
        assert dossier.ip == "192.168.10.202"
        assert field.field == "role"
        assert field.conflict_kind == "mismatch"

        # "Keep mine" takes it off the list without resolving it.
        await store.snooze_conflict(db, "192.168.10.202", "role", now=T0 + 3 * HOUR)
        await db.commit()
        rows, total = await store.conflicts_due(db, now=T0 + 4 * HOUR)
        assert (rows, total) == ([], 0)
    await engine.dispose()


# ---------------------------------------------------------------------------
# summarize_dossiers — the whole table, for the host list's KPI strip
# ---------------------------------------------------------------------------


async def _resolver_named(db: AsyncSession, *, now: datetime) -> int:
    """How many hosts the RESOLVER would call named, host by host.

    The oracle for the aggregate: the summary counts in SQL what
    ``resolve_dossier`` decides in Python, and the two disagreeing is the whole
    failure mode — a KPI that says 25 over a table showing 24 hostnames.
    """
    rows, _total = await store.list_dossiers(db, limit=store.MAX_LIST_LIMIT)
    return sum(
        1
        for host, fields in rows
        if resolve_dossier(host, fields, now=now).fields["hostname"].is_known
    )


async def test_summarize_counts_the_whole_table_not_a_page(settings_kratos: Settings) -> None:
    # The defect this pins has shipped twice (the Dashboard untriaged tile, the
    # Investigations 100-row page): a number taken off the first page of a paged
    # list, presented as the network's.
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        assert store.DEFAULT_LIST_LIMIT == 50
        for i in range(55):
            host = await store.upsert_host(db, f"192.168.{i}.10", last_built_at=T0)
            if i < 52:
                await store.upsert_inferred(db, host, _fact("hostname", f"h{i}"), now=T0)
        await db.commit()

        summary = await store.summarize_dossiers(db, now=T0 + HOUR)
        assert summary.hosts == 55
        assert summary.named == 52
    await engine.dispose()


async def test_summarize_named_agrees_with_the_resolver(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # Confident and fresh — the only inferred shape the resolver asserts.
        await store.upsert_inferred(
            db,
            await store.upsert_host(db, "192.168.10.10", last_built_at=T0),
            _fact("hostname", "named", confidence=0.9),
            now=T0,
        )
        # Under `dossier_min_confidence` — stored, withheld by the resolver.
        await store.upsert_inferred(
            db,
            await store.upsert_host(db, "192.168.10.11", last_built_at=T0),
            _fact("hostname", "unsure", confidence=0.4, strength="weak"),
            now=T0,
        )
        # Fresh when it was written, stale by the time it is counted.
        await store.upsert_inferred(
            db,
            await store.upsert_host(db, "192.168.10.12", last_built_at=T0),
            _fact("hostname", "forgotten", confidence=0.9),
            now=T0 - timedelta(hours=100),
        )
        # The operator lane: no inference at all, and it never goes stale.
        await store.upsert_host(db, "192.168.10.13", last_built_at=T0)
        await store.set_override(db, "192.168.10.13", "hostname", "declared", now=T0)
        # No hostname row whatsoever.
        await store.upsert_host(db, "192.168.10.14", last_built_at=T0)
        await db.commit()

        now = T0 + HOUR
        summary = await store.summarize_dossiers(db, now=now)
        assert summary.hosts == 5
        assert summary.named == 2  # the confident one and the declared one
        assert summary.named == await _resolver_named(db, now=now)

        # And it tracks the knobs rather than hardcoding their defaults: drop the
        # floor and the weak answer resolves, widen nothing and the stale one
        # stays withheld.
        loose = await store.summarize_dossiers(db, now=now, min_confidence=0.3)
        assert loose.named == 3
        patient = await store.summarize_dossiers(db, now=now, staleness_hours=200)
        assert patient.named == 3
    await engine.dispose()


async def test_summarize_reporting_counts_the_hostlog_rung(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # An agent on the machine reports its own name.
        await store.upsert_inferred(
            db,
            await store.upsert_host(db, "192.168.10.10", last_built_at=T0),
            _fact("hostname", "reports", source="hostlog"),
            now=T0,
        )
        # A name the network overheard. Named, but nothing on the box is talking.
        await store.upsert_inferred(
            db,
            await store.upsert_host(db, "192.168.10.11", last_built_at=T0),
            _fact("hostname", "overheard", source="banner"),
            now=T0,
        )
        # An agent that has stopped: the fact is older than the staleness window,
        # so it is not evidence of coverage NOW.
        await store.upsert_inferred(
            db,
            await store.upsert_host(db, "192.168.10.12", last_built_at=T0),
            _fact("os_family", "linux", source="hostlog"),
            now=T0 - timedelta(hours=100),
        )
        # An agent whose report an operator has overruled. An override suppresses
        # EFFECT, never OBSERVATION — the machine is still shipping logs, which
        # is the only question this card asks.
        host = await store.upsert_host(db, "192.168.10.13", last_built_at=T0)
        await store.upsert_inferred(db, host, _fact("hostname", "self", source="hostlog"), now=T0)
        await store.set_override(db, "192.168.10.13", "hostname", "mine", now=T0)
        await db.commit()

        summary = await store.summarize_dossiers(db, now=T0 + HOUR)
        assert summary.hosts == 4
        assert summary.reporting == 2
    await engine.dispose()


async def test_summarize_reports_build_coverage_and_sweep_freshness(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # Seen on the wire, never built — the census reached it, the sweep did not.
        await store.upsert_host(db, "192.168.10.10", last_seen=T0)
        await store.upsert_host(db, "192.168.10.11", last_built_at=T0)
        # Built, and the build failed. It has a stamp but no clean answer.
        await store.upsert_host(
            db, "192.168.10.12", last_built_at=T0 + HOUR, build_error="grid timeout"
        )
        await db.commit()

        summary = await store.summarize_dossiers(db, now=T0 + 2 * HOUR)
        assert summary.hosts == 3
        assert summary.never_built == 2
        # The NEWEST stamp in the table, so the strip can date its own numbers.
        assert summary.last_built_at == T0 + HOUR
    await engine.dispose()


async def test_summarize_conflicts_is_the_conflicts_due_count(settings_kratos: Settings) -> None:
    # One definition of "needs review", not two: the strip's card and the queue
    # under it are the same predicate or they will drift.
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await _conflicting_host(db)
        for i in range(3):
            await store.upsert_inferred(
                db, host, _fact("role", "hypervisor", source="behaviour"), now=T0 + i * HOUR
            )
        await db.commit()

        now = T0 + 3 * HOUR
        _rows, due = await store.conflicts_due(db, now=now)
        assert due == 1
        assert (await store.summarize_dossiers(db, now=now)).conflicts == due

        # Below the observation threshold, and snoozed, both mean "not due" —
        # and the card has to say so too.
        raised = await store.summarize_dossiers(db, now=now, min_observations=9)
        assert raised.conflicts == 0
        await store.snooze_conflict(db, "192.168.10.202", "role", now=now)
        await db.commit()
        _rows, due = await store.conflicts_due(db, now=now + HOUR)
        assert (await store.summarize_dossiers(db, now=now + HOUR)).conflicts == due == 0
    await engine.dispose()


async def test_summarize_roles_resolve_the_operator_lane_over_the_inferred(
    settings_kratos: Settings,
) -> None:
    """The role mix behind the host list's distribution bar.

    Effective role per host = ``coalesce(operator_value, inferred_value)`` (the
    ``list_dossiers`` role-filter spelling) with the resolver's two gates on the
    inferred side (the ``named`` count's spelling) — composed from the two
    existing resolutions, not a third one. A host whose role the resolver would
    withhold contributes to NO bucket: the bar's gray remainder is "no resolved
    role", never a role the row beneath renders as a dash.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # Two servers the sweep is sure about.
        for n in (10, 11):
            await store.upsert_inferred(
                db,
                await store.upsert_host(db, f"192.168.10.{n}", last_built_at=T0),
                _fact("role", "server", source="behaviour"),
                now=T0,
            )
        # The operator lane outranks a disagreeing inference — this host is a
        # hypervisor to the bar, not a server.
        await store.upsert_inferred(
            db,
            await store.upsert_host(db, "192.168.10.12", last_built_at=T0),
            _fact("role", "server", source="behaviour"),
            now=T0,
        )
        await store.set_override(db, "192.168.10.12", "role", "hypervisor", now=T0)
        # Below the confidence floor: stored, withheld, not counted.
        await store.upsert_inferred(
            db,
            await store.upsert_host(db, "192.168.10.13", last_built_at=T0),
            _fact("role", "workstation", confidence=0.4, strength="weak"),
            now=T0,
        )
        # Fresh once, stale by the time it is counted.
        await store.upsert_inferred(
            db,
            await store.upsert_host(db, "192.168.10.14", last_built_at=T0),
            _fact("role", "workstation"),
            now=T0 - timedelta(hours=100),
        )
        # No role row at all.
        await store.upsert_host(db, "192.168.10.15", last_built_at=T0)
        await db.commit()

        now = T0 + HOUR
        summary = await store.summarize_dossiers(db, now=now)
        assert summary.hosts == 6
        assert summary.roles == {"server": 2, "hypervisor": 1}

        # The knobs travel: drop the floor and the weak workstation resolves.
        loose = await store.summarize_dossiers(db, now=now, min_confidence=0.3)
        assert loose.roles == {"server": 2, "hypervisor": 1, "workstation": 1}
    await engine.dispose()


async def test_summarize_costs_four_aggregate_queries(settings_kratos: Settings) -> None:
    """Four statements, none of them per-host.

    The constancy comes from the SHAPE — nothing in :func:`summarize_dossiers`
    iterates hosts — so twenty rows demonstrate it rather than prove it for
    every size. What the count is protecting is real: this read runs on every
    load of the landing screen against a table capped at 5,000 hosts x ~12
    fields, and the N+1 shape ``_fields_for`` prevents one layer down would be
    the connection-pool pressure that has frozen this app before. (The fourth
    statement is the role-mix GROUP BY behind the distribution bar — grouped,
    still not per-host.)
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for n in range(1, 21):
            host = await store.upsert_host(db, f"192.168.10.{n}", last_built_at=T0)
            await store.upsert_inferred(db, host, _fact("hostname", f"box-{n}"), now=T0)
        await db.commit()

    selects: list[str] = []

    def _record(conn: Any, cursor: Any, statement: str, *args: Any) -> None:
        if statement.lstrip().upper().startswith("SELECT"):
            selects.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", _record)
    try:
        async with maker() as db:
            summary = await store.summarize_dossiers(db, now=T0 + HOUR)
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", _record)

    assert len(selects) == 4, selects
    assert (summary.hosts, summary.named) == (20, 20)
    await engine.dispose()


async def test_summarize_an_empty_table_is_zeroes_not_nulls(settings_kratos: Settings) -> None:
    # A count of nothing is 0; the sweep stamp of nothing is None. The strip
    # renders a dash only when it could not ASK, so the store must never hand it
    # a null it would have to invent a number for.
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        summary = await store.summarize_dossiers(db, now=T0)
        assert (summary.hosts, summary.never_built, summary.named) == (0, 0, 0)
        assert (summary.reporting, summary.conflicts) == (0, 0)
        assert summary.roles == {}
        assert summary.last_built_at is None
    await engine.dispose()


# ---------------------------------------------------------------------------
# prune
# ---------------------------------------------------------------------------


async def test_prune_spares_rows_with_any_override(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for i in range(5):
            await store.upsert_host(db, f"192.168.10.{10 + i}", last_seen=T0 + i * HOUR)
        # The oldest host carries an operator override — pruning it would throw
        # away the one thing in the table a human actually wrote.
        await store.set_override(
            db, "192.168.10.10", "criticality", "high", actor="analyst", now=T0
        )
        await db.commit()

        deleted = await store.prune(db, max_hosts=3)
        assert deleted == 2
        remaining = {row.ip for row in (await db.scalars(select(HostDossier))).all()}
        assert remaining == {"192.168.10.10", "192.168.10.13", "192.168.10.14"}

        assert await store.prune(db, max_hosts=3) == 0  # already at the cap
    await engine.dispose()


async def test_prune_leaves_an_all_override_table_alone(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for i in range(3):
            await store.upsert_host(db, f"192.168.10.{10 + i}", last_seen=T0 + i * HOUR)
            await store.set_override(db, f"192.168.10.{10 + i}", "criticality", "high", now=T0)
        await db.commit()
        # Over the cap, but every row is hand-written: the cap yields.
        assert await store.prune(db, max_hosts=1) == 0
        assert len((await db.scalars(select(HostDossier))).all()) == 3
    await engine.dispose()


async def test_prune_takes_the_field_rows_with_it(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = await store.upsert_host(db, "192.168.10.10", last_seen=T0)
        await store.upsert_inferred(db, host, _fact("role", "server", source="behaviour"))
        await store.upsert_host(db, "192.168.10.11", last_seen=T0 + HOUR)
        await db.commit()

        assert await store.prune(db, max_hosts=1) == 1
        orphans = (await db.scalars(select(HostDossierField))).all()
        assert list(orphans) == []
    await engine.dispose()


# ---------------------------------------------------------------------------
# get_dossiers — the batch read behind the host page's peer table
# ---------------------------------------------------------------------------


async def test_get_dossiers_reads_many_hosts_in_two_queries(settings_kratos: Settings) -> None:
    """Two SELECTs however many addresses are asked for — never one per host.

    This is the whole reason the function exists. The host page resolves a
    dozen peer names on every load, and a loop over ``get_dossier`` would be
    twenty-four round trips behind one panel — the N+1 ``_fields_for`` already
    prevents one layer down.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for n in (1, 2, 3, 4, 5):
            host = await store.upsert_host(db, f"192.168.10.{n}")
            await store.upsert_inferred(db, host, _fact("hostname", f"box-{n}"))
        await db.commit()

    selects: list[str] = []

    def _record(conn: Any, cursor: Any, statement: str, *args: Any) -> None:
        if statement.lstrip().upper().startswith("SELECT"):
            selects.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", _record)
    try:
        async with maker() as db:
            rows = await store.get_dossiers(db, [f"192.168.10.{n}" for n in (1, 2, 3, 4, 5)])
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", _record)

    assert len(selects) == 2, selects
    assert {host.ip for host, _fields in rows} == {f"192.168.10.{n}" for n in (1, 2, 3, 4, 5)}
    by_ip = {host.ip: fields for host, fields in rows}
    assert [f.inferred_value for f in by_ip["192.168.10.3"] if f.field == "hostname"] == ["box-3"]
    await engine.dispose()


async def test_get_dossiers_omits_addresses_it_has_never_seen(settings_kratos: Settings) -> None:
    """Unknown peers are absent, not errors. The caller is naming addresses off
    a live aggregation, where most of them will have no row at all."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await store.upsert_host(db, "192.168.10.40")
        await db.commit()
    async with maker() as db:
        rows = await store.get_dossiers(db, ["192.168.10.40", "192.168.20.226"])
    assert [host.ip for host, _fields in rows] == ["192.168.10.40"]
    await engine.dispose()


async def test_get_dossiers_skips_path_segments_that_are_not_addresses(
    settings_kratos: Settings,
) -> None:
    """A non-address cannot name a row in a table keyed on addresses, and one
    junk entry must not cost the whole batch its answer."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await store.upsert_host(db, "192.168.10.40")
        await db.commit()
    async with maker() as db:
        rows = await store.get_dossiers(db, ["not-an-ip", "192.168.10.40"])
        assert [host.ip for host, _fields in rows] == ["192.168.10.40"]
        assert await store.get_dossiers(db, ["not-an-ip"]) == []
        assert await store.get_dossiers(db, []) == []
    await engine.dispose()


async def test_get_dossiers_matches_a_differently_spelled_ipv6_address(
    settings_kratos: Settings,
) -> None:
    """Lookups canonicalize, so a peer address the grid spelled expanded still
    finds the row the sweep stored — the same normalization ``get_dossier`` does."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await store.upsert_host(db, "2001:db8::1")
        await db.commit()
    async with maker() as db:
        rows = await store.get_dossiers(db, ["2001:0db8:0000:0000:0000:0000:0000:0001"])
    assert [host.host_key for host, _fields in rows] == ["2001:db8::1"]
    await engine.dispose()
