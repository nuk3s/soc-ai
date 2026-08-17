"""Tests for :func:`soc_ai.store.host_dossier.environment_profile` (hunt-fit).

The profile answers "what kind of network do the dossiers describe?" for the
hunt catalogue's environment-fit annotation: how many hosts effectively resolve
to a Windows os_family, how many to a domain membership, out of how many total
and how many ever built. It must speak with the RESOLVER's voice — the operator
lane wins unconditionally, the inference lane only counts when it is fresh and
confident — because a count computed on looser rules would call a network
"Windows-free" while the host page shows a Windows box, or vice versa.

Scratch-DB recipe copied from tests/test_host_dossier_store.py: a real SQLite
file migrated to head, isolated per test by the autouse ``clean_env`` fixture.
Seeding goes through the builder's/operator's own write paths (`upsert_host`,
`upsert_inferred`, `set_override`) so a test can never seed a shape the real
sweep cannot produce.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import pytest
from soc_ai.config import Settings
from soc_ai.dossier.types import Fact
from soc_ai.store import host_dossier as store
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

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
    source: str = "hostlog",
) -> Fact:
    return Fact(
        field=field,
        value=value,
        confidence=confidence,
        strength=strength,  # type: ignore[arg-type]
        source=source,  # type: ignore[arg-type]
        evidence=[f"{value} (from {source})"],
        observed_at=T0,
    )


async def _seed(
    db: AsyncSession,
    ip: str,
    *,
    facts: list[Fact] | None = None,
    built: bool = True,
) -> None:
    """One host as a sweep would write it: header (+ build stamp) + inference lane."""
    host = await store.upsert_host(
        db,
        ip,
        first_seen=T0,
        last_seen=T0,
        last_built_at=T0 if built else None,
        now=T0,
    )
    for fact in facts or []:
        await store.upsert_inferred(db, host, fact, now=T0)
    await db.commit()


async def test_empty_table_is_all_zeros(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        profile = await store.environment_profile(db, now=T0)
    assert profile == store.EnvironmentProfile(
        windows_hosts=0, domain_joined_hosts=0, total_hosts=0, built_hosts=0
    )
    await engine.dispose()


async def test_counts_windows_and_domain_joined_from_inferred_facts(
    settings_kratos: Settings,
) -> None:
    """The owner-shaped network: linux hosts count toward neither axis, a Windows
    domain-joined host counts toward both. The domain value is the domain NAME
    (``_infer_domain_membership`` emits the NTLM/Kerberos/DHCP name, never a
    boolean), so "joined" is "resolves to a non-empty value"."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for ip in ("10.0.0.11", "10.0.0.12", "10.0.0.13"):
            await _seed(db, ip, facts=[_fact("os_family", "linux")])
        await _seed(
            db,
            "10.0.0.20",
            facts=[_fact("os_family", "windows"), _fact("domain_membership", "CORP.EXAMPLE.COM")],
        )
        profile = await store.environment_profile(db, now=T0)
    assert profile.windows_hosts == 1
    assert profile.domain_joined_hosts == 1
    assert profile.total_hosts == 4
    assert profile.built_hosts == 4
    await engine.dispose()


async def test_operator_override_wins_over_inference_in_both_directions(
    settings_kratos: Settings,
) -> None:
    """The resolver's rule, not a looser coalesce: an operator "Windows" (any
    case) over an inferred "linux" counts; an operator "linux" over a fresh,
    strong inferred "windows" does NOT — the override wins unconditionally."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _seed(db, "10.0.0.30", facts=[_fact("os_family", "linux")])
        await store.set_override(db, "10.0.0.30", "os_family", "Windows", now=T0)

        await _seed(db, "10.0.0.31", facts=[_fact("os_family", "windows")])
        await store.set_override(db, "10.0.0.31", "os_family", "linux", now=T0)

        profile = await store.environment_profile(db, now=T0)
    assert profile.windows_hosts == 1  # .30 promoted by the operator; .31 demoted
    await engine.dispose()


async def test_blank_operator_domain_is_not_joined(settings_kratos: Settings) -> None:
    """An operator value of pure whitespace resolves to nothing joinable."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _seed(db, "10.0.0.40")
        await store.set_override(db, "10.0.0.40", "domain_membership", "  ", now=T0)
        profile = await store.environment_profile(db, now=T0)
    assert profile.domain_joined_hosts == 0
    await engine.dispose()


async def test_stale_and_low_confidence_inferences_are_excluded(
    settings_kratos: Settings,
) -> None:
    """The resolver's two gates apply: a fresh-but-weak windows inference and a
    strong-but-stale one both drop out. An OPERATOR windows does not expire —
    overrides carry no staleness window, exactly as the resolver reads them."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # Weak (0.5 < the 0.6 floor), fresh.
        weak = _fact("os_family", "windows", confidence=0.5, strength="weak")
        await _seed(db, "10.0.0.50", facts=[weak])
        # Strong, but the profile is asked 100h later with a 72h window.
        await _seed(db, "10.0.0.51", facts=[_fact("os_family", "windows")])
        # Operator-declared, queried at the same late clock.
        await _seed(db, "10.0.0.52")
        await store.set_override(db, "10.0.0.52", "os_family", "windows", now=T0)

        fresh = await store.environment_profile(db, now=T0)
        late = await store.environment_profile(db, now=T0 + 100 * HOUR)
    assert fresh.windows_hosts == 2  # .51 (fresh+strong) and .52 (operator); .50 below the floor
    assert late.windows_hosts == 1  # only the operator claim survives the staleness window
    await engine.dispose()


async def test_built_hosts_counts_only_swept_hosts(settings_kratos: Settings) -> None:
    """A census row nothing ever built is a host, not a built host — the
    fail-open gate ("zero dossiers ever built") keys off this distinction."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _seed(db, "10.0.0.60", built=True)
        await _seed(db, "10.0.0.61", built=False)
        profile = await store.environment_profile(db, now=T0)
    assert profile.total_hosts == 2
    assert profile.built_hosts == 1
    await engine.dispose()


async def test_the_live_profile_is_ttl_cached_between_polls(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """/hunt-templates polls the profile every 60s from every open tab, and each
    call is two whole-table scans. The live read (``now`` unset) is TTL-cached so
    a burst of polls collapses to one pair of scans per window; a call past the
    TTL re-runs. An explicit ``now`` (every test above) is never cached."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _seed(db, "10.0.0.70", facts=[_fact("os_family", "windows")])

        store._env_profile_cache.clear()
        clock = {"t": 1000.0}
        monkeypatch.setattr(store, "_monotonic", lambda: clock["t"])

        calls = {"n": 0}
        real = store._compute_environment_profile

        async def counting(*args: Any, **kwargs: Any) -> store.EnvironmentProfile:
            calls["n"] += 1
            return await real(*args, **kwargs)

        monkeypatch.setattr(store, "_compute_environment_profile", counting)

        first = await store.environment_profile(db)  # miss → one compute
        second = await store.environment_profile(db)  # within TTL → cache hit
        assert calls["n"] == 1  # the two whole-table scans did not double
        assert first == second
        # The cached value is the real computed profile, not a placeholder.
        # (windows_hosts is staleness-gated against real `now` here, so the
        # not-gated header count is the stable check.)
        assert first.total_hosts == 1

        # An explicit `now` is a point-in-time read and bypasses the cache.
        await store.environment_profile(db, now=T0)
        assert calls["n"] == 2

        # Past the TTL the live read recomputes — a completed sweep is visible
        # within one poll interval.
        clock["t"] += store._ENV_PROFILE_TTL_S + 1
        await store.environment_profile(db)
        assert calls["n"] == 3
    store._env_profile_cache.clear()
    await engine.dispose()
