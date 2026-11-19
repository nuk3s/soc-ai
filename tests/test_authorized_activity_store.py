"""The store of authorized activity: the guards, the states and the reads.

An authorization closes the case request of a true positive. A wrong row
hides an attack, so the store refuses every scope that is wider than the
design allows: no expiry, a far expiry, no source, too many sources, a source
that no agent reports, no rule name.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from soc_ai.config import Settings
from soc_ai.store import authorized_activity as aa
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import HostDossier, HostMachine, Investigation
from sqlalchemy import inspect, text

pytestmark = pytest.mark.asyncio

TARGET = "10.40.0.164"
SOURCE_A = "10.50.0.26"
SOURCE_B = "10.50.0.52"
RULE_NESTED = "ET EXPLOIT PHP php2shell Nested Empty File Control OOM (CVE-2026-109618)"
RULE = "ET EXPLOIT PHP php2shell Chunked Multipart Request without Content-Length (CVE-2026-109618)"


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def _authorize(db, *, now: datetime | None = None, **overrides):  # type: ignore[no-untyped-def]
    at = now or utcnow()
    fields = {
        "label": "php2shell test",
        "sources": [aa.ScopeEntry(SOURCE_A, "agent:a-1", "agent-a")],
        "target": aa.ScopeEntry(TARGET, f"ip:{TARGET}"),
        "rule_names": [RULE, RULE_NESTED],
        "rule_class": "exploit_attempt",
        "expires_at": at + timedelta(days=7),
        "created_by": "casey",
        "now": at,
    }
    fields.update(overrides)
    return await aa.create(db, **fields)


async def _run(db, *, authorization_id: int | None = None, created_at: datetime | None = None):  # type: ignore[no-untyped-def]
    inv = await inv_svc.create(
        db, alert_es_id=f"alert-{utcnow().timestamp()}", started_by="auto", rule_name=RULE
    )
    row = await db.get(Investigation, inv.id)
    row.status = "complete"
    row.verdict = "true_positive"
    row.authorization_id = authorization_id
    if created_at is not None:
        row.created_at = created_at
    await db.commit()
    return row


async def test_the_migration_adds_the_table_and_the_run_column(settings_kratos: Settings) -> None:
    engine, _maker = await _db(settings_kratos)
    async with engine.connect() as conn:
        tables = await conn.run_sync(lambda sc: inspect(sc).get_table_names())
        columns = await conn.run_sync(
            lambda sc: {c["name"] for c in inspect(sc).get_columns("investigations")}
        )
        indexes = await conn.run_sync(
            lambda sc: {ix["name"] for ix in inspect(sc).get_indexes("investigations")}
        )
        expiry = await conn.run_sync(
            lambda sc: {c["name"]: c for c in inspect(sc).get_columns("authorized_activity")}
        )
        head = await conn.execute(text("SELECT version_num FROM alembic_version"))
        assert head.scalar_one() == "0076"
    await engine.dispose()
    assert "authorized_activity" in tables
    assert "authorization_id" in columns
    assert "ix_investigations_authorization" in indexes
    assert expiry["expires_at"]["nullable"] is False, "the expiry is mandatory"


async def test_the_downgrade_removes_both(settings_kratos: Settings) -> None:
    from alembic import command
    from soc_ai.store.db import _migration_config

    engine = make_engine(settings_kratos)
    await run_migrations(engine)

    def _down(connection) -> None:  # type: ignore[no-untyped-def]
        config = _migration_config()
        config.attributes["connection"] = connection
        command.downgrade(config, "0065")

    async with engine.begin() as conn:
        await conn.run_sync(_down)
        tables = await conn.run_sync(lambda sc: inspect(sc).get_table_names())
        columns = await conn.run_sync(
            lambda sc: {c["name"] for c in inspect(sc).get_columns("investigations")}
        )
    await engine.dispose()
    assert "authorized_activity" not in tables
    assert "authorization_id" not in columns


async def test_a_new_row_is_active_and_holds_the_scope(settings_kratos: Settings) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        row = await _authorize(db)
        scope = aa.scope_of(row)
    assert aa.state_of(row) == aa.STATE_ACTIVE
    assert scope.sources == (aa.ScopeEntry(SOURCE_A, "agent:a-1", "agent-a"),)
    assert scope.target == aa.ScopeEntry(TARGET, f"ip:{TARGET}")
    assert (scope.rule_names, scope.rule_class) == ((RULE, RULE_NESTED), "exploit_attempt")
    assert scope.expires_at - scope.starts_at == timedelta(days=7)


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"label": "   "}, "label_required"),
        ({"label": "x" * 121}, "label_too_long"),
        ({"sources": []}, "source_required"),
        (
            {"sources": [aa.ScopeEntry(f"10.50.0.{n}", "agent:a-1") for n in range(1, 10)]},
            "too_many_sources",
        ),
        ({"sources": [aa.ScopeEntry("not-an-address", "agent:a-1")]}, "bad_source"),
        ({"sources": [aa.ScopeEntry(TARGET, "agent:a-1")]}, "target_is_source"),
        # A source must be an address that an agent reports.
        ({"sources": [aa.ScopeEntry(SOURCE_A, None)]}, "source_not_agent_address"),
        ({"sources": [aa.ScopeEntry(SOURCE_A, f"ip:{SOURCE_A}")]}, "source_not_agent_address"),
        (
            {"sources": [aa.ScopeEntry(SOURCE_A, "mac:aa:bb:cc:dd:ee:ff")]},
            "source_not_agent_address",
        ),
        ({"rule_names": []}, "rule_required"),
        ({"rule_names": ["  "]}, "rule_required"),
        ({"rule_names": [f"ET TEST rule {n}" for n in range(21)]}, "too_many_rules"),
        ({"rule_class": ""}, "class_required"),
    ],
)
async def test_the_store_refuses_a_scope_with_a_missing_part(
    settings_kratos: Settings, overrides: dict, reason: str
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        with pytest.raises(aa.ScopeError) as caught:
            await _authorize(db, **overrides)
    assert caught.value.reason == reason


async def test_the_expiry_is_bounded_on_both_sides(settings_kratos: Settings) -> None:
    _engine, maker = await _db(settings_kratos)
    now = utcnow()
    async with maker() as db:
        with pytest.raises(aa.ScopeError) as past:
            await _authorize(db, now=now, expires_at=now - timedelta(seconds=1))
        with pytest.raises(aa.ScopeError) as far:
            await _authorize(db, now=now, expires_at=now + timedelta(days=30, seconds=1))
        # The bound itself is inside.
        edge = await _authorize(db, now=now, expires_at=now + timedelta(days=30))
        with pytest.raises(aa.ScopeError) as early:
            await _authorize(db, now=now, starts_at=now - timedelta(days=30, seconds=1))
        with pytest.raises(aa.ScopeError) as late:
            await _authorize(db, now=now, starts_at=now + timedelta(seconds=1))
    assert past.value.reason == "expiry_in_past"
    assert far.value.reason == "expiry_too_far"
    assert edge.id is not None
    assert early.value.reason == "start_too_early"
    assert late.value.reason == "start_in_future"


async def test_a_revoke_outranks_an_expiry_and_keeps_the_first_actor(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    now = utcnow()
    async with maker() as db:
        row = await _authorize(db, now=now - timedelta(days=8))
        assert aa.state_of(row, now) == aa.STATE_EXPIRED
        revoked, changed = await aa.revoke(db, row.id, by="casey", reason="wrong  target")
        again, changed_again = await aa.revoke(db, row.id, by="dana", reason="second try")
        missing, changed_missing = await aa.revoke(db, 9999, by="casey", reason="x")
    assert changed is True
    assert revoked is not None and aa.state_of(revoked, now) == aa.STATE_REVOKED
    assert (revoked.revoked_by, revoked.revoke_reason) == ("casey", "wrong target")
    assert changed_again is False
    assert again is not None and again.revoked_by == "casey"
    assert (missing, changed_missing) == (None, False)


async def test_in_force_drops_a_revoked_row_and_a_row_that_ended_long_ago(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    now = utcnow()
    async with maker() as db:
        live = await _authorize(db, label="live")
        ended = await _authorize(db, label="ended", now=now - timedelta(days=9))
        old = await _authorize(db, label="old", now=now - timedelta(days=20))
        gone = await _authorize(db, label="gone")
        await aa.revoke(db, gone.id, by="casey", reason="wrong")
        scopes = await aa.in_force(db, now=now)
        cards = await aa.list_recent(db, now=now)
        active_only = await aa.list_recent(db, now=now, ended=False)
    assert [s.label for s in scopes] == ["live", "ended"], (
        "an expiry up to 7 days back stays, so a late triage of an alert from inside "
        "the window still matches. A revoked row matches nothing."
    )
    assert old.id not in {s.id for s in scopes}
    assert [c.label for c in cards] == ["live", "gone", "ended"]
    assert [c.label for c in active_only] == ["live"]
    assert live.id and ended.id


async def test_an_expiry_gets_one_record(settings_kratos: Settings) -> None:
    _engine, maker = await _db(settings_kratos)
    now = utcnow()
    async with maker() as db:
        ended = await _authorize(db, label="ended", now=now - timedelta(days=8))
        await _authorize(db, label="live")
        revoked = await _authorize(db, label="revoked", now=now - timedelta(days=8))
        await aa.revoke(db, revoked.id, by="casey", reason="wrong")
        due = await aa.unrecorded_expiries(db, now=now)
        await aa.mark_expiry_recorded(db, ended.id, now=now)
        after = await aa.unrecorded_expiries(db, now=now)
        recent = await aa.recently_expired(db, since=now - timedelta(days=2), now=now)
    assert [r.label for r in due] == ["ended"], "a revoke is not an expiry"
    assert after == []
    assert [r.label for r in recent] == ["ended"]


async def test_an_address_resolves_to_its_machine_with_the_type_of_the_join(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        agent = HostMachine(machine_key="agent:a-1", name="agent-a", address_count=2)
        bare = HostMachine(machine_key=f"ip:{TARGET}", address_count=1)
        retired = HostMachine(machine_key="mac:aa:bb:cc:dd:ee:ff", address_count=0)
        db.add_all([agent, bare, retired])
        await db.flush()
        db.add_all(
            [
                HostDossier(
                    host_key=SOURCE_A, ip=SOURCE_A, machine_id=agent.id, address_kind="agent"
                ),
                HostDossier(
                    host_key="10.50.0.27", ip="10.50.0.27", machine_id=agent.id, address_kind="name"
                ),
                HostDossier(
                    host_key="172.17.0.2",
                    ip="172.17.0.2",
                    machine_id=agent.id,
                    address_kind="container",
                ),
                HostDossier(host_key=TARGET, ip=TARGET, machine_id=bare.id, address_kind="network"),
                HostDossier(host_key="10.50.0.99", ip="10.50.0.99", machine_id=retired.id),
            ]
        )
        await db.commit()
        refs = await aa.machine_refs(
            db, [SOURCE_A, "10.50.0.27", "172.17.0.2", TARGET, "10.50.0.99", "203.0.113.9", None]
        )
    assert refs[SOURCE_A] == aa.MachineRef("agent:a-1", "agent-a", "agent")
    assert refs["10.50.0.27"] == aa.MachineRef("agent:a-1", "agent-a", "name")
    assert refs["172.17.0.2"] == aa.MachineRef("agent:a-1", "agent-a", "container")
    assert aa.machine_key_now(refs["172.17.0.2"]) is None, (
        "the traffic of a container is its own workload"
    )
    assert refs[TARGET] == aa.MachineRef(f"ip:{TARGET}", None, "network")
    assert refs["10.50.0.99"] is None, "a retired machine holds no address"
    assert refs["203.0.113.9"] is None
    # A bridge network repeats on every container host.
    async with maker() as db:
        on_bridge = await aa.bridge_addresses(db, ["172.17.0.1", "172.17.0.9", SOURCE_A, None])
    assert on_bridge == {"172.17.0.1", "172.17.0.9"}


@pytest.mark.parametrize(
    ("ref", "on_bridge", "source", "reason"),
    [
        (aa.MachineRef("agent:a-1", "agent-a", "agent"), False, True, None),
        (aa.MachineRef("agent:a-1", "agent-a", "name"), False, True, "source_joined_by_name"),
        (aa.MachineRef("agent:a-1", "agent-a", "dhcp"), False, True, "source_joined_by_lease"),
        (aa.MachineRef("agent:a-1", "agent-a", "container"), False, True, "source_on_bridge"),
        (aa.MachineRef("agent:a-1", "agent-a", "agent"), True, True, "source_on_bridge"),
        (aa.MachineRef(f"ip:{SOURCE_A}", None, "network"), False, True, "source_not_agent_address"),
        (None, False, True, "source_not_agent_address"),
        # A target may be an address that no agent reports.
        (aa.MachineRef(f"ip:{TARGET}", None, "network"), False, False, None),
        (None, False, False, None),
        (aa.MachineRef("agent:t-1", "web", "agent"), False, False, None),
        (aa.MachineRef("agent:t-1", "web", "container"), False, False, "target_on_bridge"),
        (None, True, False, "target_on_bridge"),
        (aa.MachineRef("agent:t-1", "web", "name"), False, False, "target_joined_by_name"),
        (
            aa.MachineRef("mac:aa:bb:cc:dd:ee:ff", None, "dhcp"),
            False,
            False,
            "target_joined_by_lease",
        ),
    ],
)
async def test_only_a_proven_address_can_be_in_a_scope(
    ref: aa.MachineRef | None, on_bridge: bool, source: bool, reason: str | None
) -> None:
    problem = aa.address_problem("10.50.0.26", ref, on_bridge=on_bridge, source=source)
    assert (problem[0] if problem else None) == reason
    if problem:
        assert "10.50.0.26" in problem[1]


async def test_the_counts_split_the_runs_at_the_decision(settings_kratos: Settings) -> None:
    _engine, maker = await _db(settings_kratos)
    now = utcnow()
    async with maker() as db:
        row = await _authorize(db, now=now - timedelta(hours=2))
        other = await _authorize(db, label="other")
        await _run(db, authorization_id=row.id, created_at=now - timedelta(days=1))
        await _run(db, authorization_id=row.id, created_at=now - timedelta(hours=1))
        last = await _run(db, authorization_id=row.id, created_at=now - timedelta(minutes=5))
        await _run(db)
        counts = await aa.run_counts(db, [row.id, other.id])
    assert counts[row.id].total == 3
    assert counts[row.id].since_decision == 2
    assert counts[row.id].earlier == 1
    assert counts[row.id].last_at == last.created_at
    assert counts[other.id] == aa.RunCount()


async def test_the_mark_holds_after_an_expiry_and_not_after_a_revoke(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    now = utcnow()
    async with maker() as db:
        ended = await _authorize(db, label="ended", now=now - timedelta(days=8))
        live = await _authorize(db, label="live")
        on_ended = await _run(db, authorization_id=ended.id)
        on_live = await _run(db, authorization_id=live.id)
        plain = await _run(db)
        dangling = await _run(db, authorization_id=9999)
        assert await aa.holds_run(db, on_ended) is True, "an expiry keeps the marks"
        assert await aa.holds_run(db, on_live) is True
        assert await aa.holds_run(db, plain) is False
        assert await aa.holds_run(db, dangling) is False, "no row, no mark"
        marks = await aa.marks_for(db, [ended.id, live.id, None], now=now)
        assert (marks[ended.id].state, marks[ended.id].holds) == (aa.STATE_EXPIRED, True)
        assert (marks[live.id].state, marks[live.id].holds) == (aa.STATE_ACTIVE, True)
        await aa.revoke(db, live.id, by="casey", reason="wrong")
        assert await aa.holds_run(db, on_live) is False, "a revoke returns the run"
        marks = await aa.marks_for(db, [live.id], now=now)
        assert (marks[live.id].state, marks[live.id].holds) == (aa.STATE_REVOKED, False)


async def test_a_rule_name_matches_by_its_exact_text() -> None:
    """No prefix and no pattern. Only the whitespace is folded, and the case stays."""
    assert aa.rule_name_key("  ET  SCAN   NMAP ") == "ET SCAN NMAP"
    assert aa.rule_name_key("ET SCAN NMAP") != aa.rule_name_key("ET SCAN Nmap")
    assert aa.rule_name_key("ET SCAN NMAP") != aa.rule_name_key("ET SCAN NMAP -sS window 1024")
    assert aa.rule_name_key(None) == ""


async def test_a_revoke_reads_every_marked_run_in_batches(settings_kratos: Settings) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        row = await _authorize(db)
        ids = sorted([(await _run(db, authorization_id=row.id)).id for _ in range(7)])
        await _run(db)
        seen: list[str] = []
        after = ""
        while True:
            batch = await aa.runs_after(db, row.id, after=after, limit=3)
            if not batch:
                break
            seen.extend(run.id for run in batch)
            after = batch[-1].id
    assert seen == ids, "no run is left out and none is read twice"


async def test_only_a_matched_report_names_an_authorization() -> None:
    assert aa.authorization_id_of({"authorized_activity": {"state": "matched", "id": 3}}) == 3
    assert aa.authorization_id_of({"authorized_activity": {"state": "outside", "id": 3}}) is None
    assert aa.authorization_id_of({"authorized_activity": {"state": "matched", "id": "3"}}) is None
    assert aa.authorization_id_of({"verdict": "true_positive"}) is None
    assert aa.authorization_id_of(None) is None
