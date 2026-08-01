"""Regression tests for the 2026-07-30 review — store + triage bucket (B05).

Covers:
  * F07 — `_latest_by` / `latest_complete_for_rules` / `override_counts_by_rule`
    used a GLOBAL `ORDER BY … LIMIT` while keeping the newest row(s) per key in
    Python. One noisy rule's recent rows could evict every other rule from the
    limit, silently dropping a rule's standing verdict / override tally. The fix
    partitions per key with a window function.
  * F27 — auto-triage `plan_targets` fetched every group's events with the
    default `kind="suricata"`, so a Zeek notice group (whose name lives in
    `notice.note`) fetched zero events and was never investigated nor counted.
  * F56 — `run_auto_triage` reused ONE `InvestigationContext` across all
    targets, leaking a prior target's `default_time_anchor` into a later
    target's Phase-D PCAP fetch. The fix builds a fresh ctx per target.
  * F28 — `probe_model_fitness` had no demo short-circuit, so a demo Config page
    graded the analyst model FAIL (DemoEgressBlocked on every leg).
"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

from pydantic import SecretStr
from soc_ai.config import Settings
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Investigation
from soc_ai.webui import alerts_query as aq
from soc_ai.webui import autotriage as at
from soc_ai.webui import probes
from soc_ai.webui.autotriage import Target


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def _complete(
    db: Any, *, rule_name: str, verdict: str, alert_es_id: str, age_days: int = 0
) -> Investigation:
    inv = await inv_svc.create(db, alert_es_id=alert_es_id, started_by="t", rule_name=rule_name)
    await inv_svc.finalize(db, inv.id, status="complete", verdict=verdict, confidence=0.9)
    if age_days:
        row = await db.get(Investigation, inv.id)
        row.created_at = utcnow() - timedelta(days=age_days)
        await db.commit()
    return inv


# ---------------------------------------------------------------------------
# F07 — per-key bounding (a noisy rule must not evict its neighbours)
# ---------------------------------------------------------------------------


async def test_latest_complete_for_rules_keeps_each_rule_under_noisy_sibling(
    settings_kratos: Settings,
) -> None:
    """A rule with 25 fresh verdicts (> the old 2*10 global budget) must not
    push a quieter rule's single older standing verdict out of the result."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        b = await _complete(
            db, rule_name="RULE_B", verdict="false_positive", alert_es_id="b1", age_days=2
        )
        for i in range(25):
            await _complete(db, rule_name="RULE_A", verdict="true_positive", alert_es_id=f"a{i}")

        got = await inv_svc.latest_complete_for_rules(db, ["RULE_A", "RULE_B"])
        # Before the fix, RULE_B's row fell outside the top-20 global LIMIT.
        assert set(got) == {"RULE_A", "RULE_B"}
        assert got["RULE_B"].id == b.id
    await engine.dispose()


async def test_latest_for_rules_keeps_each_rule_under_noisy_sibling(
    settings_kratos: Settings,
) -> None:
    """Same per-key bounding regression, through the shared `_latest_by` helper."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        b = await _complete(
            db, rule_name="RULE_B", verdict="false_positive", alert_es_id="b1", age_days=2
        )
        for i in range(25):
            await _complete(db, rule_name="RULE_A", verdict="true_positive", alert_es_id=f"a{i}")

        got = await inv_svc.latest_for_rules(db, ["RULE_A", "RULE_B"])
        assert set(got) == {"RULE_A", "RULE_B"}
        assert got["RULE_B"].id == b.id
    await engine.dispose()


async def test_override_counts_keeps_each_rule_under_noisy_sibling(
    settings_kratos: Settings,
) -> None:
    """A rule with 51 fresh plain completions (> the old 2*25 global budget)
    must not evict a quieter rule's analyst override from the tally."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # RULE_B: one older manual override (needs_more_info → false_positive).
        m = await _complete(
            db, rule_name="RULE_B", verdict="needs_more_info", alert_es_id="o1", age_days=2
        )
        await inv_svc.resolve(
            db,
            m.id,
            verdict="false_positive",
            confidence=1.0,
            rationale="Analyst confirmed benign.",
            recommended_actions=None,
            resolved_by="alice",
            resolved_via="manual",
        )
        # Re-age the row: resolve() does not touch created_at, but keep it old.
        rowb = await db.get(Investigation, m.id)
        rowb.created_at = utcnow() - timedelta(days=2)
        await db.commit()
        # RULE_A: 51 newer, non-override completions.
        for i in range(51):
            await _complete(db, rule_name="RULE_A", verdict="false_positive", alert_es_id=f"a{i}")

        counts = await inv_svc.override_counts_by_rule(db, ["RULE_A", "RULE_B"])
        # Before the fix, RULE_B's override row fell outside the global LIMIT.
        assert "RULE_B" in counts
        assert counts["RULE_B"]["overridden_to_fp"] == 1
        assert counts["RULE_B"]["manual_resolved"] == 1
    await engine.dispose()


# ---------------------------------------------------------------------------
# F27 — plan_targets must fetch each group's events with the group's own kind
# ---------------------------------------------------------------------------


class _MiniState:
    """Minimal app.state stand-in for plan_targets / run_auto_triage unit tests."""

    def __init__(self, settings: Settings, elastic: Any = None) -> None:
        self.settings = settings
        self.elastic = elastic


def test_plan_targets_passes_group_kind_to_fetch_group_events(
    settings_kratos: Settings,
) -> None:
    """A Zeek notice group must be fetched with kind='notice' (its name lives in
    notice.note); the buggy default 'suricata' filters rule.name and returns []."""
    suricata = aq.AlertGroup(
        rule_name="ET SCAN thing",
        count=3,
        severity="high",
        latest_ts="2026-06-12T06:41:00.000Z",
        latest_id="ev1",
        kind="suricata",
    )
    notice = aq.AlertGroup(
        rule_name="ATTACK::ICMP Backdoor",
        count=1,
        severity="high",
        latest_ts="2026-06-12T06:41:00.000Z",
        latest_id="n1",
        kind="notice",
    )

    calls: list[tuple[str, str]] = []

    async def fake_fetch_groups(
        elastic: Any, settings: Any, *, time_range: str, severity: str, oql: str | None
    ) -> tuple[list[aq.AlertGroup], Any]:
        return [suricata, notice], None

    async def fake_fetch_group_events(
        elastic: Any,
        settings: Any,
        *,
        rule_name: str,
        kind: str = "suricata",
        time_range: str = "24h",
        oql: str | None = None,
        size: int = 20,
    ) -> list[aq.AlertEvent]:
        calls.append((rule_name, kind))
        return []

    state = _MiniState(settings_kratos, AsyncMock())
    with (
        patch.object(at.aq, "fetch_groups", fake_fetch_groups),
        patch.object(at.aq, "fetch_group_events", fake_fetch_group_events),
    ):
        asyncio.run(at.plan_targets(state, time_range="24h", oql=None, severities=("high",)))

    kinds = dict(calls)
    assert kinds.get("ATTACK::ICMP Backdoor") == "notice"
    assert kinds.get("ET SCAN thing") == "suricata"


# ---------------------------------------------------------------------------
# F56 — each sweep target gets a fresh InvestigationContext
# ---------------------------------------------------------------------------


def test_run_auto_triage_uses_fresh_ctx_per_target(settings_kratos: Settings) -> None:
    """Reusing one ctx leaks the previous target's per-run tool state
    (default_time_anchor) into a later target's Phase-D PCAP fetch."""
    made: list[Any] = []

    def fake_ctx_from_state(state: Any) -> Any:
        c = SimpleNamespace(idx=len(made))
        made.append(c)
        return c

    seen: list[Any] = []

    async def fake_run_recorded(
        state: Any, *, ctx: Any, alert_id: str, started_by: str, rule_name: str | None = None
    ):  # type: ignore[no-untyped-def]
        seen.append(ctx)
        for _ in ():  # an async generator that yields nothing
            yield

    targets = [
        Target(alert_es_id="a1", rule_name="R1", src_ip="", dst_ip=""),
        Target(alert_es_id="a2", rule_name="R2", src_ip="", dst_ip=""),
    ]
    state = _MiniState(settings_kratos)
    with (
        patch.object(at, "ctx_from_state", fake_ctx_from_state),
        patch.object(at, "run_recorded", fake_run_recorded),
    ):
        asyncio.run(at.run_auto_triage(state, targets=targets, started_by="t"))

    assert len(seen) == 2
    # Before the fix both targets received the SAME ctx object.
    assert seen[0] is not seen[1]


# ---------------------------------------------------------------------------
# F28 — probe_model_fitness must not grade FAIL in demo mode
# ---------------------------------------------------------------------------


def _demo_settings() -> Settings:
    s = Settings(
        so_host="https://so.example.com",
        so_username="analyst",
        so_password=SecretStr("password123"),
        es_hosts=["https://so.example.com:9200"],
        litellm_base_url="http://localhost:4000",
    )
    s.soc_ai_demo = True
    s.analyst_model = "demo-analyst"
    return s


async def test_probe_model_fitness_demo_mode_passes_without_egress() -> None:
    """In demo mode the fitness probe must short-circuit to a non-alarming PASS
    (no legs, no model built) rather than grading FAIL via DemoEgressBlocked."""
    settings = _demo_settings()
    result = await probes.probe_model_fitness(settings)
    assert result["grade"] == "pass"
    assert result["legs"] == []
    assert result["model"] == "demo-analyst"
    assert "demo" in result["detail"].lower()
