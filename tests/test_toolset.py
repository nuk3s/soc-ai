"""Unified tool-surface module: one registration site, one Phase-D source."""

from __future__ import annotations

import inspect
from datetime import datetime, timedelta
from typing import Any, get_args
from unittest.mock import AsyncMock

import pytest
from pydantic_ai import Agent
from pydantic_ai.models.test import TestModel
from soc_ai.agent.orchestrator import InvestigationContext
from soc_ai.agent.targeted_investigator import _dispatch_table
from soc_ai.agent.toolset import PHASE_D_TOOLS, register_read_tools
from soc_ai.config import Settings
from soc_ai.store.models import HostDossier, HostDossierField
from soc_ai.triage_models import TargetedGap

from tests.test_tool_surface import INVESTIGATOR_EXPECTED, _all_flags_on


def _agent_with(role: str, settings: Settings, **ctx_kwargs: Any) -> Agent:
    agent: Agent = Agent(TestModel(call_tools=[]), output_type=str, system_prompt="x")
    ctx = InvestigationContext(
        settings=settings, auth=AsyncMock(), elastic=AsyncMock(), **ctx_kwargs
    )
    register_read_tools(agent, ctx, role=role)  # type: ignore[arg-type]
    return agent


def _names(agent: Agent) -> set[str]:
    return set(agent._function_toolset.tools)


def test_roles_register_disjoint_extras(settings_kratos: Settings) -> None:
    inv = _names(_agent_with("investigator", settings_kratos))
    chat = _names(_agent_with("chat", settings_kratos))
    hunt = _names(_agent_with("hunt", settings_kratos))
    assert {"t_query_detections", "t_get_playbooks", "t_lookup_runbook"} <= inv - chat
    assert "t_suggest_rule_tuning" in chat and "t_suggest_rule_tuning" not in hunt
    assert hunt <= chat  # hunt is the minimal surface


def test_hunt_oql_default_window_is_wide(settings_kratos: Settings) -> None:
    hunt = _agent_with("hunt", settings_kratos)
    fn = hunt._function_toolset.tools["t_query_events_oql"].function
    assert inspect.signature(fn).parameters["time_range_minutes"].default == 1440
    inv = _agent_with("investigator", settings_kratos)
    fn = inv._function_toolset.tools["t_query_events_oql"].function
    assert inspect.signature(fn).parameters["time_range_minutes"].default == 60


def test_gated_tools_absent_when_flags_off(settings_kratos: Settings) -> None:
    """Registration-time gating in every role (normalized; investigator too)."""
    gated = {
        "t_shodan_internetdb",
        "t_greynoise",
        "t_shodan_host",
        "t_cve_lookup",
        "t_get_pcap",
        "t_web_search",
        "t_crawl_page",
    }
    for role in ("investigator", "chat", "hunt"):
        names = _names(_agent_with(role, settings_kratos))
        assert not (gated & names), (role, sorted(gated & names))


def test_investigator_flags_on_matches_golden_set(settings_kratos: Settings) -> None:
    """The unified module reproduces the investigator surface exactly.

    ``INVESTIGATOR_EXPECTED`` is the golden set captured from the live
    ``build_investigator`` at rewire time — it pins the unified module against
    the pre-rewire surface and will catch any unintended registration drift.
    """
    agent = _agent_with("investigator", _all_flags_on(settings_kratos))
    assert _names(agent) == INVESTIGATOR_EXPECTED


def test_targeted_gap_literal_matches_phase_d_tools() -> None:
    """The TargetedGap Literal is a GATED copy of the dispatch surface."""
    literal_names = set(get_args(TargetedGap.model_fields["tool_name"].annotation))
    assert literal_names == set(PHASE_D_TOOLS)


def test_phase_d_dispatch_table_matches_phase_d_tools() -> None:
    """Drift gate: the Phase-D dispatch table keys == PHASE_D_TOOLS exactly.

    _dispatch_named_tool validates tool_name against PHASE_D_TOOLS before the
    table lookup, so a table key missing from the tuple would be unreachable
    and a tuple entry missing from the table would KeyError — both are drift.
    """
    assert set(_dispatch_table()) == set(PHASE_D_TOOLS)


@pytest.mark.asyncio
async def test_dedup_wrapping_runs_through_registered_tool(settings_kratos: Settings) -> None:
    """Behavioral proof the house wrapping runs THROUGH the module (not just
    name parity): the second identical call to a registered tool short-circuits
    with the structured duplicate-hint dict instead of re-running the tool."""
    agent = _agent_with("investigator", settings_kratos)
    tool = agent._function_toolset.tools["t_query_cases"]

    first = await tool.function(query="ransomware")
    second = await tool.function(query="ransomware")

    # First call went through to the (mocked) elastic ctx — whatever it
    # returned, it is NOT the duplicate payload.
    assert not (isinstance(first, dict) and first.get("duplicate_call"))
    assert isinstance(second, dict)
    assert second["duplicate_call"] is True
    assert second["tool_name"] == "t_query_cases"
    assert "hint" in second


# ---------------------------------------------------------------------------
# t_host_dossier — the durable asset record, read from the local store
# ---------------------------------------------------------------------------


class _FakeSession:
    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False


def _sessionmaker() -> Any:
    return _FakeSession


def _dossier_settings(settings: Settings, *, enabled: bool = True) -> Settings:
    return settings.model_copy(update={"dossier_enabled": enabled})


def _stored() -> tuple[HostDossier, list[HostDossierField]]:
    """A host the sweep called a hypervisor and an operator called critical."""
    now = datetime.now().replace(microsecond=0)
    host = HostDossier(
        host_key="192.168.10.202",
        ip="192.168.10.202",
        first_seen=now - timedelta(days=65),
        last_seen=now - timedelta(minutes=3),
        event_count=3412,
    )
    rows = [
        HostDossierField(
            field="role",
            inferred_value="hypervisor",
            inferred_confidence=0.9,
            inferred_source="behaviour",
            inferred_last_run_at=now - timedelta(hours=1),
            inferred_evidence={"behaviour": {"strings": ["responds on tcp/8006 (from behaviour)"]}},
        ),
        HostDossierField(
            field="criticality",
            operator_value="high",
            operator_actor="analyst",
            operator_set_at=now - timedelta(days=5),
            # The builder keeps observing an overridden field; the tool must
            # report both lanes so the model can see what is being suppressed.
            inferred_value="medium",
            inferred_confidence=0.9,
            inferred_source="behaviour",
            inferred_last_run_at=now - timedelta(hours=1),
        ),
    ]
    return host, rows


@pytest.mark.asyncio
async def test_host_dossier_reports_operator_and_inferred_lanes(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from soc_ai.store import host_dossier as store

    async def _get(db: object, ip: str) -> tuple[HostDossier, list[HostDossierField]] | None:
        return _stored() if ip == "192.168.10.202" else None

    monkeypatch.setattr(store, "get_dossier", _get)
    agent = _agent_with(
        "investigator", _dossier_settings(settings_kratos), db_sessionmaker=_sessionmaker()
    )
    result = await agent._function_toolset.tools["t_host_dossier"].function(ip="192.168.10.202")

    assert result["found"] is True
    role = result["fields"]["role"]
    assert role["value"] == "hypervisor"
    assert role["source"] == "behaviour"
    assert role["strength"] == "strong"
    crit = result["fields"]["criticality"]
    assert crit["value"] == "high"
    assert crit["source"] == "operator"
    assert crit["operator_actor"] == "analyst"
    # An override suppresses effect, never observation.
    assert crit["inferred_value"] == "medium"


@pytest.mark.asyncio
async def test_host_dossier_absence_is_an_answer(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ "No dossier" must not read as "nothing notable about this host"."""
    from soc_ai.store import host_dossier as store

    async def _none(db: object, ip: str) -> None:
        return None

    monkeypatch.setattr(store, "get_dossier", _none)
    agent = _agent_with("chat", _dossier_settings(settings_kratos), db_sessionmaker=_sessionmaker())
    result = await agent._function_toolset.tools["t_host_dossier"].function(ip="8.8.8.8")

    assert result["found"] is False
    assert "not evidence" in result["note"].lower()


@pytest.mark.asyncio
async def test_host_dossier_disabled_answers_instead_of_vanishing(
    settings_kratos: Settings,
) -> None:
    """Registered even when off: an unregistered tool leaves the model guessing,
    and a local-DB read is not worth a registration gate."""
    agent = _agent_with(
        "hunt",
        _dossier_settings(settings_kratos, enabled=False),
        db_sessionmaker=_sessionmaker(),
    )
    assert "t_host_dossier" in _names(agent)
    result = await agent._function_toolset.tools["t_host_dossier"].function(ip="192.168.10.202")
    assert result == {"available": False, "reason": "host dossier disabled"}


@pytest.mark.asyncio
async def test_host_dossier_without_a_database_says_so(settings_kratos: Settings) -> None:
    agent = _agent_with("investigator", _dossier_settings(settings_kratos))
    result = await agent._function_toolset.tools["t_host_dossier"].function(ip="192.168.10.202")
    assert result["available"] is False


@pytest.mark.asyncio
async def test_host_dossier_dedups_and_survives_a_store_failure(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from soc_ai.store import host_dossier as store

    async def _get(db: object, ip: str) -> tuple[HostDossier, list[HostDossierField]] | None:
        return _stored()

    monkeypatch.setattr(store, "get_dossier", _get)
    agent = _agent_with(
        "investigator", _dossier_settings(settings_kratos), db_sessionmaker=_sessionmaker()
    )
    tool = agent._function_toolset.tools["t_host_dossier"].function
    assert (await tool(ip="192.168.10.202"))["found"] is True
    assert (await tool(ip="192.168.10.202"))["duplicate_call"] is True

    async def _boom(db: object, ip: str) -> None:
        raise RuntimeError("no such table: host_dossier")

    monkeypatch.setattr(store, "get_dossier", _boom)
    failed = await tool(ip="192.168.10.7")
    assert failed["error"] is True
    assert failed["type"] == "RuntimeError"


# ---------------------------------------------------------------------------
# Egress-tool identifier threading (finding search-guard-ignores-db-identifiers)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_egress_tool_idents_prefers_preseeded(settings_kratos: Settings) -> None:
    """The orchestrator pre-seeds the set it already resolved for EgressGuard; the
    helper returns it without a second DB round-trip."""
    from soc_ai.agent.toolset import _egress_tool_idents

    ctx = InvestigationContext(settings=settings_kratos, auth=AsyncMock(), elastic=AsyncMock())
    ctx.effective_internal_suffixes = (".discovered.example",)
    ctx.effective_internal_hosts = ("jumpbox",)
    ctx._egress_idents_resolved = True
    sfx, hosts = await _egress_tool_idents(ctx)
    assert sfx == (".discovered.example",)
    assert hosts == ("jumpbox",)


@pytest.mark.asyncio
async def test_egress_tool_idents_none_without_db(settings_kratos: Settings) -> None:
    """No DB session ⇒ (None, None): the tool guard falls back to raw settings."""
    from soc_ai.agent.toolset import _egress_tool_idents

    ctx = InvestigationContext(
        settings=settings_kratos, auth=AsyncMock(), elastic=AsyncMock(), db_sessionmaker=None
    )
    sfx, hosts = await _egress_tool_idents(ctx)
    assert sfx is None and hosts is None
    assert ctx._egress_idents_resolved is True


@pytest.mark.asyncio
async def test_web_search_closure_threads_effective_idents(
    settings_kratos: Settings, monkeypatch: Any
) -> None:
    """The t_web_search closure passes the ctx's effective identifier sets through
    to web_search (the actual egress guard input)."""
    captured: dict[str, Any] = {}

    async def _fake_web_search(
        query: str, *, settings: Any, suffixes: Any = None, extra_hosts: Any = None
    ) -> dict[str, Any]:
        captured["suffixes"] = suffixes
        captured["extra_hosts"] = extra_hosts
        return {"ok": True}

    monkeypatch.setattr("soc_ai.agent.toolset.web_search", _fake_web_search)
    agent: Agent = Agent(TestModel(call_tools=[]), output_type=str, system_prompt="x")
    ctx = InvestigationContext(
        settings=_all_flags_on(settings_kratos), auth=AsyncMock(), elastic=AsyncMock()
    )
    ctx.effective_internal_suffixes = (".disc.example",)
    ctx.effective_internal_hosts = ("jumpbox",)
    ctx._egress_idents_resolved = True
    register_read_tools(agent, ctx, role="investigator")
    fn = agent._function_toolset.tools["t_web_search"].function
    await fn("some query")
    assert captured["suffixes"] == (".disc.example",)
    assert captured["extra_hosts"] == ("jumpbox",)
