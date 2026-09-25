"""Unified tool-surface module: one registration site, one Phase-D source."""

from __future__ import annotations

import inspect
from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import Any, get_args
from unittest.mock import AsyncMock

import pytest
from pydantic_ai import Agent
from pydantic_ai.models.test import TestModel
from soc_ai.agent.orchestrator import InvestigationContext
from soc_ai.agent.targeted_investigator import _dispatch_table
from soc_ai.agent.toolset import HUNT_ONLY, PHASE_D_TOOLS, register_read_tools
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
    # Hunt's only extras over chat are the network-wide analytics sweeps
    # (HUNT_ONLY, 1.3 slice 2) — everything else hunt gets is also on chat.
    assert hunt - chat == HUNT_ONLY
    assert hunt <= chat | HUNT_ONLY


def test_hunt_only_analytics_registered_on_hunt_alone(settings_kratos: Settings) -> None:
    """The four behavioral-analytics sweeps (1.3 slice 2) are hunt-exclusive:
    present on the hunt agent's registered surface, absent from investigator
    and chat."""
    inv = _names(_agent_with("investigator", settings_kratos))
    chat = _names(_agent_with("chat", settings_kratos))
    hunt = _names(_agent_with("hunt", settings_kratos))
    assert hunt >= HUNT_ONLY
    assert HUNT_ONLY.isdisjoint(inv)
    assert HUNT_ONLY.isdisjoint(chat)


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


# ---------------------------------------------------------------------------
# Tools that cannot answer are not offered (reasoning-turn audit 2026-09-19,
# W1/W4). An offered tool costs one model turn when the model calls it: 18 s on
# production. ``t_get_playbooks`` returned ``[]`` on all 24 production calls,
# and ``t_get_rule_content`` was called 11 times for text the prompt carried.
# ---------------------------------------------------------------------------


class _PlaybookEs:
    """Minimal ES double: counts searches, answers with a fixed hit list."""

    def __init__(self, hits: list[dict[str, Any]]) -> None:
        self.hits = hits
        self.calls = 0

    async def search(self, index: str, query: dict[str, Any], **kwargs: Any) -> Any:
        self.calls += 1
        return SimpleNamespace(hits=list(self.hits))


@pytest.fixture(autouse=True)
def _clean_playbook_cache() -> Any:
    from soc_ai.agent.toolset import reset_playbook_presence_cache

    reset_playbook_presence_cache()
    yield
    reset_playbook_presence_cache()


def _ctx_with(settings: Settings, elastic: Any, **kwargs: Any) -> InvestigationContext:
    return InvestigationContext(settings=settings, auth=AsyncMock(), elastic=elastic, **kwargs)


def _registered(ctx: InvestigationContext, role: str = "investigator") -> set[str]:
    agent: Agent = Agent(TestModel(call_tools=[]), output_type=str, system_prompt="x")
    register_read_tools(agent, ctx, role=role)  # type: ignore[arg-type]
    return _names(agent)


@pytest.mark.asyncio
async def test_playbook_tool_is_not_offered_when_the_instance_has_none(
    settings_kratos: Settings,
) -> None:
    from soc_ai.agent.toolset import prime_playbook_presence

    ctx = _ctx_with(settings_kratos, _PlaybookEs([]))
    assert await prime_playbook_presence(ctx) is False
    assert "t_get_playbooks" not in _registered(ctx)


@pytest.mark.asyncio
async def test_playbook_tool_is_offered_when_the_instance_has_one(
    settings_kratos: Settings,
) -> None:
    from soc_ai.agent.toolset import prime_playbook_presence

    ctx = _ctx_with(settings_kratos, _PlaybookEs([{"_source": {"name": "phishing"}}]))
    assert await prime_playbook_presence(ctx) is True
    assert "t_get_playbooks" in _registered(ctx)


@pytest.mark.asyncio
async def test_an_unprobed_or_failing_grid_still_offers_the_playbook_tool(
    settings_kratos: Settings,
) -> None:
    """FAIL OPEN, twice over. A grid that did not answer says nothing about
    whether playbooks exist, and a run that never probed must behave as it
    always did."""

    class _Broken:
        async def search(self, *a: Any, **k: Any) -> Any:
            raise RuntimeError("grid unreachable")

    from soc_ai.agent.toolset import prime_playbook_presence

    unprobed = _ctx_with(settings_kratos, _PlaybookEs([]))
    assert "t_get_playbooks" in _registered(unprobed)

    broken = _ctx_with(settings_kratos, _Broken())
    assert await prime_playbook_presence(broken) is True
    assert "t_get_playbooks" in _registered(broken)


@pytest.mark.asyncio
async def test_the_playbook_probe_answers_from_cache_within_the_hour(
    settings_kratos: Settings,
) -> None:
    from soc_ai.agent.toolset import prime_playbook_presence

    es = _PlaybookEs([])
    ctx = _ctx_with(settings_kratos, es)
    assert await prime_playbook_presence(ctx) is False
    assert await prime_playbook_presence(ctx) is False
    assert es.calls == 1


@pytest.mark.asyncio
async def test_the_playbook_probe_reads_the_playbook_index(
    settings_kratos: Settings,
) -> None:
    class _Recorder(_PlaybookEs):
        index: str = ""

        async def search(self, index: str, query: dict[str, Any], **kwargs: Any) -> Any:
            self.index = index
            return await super().search(index, query, **kwargs)

    from soc_ai.agent.toolset import prime_playbook_presence

    es = _Recorder([])
    await prime_playbook_presence(_ctx_with(settings_kratos, es))
    assert es.index == settings_kratos.playbooks_index_pattern


def test_rule_content_tool_is_not_offered_when_the_prompt_carries_the_rule(
    settings_kratos: Settings,
) -> None:
    ctx = _ctx_with(settings_kratos, AsyncMock(), rule_body_in_prompt=True)
    assert "t_get_rule_content" not in _registered(ctx)
    # The flag belongs to the investigation loop. Every other role keeps the tool.
    assert "t_get_rule_content" in _registered(ctx, role="chat")
    assert "t_get_rule_content" in _registered(_ctx_with(settings_kratos, AsyncMock()))


# ---------------------------------------------------------------------------
# R6: "the prefetch already has this" must mean the record is there
# ---------------------------------------------------------------------------


def _enriched_with(events: list[Any]) -> Any:
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    return EnrichedAlertContext(
        alert=SoAlert(id="alert-001", network_community_id="1:abc=="),
        community_id_events=events,
    )


def test_a_pivot_that_returned_nothing_is_not_a_prefetched_record() -> None:
    """01M2WG06 seq 7: the stub answered "prefetch already has this" while
    ``community_id_events`` was empty. The model recovered with OQL and found
    the WireGuard record that decided the case."""
    from soc_ai.agent.toolset import prefetched_community_ids

    assert prefetched_community_ids(_enriched_with([])) == set()


def test_a_prefetched_record_puts_its_community_id_on_the_list() -> None:
    from soc_ai.agent.toolset import prefetched_community_ids
    from soc_ai.so_client.models import SoAlert

    events = [SoAlert(id="zeek-1", network_community_id="1:abc==")]
    assert prefetched_community_ids(_enriched_with(events)) == {"1:abc=="}


@pytest.mark.asyncio
async def test_zeek_query_runs_when_the_prefetch_holds_no_record(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stub short-circuits on presence, so an absent record means a query."""
    ran: list[str] = []

    async def _query(community_id: str, **kwargs: Any) -> list[dict[str, Any]]:
        ran.append(community_id)
        return [{"_id": "zeek-1"}]

    monkeypatch.setattr("soc_ai.agent.toolset.query_zeek_logs", _query)
    ctx = _ctx_with(settings_kratos, AsyncMock())
    ctx.prefetched_community_ids = set()
    agent: Agent = Agent(TestModel(call_tools=[]), output_type=str, system_prompt="x")
    register_read_tools(agent, ctx, role="investigator")
    result = await agent._function_toolset.tools["t_query_zeek_logs"].function(
        community_id="1:abc=="
    )
    assert ran == ["1:abc=="]
    assert result == [{"_id": "zeek-1"}]


def test_clamp_tool_result_clips_long_string_leaves_of_plain_dicts() -> None:
    """A plain dict (no hits/items/rows list, no aggregations) over budget must
    shrink, not merely be tagged. t_get_event_raw returns the raw ES _source,
    and a Suricata alert carries payload + payload_printable + the full EVE
    copy in message — 100KB+ that would otherwise land verbatim in the loop.
    """
    import json

    from soc_ai.agent.toolset import _TOOL_RESULT_BUDGET_BYTES, _clamp_tool_result

    big = {
        "_id": "x",
        "payload": "A" * 200_000,
        "event": {"original": "B" * 50_000, "kind": "alert"},
        "message": "C" * 50_000,
    }
    out = _clamp_tool_result(big)

    assert out["__truncated__"] is True
    assert len(json.dumps(out)) <= _TOOL_RESULT_BUDGET_BYTES + 512
    # Every key survives; only the oversized string leaves are shortened.
    assert set(big) <= set(out)
    assert out["_id"] == "x"
    assert out["event"]["kind"] == "alert"
    assert len(out["payload"]) < len(big["payload"])
    assert len(out["event"]["original"]) < len(big["event"]["original"])
    assert len(out["message"]) < len(big["message"])
    # The clip is announced in-band and the affected paths are listed.
    assert "clipped" in out["payload"]
    assert {"payload", "event.original", "message"} <= set(out["__clipped_fields__"])
    # The caller's dict is never mutated.
    assert len(big["payload"]) == 200_000
