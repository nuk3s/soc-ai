"""The dossier reaching the model: prompt wiring for the investigation pipeline.

``soc_ai/dossier/prompt.py`` renders a block; this file proves the block is
actually IN the product. The motivating failure is concrete: soc-ai attributed
SSH probing to 192.168.10.202 without knowing it was the hypervisor hosting the
Security Onion node and the rest of the network's core services, whose own policy
forbids interactive SSH. A renderer with no caller does not fix that — the
investigation prompt has to carry the asset context on every run, at every site
that reaches a verdict.

Four sites, because the pipeline has four different ways to end up writing one:

* round 1 (the tool-less synthesis that settles most alerts),
* the investigation loop's investigator prompt,
* the transcript synthesizer — the real blind spot, since the post-loop verdict
  writer sees only the transcript and the candidate, no enriched JSON at all,
* round 2 after a Phase-D targeted dispatch.

Two properties matter as much as presence:

* **ordering** — the block is composed BEFORE ``guard.sanitize_text``, or the
  dossier's internal hostnames and IPs egress to a cloud analyst model in the
  clear. The test patches the guard and reads what it was handed, rather than
  inferring ordering from the output;
* **budget** — the block is paid for out of the enriched context's budget, not
  on top of it, and the subtraction is clamped so a fat dossier cannot grind
  the correlation signal away.

NO real gateway/model is called: the synth agent is a stub whose ``run`` is an
``AsyncMock``, so ``fake_agent.run.call_args[0][0]`` IS the composed outbound
message, captured after the sanitize sweep and the fail-closed egress check.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic_ai import Agent
from pydantic_ai.models.test import TestModel
from soc_ai.agent import context_budget
from soc_ai.agent.orchestrator import InvestigationContext, investigate
from soc_ai.agent.triage import InvestigationTranscript, TargetedGap, TriageReport
from soc_ai.config import Settings
from soc_ai.dossier.prompt import HEADING
from soc_ai.dossier.types import Fact
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.models import SoAlert
from soc_ai.store import host_dossier as dossier_store
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.tools.get_alert_context import EnrichedAlertContext

# An INFO-class rule: it must not trip the malware/exploit "definitely
# investigate" gate, which would skip round 1 and muddy what these tests
# measure. Source is internal (the dossier only knows internal hosts);
# destination is external, so the block has to state its absence out loud.
RULE = "ET INFO Periodic Gateway Heartbeat"
SRC = "192.168.10.202"
DST = "8.8.8.8"

ROLE_LINE = "role: hypervisor"


def _enriched(alert_id: str = "alert-001") -> EnrichedAlertContext:
    return EnrichedAlertContext(
        alert=SoAlert(
            id=alert_id,
            severity_label="low",
            rule_name=RULE,
            source_ip=SRC,
            destination_ip=DST,
        ),
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def _seed_dossier(maker: Any, ip: str = SRC, hostname: str = "pve01") -> None:
    """One built host: hypervisor role, an operator policy, a hostname.

    Mirrors the 192.168.10.202 case the feature exists for — the facts a verdict
    should be able to lean on, and the operator policy no telemetry could have
    produced.

    *hostname* is a parameter because one caller needs a name the narrative
    grounding checker actually detects: its hostname pattern wants a hyphen, so
    a test that seeds ``pve01`` and then asserts the name came back grounded is
    asserting nothing.
    """
    now = datetime.now(UTC)
    async with maker() as db:
        host = await dossier_store.upsert_host(
            db,
            ip,
            first_seen=now,
            last_seen=now,
            event_count=3412,
            last_built_at=now,
            now=now,
        )
        for fact in (
            Fact(
                field="role",
                value="hypervisor",
                confidence=0.9,
                strength="strong",
                source="behaviour",
                evidence=["responds on tcp/8006, tcp/8007 (from behaviour)"],
                observed_at=now,
            ),
            Fact(
                field="hostname",
                value=hostname,
                confidence=0.9,
                strength="strong",
                source="banner",
                evidence=[f"{hostname} (from dhcp)"],
                observed_at=now,
            ),
        ):
            await dossier_store.upsert_inferred(db, host, fact, now=now)
        await dossier_store.set_override(
            db,
            ip,
            "policy_notes",
            "no interactive SSH; API-token access only",
            actor="analyst",
            now=now,
        )
        await db.commit()


def _make_ctx(settings: Settings, maker: Any = None) -> InvestigationContext:
    fake_es = AsyncMock()
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        elastic = ElasticClient(settings)
    return InvestigationContext(
        settings=settings,
        auth=AsyncMock(),
        elastic=elastic,
        db_sessionmaker=maker,
    )


def _report(gap: TargetedGap | None = None) -> TriageReport:
    return TriageReport(
        verdict="false_positive",
        confidence=0.85,
        summary="Internal heartbeat; expected periodic traffic.",
        citations=["alert.severity_label"],
        recommended_actions=[],
        gap_for_investigator=gap,
    )


def _strong_benign_candidate() -> Any:
    """Strong benign template match so a zero-tool FP verdict settles round-1."""
    from soc_ai.agent.decision_templates import CandidateVerdict

    return CandidateVerdict(
        verdict="false_positive",
        confidence=0.85,
        cited_evidence=["alert.severity_label"],
        template_id="clean_internal_traffic",
        rationale="internal scanner",
    )


async def _drive(
    ctx: InvestigationContext,
    report: TriageReport | None = None,
    *,
    targeted_result: dict[str, Any] | None = None,
) -> tuple[list[Any], Any]:
    """Run the round-1-settled pipeline with a stubbed synth agent.

    Returns ``(events, fake_agent)``; ``fake_agent.run.call_args_list[n][0][0]``
    is the composed outbound message for round n+1.
    """
    report = report or _report()
    fake_agent = Agent(
        model=TestModel(call_tools=[], custom_output_args=report),
        system_prompt="stub",
        output_type=TriageReport,
    )
    fake_agent.run = AsyncMock(return_value=MagicMock(output=report))

    async def _stub_enriched(aid: str, **_kw: Any) -> Any:
        return _enriched(aid)

    async def _stub_targeted(*_a: Any, **_kw: Any) -> Any:
        return targeted_result or {"ok": True}

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[], custom_output_args=report),
        ),
        patch("soc_ai.agent.orchestrator.build_synth_first_agent", return_value=fake_agent),
        patch(
            "soc_ai.agent.decision_templates.match_decision_template",
            return_value=_strong_benign_candidate(),
        ),
        patch(
            "soc_ai.agent.targeted_investigator.run_targeted_investigation",
            side_effect=_stub_targeted,
        ),
    ):
        events = [ev async for ev in investigate("alert-001", ctx=ctx)]
    return events, fake_agent


# ---------------------------------------------------------------------------
# Loop-path doubles (the investigator streams nodes via agent.iter())
# ---------------------------------------------------------------------------


class _FakeIterNode:
    def __init__(self, message: Any) -> None:
        self.model_response = message


class _FakeAgentRun:
    def __init__(self, messages: list[Any], result: Any) -> None:
        self._nodes = [_FakeIterNode(m) for m in messages]
        self.result = result

    def __aiter__(self) -> Any:
        return self._agen()

    async def _agen(self) -> Any:
        for node in self._nodes:
            yield node


class _FakeIterCM:
    def __init__(self, run: _FakeAgentRun) -> None:
        self._run = run

    async def __aenter__(self) -> _FakeAgentRun:
        return self._run

    async def __aexit__(self, *exc: Any) -> bool:
        return False


async def _drive_loop(ctx: InvestigationContext) -> tuple[Any, Any]:
    """Force the tool-driven loop; return ``(fake_investigator, fake_loop_synth)``."""
    from types import SimpleNamespace

    transcript = InvestigationTranscript(
        evidence=[
            "t_query_zeek_logs(community_id=1:abc) -> conn_state=SF (tool t_query_zeek_logs)"
        ],
        tentative_summary="Routine management-plane traffic.",
        open_questions=[],
    )
    loop_msg = SimpleNamespace(
        parts=[
            SimpleNamespace(tool_name="t_query_zeek_logs", args={}, tool_call_id="tc1"),
            SimpleNamespace(
                tool_name="t_query_zeek_logs",
                content={"conn": []},
                tool_call_id="tc1",
                part_kind="tool-return",
            ),
        ]
    )
    inv_result = MagicMock()
    inv_result.output = transcript
    inv_result.all_messages = MagicMock(return_value=[loop_msg])
    inv_result.usage = MagicMock(side_effect=RuntimeError("no usage in stub"))
    fake_investigator = MagicMock()
    fake_investigator.iter = MagicMock(
        return_value=_FakeIterCM(_FakeAgentRun([loop_msg], inv_result))
    )

    loop_synth_result = MagicMock()
    loop_synth_result.output = _report()
    loop_synth_result.usage = MagicMock(side_effect=RuntimeError("no usage in stub"))
    fake_loop_synth = MagicMock()
    fake_loop_synth.run = AsyncMock(return_value=loop_synth_result)

    async def _stub_enriched(aid: str, **_kw: Any) -> Any:
        return _enriched(aid)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[]),
        ),
        patch("soc_ai.agent.orchestrator.build_investigator", return_value=fake_investigator),
        patch("soc_ai.agent.orchestrator.build_synthesizer", return_value=fake_loop_synth),
    ):
        [ev async for ev in investigate("alert-001", ctx=ctx, deep=True)]
    return fake_investigator, fake_loop_synth


# =====================================================================
# The block is in the prompt
# =====================================================================


@pytest.mark.asyncio
async def test_round1_prompt_carries_the_dossier_block(settings_kratos: Settings) -> None:
    """THE regression: without this the model never learns what the host IS, and
    SSH probing from a hypervisor reads like SSH probing from anything else."""
    settings_kratos.investigate_when_unsure = False
    engine, maker = await _db(settings_kratos)
    await _seed_dossier(maker)
    ctx = _make_ctx(settings_kratos, maker)

    _events, fake_agent = await _drive(ctx)

    msg = fake_agent.run.call_args[0][0]
    assert HEADING in msg
    assert ROLE_LINE in msg
    assert "no interactive SSH" in msg  # the operator policy the verdict must respect
    # The external endpoint is named as having no record — silence would read as
    # "nothing notable about that one".
    assert "no dossier" in msg
    await engine.dispose()


@pytest.mark.asyncio
async def test_dossier_block_sits_ahead_of_the_enriched_context(
    settings_kratos: Settings,
) -> None:
    """The model learns what the hosts ARE before it reads what they DID, and
    the current evidence still arrives last (recency)."""
    settings_kratos.investigate_when_unsure = False
    engine, maker = await _db(settings_kratos)
    await _seed_dossier(maker)
    ctx = _make_ctx(settings_kratos, maker)

    _events, fake_agent = await _drive(ctx)

    msg = fake_agent.run.call_args[0][0]
    assert msg.index(HEADING) < msg.index("## Enriched alert context")
    await engine.dispose()


@pytest.mark.asyncio
async def test_dossier_block_absent_when_the_context_switch_is_off(
    settings_kratos: Settings,
) -> None:
    """``dossier_context_enabled`` is a live config-console toggle. It has to
    control something."""
    settings_kratos.investigate_when_unsure = False
    settings_kratos.dossier_context_enabled = False
    engine, maker = await _db(settings_kratos)
    await _seed_dossier(maker)
    ctx = _make_ctx(settings_kratos, maker)

    events, fake_agent = await _drive(ctx)

    assert HEADING not in fake_agent.run.call_args[0][0]
    assert not any(e.kind == "host_dossier" for e in events)
    await engine.dispose()


@pytest.mark.asyncio
async def test_no_swept_host_means_no_block_and_no_event(settings_kratos: Settings) -> None:
    """A deployment that has not swept yet pays nothing: no block, no timeline
    row, no tokens."""
    settings_kratos.investigate_when_unsure = False
    engine, maker = await _db(settings_kratos)  # empty host_dossier table
    ctx = _make_ctx(settings_kratos, maker)

    events, fake_agent = await _drive(ctx)

    assert HEADING not in fake_agent.run.call_args[0][0]
    assert not any(e.kind == "host_dossier" for e in events)
    await engine.dispose()


@pytest.mark.asyncio
async def test_host_dossier_timeline_event_carries_real_values(
    settings_kratos: Settings,
) -> None:
    """The timeline is local storage, never egress — it records what was
    actually injected, with real addresses, so an analyst can audit the claim."""
    settings_kratos.investigate_when_unsure = False
    engine, maker = await _db(settings_kratos)
    await _seed_dossier(maker)
    ctx = _make_ctx(settings_kratos, maker)

    events, _fake_agent = await _drive(ctx)

    ev = next(e for e in events if e.kind == "host_dossier")
    assert ev.payload["hosts"] == {SRC: "source", DST: "destination"}
    assert SRC in ev.payload["block"]
    assert ROLE_LINE in ev.payload["block"]
    await engine.dispose()


@pytest.mark.asyncio
async def test_investigator_loop_prompt_carries_the_dossier_block(
    settings_kratos: Settings,
) -> None:
    """Grid inventory and host dossier are the same class of ambient ground
    truth; the loop prompt carries both."""
    engine, maker = await _db(settings_kratos)
    await _seed_dossier(maker)
    ctx = _make_ctx(settings_kratos, maker)

    fake_investigator, _synth = await _drive_loop(ctx)

    msg = fake_investigator.iter.call_args[0][0]
    assert HEADING in msg
    assert ROLE_LINE in msg
    await engine.dispose()


@pytest.mark.asyncio
async def test_transcript_synthesizer_prompt_carries_the_dossier_block(
    settings_kratos: Settings,
) -> None:
    """The post-loop verdict writer is the real blind spot: it sees the
    transcript and the candidate and nothing else — no enriched JSON, no
    inventory, no memory. It writes the verdict."""
    engine, maker = await _db(settings_kratos)
    await _seed_dossier(maker)
    ctx = _make_ctx(settings_kratos, maker)

    _investigator, fake_loop_synth = await _drive_loop(ctx)

    msg = fake_loop_synth.run.call_args[0][0]
    assert HEADING in msg
    assert "no interactive SSH" in msg
    await engine.dispose()


@pytest.mark.asyncio
async def test_round2_prompt_carries_the_dossier_block(settings_kratos: Settings) -> None:
    """Unlike the memory blocks, asset facts are not round-1-only: the round-2
    synthesis is a verdict site too."""
    settings_kratos.investigate_when_unsure = False
    engine, maker = await _db(settings_kratos)
    await _seed_dossier(maker)
    ctx = _make_ctx(settings_kratos, maker)

    gap = TargetedGap(
        question="Is the destination on a blocklist?",
        tool_name="t_enrich_ip",
        tool_args={"ip": DST},
        why_this_matters="reputation would settle it",
    )
    _events, fake_agent = await _drive(ctx, _report(gap))

    assert len(fake_agent.run.call_args_list) >= 2, "Phase D did not re-synthesize"
    round2 = fake_agent.run.call_args_list[1][0][0]
    assert HEADING in round2
    assert ROLE_LINE in round2
    # Exactly once. Round 2 rebuilds its base message from scratch today; a
    # refactor that fed it round 1's composed text instead would inject twice
    # and pay the dossier's budget twice, which nothing else would notice.
    assert round2.count(HEADING) == 1
    await engine.dispose()


# =====================================================================
# Egress ordering: composed BEFORE sanitize_text, never after
# =====================================================================


@pytest.mark.asyncio
async def test_block_is_composed_before_the_egress_sanitize(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Patch the guard and read what it was HANDED.

    Appending the dossier after the sweep leaks internal hostnames, IPs and MACs
    to a cloud analyst model; appending it between the sweep and the fail-closed
    residue gate kills every investigation on a redacted deployment. The only
    correct position is before both, and the proof is that the guard saw the raw
    text and the model did not.
    """
    from soc_ai.agent.egress_guard import EgressGuard

    settings_kratos.investigate_when_unsure = False
    settings_kratos.analyst_cloud_redaction = True
    settings_kratos.analyst_redaction_fail_closed = True
    engine, maker = await _db(settings_kratos)
    await _seed_dossier(maker)
    ctx = _make_ctx(settings_kratos, maker)

    handed: list[str] = []
    real_sanitize = EgressGuard.sanitize_text

    def _spy(self: Any, text: str) -> str:
        handed.append(text)
        return real_sanitize(self, text)  # type: ignore[arg-type]

    monkeypatch.setattr(EgressGuard, "sanitize_text", _spy)

    events, fake_agent = await _drive(ctx)

    assert fake_agent.run.called, "the model call must proceed (nothing leaked)"
    assert not any(e.kind == "egress_blocked" for e in events)
    # The guard was handed the RAW block…
    assert any(HEADING in text and SRC in text for text in handed), (
        "the dossier block never reached sanitize_text — it is being composed "
        "after the egress sweep"
    )
    # …and what actually egressed carries the block's prose but not the address.
    msg = fake_agent.run.call_args[0][0]
    assert HEADING in msg
    assert ROLE_LINE in msg
    assert SRC not in msg
    await engine.dispose()


# =====================================================================
# Budget: paid for out of the enriched context, and clamped
# =====================================================================


@pytest.mark.asyncio
async def test_dossier_cost_is_subtracted_from_the_enriched_budget(
    settings_kratos: Settings,
) -> None:
    """A large dossier must not squeeze real evidence out of the window by
    arriving on top of a budget that was already fully spent."""
    settings_kratos.investigate_when_unsure = False
    settings_kratos.model_context_window_tokens = 40_000
    engine, maker = await _db(settings_kratos)
    await _seed_dossier(maker)
    ctx = _make_ctx(settings_kratos, maker)

    seen: list[int | None] = []
    real_trim = context_budget.trim_enriched_for_budget

    def _spy(enriched: Any, budget: int | None) -> Any:
        seen.append(budget)
        return real_trim(enriched, budget)

    with patch.object(context_budget, "trim_enriched_for_budget", _spy):
        events, _fake_agent = await _drive(ctx)

    block = next(e for e in events if e.kind == "host_dossier").payload["block"]
    full = context_budget.input_budget_tokens(40_000)
    assert full is not None
    # The timeline event carries the STRIPPED block; the budget is charged for
    # what the prompt actually carries, which the wrapper blank-line-prefixes.
    # Compare against the same string, or the chars/4 estimate lands a token out
    # whenever the block length happens to sit near a bucket boundary.
    assert seen == [full - context_budget.estimate_tokens("\n\n" + block)]
    await engine.dispose()


@pytest.mark.asyncio
async def test_budget_subtraction_is_clamped_to_a_floor(settings_kratos: Settings) -> None:
    """``trim_enriched_for_budget`` grinds every pivot to two events and STILL
    returns an over-budget string, so an unclamped subtraction buys nothing and
    costs the whole correlation signal."""
    from soc_ai.agent.orchestrator import _MIN_ENRICHED_BUDGET

    settings_kratos.investigate_when_unsure = False
    settings_kratos.model_context_window_tokens = 1_200  # tiny window, big dossier
    engine, maker = await _db(settings_kratos)
    await _seed_dossier(maker)
    ctx = _make_ctx(settings_kratos, maker)

    seen: list[int | None] = []
    real_trim = context_budget.trim_enriched_for_budget

    def _spy(enriched: Any, budget: int | None) -> Any:
        seen.append(budget)
        return real_trim(enriched, budget)

    with patch.object(context_budget, "trim_enriched_for_budget", _spy):
        await _drive(ctx)

    assert seen == [_MIN_ENRICHED_BUDGET]
    await engine.dispose()


@pytest.mark.asyncio
async def test_unknown_model_window_still_disables_trimming(settings_kratos: Settings) -> None:
    """Window discovery is best-effort. An unknown window means "no accounting",
    and subtracting a dossier cost from ``None`` must not invent a budget."""
    settings_kratos.investigate_when_unsure = False
    engine, maker = await _db(settings_kratos)
    await _seed_dossier(maker)
    ctx = _make_ctx(settings_kratos, maker)

    seen: list[int | None] = []
    real_trim = context_budget.trim_enriched_for_budget

    def _spy(enriched: Any, budget: int | None) -> Any:
        seen.append(budget)
        return real_trim(enriched, budget)

    with (
        patch.object(context_budget, "resolve_model_window", AsyncMock(return_value=None)),
        patch.object(context_budget, "trim_enriched_for_budget", _spy),
    ):
        await _drive(ctx)

    assert seen == [None]
    await engine.dispose()


# =====================================================================
# The composition helper
# =====================================================================


def test_inject_places_the_block_ahead_of_its_anchor() -> None:
    from soc_ai.agent.orchestrator import _inject_dossier_block

    out = _inject_dossier_block("head\n\n## Enriched alert context\n\nbody", "\n\nDOSSIER")
    assert out == "head\n\nDOSSIER\n\n## Enriched alert context\n\nbody"


def test_inject_uses_the_transcript_anchor_when_there_is_no_enriched_section() -> None:
    """The post-loop synthesizer message has no enriched-context section — the
    dossier goes ahead of the transcript, not after "produce the report now"."""
    from soc_ai.agent.orchestrator import _inject_dossier_block

    out = _inject_dossier_block("prior\n\n## Investigation transcript\n\nbody", "\n\nDOSSIER")
    assert out == "prior\n\nDOSSIER\n\n## Investigation transcript\n\nbody"


def test_inject_appends_when_no_anchor_is_present() -> None:
    """A prompt shape that grows a new heading must degrade to "at the end",
    never to "dropped"."""
    from soc_ai.agent.orchestrator import _inject_dossier_block

    assert _inject_dossier_block("no anchor here", "\n\nDOSSIER") == "no anchor here\n\nDOSSIER"


def test_inject_is_a_no_op_for_an_empty_block() -> None:
    from soc_ai.agent.orchestrator import _inject_dossier_block

    msg = "head\n\n## Enriched alert context\n\nbody"
    assert _inject_dossier_block(msg, "") == msg


def test_dossier_hosts_keeps_source_first_and_dedups(settings_kratos: Settings) -> None:
    """Order is the caller's, so the source host reads first; a host that is both
    endpoints is described once, not twice."""
    from soc_ai.agent.orchestrator import dossier_hosts_for_alert

    both = EnrichedAlertContext(alert=SoAlert(id="a", source_ip=SRC, destination_ip=DST))
    assert dossier_hosts_for_alert(both, settings_kratos) == {
        SRC: "source",
        DST: "destination",
    }
    same = EnrichedAlertContext(alert=SoAlert(id="a", source_ip=SRC, destination_ip=SRC))
    assert dossier_hosts_for_alert(same, settings_kratos) == {SRC: "source"}
    bare = EnrichedAlertContext(alert=SoAlert(id="a"))
    assert dossier_hosts_for_alert(bare, settings_kratos) == {}


# =====================================================================
# Widening: every internal host the alert's group events name
# =====================================================================


def _peer(n: int, *, src: str, dst: str) -> SoAlert:
    return SoAlert(id=f"e{n}", source_ip=src, destination_ip=dst)


def test_dossier_hosts_widens_to_the_groups_internal_ips(settings_kratos: Settings) -> None:
    """The endpoints are two of the hosts in an alert, not all of them.

    The motivating incident's real actor was a VM one pivot away from the
    address the alert named — visible in the prefetched pivot events all along.
    Source and destination still read first (the renderer's order is ours), and
    the group's addresses follow in the order the pivots carry them.
    """
    from soc_ai.agent.orchestrator import dossier_hosts_for_alert

    context = EnrichedAlertContext(
        alert=SoAlert(id="a", source_ip=SRC, destination_ip=DST),
        community_id_events=[_peer(1, src="192.168.10.30", dst=SRC)],
        host_events=[_peer(2, src=SRC, dst="192.168.10.31")],
    )
    hosts = dossier_hosts_for_alert(context, settings_kratos)

    assert list(hosts) == [SRC, DST, "192.168.10.30", "192.168.10.31"]
    assert hosts["192.168.10.30"] == "related event"


def test_dossier_hosts_leaves_external_group_ips_out(settings_kratos: Settings) -> None:
    """An external peer in a pivot event has no dossier and never will.

    The alert's OWN destination is different: it is named whether it is internal
    or not, because "the network sweep has no record of this address" is a
    statement the block owes the model about the host under discussion.
    """
    from soc_ai.agent.orchestrator import dossier_hosts_for_alert

    context = EnrichedAlertContext(
        alert=SoAlert(id="a", source_ip=SRC, destination_ip=DST),
        user_events=[_peer(1, src="203.0.113.7", dst="192.168.10.40")],
    )
    hosts = dossier_hosts_for_alert(context, settings_kratos)

    assert "203.0.113.7" not in hosts
    assert hosts == {SRC: "source", DST: "destination", "192.168.10.40": "related event"}


@pytest.mark.asyncio
async def test_wide_group_is_bounded_at_eight_hosts_and_says_how_many_it_dropped(
    settings_kratos: Settings,
) -> None:
    """Bounded, and NOT silently: the prompt carries eight hosts and states the
    remainder, because a list that just stops reads as "that was all of them"."""
    from soc_ai.agent.orchestrator import dossier_hosts_for_alert
    from soc_ai.dossier.prompt import host_dossier_prompt_block

    settings_kratos.investigate_when_unsure = False
    engine, maker = await _db(settings_kratos)
    await _seed_dossier(maker)
    ctx = _make_ctx(settings_kratos, maker)

    # 12 hosts in play: the two endpoints plus ten internal peers.
    peers = [f"192.168.10.{n}" for n in range(11, 21)]
    context = EnrichedAlertContext(
        alert=SoAlert(id="a", source_ip=SRC, destination_ip=DST),
        community_id_events=[_peer(i, src=ip, dst=SRC) for i, ip in enumerate(peers)],
    )
    hosts = dossier_hosts_for_alert(context, settings_kratos)
    assert len(hosts) == 12

    block = await host_dossier_prompt_block(hosts, ctx=ctx)

    assert SRC in block and DST in block
    assert "192.168.10.16" in block, "the eighth host should be described"
    assert "192.168.10.17" not in block, "the ninth host is past the cap"
    assert "+4 more hosts omitted" in block
    await engine.dispose()
