"""Tests for the chat-manager verdict-proposal meta contract.

End-to-end testing of _run_turn against a live pydantic-ai agent mock would
require constructing fake RunResult objects that match the installed pydantic-ai
version's internal message structure — too brittle and version-sensitive. Instead
these tests pin the meta shape that _run_turn MUST produce (Task 7 contract) and
the _extract_tool_evidence helper logic, exercising the Task-6 validator integration
that the FE and resolve endpoint depend on.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from soc_ai.agent.proposal_validation import Proposal, validate_proposal
from soc_ai.webui.chat_manager import _extract_tool_evidence, _extract_tools, _run_turn


def test_verdict_proposal_meta_contract() -> None:
    proposal = Proposal(
        verdict="true_positive",
        confidence=0.8,
        rationale="C2 confirmed",
        citations=["enrich_indicator"],
        recommended_actions=[],
    )
    evidence = [{"tool": "enrich_indicator", "result": "1.2.3.4 malicious"}]
    v = validate_proposal(proposal, tool_evidence=evidence)
    meta = {
        "kind": "verdict_proposal",
        "validation": "pass" if v.ok else "fail",
        "objection": v.objection,
        "token": "deterministic-in-test",
        "proposal": {
            "verdict": proposal.verdict,
            "confidence": proposal.confidence,
            "rationale": proposal.rationale,
            "citations": proposal.citations,
            "recommended_actions": proposal.recommended_actions,
        },
    }
    assert meta["kind"] == "verdict_proposal"
    assert meta["validation"] == "pass"
    assert meta["proposal"]["verdict"] == "true_positive"


def test_verdict_proposal_meta_contract_fp_fail() -> None:
    """Proposal with no grounded citations produces a fail validation."""
    proposal = Proposal(
        verdict="false_positive",
        confidence=0.9,
        rationale="nothing malicious seen",
        citations=["alert.rule_name"],  # self-referential, not evidence
        recommended_actions=[],
    )
    evidence: list[dict] = []  # no tool calls at all
    v = validate_proposal(proposal, tool_evidence=evidence)
    meta = {
        "kind": "verdict_proposal",
        "validation": "pass" if v.ok else "fail",
        "objection": v.objection,
        "proposal": {
            "verdict": proposal.verdict,
            "confidence": proposal.confidence,
            "rationale": proposal.rationale,
            "citations": proposal.citations,
            "recommended_actions": proposal.recommended_actions,
        },
    }
    assert meta["validation"] == "fail"
    assert meta["objection"] is not None
    assert meta["proposal"]["verdict"] == "false_positive"


def test_extract_tool_evidence_excludes_propose_verdict() -> None:
    """_extract_tool_evidence must not include propose_verdict in evidence."""
    from pydantic_ai.messages import ToolReturnPart

    class _FakePart:
        def __init__(self, type_name: str, tool_name: str, content: str) -> None:
            self._type_name = type_name
            self.tool_name = tool_name
            self.content = content

        def __class_getitem__(cls, item):  # type: ignore[override]
            return cls

    class _FakeMsg:
        def __init__(self, parts: list) -> None:
            self.parts = parts

    class _FakeResult:
        def all_messages(self):  # type: ignore[override]
            # Build real ToolReturnPart instances so type().__name__ == "ToolReturnPart"
            enrich_part = ToolReturnPart(
                tool_name="t_enrich_ip",
                content="1.2.3.4 is malicious",
                tool_call_id="tc-1",
            )
            propose_part = ToolReturnPart(
                tool_name="propose_verdict",
                content="Proposal recorded.",
                tool_call_id="tc-2",
            )

            class Msg:
                def __init__(self, parts):
                    self.parts = parts

            return [Msg([enrich_part, propose_part])]

    result = _FakeResult()
    evidence = _extract_tool_evidence(result)
    tool_names = [e["tool"] for e in evidence]
    assert "propose_verdict" not in tool_names
    assert "t_enrich_ip" in tool_names
    assert len(evidence) == 1
    assert evidence[0]["result"] == "1.2.3.4 is malicious"


def test_extract_tools_ignores_return_parts() -> None:
    """_extract_tools only captures ToolCallPart names, not ToolReturnPart."""
    from pydantic_ai.messages import ToolCallPart

    class Msg:
        def __init__(self, parts):
            self.parts = parts

    class FakeResult:
        def all_messages(self):
            call_part = ToolCallPart(
                tool_name="t_query_events_oql",
                args='{"query": "test"}',
                tool_call_id="tc-1",
            )

            class ReturnPartMimic:
                # Deliberately NOT a ToolCallPart — _extract_tools must skip it
                pass

            return [Msg([call_part, ReturnPartMimic()])]

    result = FakeResult()
    names = _extract_tools(result)
    assert names == ["t_query_events_oql"]


# ---------------------------------------------------------------------------
# BUG #10 — error-path guard + timeout
# ---------------------------------------------------------------------------


def _make_state(*, finish_side_effect: Any = None) -> MagicMock:
    """Build a minimal fake app state for _run_turn tests."""
    settings = MagicMock()
    # A bare MagicMock auto-returns a truthy attr for soc_ai_demo, which would
    # fire the demo canned-reply short-circuit in _run_turn and bypass the live
    # path these tests exercise. Real Settings default soc_ai_demo=False.
    settings.soc_ai_demo = False
    settings.analyst_model = "test-model"
    settings.chat_turn_timeout_s = 180

    # inv_svc.get_with_events returns (inv, events)
    inv = MagicMock()
    inv.id = "inv-test"
    inv.alert_es_id = "es-test"
    inv.rule_name = "ET TEST"
    inv.src_ip = "10.0.0.1"
    inv.dest_ip = "10.0.0.2"
    inv.verdict = "false_positive"
    inv.confidence = 0.9
    inv.rationale = "benign"
    inv.summary = ""

    finish_mock = AsyncMock(side_effect=finish_side_effect)

    db = AsyncMock()
    db_cm = MagicMock()
    db_cm.__aenter__ = AsyncMock(return_value=db)
    db_cm.__aexit__ = AsyncMock(return_value=False)

    state = MagicMock()
    state.settings = settings
    state.db_sessionmaker = MagicMock(return_value=db_cm)

    return state, inv, finish_mock


def test_run_turn_agent_error_persists_error_row() -> None:
    """BUG #10(a): when the chat agent raises, an error assistant message is
    persisted with status='error' and pending clears (no exception escapes)."""

    inv = MagicMock()
    inv.id = "inv-err"
    inv.alert_es_id = "es-err"
    inv.rule_name = "ET FAIL"
    inv.src_ip = "10.0.0.1"
    inv.dest_ip = "10.0.0.2"
    inv.verdict = "false_positive"
    inv.confidence = 0.8
    inv.rationale = "benign"
    inv.summary = ""

    finish_mock = AsyncMock()

    db = AsyncMock()
    db_cm = MagicMock()
    db_cm.__aenter__ = AsyncMock(return_value=db)
    db_cm.__aexit__ = AsyncMock(return_value=False)

    settings = MagicMock()
    # A bare MagicMock auto-returns a truthy attr for soc_ai_demo, which would
    # fire the demo canned-reply short-circuit in _run_turn and bypass the live
    # path these tests exercise. Real Settings default soc_ai_demo=False.
    settings.soc_ai_demo = False
    settings.analyst_model = "test-model"
    settings.chat_turn_timeout_s = 180

    state = MagicMock()
    state.settings = settings
    state.db_sessionmaker = MagicMock(return_value=db_cm)

    _get_with_events = AsyncMock(return_value=(inv, []))
    _history = AsyncMock(return_value=[("user", "hello")])
    _alert_ctx = AsyncMock(side_effect=RuntimeError("ES down"))

    with (
        patch("soc_ai.webui.chat_manager.inv_svc.get_with_events", _get_with_events),
        patch("soc_ai.webui.chat_manager.chat_svc.history_for_agent", _history),
        patch("soc_ai.webui.chat_manager.get_alert_context", _alert_ctx),
        patch("soc_ai.webui.chat_manager.build_chat_agent") as mock_build,
        patch("soc_ai.webui.chat_manager.chat_svc.finish_assistant", finish_mock),
        patch("soc_ai.webui.chat_manager.build_investigator_model", MagicMock()),
    ):
        # Agent.run raises → should trigger the error path
        agent_mock = MagicMock()
        agent_mock.run = AsyncMock(side_effect=RuntimeError("LLM gateway exploded"))
        mock_build.return_value = agent_mock

        asyncio.run(_run_turn(state, "inv-err", 42))

    # finish_assistant called once with status="error"
    finish_mock.assert_called_once()
    # finish_assistant(db, assistant_msg_id, content=..., status=..., meta=...)
    assert finish_mock.call_args.kwargs.get("status") == "error"


def test_run_turn_error_write_failure_is_logged_not_propagated(caplog: Any) -> None:
    """BUG #10(b): if finish_assistant raises in the error path, the exception
    is logged (not propagated) so the background task doesn't die silently."""

    inv = MagicMock()
    inv.id = "inv-dberr"
    inv.alert_es_id = "es-dberr"
    inv.rule_name = "ET DBERR"
    inv.src_ip = "10.0.0.1"
    inv.dest_ip = "10.0.0.2"
    inv.verdict = "false_positive"
    inv.confidence = 0.8
    inv.rationale = "benign"
    inv.summary = ""

    # First call (error path) raises; there's only one call here since the
    # agent itself raises before the success-path finish_assistant.
    finish_mock = AsyncMock(side_effect=RuntimeError("DB went away"))

    db = AsyncMock()
    db_cm = MagicMock()
    db_cm.__aenter__ = AsyncMock(return_value=db)
    db_cm.__aexit__ = AsyncMock(return_value=False)

    settings = MagicMock()
    # A bare MagicMock auto-returns a truthy attr for soc_ai_demo, which would
    # fire the demo canned-reply short-circuit in _run_turn and bypass the live
    # path these tests exercise. Real Settings default soc_ai_demo=False.
    settings.soc_ai_demo = False
    settings.analyst_model = "test-model"
    settings.chat_turn_timeout_s = 180

    state = MagicMock()
    state.settings = settings
    state.db_sessionmaker = MagicMock(return_value=db_cm)

    _get_with_events2 = AsyncMock(return_value=(inv, []))
    _history2 = AsyncMock(return_value=[("user", "hello")])
    _alert_ctx2 = AsyncMock(side_effect=RuntimeError("ES down"))

    with (
        caplog.at_level(logging.ERROR, logger="soc_ai.webui.chat_manager"),
        patch("soc_ai.webui.chat_manager.inv_svc.get_with_events", _get_with_events2),
        patch("soc_ai.webui.chat_manager.chat_svc.history_for_agent", _history2),
        patch("soc_ai.webui.chat_manager.get_alert_context", _alert_ctx2),
        patch("soc_ai.webui.chat_manager.build_chat_agent") as mock_build,
        patch("soc_ai.webui.chat_manager.chat_svc.finish_assistant", finish_mock),
        patch("soc_ai.webui.chat_manager.build_investigator_model", MagicMock()),
    ):
        agent_mock = MagicMock()
        agent_mock.run = AsyncMock(side_effect=RuntimeError("LLM gateway exploded"))
        mock_build.return_value = agent_mock

        # Must not raise — the secondary DB error should be swallowed + logged
        asyncio.run(_run_turn(state, "inv-dberr", 99))

    # The secondary failure must be logged
    log_messages = [r.message for r in caplog.records]
    assert any("FAILED to persist error row" in m and "99" in m for m in log_messages), (
        f"Expected 'FAILED to persist error row for msg=99' in logs; got: {log_messages}"
    )


# ---------------------------------------------------------------------------
# Catchable timeout: a turn that exceeds chat_turn_timeout_s resolves to a
# terminal error row (NOT stuck pending) with a user-facing message.
# ---------------------------------------------------------------------------


def test_run_turn_timeout_persists_user_facing_error_row() -> None:
    """A turn whose agent.run exceeds chat_turn_timeout_s must resolve the
    assistant row to status='error' with a user-facing, actionable message —
    NOT leave it stuck pending. We use a tiny timeout and a slow agent.run.

    This is the regression guard for the wait_for-cancellation root cause:
    `asyncio.timeout` raises TimeoutError (a normal Exception), so the error
    path runs; the old `wait_for` wrapper raised CancelledError (BaseException),
    which the except never caught.
    """

    inv = MagicMock()
    inv.id = "inv-slow"
    inv.alert_es_id = "es-slow"
    inv.rule_name = "ET SLOW"
    inv.src_ip = "10.0.0.1"
    inv.dest_ip = "10.0.0.2"
    inv.verdict = "false_positive"
    inv.confidence = 0.8
    inv.rationale = "benign"
    inv.summary = ""

    finish_mock = AsyncMock()

    db = AsyncMock()
    db_cm = MagicMock()
    db_cm.__aenter__ = AsyncMock(return_value=db)
    db_cm.__aexit__ = AsyncMock(return_value=False)

    settings = MagicMock()
    # A bare MagicMock auto-returns a truthy attr for soc_ai_demo, which would
    # fire the demo canned-reply short-circuit in _run_turn and bypass the live
    # path these tests exercise. Real Settings default soc_ai_demo=False.
    settings.soc_ai_demo = False
    settings.analyst_model = "test-model"
    settings.chat_turn_timeout_s = 0.01  # tiny → fires immediately

    state = MagicMock()
    state.settings = settings
    state.db_sessionmaker = MagicMock(return_value=db_cm)

    _get_with_events = AsyncMock(return_value=(inv, []))
    _history = AsyncMock(return_value=[("user", "hello")])
    _alert_ctx = AsyncMock(side_effect=RuntimeError("ES down"))

    async def _slow_run(_prompt: str) -> Any:
        await asyncio.sleep(5)  # far longer than the 0.01s timeout

    with (
        patch("soc_ai.webui.chat_manager.inv_svc.get_with_events", _get_with_events),
        patch("soc_ai.webui.chat_manager.chat_svc.history_for_agent", _history),
        patch("soc_ai.webui.chat_manager.get_alert_context", _alert_ctx),
        patch("soc_ai.webui.chat_manager.build_chat_agent") as mock_build,
        patch("soc_ai.webui.chat_manager.chat_svc.finish_assistant", finish_mock),
        patch("soc_ai.webui.chat_manager.build_investigator_model", MagicMock()),
    ):
        agent_mock = MagicMock()
        agent_mock.run = AsyncMock(side_effect=_slow_run)
        mock_build.return_value = agent_mock

        # Must NOT raise (no CancelledError escapes) and must finish promptly.
        asyncio.run(_run_turn(state, "inv-slow", 7))

    finish_mock.assert_called_once()
    assert finish_mock.call_args.kwargs.get("status") == "error"
    content = finish_mock.call_args.kwargs.get("content", "")
    # User-facing + actionable, with the real seconds substituted in.
    assert "ran out of time" in content
    assert "0.01" in content
    assert "narrower" in content


def test_run_turn_timeout_error_passthrough() -> None:
    """When agent.run itself raises TimeoutError (the asyncio.timeout deadline
    surfaces here), the timeout branch — not the generic-exception branch —
    fires, producing the user-facing 'ran out of time' message."""

    inv = MagicMock()
    inv.id = "inv-to"
    inv.alert_es_id = "es-to"
    inv.rule_name = "ET TO"
    inv.src_ip = "10.0.0.1"
    inv.dest_ip = "10.0.0.2"
    inv.verdict = "false_positive"
    inv.confidence = 0.8
    inv.rationale = "benign"
    inv.summary = ""

    finish_mock = AsyncMock()

    db = AsyncMock()
    db_cm = MagicMock()
    db_cm.__aenter__ = AsyncMock(return_value=db)
    db_cm.__aexit__ = AsyncMock(return_value=False)

    settings = MagicMock()
    # A bare MagicMock auto-returns a truthy attr for soc_ai_demo, which would
    # fire the demo canned-reply short-circuit in _run_turn and bypass the live
    # path these tests exercise. Real Settings default soc_ai_demo=False.
    settings.soc_ai_demo = False
    settings.analyst_model = "test-model"
    settings.chat_turn_timeout_s = 42

    state = MagicMock()
    state.settings = settings
    state.db_sessionmaker = MagicMock(return_value=db_cm)

    _get_with_events = AsyncMock(return_value=(inv, []))
    _history = AsyncMock(return_value=[("user", "hello")])
    _alert_ctx = AsyncMock(side_effect=RuntimeError("ES down"))

    with (
        patch("soc_ai.webui.chat_manager.inv_svc.get_with_events", _get_with_events),
        patch("soc_ai.webui.chat_manager.chat_svc.history_for_agent", _history),
        patch("soc_ai.webui.chat_manager.get_alert_context", _alert_ctx),
        patch("soc_ai.webui.chat_manager.build_chat_agent") as mock_build,
        patch("soc_ai.webui.chat_manager.chat_svc.finish_assistant", finish_mock),
        patch("soc_ai.webui.chat_manager.build_investigator_model", MagicMock()),
    ):
        agent_mock = MagicMock()
        agent_mock.run = AsyncMock(side_effect=TimeoutError())
        mock_build.return_value = agent_mock

        asyncio.run(_run_turn(state, "inv-to", 8))

    finish_mock.assert_called_once()
    assert finish_mock.call_args.kwargs.get("status") == "error"
    content = finish_mock.call_args.kwargs.get("content", "")
    assert "ran out of time" in content
    assert "42" in content


def test_run_turn_caveats_fabricated_tool_citations_on_zero_tool_turn() -> None:
    """F1: a zero-tool answer that cites tools it never ran ("verified by the
    tools", t_enrich_ip(...)) is force-caveated and marked ungrounded, never
    presented to the analyst as verified evidence."""
    from soc_ai.agent.narrative_grounding import UNVERIFIED_CAVEAT

    captured: dict[str, Any] = {}

    async def _finish(_db: Any, _msg_id: int, *, content: str, status: str, meta: Any) -> None:
        captured["content"] = content
        captured["meta"] = meta

    inv = MagicMock()
    inv.id = "inv-fab"
    inv.alert_es_id = "es-fab"
    inv.rule_name = "ET TEST"
    inv.src_ip = "10.0.0.1"
    inv.dest_ip = "10.0.0.2"
    inv.verdict = "false_positive"
    inv.confidence = 0.9
    inv.rationale = "benign"
    inv.summary = ""

    db = AsyncMock()
    db_cm = MagicMock()
    db_cm.__aenter__ = AsyncMock(return_value=db)
    db_cm.__aexit__ = AsyncMock(return_value=False)
    settings = MagicMock()
    # A bare MagicMock auto-returns a truthy attr for soc_ai_demo, which would
    # fire the demo canned-reply short-circuit in _run_turn and bypass the live
    # path these tests exercise. Real Settings default soc_ai_demo=False.
    settings.soc_ai_demo = False
    settings.analyst_model = "test-model"
    settings.chat_turn_timeout_s = 180
    state = MagicMock()
    state.settings = settings
    state.db_sessionmaker = MagicMock(return_value=db_cm)

    result = MagicMock()
    result.output = (
        "This is benign. Verified by the tools listed, t_enrich_ip(10.0.0.1) found nothing."
    )

    with (
        patch(
            "soc_ai.webui.chat_manager.inv_svc.get_with_events", AsyncMock(return_value=(inv, []))
        ),
        patch(
            "soc_ai.webui.chat_manager.chat_svc.history_for_agent",
            AsyncMock(return_value=[("user", "why fp?")]),
        ),
        patch("soc_ai.webui.chat_manager.get_alert_context", AsyncMock(return_value=MagicMock())),
        patch(
            "soc_ai.webui.chat_manager.check_narrative_grounding",
            return_value=MagicMock(grounded=True),
        ),
        patch("soc_ai.webui.chat_manager.build_chat_agent") as mock_build,
        patch(
            "soc_ai.webui.chat_manager.chat_svc.finish_assistant", AsyncMock(side_effect=_finish)
        ),
        patch("soc_ai.webui.chat_manager.build_investigator_model", MagicMock()),
        patch("soc_ai.webui.chat_manager._extract_tools", return_value=[]),
        patch("soc_ai.webui.chat_manager._extract_tool_evidence", return_value=[]),
    ):
        agent_mock = MagicMock()
        agent_mock.run = AsyncMock(return_value=result)
        mock_build.return_value = agent_mock
        asyncio.run(_run_turn(state, "inv-fab", 7))

    assert captured["meta"]["tools"] == []
    assert captured["meta"]["narrative_grounding"]["grounded"] is False
    assert UNVERIFIED_CAVEAT in captured["content"]


# ---------------------------------------------------------------------------
# U4: online-enrichment tool registration is gated by the master egress toggle
# ---------------------------------------------------------------------------


def test_chat_online_tools_gated_by_master_toggle(settings_kratos: Any) -> None:
    """t_greynoise/t_shodan_*/t_cve_lookup are only registered on the chat
    agent when allow_online_enrichment is on — an OFF toggle must not leave
    tools that answer 'skipped (online enrichment off)' for the model to
    waste a call on."""
    from pydantic_ai.models.test import TestModel
    from soc_ai.agent.chat_agent import build_chat_agent
    from soc_ai.agent.orchestrator import InvestigationContext

    online = {"t_greynoise", "t_shodan_internetdb", "t_shodan_host", "t_cve_lookup"}

    def _tool_names(settings: Any) -> set[str]:
        ctx = InvestigationContext(settings=settings, auth=AsyncMock(), elastic=AsyncMock())
        agent = build_chat_agent(TestModel(call_tools=[]), ctx, system_prompt="chat")
        return set(agent._function_toolset.tools.keys())  # type: ignore[attr-defined]

    assert settings_kratos.allow_online_enrichment is False  # fixture default
    names_off = _tool_names(settings_kratos)
    assert not (online & names_off), sorted(online & names_off)
    assert "t_query_events_oql" in names_off  # core read surface unaffected

    settings_on = settings_kratos.model_copy(update={"allow_online_enrichment": True})
    names_on = _tool_names(settings_on)
    assert online <= names_on, sorted(online - names_on)
