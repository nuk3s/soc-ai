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
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from soc_ai.agent.proposal_validation import Proposal, validate_proposal
from soc_ai.webui.chat_manager import _run_turn
from soc_ai.webui.chat_turn import _extract_tool_evidence, _extract_tools


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
        patch("soc_ai.webui.chat_turn.build_investigator_model", MagicMock()),
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


def test_run_turn_error_content_is_scrubbed_before_persisting() -> None:
    """F75: the catch-all handler stringifies the raised exception into the
    persisted (and later analyst-rendered) error content. If that exception's
    message happens to embed a credential-shaped substring (e.g. a verbose
    gateway/provider error body echoing an Authorization header), it must be
    scrubbed the same way probes.py's ``_scrub`` protects other user-facing
    error surfaces — not stored/rendered verbatim."""

    inv = MagicMock()
    inv.id = "inv-secret"
    inv.alert_es_id = "es-secret"
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
    settings.soc_ai_demo = False
    settings.analyst_model = "test-model"
    settings.chat_turn_timeout_s = 180

    state = MagicMock()
    state.settings = settings
    state.db_sessionmaker = MagicMock(return_value=db_cm)

    _get_with_events = AsyncMock(return_value=(inv, []))
    _history = AsyncMock(return_value=[("user", "hello")])
    _alert_ctx = AsyncMock(side_effect=RuntimeError("ES down"))

    secret_token = "sk-live-abc123SECRET"  # pragma: allowlist secret

    with (
        patch("soc_ai.webui.chat_manager.inv_svc.get_with_events", _get_with_events),
        patch("soc_ai.webui.chat_manager.chat_svc.history_for_agent", _history),
        patch("soc_ai.webui.chat_manager.get_alert_context", _alert_ctx),
        patch("soc_ai.webui.chat_manager.build_chat_agent") as mock_build,
        patch("soc_ai.webui.chat_manager.chat_svc.finish_assistant", finish_mock),
        patch("soc_ai.webui.chat_turn.build_investigator_model", MagicMock()),
    ):
        agent_mock = MagicMock()
        agent_mock.run = AsyncMock(
            side_effect=RuntimeError(f"gateway 401: Authorization: Bearer {secret_token}")
        )
        mock_build.return_value = agent_mock

        asyncio.run(_run_turn(state, "inv-secret", 42))

    finish_mock.assert_called_once()
    content = finish_mock.call_args.kwargs.get("content", "")
    assert secret_token not in content
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
        patch("soc_ai.webui.chat_turn.build_investigator_model", MagicMock()),
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
        patch("soc_ai.webui.chat_turn.build_investigator_model", MagicMock()),
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
        patch("soc_ai.webui.chat_turn.build_investigator_model", MagicMock()),
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
            "soc_ai.webui.chat_turn.check_narrative_grounding",
            return_value=MagicMock(grounded=True),
        ),
        patch("soc_ai.webui.chat_manager.build_chat_agent") as mock_build,
        patch(
            "soc_ai.webui.chat_manager.chat_svc.finish_assistant", AsyncMock(side_effect=_finish)
        ),
        patch("soc_ai.webui.chat_turn.build_investigator_model", MagicMock()),
        patch("soc_ai.webui.chat_turn._extract_tools", return_value=[]),
        patch("soc_ai.webui.chat_turn._extract_tool_evidence", return_value=[]),
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


def test_run_turn_scopes_caveat_when_tools_ran() -> None:
    """A turn that RAN tools but asserted an ungrounded artifact gets the
    scoped caveat naming the suspect claim — the blanket 'not backed by a tool
    result' under a real tool-call footer read as a contradiction (dogfood
    2026-07-15)."""
    from soc_ai.agent.narrative_grounding import UNVERIFIED_CAVEAT

    captured: dict[str, Any] = {}

    async def _finish(_db: Any, _msg_id: int, *, content: str, status: str, meta: Any) -> None:
        captured["content"] = content
        captured["meta"] = meta

    inv = MagicMock()
    inv.id = "inv-scoped"
    inv.alert_es_id = "es-scoped"
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
    settings.soc_ai_demo = False
    settings.analyst_model = "test-model"
    settings.chat_turn_timeout_s = 180
    state = MagicMock()
    state.settings = settings
    state.db_sessionmaker = MagicMock(return_value=db_cm)

    result = MagicMock()
    result.output = "The host also resolved ad.local repeatedly."

    grounding = MagicMock(grounded=False, ungrounded=["ad.local"], reason="ungrounded")
    with (
        patch(
            "soc_ai.webui.chat_manager.inv_svc.get_with_events", AsyncMock(return_value=(inv, []))
        ),
        patch(
            "soc_ai.webui.chat_manager.chat_svc.history_for_agent",
            AsyncMock(return_value=[("user", "anything else?")]),
        ),
        patch("soc_ai.webui.chat_manager.get_alert_context", AsyncMock(return_value=MagicMock())),
        patch("soc_ai.webui.chat_turn.check_narrative_grounding", return_value=grounding),
        patch("soc_ai.webui.chat_manager.build_chat_agent") as mock_build,
        patch(
            "soc_ai.webui.chat_manager.chat_svc.finish_assistant", AsyncMock(side_effect=_finish)
        ),
        patch("soc_ai.webui.chat_turn.build_investigator_model", MagicMock()),
        patch("soc_ai.webui.chat_turn._extract_tools", return_value=["t_query_events_oql"]),
        patch(
            "soc_ai.webui.chat_turn._extract_tool_evidence",
            return_value=[{"tool": "t_query_events_oql", "result": "127 matches"}],
        ),
    ):
        agent_mock = MagicMock()
        agent_mock.run = AsyncMock(return_value=result)
        mock_build.return_value = agent_mock
        asyncio.run(_run_turn(state, "inv-scoped", 9))

    assert captured["meta"]["narrative_grounding"]["grounded"] is False
    assert "ad.local" in captured["content"]
    assert "Partially unverified" in captured["content"]
    assert UNVERIFIED_CAVEAT not in captured["content"]


# ── The alert's hosts, seeded as identity — and therefore as grounding ───────
#
# ``seed_context`` is not just the prompt's anchor: it is the corpus
# ``check_narrative_grounding`` grades the answer against. Putting the dossier
# there is what makes "pve01 is the hypervisor" a GROUNDED sentence instead of
# one that ships under an ⚠ Unverified caveat — the same reason the general
# chat seeds the grid's identifiers.

CHAT_SRC = "192.168.10.202"
CHAT_PEER = "192.168.10.30"
CHAT_DST = "8.8.8.8"
CHAT_HOSTNAME = "pve-01"


async def _seeded_state(settings: Any) -> tuple[Any, Any]:
    """(engine, state) on a scratch DB holding one built host."""
    from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

    from tests.test_dossier_orchestrator import _seed_dossier

    engine = make_engine(settings)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    # A hyphenated name on purpose: the grounding checker's hostname pattern
    # wants one, so seeding `pve01` would make the grounded assertion vacuous.
    await _seed_dossier(maker, CHAT_SRC, hostname=CHAT_HOSTNAME)

    state = SimpleNamespace(
        settings=settings,
        db_sessionmaker=maker,
        auth=AsyncMock(),
        elastic=AsyncMock(),
        misp=None,
        audit=None,
        enrichment=SimpleNamespace(blocklist=None, maxmind=None, cloud=None),
    )
    return engine, state


def _chat_investigation() -> Any:
    inv = MagicMock()
    inv.id = "inv-dossier"
    inv.alert_es_id = "es-1"
    inv.rule_name = "ET INFO Session Traffic"
    inv.src_ip = CHAT_SRC
    inv.dest_ip = CHAT_DST
    inv.verdict = "false_positive"
    inv.confidence = 0.8
    inv.rationale = "routine management traffic"
    inv.summary = ""
    return inv


async def _chat_seed_context(state: Any) -> str:
    """The seed ``_investigation_spec`` composes for one investigation."""
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext
    from soc_ai.webui.chat_manager import _investigation_spec

    alert_context = EnrichedAlertContext(
        alert=SoAlert(id="es-1", rule_name="ET INFO", source_ip=CHAT_SRC, destination_ip=CHAT_DST),
        community_id_events=[SoAlert(id="e1", source_ip=CHAT_PEER, destination_ip=CHAT_SRC)],
    )
    with (
        patch(
            "soc_ai.webui.chat_manager.inv_svc.get_with_events",
            AsyncMock(return_value=(_chat_investigation(), [])),
        ),
        patch(
            "soc_ai.webui.chat_manager.chat_svc.history_for_agent",
            AsyncMock(return_value=[("user", "is that host allowed to answer SSH?")]),
        ),
        patch(
            "soc_ai.webui.chat_manager.get_alert_context",
            AsyncMock(return_value=alert_context),
        ),
    ):
        inputs = await _investigation_spec(state, "inv-dossier", 1).prepare()
    assert inputs is not None
    return inputs.seed_context


def test_chat_seed_carries_the_alerts_host_identities(settings_kratos: Any) -> None:
    from soc_ai.dossier.prompt import HEADING

    async def _go() -> str:
        engine, state = await _seeded_state(settings_kratos)
        try:
            return await _chat_seed_context(state)
        finally:
            await engine.dispose()

    seed = asyncio.run(_go())
    assert HEADING in seed
    assert "role: hypervisor" in seed
    assert CHAT_HOSTNAME in seed
    # The alert's own verdict is still the head of the block, not displaced.
    assert seed.startswith("Alert: ")
    # …and the widening reaches the group's peer, not just the two endpoints.
    assert CHAT_PEER in seed


def test_chat_seed_grounds_an_answer_that_names_the_host(settings_kratos: Any) -> None:
    """The payoff, and the reason the block goes in seed_context rather than
    straight into the system prompt: ``check_narrative_grounding`` grades the
    answer against seed_context, so naming the host correctly becomes a GROUNDED
    sentence instead of one that ships wearing an ⚠ Unverified caveat."""
    from soc_ai.agent.narrative_grounding import check_narrative_grounding
    from soc_ai.dossier.prompt import HEADING

    answer = f"**No.** {CHAT_HOSTNAME} (hypervisor, {CHAT_SRC}) has a policy of no interactive SSH."

    async def _go() -> str:
        engine, state = await _seeded_state(settings_kratos)
        try:
            return await _chat_seed_context(state)
        finally:
            await engine.dispose()

    seed = asyncio.run(_go())
    probe = check_narrative_grounding(answer, seed_context=seed, tool_evidence=[])
    assert probe.grounded, probe.ungrounded
    assert probe.ungrounded == [], "the host's own name must not read as a fabrication"

    # Proof the block is what did it: graded against the seed WITHOUT it, the
    # same true sentence is flagged as an invented hostname.
    without_block = seed.split(HEADING)[0]
    assert (
        CHAT_HOSTNAME
        in check_narrative_grounding(
            answer, seed_context=without_block, tool_evidence=[]
        ).ungrounded
    )


def test_chat_seed_has_no_block_when_the_context_switch_is_off(settings_kratos: Any) -> None:
    from soc_ai.dossier.prompt import HEADING

    settings_kratos.dossier_context_enabled = False

    async def _go() -> str:
        engine, state = await _seeded_state(settings_kratos)
        try:
            return await _chat_seed_context(state)
        finally:
            await engine.dispose()

    assert HEADING not in asyncio.run(_go())


def test_chat_seed_block_reaches_the_engines_egress_sweep(settings_kratos: Any) -> None:
    """The chat sites rely on a STRUCTURAL argument — ``run_chat_turn`` is the
    only consumer of ``seed_context`` and it sweeps the composed prompt — so
    lock it by driving the real engine, not by re-doing its composition here.

    Sanitizing inside ``_prepare`` instead would hand the guard a pre-labelled
    string and the block's real addresses would never reach it.
    """
    from soc_ai.agent.egress_guard import EgressGuard
    from soc_ai.dossier.prompt import HEADING
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext
    from soc_ai.webui.chat_manager import _investigation_spec
    from soc_ai.webui.chat_turn import run_chat_turn

    settings_kratos.analyst_cloud_redaction = True
    handed: list[str] = []
    real_sanitize = EgressGuard.sanitize_text

    def _spy(self: Any, text: str) -> str:
        handed.append(text)
        return real_sanitize(self, text)  # type: ignore[arg-type]

    alert_context = EnrichedAlertContext(
        alert=SoAlert(id="es-1", rule_name="ET INFO", source_ip=CHAT_SRC, destination_ip=CHAT_DST),
        community_id_events=[SoAlert(id="e1", source_ip=CHAT_PEER, destination_ip=CHAT_SRC)],
    )

    async def _go() -> str:
        engine, state = await _seeded_state(settings_kratos)
        try:
            agent_mock = MagicMock()
            agent_mock.run = AsyncMock(return_value=MagicMock(output="ok", all_messages=list))
            with (
                patch(
                    "soc_ai.webui.chat_manager.inv_svc.get_with_events",
                    AsyncMock(return_value=(_chat_investigation(), [])),
                ),
                patch(
                    "soc_ai.webui.chat_manager.chat_svc.history_for_agent",
                    AsyncMock(return_value=[("user", "is that host allowed to answer SSH?")]),
                ),
                patch(
                    "soc_ai.webui.chat_manager.get_alert_context",
                    AsyncMock(return_value=alert_context),
                ),
                patch("soc_ai.webui.chat_manager.chat_svc.finish_assistant", AsyncMock()),
                patch("soc_ai.webui.chat_manager.chat_svc.set_progress", AsyncMock()),
                patch("soc_ai.webui.chat_turn.build_investigator_model", MagicMock()),
                patch("soc_ai.webui.chat_turn.inventory_prompt_block", AsyncMock(return_value="")),
                patch("soc_ai.webui.chat_manager.build_chat_agent") as mock_build,
                patch.object(EgressGuard, "sanitize_text", _spy),
            ):
                mock_build.return_value = agent_mock
                await run_chat_turn(state, _investigation_spec(state, "inv-dossier", 1))
                return str(mock_build.call_args.kwargs["system_prompt"])
        finally:
            await engine.dispose()

    built_with = asyncio.run(_go())

    # The guard was handed ONE string carrying the system prompt's own header,
    # the dossier block AND the raw address — i.e. the engine composed first and
    # swept the whole thing. Asserting only "the block reached the guard" would
    # also pass if the block were swept on its own before composition.
    assert any(
        "investigation assistant" in text and HEADING in text and CHAT_SRC in text
        for text in handed
    ), "the dossier block was not swept as part of the composed system prompt"
    # The agent was built with the labelled prompt: block prose in, address out.
    assert HEADING in built_with
    assert "role: hypervisor" in built_with
    assert CHAT_SRC not in built_with
