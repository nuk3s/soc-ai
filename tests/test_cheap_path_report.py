"""What the cheap path hands the analyst (review 2026-11-13, D3).

Production, 2026-10-31 to 2026-11-13: 24 of 29 cheap-path runs wrote prompt
talk to the analyst. A summary began "Keep the candidate verdict. I refine
confidence from 0.85 to 0.80." Seven runs offered a comment on a case that did
not exist. No run offered Acknowledge.

The round-1 prompt asked the model to "Keep it, override it, or refine it",
and the model answered in the summary. The prompt named no write tool, so the
model chose ``add_case_comment`` and made up a case id.

Three parts hold the fix. The prompt states a contract for the summary and for
the actions. The cheap class removes the sentences that answer the prompt, and
it offers Acknowledge on a false positive. Every path drops a case comment
when the run can have no case.
"""

from __future__ import annotations

import asyncio
import inspect
import re
from typing import Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.agent import budget
from soc_ai.agent.decision_templates import CandidateVerdict
from soc_ai.agent.prompts import (
    SYNTH_FIRST_SYSTEM_PROMPT,
    SYNTHESIZER_PROMPT,
    build_investigator_prompt,
    build_synth_first_user_message,
)
from soc_ai.agent.triage import RecommendedAction, TriageReport
from soc_ai.config import Settings
from soc_ai.tools import get_tool
from soc_ai.triage_models import drop_case_comments_without_a_case

from tests.test_agent import _make_ctx, _strong_benign_candidate
from tests.test_budget_classes import _drive, _report
from tests.test_needs_you_count import client  # noqa: F401 - the shared fixture

_ALERT = "alert-001"

# The summary of production run 01M78W5CYACJCRB4B8GMFC5936, cut to four sentences.
_PROD_SUMMARY = (
    "Keep the candidate verdict. I refine confidence from 0.85 to 0.80. "
    "The payload bytes match RFC 5389 STUN. "
    "Zeek parsed the flow as spicy_stun and recorded state SF."
)
_PROD_COMMENT = RecommendedAction(
    tool_name="add_case_comment",
    tool_args={"case_id": "alert-6R690aEBLWkWRQIwvfoS", "comment": "STUN exchange confirmed."},
    rationale="The verdict is decisive and the payload plus clean conn provide positive evidence.",
)
_ACK = RecommendedAction(
    tool_name="ack_alert",
    tool_args={"alert_id": _ALERT},
    rationale="The payload is a solicited STUN exchange with a cloud address.",
)
_ESCALATE = RecommendedAction(
    tool_name="escalate_to_case",
    tool_args={"alert_id": _ALERT, "case_title": "t", "case_description": "d"},
    rationale="The beacon matches a known C2 address.",
)
_COMMENT = RecommendedAction(
    tool_name="add_case_comment",
    tool_args={"comment": "The second host shows the same beacon."},
    rationale="The case needs the second host.",
)


def _fp(
    summary: str = "The payload bytes match RFC 5389 STUN. Zeek recorded state SF.",
    actions: list[RecommendedAction] | None = None,
    verdict: str = "false_positive",
) -> TriageReport:
    return TriageReport(
        verdict=verdict,
        confidence=0.8,
        summary=summary,
        citations=["alert.payload_printable"],
        recommended_actions=list(actions or []),
    )


def _settle(report: TriageReport, run_class: str = budget.CHEAP) -> tuple[TriageReport, Any]:
    return budget.settle_report_actions(report, alert_id=_ALERT, run_class=run_class)


def _tools(report: TriageReport) -> list[str]:
    return [a.tool_name for a in report.recommended_actions]


# ── The production shape ────────────────────────────────────────────────────


def test_the_production_run_gets_analyst_text_and_an_acknowledge() -> None:
    settled, audit = _settle(_fp(_PROD_SUMMARY, [_PROD_COMMENT]))
    assert settled.summary == (
        "The payload bytes match RFC 5389 STUN. "
        "Zeek parsed the flow as spicy_stun and recorded state SF."
    )
    assert _tools(settled) == ["ack_alert"]
    ack = settled.recommended_actions[0]
    assert ack.tool_args == {"alert_id": _ALERT}
    # The first reason is the headline of the row. It is the first sentence
    # the analyst can use.
    assert ack.rationale == "The payload bytes match RFC 5389 STUN."
    assert audit == {
        "dropped_case_comments": 1,
        "prompt_talk_removed": 2,
        "ack_added": True,
    }
    # The verdict and the confidence are the model's.
    assert (settled.verdict, settled.confidence) == ("false_positive", 0.8)
    assert settled.citations == ["alert.payload_printable"]


@pytest.mark.parametrize(
    "sentence",
    [
        "Keep the candidate.",
        "Keep the candidate verdict.",
        "I keep the candidate verdict.",
        "I keep the candidate verdict of false_positive.",
        "I refine the candidate verdict.",
        "I adjust the candidate verdict.",
        "I refine confidence from 0.85 to 0.80.",
        "I lower the confidence to 0.7.",
        "I adjust my confidence.",
        "I keep the confidence.",
    ],
)
def test_a_sentence_that_answers_the_prompt_is_removed(sentence: str) -> None:
    settled, audit = _settle(_fp(f"{sentence} The payload is a STUN binding request.", [_ACK]))
    assert settled.summary == "The payload is a STUN binding request."
    assert audit is not None and audit["prompt_talk_removed"] == 1


def test_a_false_positive_with_no_action_offers_acknowledge() -> None:
    settled, audit = _settle(_fp(actions=[]))
    assert _tools(settled) == ["ack_alert"]
    assert settled.recommended_actions[0].tool_args == {"alert_id": _ALERT}
    assert settled.recommended_actions[0].rationale == "The payload bytes match RFC 5389 STUN."
    assert audit == {"dropped_case_comments": 0, "prompt_talk_removed": 0, "ack_added": True}


def test_a_reason_that_answers_the_prompt_takes_the_first_summary_sentence() -> None:
    talk = _ACK.model_copy(update={"rationale": "Keep the candidate verdict."})
    settled, _audit = _settle(_fp(actions=[talk]))
    assert _tools(settled) == ["ack_alert"]
    assert settled.recommended_actions[0].rationale == "The payload bytes match RFC 5389 STUN."


# ── Negative controls ───────────────────────────────────────────────────────


def test_a_report_that_is_already_right_is_not_touched() -> None:
    """NEGATIVE CONTROL. The same object comes back, and nothing is recorded."""
    report = _fp(actions=[_ACK])
    settled, audit = _settle(report)
    assert settled is report
    assert audit is None


@pytest.mark.parametrize(
    "sentence",
    [
        "The host is a candidate for isolation.",
        "The feed lists the domain as a candidate C2 address.",
        "The user agent names a release candidate build of the client.",
        "The keepalive holds the session open.",
        "Confidence in the feed is low because it is three years old.",
        "The server refines the session key after the handshake.",
        "The analyst can override the block on the proxy.",
        "The proxy rejected the candidate certificate of the client.",
        # The review of the lane: each of these went whole, with its evidence.
        "The ICE agent kept the candidate from 10.20.30.20 and sent STUN binding requests to "
        "142.250.82.127:19302.",
        "The browser rejected the candidate and retried through the TURN relay 198.51.100.4.",
        "The peer refined the candidate, then opened UDP 3478 to 203.0.113.44.",
        "The server rejected the candidate certificate from 203.0.113.9.",
        "The verdict is decisive: the payload is a STUN binding request to stun.l.google.com.",
        "Positive evidence exists in conn.log: 62 bytes to 142.250.82.127 on UDP 19302.",
        "I override the candidate because the payload carries a PowerShell download cradle "
        "to 203.0.113.5.",
        "Positive evidence exists: the blocklist returned a hit for 203.0.113.7 on feed urlhaus.",
        "The candidate verdict does not fit: conn.log shows 48 MB sent to 198.51.100.9 on "
        "port 443.",
        "I lower the confidence because host 10.20.30.31 also resolved evil.example 40 times "
        "in 60 seconds.",
        # A form of prompt talk that is not exact stays too. A missed echo
        # costs one odd sentence. A wrong strip costs the evidence.
        "I override the candidate because the payload is benign.",
        "I keep the candidate verdict because zeek.conn shows state SF.",
        "I refine confidence from 0.85 to 0.80 after 3 retries.",
        "The decision template matches this alert.",
        "The verdict is decisive and the clean conn gives positive evidence.",
        "Keep the candidate from 10.20.30.20.",
    ],
)
def test_a_sentence_about_the_evidence_is_kept(sentence: str) -> None:
    """NEGATIVE CONTROL on the path the strip would miss: the same words in a
    sentence about the evidence. The strip takes a whole sentence of an exact
    form, and it never takes a sentence that holds an address, a port, a
    count, a dataset or a record name."""
    report = _fp(f"{sentence} The payload is a STUN binding request.", [_ACK])
    settled, audit = _settle(report)
    assert settled is report
    assert audit is None


def test_a_summary_of_prompt_talk_only_is_kept() -> None:
    """NEGATIVE CONTROL. The analyst never gets an empty summary."""
    report = _fp("Keep the candidate verdict. I refine confidence from 0.85 to 0.80.", [_ACK])
    settled, _audit = _settle(report)
    assert settled.summary == report.summary


def test_the_model_acknowledge_keeps_its_own_reason() -> None:
    settled, _audit = _settle(_fp(_PROD_SUMMARY, [_ACK]))
    assert settled.recommended_actions == [_ACK]


def test_a_standard_run_keeps_its_text_and_gets_no_acknowledge() -> None:
    """NEGATIVE CONTROL. The loop wrote this report. The item is the cheap class."""
    report = _fp(_PROD_SUMMARY, [])
    for run_class in (budget.STANDARD, budget.DEEP, budget.RULE_PRIOR):
        settled, audit = _settle(report, run_class)
        assert settled is report, run_class
        assert audit is None, run_class


@pytest.mark.parametrize("verdict", ["true_positive", "needs_more_info", "inconclusive"])
def test_only_a_false_positive_gets_the_acknowledge(verdict: str) -> None:
    """NEGATIVE CONTROL. No acknowledge is offered on any other verdict."""
    settled, _audit = _settle(_fp(actions=[], verdict=verdict))
    assert _tools(settled) == []


# ── A case comment needs a case, on every path ──────────────────────────────


@pytest.mark.parametrize("run_class", [budget.CHEAP, budget.STANDARD, budget.DEEP])
def test_a_comment_with_no_case_is_dropped_on_every_path(run_class: str) -> None:
    report = _fp(actions=[_ACK, _COMMENT])
    settled, audit = _settle(report, run_class)
    assert settled.recommended_actions == [_ACK]
    assert audit is not None and audit["dropped_case_comments"] == 1


def test_a_true_positive_with_a_lone_comment_loses_it() -> None:
    report = _fp(actions=[_COMMENT], verdict="true_positive")
    settled, audit = _settle(report, budget.STANDARD)
    assert _tools(settled) == []
    assert audit == {"dropped_case_comments": 1, "prompt_talk_removed": 0, "ack_added": False}


def test_a_comment_beside_an_escalate_is_kept() -> None:
    """NEGATIVE CONTROL. The escalate opens the case that the comment needs.
    The card keeps the comment off until the analyst runs the escalate."""
    report = _fp(actions=[_ESCALATE, _COMMENT], verdict="true_positive")
    settled, audit = _settle(report, budget.STANDARD)
    assert settled is report
    assert audit is None


def test_the_rule_reads_stored_actions_too() -> None:
    """The chat path stores actions as objects with no model class."""
    comment = {"tool_name": "add_case_comment", "tool_args": {"comment": "x"}}
    ack = {"tool_name": "ack_alert", "tool_args": {}}
    escalate = {"tool_name": "escalate_to_case", "tool_args": {}}
    assert drop_case_comments_without_a_case([ack, comment]) == ([ack], 1)
    assert drop_case_comments_without_a_case([ack, comment], case_open=True) == ([ack, comment], 0)
    assert drop_case_comments_without_a_case([comment, escalate]) == ([comment, escalate], 0)
    assert drop_case_comments_without_a_case([]) == ([], 0)
    # A stored list can hold a value that is no action.
    assert drop_case_comments_without_a_case([None, "x", comment]) == ([None, "x"], 1)


# ── The prompt contract ─────────────────────────────────────────────────────


def _candidate() -> CandidateVerdict:
    return CandidateVerdict(
        verdict="false_positive",
        confidence=0.85,
        cited_evidence=["alert.rule_name"],
        template_id="stun_quic_keepalive",
        rationale="STUN keepalive",
        authority="dispositive",
    )


def test_the_round1_prompt_asks_for_no_answer_about_the_candidate() -> None:
    message = build_synth_first_user_message(_ALERT, "{}", ["- e"], _candidate())
    for text in (SYNTH_FIRST_SYSTEM_PROMPT, message):
        assert "Keep it, override it, or refine it" not in text
        assert "explain why in the summary" not in text
    assert "Do not write about the candidate" in SYNTH_FIRST_SYSTEM_PROMPT
    assert "Do not write about the candidate" in message


def test_the_round1_prompt_states_the_summary_and_the_actions() -> None:
    prompt = SYNTH_FIRST_SYSTEM_PROMPT
    assert "**`summary`** is text for the analyst" in prompt
    assert "`ack_alert(alert_id)`" in prompt
    assert "`escalate_to_case(alert_id, case_title, case_description)`" in prompt
    assert "Do not recommend `add_case_comment`" in prompt
    assert "For a `false_positive` verdict, recommend `ack_alert`" in prompt


_TOOL_CALL = re.compile(r"`(ack_alert|escalate_to_case|add_case_comment)\(([^)`]*)\)`")


_LOOP_REPORT_PROMPT = build_investigator_prompt(emits_report=True)


@pytest.mark.parametrize(
    "prompt",
    [SYNTH_FIRST_SYSTEM_PROMPT, SYNTHESIZER_PROMPT, _LOOP_REPORT_PROMPT],
    ids=["round1", "round2", "loop"],
)
def test_each_argument_a_prompt_names_is_an_argument_of_the_tool(prompt: str) -> None:
    """The loop prompt named ``description`` for ``add_case_comment``. The tool
    takes ``comment``, so the console dropped the argument and the write failed."""
    named = _TOOL_CALL.findall(prompt)
    assert named, "the prompt names no write tool"
    for tool_name, args in named:
        signature = inspect.signature(get_tool(tool_name).func)
        for arg in (a.strip().rstrip("?") for a in args.split(",")):
            assert arg in signature.parameters, f"{tool_name} takes no argument {arg!r}"


@pytest.mark.parametrize(
    "prompt", [SYNTHESIZER_PROMPT, _LOOP_REPORT_PROMPT], ids=["round2", "loop"]
)
def test_the_loop_prompts_tie_a_comment_to_an_escalate(prompt: str) -> None:
    assert "`case_id` was named in the evidence" not in prompt
    assert "only beside an `escalate_to_case`" in prompt


# ── The run ─────────────────────────────────────────────────────────────────


async def test_a_cheap_run_records_the_settled_report(settings_kratos: Settings) -> None:
    """The whole path: the model writes the production shape, and the record
    holds analyst text, one Acknowledge action and the reason of the change."""
    ctx = _make_ctx(settings_kratos)
    # A citation the stub alert resolves, so no gate changes the cheap verdict.
    round1 = _fp(_PROD_SUMMARY, [_PROD_COMMENT]).model_copy(
        update={"citations": ["alert.rule_name"], "confidence": 0.85}
    )
    events, _synth, _inv = await _drive(ctx, candidate=_strong_benign_candidate(), round1=round1)
    report = _report(events)
    assert report["run_class"] == "cheap"
    assert report["verdict"] == "false_positive"
    assert report["summary"].startswith("The payload bytes match RFC 5389 STUN.")
    assert "candidate" not in report["summary"]
    assert [a["tool_name"] for a in report["recommended_actions"]] == ["ack_alert"]
    assert report["recommended_actions"][0]["tool_args"] == {"alert_id": "alert-001"}
    # The local report wrote this verdict. No Oracle changed it.
    assert report["local_verdict"] is None
    blocked = [e for e in events if e.kind == "recommended_actions_blocked"]
    assert [e.payload for e in blocked] == [
        {"blocked_count": 1, "reason": "no_case_for_comment", "tools": ["add_case_comment"]}
    ]
    done = next(e for e in events if e.kind == "done")
    assert done.payload["recommended_count"] == 1


async def test_a_standard_run_drops_a_lone_comment_and_adds_nothing(
    settings_kratos: Settings,
) -> None:
    """NEGATIVE CONTROL on the run. The loop report keeps its text, and the
    console adds no action to it."""
    ctx = _make_ctx(settings_kratos)
    ctx.requested_run_class = "standard"
    loop_report = TriageReport(
        verdict="false_positive",
        confidence=0.88,
        summary="Keep the candidate. The Zeek record shows a keepalive to a known service.",
        citations=["(tool t_query_zeek_logs)"],
        recommended_actions=[_COMMENT],
    )
    with patch("tests.test_budget_classes._loop_report", return_value=loop_report):
        events, _synth, _inv = await _drive(
            ctx, candidate=_strong_benign_candidate(), round1=_fp(actions=[])
        )
    report = _report(events)
    assert report["run_class"] == "standard"
    assert report["summary"].startswith("Keep the candidate.")
    assert report["recommended_actions"] == []
    assert [e.payload["blocked_count"] for e in events if e.kind == "recommended_actions_blocked"]


def test_the_timeline_names_the_dropped_comment() -> None:
    from soc_ai.webui.timeline_labels import title_for

    title = title_for(
        "recommended_actions_blocked",
        {"blocked_count": 1, "reason": "no_case_for_comment", "tools": ["add_case_comment"]},
    )
    assert title == "Removed 1 case comment action. This investigation opened no case"
    # The older reason keeps its words.
    assert title_for("recommended_actions_blocked", {"blocked_count": 2}) == (
        "Withheld 2 recommended action(s): confidence below floor"
    )


# ── The chat path writes actions too ────────────────────────────────────────


def _apply_proposal(
    client: TestClient,  # noqa: F811 - the fixture
    actions: list[dict[str, Any]],
    *,
    opened_case: str | None = None,
) -> list[str]:
    """Apply a chat proposal with ``actions``, and return the stored tool names."""
    from soc_ai.store import chat as chat_svc
    from soc_ai.store import investigations as inv_svc
    from soc_ai.store.models import Investigation

    async def seed() -> tuple[str, int]:
        async with client.app.state.db_sessionmaker() as db:
            inv = await inv_svc.create(db, alert_es_id="ev-chat", started_by="t")
            await inv_svc.finalize(
                db,
                inv.id,
                status="complete",
                verdict="needs_more_info",
                confidence=0.4,
                rationale="need more",
            )
            if opened_case:
                receipt = {
                    "success": True,
                    "tool_name": "escalate_to_case",
                    "case_id": opened_case,
                    "action_key": "earlier",
                }
                await inv_svc.append_events(
                    db, inv.id, [{"sequence": 1, "kind": "action_executed", "payload": receipt}]
                )
            msg = await chat_svc.create_pending_assistant(db, inv.id)
            await chat_svc.finish_assistant(
                db,
                msg.id,
                content="I propose true_positive.",
                status="done",
                meta={
                    "kind": "verdict_proposal",
                    "validation": "pass",
                    "token": "tok",
                    "proposal": {
                        "verdict": "true_positive",
                        "confidence": 0.8,
                        "rationale": "The beacon is real.",
                        "recommended_actions": actions,
                    },
                },
            )
            return str(inv.id), int(msg.id)

    inv_id, msg_id = asyncio.run(seed())
    res = client.post(
        f"/api/v1/investigations/{inv_id}/resolve", json={"message_id": msg_id, "token": "tok"}
    )
    assert res.status_code == 200, res.text

    async def stored() -> list[str]:
        async with client.app.state.db_sessionmaker() as db:
            run = await db.get(Investigation, inv_id)
            assert run is not None
            return [a["tool_name"] for a in run.report["recommended_actions"]]

    return asyncio.run(stored())


_CHAT_COMMENT = {
    "tool_name": "add_case_comment",
    "tool_args": {"case_id": "made-up", "comment": "note"},
    "rationale": "Record the second host.",
}
_CHAT_ESCALATE = {
    "tool_name": "escalate_to_case",
    "tool_args": {"case_title": "t", "case_description": "d"},
    "rationale": "The beacon is real.",
}


def test_a_chat_proposal_loses_a_comment_with_no_case(client: TestClient) -> None:  # noqa: F811
    assert _apply_proposal(client, [_CHAT_COMMENT]) == []


def test_a_chat_proposal_keeps_a_comment_beside_an_escalate(client: TestClient) -> None:  # noqa: F811
    stored = _apply_proposal(client, [_CHAT_ESCALATE, _CHAT_COMMENT])
    assert stored == ["escalate_to_case", "add_case_comment"]


def test_a_chat_proposal_keeps_a_comment_on_the_case_the_run_opened(
    client: TestClient,  # noqa: F811
) -> None:
    """NEGATIVE CONTROL. The run opened a case earlier, so the comment has a
    target and the execute route accepts it."""
    assert _apply_proposal(client, [_CHAT_COMMENT], opened_case="case-9") == ["add_case_comment"]


# ── A kept comment gets its case, or a plain reason (review, defect 8) ──────


def _seed_escalate_and_comment(
    client: TestClient,  # noqa: F811
    run_id: str,
    alert_id: str,
    events: list[tuple[str, dict[str, Any]]] | None = None,
) -> None:
    from tests.test_pending_action_rows import _COMMENT as comment
    from tests.test_pending_action_rows import _ESCALATE as escalate
    from tests.test_pending_action_rows import _seed

    _seed(client, run_id, alert_id=alert_id, actions=[escalate, comment], events=events)


def test_an_escalate_that_finds_the_case_stores_it_for_the_comment(client: TestClient) -> None:  # noqa: F811
    """The alert is on a case that a group escalate opened. The press opens no
    second case. It stores the case that the ledger names, so the comment
    beside it has its target."""
    from tests.test_escalate_dedup import _hold

    _seed_escalate_and_comment(client, "INV-ON-CASE", "alert-on-a-case-0001")
    _hold(client, "alert-on-a-case-0001", "case-from-the-group")

    async def no_link(*_args: Any, **_kwargs: Any) -> dict[str, str]:
        return {}

    with patch("soc_ai.api.webui.routes_alert_actions.case_ids_for_alerts", no_link):
        out = client.post("/api/v1/investigations/INV-ON-CASE/actions/0/execute").json()
    assert out["status"] == "executed", out
    assert out["detail"] == (
        "This alert is already on Security Onion case case-from-the-group. "
        "soc-ai opened no second case."
    )
    actions = client.get("/api/v1/investigations/INV-ON-CASE").json()["actions"]
    assert actions[0]["applied"] is True
    assert (actions[1]["applied"], actions[1]["blockedReason"]) == (False, None)
    scope = client.get("/api/v1/investigations/INV-ON-CASE/actions/1/scope").json()
    assert scope["scope"] == "case"


def test_a_comment_with_no_known_case_is_closed_with_a_reason(client: TestClient) -> None:  # noqa: F811
    """The record says the escalate is done and names no case. The comment
    said "Escalate the alert first", which no one could do. It now reads as
    closed, with the reason, and it has no write button."""
    receipt = {
        "index": 0,
        "success": True,
        "by": "ana",
        "tool_name": "escalate_to_case",
        "note": "already_escalated",
    }
    _seed_escalate_and_comment(
        client, "INV-NO-ID", "alert-no-case-id-001", events=[("action_executed", receipt)]
    )
    actions = client.get("/api/v1/investigations/INV-NO-ID").json()["actions"]
    assert actions[1]["applied"] is True
    assert actions[1]["appliedBy"] is None
    assert actions[1]["appliedNote"] == (
        "The alert is already on a Security Onion case, and soc-ai does not know the "
        "case. Add the comment in Security Onion."
    )


def test_a_comment_before_its_escalate_keeps_the_first_reason(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL. No escalate ran yet, so the advice is still right."""
    _seed_escalate_and_comment(client, "INV-FRESH", "alert-fresh-00000001")
    actions = client.get("/api/v1/investigations/INV-FRESH").json()["actions"]
    assert actions[1]["applied"] is False
    assert actions[1]["blockedReason"] == (
        "This investigation opened no Security Onion case. Escalate the alert first."
    )
