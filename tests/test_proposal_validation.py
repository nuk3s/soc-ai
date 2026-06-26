from __future__ import annotations

from soc_ai.agent.proposal_validation import Proposal, validate_proposal


def _tool_evidence() -> list[dict]:
    # Mirrors the shape chat_manager extracts from result.all_messages():
    # a list of {"tool": name, "result": <stringified output>} entries.
    return [
        {"tool": "query_events_oql", "result": "hit _id=ev-9 community_id=1:abc dst=1.2.3.4"},
        {"tool": "enrich_indicator", "result": "1.2.3.4 reputation=malicious source=feodo"},
    ]


def test_grounded_proposal_passes() -> None:
    p = Proposal(
        verdict="true_positive",
        confidence=0.8,
        rationale="C2 confirmed",
        citations=["enrich_indicator", "(id ev-9)"],
        recommended_actions=[],
    )
    v = validate_proposal(p, tool_evidence=_tool_evidence())
    assert v.ok is True
    assert v.objection is None


def test_ungrounded_proposal_fails() -> None:
    p = Proposal(
        verdict="true_positive",
        confidence=0.9,
        rationale="trust me",
        citations=["(path alert.classtype)"],
        recommended_actions=[],
    )
    v = validate_proposal(p, tool_evidence=_tool_evidence())
    assert v.ok is False
    assert v.objection and "evidence" in v.objection.lower()


def test_no_citations_fails() -> None:
    p = Proposal(
        verdict="false_positive",
        confidence=0.7,
        rationale="benign",
        citations=[],
        recommended_actions=[],
    )
    v = validate_proposal(p, tool_evidence=_tool_evidence())
    assert v.ok is False


def test_needs_more_info_is_never_applyable() -> None:
    p = Proposal(
        verdict="needs_more_info",
        confidence=0.5,
        rationale="still unsure",
        citations=["enrich_indicator"],
        recommended_actions=[],
    )
    v = validate_proposal(p, tool_evidence=_tool_evidence())
    assert v.ok is False
    assert v.objection and "verdict" in v.objection.lower()


def test_junk_and_empty_citations_do_not_ground() -> None:
    """A short substring of a tool name, or an empty/blank citation, is not evidence."""
    p = Proposal(
        verdict="true_positive",
        confidence=0.9,
        rationale="x",
        citations=["in", "enr", "(path )", ""],
        recommended_actions=[],
    )
    v = validate_proposal(p, tool_evidence=_tool_evidence())
    assert v.ok is False
    assert v.objection and "evidence" in v.objection.lower()
