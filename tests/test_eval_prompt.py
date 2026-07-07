"""Unit tests for the eval-harness prompt builder.

Focus: the user message has the three required sections, embeds the
verbatim system prompts the agent itself runs against (so the oracle can
critique them), and never inlines a string that didn't already pass
through the sanitizer.
"""

from __future__ import annotations

from soc_ai.agent.prompts import (
    INVESTIGATOR_PROMPT,
    SYNTH_FIRST_SYSTEM_PROMPT,
    SYNTHESIZER_PROMPT,
)
from soc_ai.eval.prompt import (
    SYSTEM_PROMPT,
    architecture_block,
    build_user_message,
)


def test_system_prompt_calls_out_label_semantics_and_role() -> None:
    """The system prompt must instruct the oracle (a) about opaque labels and
    (b) to be honest about uncertainty — both load-bearing for the harness."""
    assert "IP_01" in SYSTEM_PROMPT  # label format
    assert "uncertain" in SYSTEM_PROMPT.lower()
    assert "Markdown" in SYSTEM_PROMPT


def test_architecture_block_includes_all_verbatim_prompts() -> None:
    block = architecture_block()
    # Must include all three live system prompts verbatim so the oracle can
    # suggest prompt-level edits: the synth-first verdict writer, the
    # investigation-loop investigator, and the loop-concluding synthesizer.
    assert SYNTH_FIRST_SYSTEM_PROMPT in block
    assert INVESTIGATOR_PROMPT in block
    assert SYNTHESIZER_PROMPT in block
    assert "synthesis_confidence_floor" in block


def test_architecture_block_describes_the_current_pipeline() -> None:
    """The grading input must describe the REAL pipeline, not the deleted
    two-stage investigator->synthesizer->retask flow."""
    block = architecture_block()
    # Collapse the summary's hard line-wraps so multi-word phrase checks
    # aren't broken by a wrap point.
    flat = " ".join(block.split())
    # The deleted flow must not be described to the judge. Scope the check to
    # the summary itself — the verbatim agent prompts embedded below it are
    # the live runtime prompts and are quoted as-is (the loop's
    # investigator->synthesizer handoff legitimately self-describes as
    # two-stage there).
    summary = flat.split("## Round-1", 1)[0]
    assert "two-stage" not in summary.lower()
    assert "retask round" not in summary.lower()
    # The real stages, in the summary.
    assert "decision template" in summary.lower()
    assert "definitely-investigate" in summary.lower()
    assert "targeted dispatch" in summary.lower()
    assert "investigation loop" in summary.lower()
    assert "evidence gate" in summary.lower()
    assert "malware-label payload gate" in summary.lower()
    assert "Oracle" in summary
    # Event kinds the pipeline actually emits (spot-check the ones the old
    # text got wrong or omitted).
    for kind in (
        "`enriched_alert_context`",
        "`decision_template_match`",
        "`synth_round1_skipped`",
        "`investigation_loop_entered`",
        "`targeted_dispatch`",
        "`targeted_tool_result`",
        "`citation_validation`",
        "`evidence_gate_downgrade`",
        "`auto_ack`",
    ):
        assert kind in block, f"missing event kind {kind} in architecture block"
    # Kinds the pipeline does NOT emit anymore must be gone.
    assert "`alert_context`" not in block
    assert "`approval_required`" not in block
    # `retask` is still emitted (co-emitted with each Phase-D dispatch) and
    # must be explained as such so the judge doesn't infer a re-run round.
    assert "`retask`" in block
    assert "Phase-D dispatches" in block


def test_user_message_has_all_three_question_sections() -> None:
    msg = build_user_message(
        alert_id_label="IP_01",
        sanitized_events=[
            {"kind": "session_start", "sequence": 1, "payload": {"alert_id": "IP_01"}},
        ],
        sanitized_report={
            "verdict": "false_positive",
            "confidence": 0.75,
            "summary": "DNS query to storyblok.com from HOST_01.",
            "citations": ["alert-abc"],
            "recommended_actions": [],
        },
    )
    assert "## 1. Verdict" in msg or "1. **Is this conclusion correct?**" in msg
    assert "2. **Why?**" in msg
    assert "3. **Architecture changes" in msg
    assert "false_positive" in msg
    assert "storyblok.com" in msg


def test_user_message_handles_missing_report() -> None:
    msg = build_user_message(
        alert_id_label="IP_01",
        sanitized_events=[],
        sanitized_report=None,
    )
    assert "no triage_report" in msg.lower()
    # Three questions still asked.
    assert "1. **Is this conclusion correct?**" in msg
    assert "2. **Why?**" in msg
    assert "3. **Architecture changes" in msg


def test_user_message_contains_agreement_instruction() -> None:
    """The built prompt must contain the fill-in-the-blank AGREEMENT instruction
    in angle-bracket form so the oracle emits a machine-readable verdict and the
    instruction text itself cannot be misclassified by the batch parser."""
    msg = build_user_message(
        alert_id_label="IP_01",
        sanitized_events=[],
        sanitized_report=None,
    )
    assert "AGREEMENT: <yes|no|partial>" in msg


def test_build_user_message_with_expected_verdict_adds_ground_truth_block() -> None:
    """build_user_message(..., expected_verdict='true_positive') must embed the
    ground-truth block so the oracle grades synth rows factually."""
    msg = build_user_message(
        alert_id_label="IP_01",
        sanitized_events=[],
        sanitized_report={
            "verdict": "false_positive",
            "confidence": 0.5,
            "summary": "x",
            "citations": [],
            "recommended_actions": [],
        },
        expected_verdict="true_positive",
    )
    assert "## Ground truth (synthetic scenario)" in msg
    assert "true_positive" in msg
    assert "planted, known-correct verdict" in msg


def test_build_user_message_without_expected_verdict_is_unchanged() -> None:
    """Without expected_verdict, the message must be byte-identical to the
    previous no-param form (backward compat for real-alert grading)."""
    base_msg = build_user_message(
        alert_id_label="IP_01",
        sanitized_events=[],
        sanitized_report=None,
    )
    msg_with_none = build_user_message(
        alert_id_label="IP_01",
        sanitized_events=[],
        sanitized_report=None,
        expected_verdict=None,
    )
    assert base_msg == msg_with_none
    assert "Ground truth" not in base_msg


def test_user_message_does_not_leak_raw_internal_strings() -> None:
    """The harness sanitizes BEFORE calling build_user_message — but
    a regression in the harness (e.g. forgetting to sanitize one
    field) shouldn't be invisible in the prompt. As a defense-in-depth
    sanity check, verify that if all inputs are already opaque labels,
    the output contains zero raw private-IP-shaped strings."""
    msg = build_user_message(
        alert_id_label="IP_01",
        sanitized_events=[
            {
                "kind": "tool_call",
                "sequence": 2,
                "payload": {"tool_name": "t_enrich_ip", "args": {"ip": "IP_02"}},
            },
            {
                "kind": "tool_result",
                "sequence": 3,
                "payload": {
                    "tool_name": "t_enrich_ip",
                    "result": {"ip": "IP_02", "internal": True},
                },
            },
        ],
        sanitized_report={
            "verdict": "false_positive",
            "confidence": 0.7,
            "summary": "HOST_01 queried storyblok.com",
            "citations": [],
            "recommended_actions": [],
        },
    )
    # No raw RFC1918 / CGNAT / loopback IPs anywhere in the prompt.
    import re

    # Match private-IP-shaped octets only when they're actually IP-like
    # (followed by another digit-dot-digit). `### 10. Total alerts`
    # is a section heading, not a leak.
    private_ip_re = re.compile(
        r"\b(?:"
        r"10|192\.168|172\.(?:1[6-9]|2\d|3[01])|127|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])"
        r")\.\d+\.\d+"
    )
    assert not private_ip_re.search(msg), f"raw private IP leaked: {msg[:200]!r}"
