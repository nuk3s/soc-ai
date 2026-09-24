"""A disconfirming fact is a record (2026-09-19 accuracy mission).

The range's DCSync alert, six runs on the same evidence: two true positives
and four needs-more-info. Every needs-more-info run wrote the same reason,
"Ansible-driven lab provisioning could explain it", and no run held a record
that provisioning performs replication. Three mechanisms let a description of
the environment do the work of a fact:

- the round-2 synthesizer preferred needs_more_info whenever the transcript's
  open_questions were "non-empty and material", and a hypothesis counted;
- the investigator's stop rule accepted "the surrounding context (Ansible lab
  provisioning) could contradict a malicious verdict" as its second fact;
- the user message told the model "None of the conditional tools applies to
  this alert. Do not call them", because a Sigma rule carries no Suricata
  classtype, so the tool that names the driving host was never invited.

These tests pin the doctrine in the three prompts that decide a verdict. The
condition that invites the origin-chain pivot on a critical detection is pinned
in tests/test_case_conditions_severity.py.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# The rule itself
# ---------------------------------------------------------------------------


def test_the_record_rule_exists_and_is_plain() -> None:
    from soc_ai.agent.prompts import DISCONFIRMING_RECORD_RULE as rule

    lowered = rule.lower()
    assert "record" in lowered
    assert "hypothesis" in lowered
    assert "environment" in lowered
    # The one open question every miss left on the table, and the two tools
    # that answer it.
    assert "t_origin_chain" in rule
    assert "4624" in rule
    assert "—" not in rule
    # Short enough to sit in three prompts.
    assert len(rule) < 2200


def test_the_record_rule_forbids_world_knowledge_as_the_benign_explanation() -> None:
    """Round 2 wrote 'Ansible AD modules use replication' from memory."""
    from soc_ai.agent.prompts import DISCONFIRMING_RECORD_RULE as rule

    lowered = rule.lower()
    assert "knowledge" in lowered
    assert "framework" in lowered


def test_the_record_rule_answers_the_authorization_hypothesis() -> None:
    """01M2XDVV: "Is localuser a legitimate service account authorized for
    replication? No case or runbook records this activity." An empty case
    lookup became the reason for needs_more_info on a confirmed DCSync."""
    from soc_ai.agent.prompts import DISCONFIRMING_RECORD_RULE as rule

    lowered = rule.lower()
    assert "authorized" in lowered
    assert "t_prevalence" in rule
    assert "did this before" in lowered


def test_the_record_rule_says_absence_of_corroboration_is_not_a_record() -> None:
    """The Kerberoast lead (01M2X5YH): the loop found the only RC4 service
    ticket in 24 hours, for the only user SPN, from a Linux host. Round 2
    wrote 'The absence of Rubeus process, absence of kerberoast rule match,
    absence of multiple requests all reduce suspicion' and landed
    needs_more_info 0.45 on a true positive."""
    from soc_ai.agent.prompts import DISCONFIRMING_RECORD_RULE as rule

    lowered = rule.lower()
    assert "absence" in lowered
    assert "not a disconfirming record" in lowered


# ---------------------------------------------------------------------------
# Where the rule lives: the three writers of a verdict
# ---------------------------------------------------------------------------


def test_the_investigator_carries_the_record_rule_beside_the_stop_rule() -> None:
    from soc_ai.agent.prompts import _INVESTIGATOR_RUBRIC, DISCONFIRMING_RECORD_RULE

    assert DISCONFIRMING_RECORD_RULE in _INVESTIGATOR_RUBRIC
    # Still one stop rule, and the malware doctrine still sits inside it.
    assert _INVESTIGATOR_RUBRIC.count("## Stop rule") == 1
    assert _INVESTIGATOR_RUBRIC.count("—") == 0


def test_the_round_two_synthesizer_carries_the_record_rule() -> None:
    from soc_ai.agent.prompts import DISCONFIRMING_RECORD_RULE, SYNTHESIZER_PROMPT

    assert DISCONFIRMING_RECORD_RULE in SYNTHESIZER_PROMPT


def test_the_round_two_synthesizer_no_longer_prefers_nmi_on_any_open_question() -> None:
    """The sentence that turned 'could Ansible explain it' into a verdict."""
    from soc_ai.agent.prompts import SYNTHESIZER_PROMPT

    assert "non-empty and material" not in SYNTHESIZER_PROMPT
    assert "CONFIDENCE BELOW 0.6 = needs_more_info" in SYNTHESIZER_PROMPT


def test_the_report_writing_loop_carries_the_record_rule() -> None:
    from soc_ai.agent.prompts import DISCONFIRMING_RECORD_RULE, INVESTIGATOR_EMITS_REPORT_BLOCK

    assert DISCONFIRMING_RECORD_RULE in INVESTIGATOR_EMITS_REPORT_BLOCK
    assert "—" not in INVESTIGATOR_EMITS_REPORT_BLOCK


def test_the_stop_rules_do_not_stop_on_an_answerable_open_question() -> None:
    """Both stop rules say: read your open questions before you stop."""
    from soc_ai.agent.prompts import _INVESTIGATOR_RUBRIC, INVESTIGATOR_EMITS_REPORT_BLOCK

    for text in (_INVESTIGATOR_RUBRIC, INVESTIGATOR_EMITS_REPORT_BLOCK):
        lowered = text.lower()
        assert "open question" in lowered or "open_questions" in lowered
        assert "before you stop" in lowered


# ---------------------------------------------------------------------------
# The report-writing loop gets a system prompt that agrees with its job
# ---------------------------------------------------------------------------


def test_the_report_prompt_does_not_tell_the_writer_it_does_not_decide() -> None:
    """The W3 loop read 'You DO NOT decide the verdict' in its system prompt
    and 'You write the report' in its user message, and answered with a
    markdown InvestigationTranscript that failed validation (01M2X1WJ)."""
    from soc_ai.agent.prompts import (
        INVESTIGATOR_PROMPT,
        build_investigator_prompt,
    )

    report = build_investigator_prompt(emits_report=True)
    transcript = build_investigator_prompt()
    assert transcript == INVESTIGATOR_PROMPT
    assert "DO NOT decide the verdict" in transcript
    assert "DO NOT decide the verdict" not in report
    assert "InvestigationTranscript" not in report
    assert "TriageReport" in report
    assert "—" not in report.split("# OQL")[0]


def test_the_report_prompt_carries_the_verdict_policy() -> None:
    """The loop that writes the verdict reads the same verdict rules as the
    synthesizer it replaces."""
    from soc_ai.agent.prompts import SYNTHESIZER_PROMPT, build_investigator_prompt

    report = build_investigator_prompt(emits_report=True)
    for marker in ("Empty-enrichment rule", "No-web-footprint rule", "Concurrent-context rule"):
        assert marker in SYNTHESIZER_PROMPT
        assert marker in report
    assert "DISCONFIRMING" in report or "disconfirming" in report


def test_the_orchestrator_hands_the_report_prompt_to_the_report_writing_loop(
    settings_kratos: Any,
) -> None:
    from pydantic_ai.models.test import TestModel
    from soc_ai.agent.orchestrator import build_investigator
    from soc_ai.agent.prompts import INVESTIGATOR_PROMPT, build_investigator_prompt

    from tests.test_agent import _make_ctx

    ctx = _make_ctx(settings_kratos)
    transcript_agent = build_investigator(TestModel(), ctx)
    report_agent = build_investigator(TestModel(), ctx, emits_report=True)
    assert transcript_agent._system_prompts == (INVESTIGATOR_PROMPT,)
    assert report_agent._system_prompts == (build_investigator_prompt(emits_report=True),)


def test_the_shared_hard_rules_name_no_stage_that_may_not_run() -> None:
    """The report-writing loop has no synthesizer after it, and its report
    has no `open_questions` field. A rule that names either reads as an
    instruction to hand the work on."""
    from soc_ai.agent.prompts import build_investigator_prompt

    report = build_investigator_prompt(emits_report=True).split("# OQL")[0].lower()
    assert "synthesizer" not in report
    assert "investigationtranscript" not in report
    assert "tentative_summary" not in report


def test_the_record_rule_says_nmi_needs_a_gap_a_tool_can_close() -> None:
    """01M2XGA1: an HTTP 200 to a Tor exit node whose body is
    `uid=0(root) gid=0(root) groups=0(root)`. The verdict was
    needs_more_info 0.50 because "No Zeek records or endpoint agent confirm
    whether the text is live command output or a static page ... that
    distinction is unverifiable". No tool on that grid could close it.
    01M2XD11 and 01M2X5YH landed the same way on the Kerberoast lead."""
    from soc_ai.agent.prompts import DISCONFIRMING_RECORD_RULE as rule

    lowered = rule.lower()
    assert "needs_more_info` is for a gap a tool call can close" in lowered
    assert "no tool on this grid can close" in lowered
    assert "records in hand" in lowered
