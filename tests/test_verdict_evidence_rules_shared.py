"""Every writer of a verdict reads the evidence doctrine (2026-09-19).

The doctrine that says what counts as evidence was written for the synth-first
(round-1) synthesizer and lived only in its prompt. W2 of the turn audit then
made round 1 run only when a dispositive template can settle the alert, so on
nearly every alert no stage read those rules.

The range measured the cost on an impacket WMIExec alert whose ground truth is
a true positive. The loop decoded the payload and wrote "the DCERPC payload
carries the WMIExec command `cmd.exe /Q /c whoami 1> ...ADMIN$...`, which is
remote command execution". The round-2 synthesis then wrote "which is benign
remote command execution ... Both endpoints are internal ... consistent with
benign east-west administrative traffic" and landed `false_positive` 0.70,
twice (01M2XCFM, 01M2XCYE). The rule that forbids that argument,
"Internal-to-internal is NOT exculpatory for an east-west attack class", was in
the prompt that did not run.
"""

from __future__ import annotations

import pytest

_MARKERS = (
    "Internal-to-internal is NOT exculpatory",
    "Stacked first-seen on an attack-class signature is NOT benign novelty",
    "A behavioral-summary aggregate is decisive on its own",
    "A decoy has no benign baseline",
    "A count is a count of DOCUMENTS",
    "Never infer an indicator's owner",
    "Volume and confirmed behavior ARE positive evidence",
    "A reputation hit plus a completed connection warrants 0.70 or more",
    "ICMP echo direction is decisive",
)


def _prompts() -> dict[str, str]:
    from soc_ai.agent.prompts import (
        SYNTH_FIRST_SYSTEM_PROMPT,
        SYNTHESIZER_PROMPT,
        build_investigator_prompt,
    )

    return {
        "round 1": SYNTH_FIRST_SYSTEM_PROMPT,
        "round 2": SYNTHESIZER_PROMPT,
        "report loop": build_investigator_prompt(emits_report=True),
    }


@pytest.mark.parametrize("marker", _MARKERS)
def test_every_verdict_writer_reads_the_rule(marker: str) -> None:
    for stage, text in _prompts().items():
        assert marker in text, f"{stage} lost: {marker}"


def test_the_doctrine_is_one_text_in_one_place() -> None:
    """One block, composed three times. Two copies drift."""
    from soc_ai.agent.prompts import VERDICT_EVIDENCE_RULES

    for stage, text in _prompts().items():
        assert VERDICT_EVIDENCE_RULES in text, stage
        assert text.count("Internal-to-internal is NOT exculpatory") == 1, stage
    assert VERDICT_EVIDENCE_RULES.count("—") == 0


def test_the_bpfdoor_protection_reaches_every_verdict_writer() -> None:
    """The solicited-echo rule is the BPFDoor lesson. It kept an
    uncorroborated packet-content match from reading as C2, and it used to be
    reachable only from round 1."""
    for stage, text in _prompts().items():
        assert "SOLICITED ping exchange" in text, stage
        assert "BPFDoor" in text, stage


def test_the_investigator_that_only_gathers_does_not_get_the_verdict_rules() -> None:
    """NEGATIVE CONTROL: the transcript loop states facts and gaps. It does
    not decide, so verdict rules there would invite it to."""
    from soc_ai.agent.prompts import INVESTIGATOR_PROMPT, VERDICT_EVIDENCE_RULES

    assert VERDICT_EVIDENCE_RULES not in INVESTIGATOR_PROMPT


def test_the_remote_execution_idiom_is_named_as_a_behavior_signature() -> None:
    """The WMIExec false negative: the loop read the command as remote
    execution, and the verdict stage read `whoami` as harmless. The
    redirect to an administrative share is the tradecraft, not the
    command."""
    from soc_ai.agent.prompts import VERDICT_EVIDENCE_RULES as rules

    assert "ADMIN$" in rules
    assert "whoami" in rules
    lowered = rules.lower()
    assert "remote-execution tool" in lowered
    assert "a harmless command does not" in lowered
    assert "make the execution path harmless" in lowered


def test_the_first_seen_floor_is_not_a_ceiling() -> None:
    """The after-fix DCSync run 01M2XDVV: the loop named the driving host and
    matched the logon id to the alert, then the round-2 synthesis wrote "Per
    the stacked first-seen rule, floor at needs_more_info" and landed
    needs_more_info 0.55 on a confirmed DCSync. The word floor read as a
    ceiling."""
    from soc_ai.agent.prompts import VERDICT_EVIDENCE_RULES as rules

    lowered = rules.lower()
    assert "lower bound" in lowered
    assert "not a ceiling" in lowered
    assert "novelty then raises the finding" in lowered
