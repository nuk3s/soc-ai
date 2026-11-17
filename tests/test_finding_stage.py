"""The stage of a hunt finding (campaign design, 2026-11-13).

A run that judges a finding states how far the activity went. A stage above
``attempt`` is a claim that a record shows the effect: it stands only with
the impact ``succeeded``, which the impact guard already checked.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from soc_ai.agent import prompts
from soc_ai.config import Settings
from soc_ai.triage_models import STAGE_ORDER, TriageReport, settled_stage, stored_stage

from tests import test_hunt_subject as hs
from tests import test_impact_first_line as il


@pytest.mark.parametrize(
    ("verdict", "stage", "impact", "finding", "expected"),
    [
        ("true_positive", "action", "succeeded", True, "action"),
        ("true_positive", "action", "attempted", True, "attempt"),
        ("true_positive", "movement", "unknown", True, "attempt"),
        ("true_positive", "access", "succeeded", True, "access"),
        ("true_positive", "access", "none", True, "attempt"),
        ("true_positive", "reconnaissance", "none", True, "reconnaissance"),
        ("true_positive", "attempt", "attempted", True, "attempt"),
        ("true_positive", None, "succeeded", True, None),
        ("true_positive", "action", "succeeded", False, None),
        ("false_positive", "action", "succeeded", True, None),
        ("needs_more_info", "attempt", None, True, None),
        ("true_positive", "persistence", "succeeded", True, None),
    ],
)
def test_the_stage_that_a_report_states(
    verdict: str, stage: Any, impact: Any, finding: bool, expected: str | None
) -> None:
    assert settled_stage(verdict, stage, impact, finding=finding) == expected


def test_the_stage_order_is_lowest_first() -> None:
    assert STAGE_ORDER == ("reconnaissance", "attempt", "access", "action", "movement")


@pytest.mark.parametrize(
    ("written", "read"),
    [(" Action. ", "action"), ("MOVEMENT", "movement"), ("foothold", None), ("", None), (3, None)],
)
def test_the_report_schema_folds_the_stage(written: Any, read: str | None) -> None:
    assert il._report(stage=written).stage == read


def test_a_report_with_no_stage_key_still_validates() -> None:
    assert TriageReport(verdict="false_positive", confidence=0.7, summary="x").stage is None


def test_the_stored_stage_of_a_row() -> None:
    assert stored_stage({"stage": "action"}, "true_positive") == "action"
    assert stored_stage({"stage": "action"}, "false_positive") is None
    assert stored_stage({"stage": "foothold"}, "true_positive") is None
    assert stored_stage({}, "true_positive") is None
    assert stored_stage(None, "true_positive") is None


def test_only_the_rules_of_a_finding_run_ask_for_the_stage() -> None:
    assert prompts.STAGE_RULE in prompts.FINDING_SUBJECT_RULES
    assert prompts.STAGE_RULE in prompts.hunt_subject_rules(finding=True)
    assert "`stage`" not in prompts.hunt_subject_rules(finding=False)
    assert "`stage`" not in prompts.IMPACT_RULE


def _finding_subject() -> Any:
    return hs._subject(
        findings=[
            hs.SubjectFinding(
                ordinal=0,
                title="Exploit requests to the web server",
                hosts=[il.DST],
                citations=[hs.ANCHOR_ID],
                promoted=True,
            )
        ]
    )


async def test_a_finding_run_stores_its_stage(settings_kratos: Settings) -> None:
    report = il._report(impact="attempted", stage="attempt", citations=[hs.ANCHOR_ID])
    events, _spies = await hs._run(settings_kratos, subject=_finding_subject(), report=report)
    final = hs._payload(events, "triage_report")
    assert final["verdict"] == "true_positive", final.get("summary")
    assert final["stage"] == "attempt"


async def test_a_stage_above_attempt_falls_with_its_impact(settings_kratos: Settings) -> None:
    """The model claims a command on the target. The run fetched a flow record
    only, and that record holds no content of the event. The impact guard
    lowers the impact, and the stage follows it."""
    report = il._report(impact="succeeded", stage="action")
    with (
        patch.object(hs, "_enriched", il._pipeline_enriched),
        patch.object(hs, "_fake_investigator", lambda: il._loop_with(il.FLOW_RECORD)),
    ):
        events, _spies = await hs._run(settings_kratos, subject=_finding_subject(), report=report)
    final = hs._payload(events, "triage_report")
    assert final["verdict"] == "true_positive", final.get("summary")
    assert final["impact"] == "attempted"
    assert final["stage"] == "attempt"


async def test_a_stage_above_attempt_stands_with_a_cited_content_record(
    settings_kratos: Settings,
) -> None:
    report = il._report(impact="succeeded", stage="action", citations=[il.HTTP_ID])
    with (
        patch.object(hs, "_enriched", il._pipeline_enriched),
        patch.object(hs, "_fake_investigator", lambda: il._loop_with(il.HTTP_RECORD)),
    ):
        events, _spies = await hs._run(settings_kratos, subject=_finding_subject(), report=report)
    final = hs._payload(events, "triage_report")
    assert final["verdict"] == "true_positive", final.get("summary")
    assert final["impact"] == "succeeded"
    assert final["stage"] == "action"


async def test_an_alert_run_stores_no_stage(settings_kratos: Settings) -> None:
    """Negative control: the model wrote a stage on a run that judges no finding."""
    report = il._report(impact="attempted", stage="attempt")
    events = await il._pipeline(settings_kratos, report, il.FLOW_RECORD)
    final = hs._payload(events, "triage_report")
    assert final["verdict"] == "true_positive", final.get("summary")
    assert "stage" not in final


async def test_a_finding_run_with_no_stage_from_the_model_stores_none(
    settings_kratos: Settings,
) -> None:
    report = il._report(impact="attempted", citations=[hs.ANCHOR_ID])
    events, _spies = await hs._run(settings_kratos, subject=_finding_subject(), report=report)
    assert "stage" not in hs._payload(events, "triage_report")
