"""Score the declarative half of a scenario: did the spec fire, on the right entity?

This runs with no model call, which is the point twice over. It is cheap enough
to run on every commit, and it makes a spec regression diagnosable: if the spec
never fired there is no reason to go asking why the hunt agent missed the
finding.

It also closes the hole the 1.4.0 eval left. The hunt-journey rubric starts at an
LLM hunt and has no stage before it, so a spec that failed to fire and an agent
that failed to notice were the same result. They need opposite fixes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from soc_ai.eval.journey import JourneyStage
from soc_ai.eval.synth_loader import SpecJourney
from soc_ai.hunting.execute import SpecRun


@dataclass(frozen=True)
class SpecJourneyResult:
    """What the declarative half of a scenario proved, or failed to."""

    scenario_id: str
    spec_id: str
    reached: JourneyStage
    expected_scope_keys: list[str]
    actual_scope_keys: list[str]
    detail: str

    @property
    def passed(self) -> bool:
        return self.reached is JourneyStage.COMPLETE

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "spec_id": self.spec_id,
            "reached": str(self.reached),
            "expected_scope_keys": list(self.expected_scope_keys),
            "actual_scope_keys": list(self.actual_scope_keys),
            "detail": self.detail,
            "passed": self.passed,
        }


def score_spec_journey(scenario_id: str, journey: SpecJourney, run: SpecRun) -> SpecJourneyResult:
    """Grade one spec run against what the scenario said should happen.

    Stages, in the order they are checked:

    - ``TRIGGER_BLIND`` — the precondition matched nothing, so the plane this
      spec reads is absent. The detection is not at fault; the fixture did not
      render, or the grid does not carry that telemetry. Checked FIRST because
      a blind run's empty candidate list would otherwise read as a miss and
      send somebody to debug a working spec.
    - ``TRIGGER_DID_NOT_FIRE`` — the spec could see and surfaced nothing, or
      surfaced the wrong entity. This is a detection bug.
    - ``COMPLETE`` — every expected scope key came back, and the count matches
      if the scenario pinned one.

    An errored run is reported as ``TRIGGER_DID_NOT_FIRE`` with the error in
    ``detail`` rather than given a stage of its own: from the scorer's side the
    consequence is identical (no candidate), and the detail names the cause.
    """
    expected = list(journey.expected_scope_keys)
    actual = [c.scope_key for c in run.candidates]

    if run.error is not None:
        return SpecJourneyResult(
            scenario_id,
            journey.spec_id,
            JourneyStage.TRIGGER_DID_NOT_FIRE,
            expected,
            actual,
            f"spec {journey.spec_id} errored against the grid: {run.error}",
        )

    if run.blind:
        return SpecJourneyResult(
            scenario_id,
            journey.spec_id,
            JourneyStage.TRIGGER_BLIND,
            expected,
            actual,
            (
                f"spec {journey.spec_id} is blind: its precondition matched no documents, "
                "so the telemetry plane it reads is absent rather than clean. The fixture "
                "did not render, or this grid does not carry that data."
            ),
        )

    missing = [k for k in expected if k not in actual]
    if missing:
        seen = ", ".join(actual) if actual else "nothing"
        return SpecJourneyResult(
            scenario_id,
            journey.spec_id,
            JourneyStage.TRIGGER_DID_NOT_FIRE,
            expected,
            actual,
            (
                f"spec {journey.spec_id} saw {run.precondition_docs} documents on its plane "
                f"but did not surface {missing}; it surfaced {seen}"
            ),
        )

    if (
        journey.expected_candidate_count is not None
        and len(run.candidates) != journey.expected_candidate_count
    ):
        return SpecJourneyResult(
            scenario_id,
            journey.spec_id,
            JourneyStage.TRIGGER_DID_NOT_FIRE,
            expected,
            actual,
            (
                f"spec {journey.spec_id} surfaced {len(run.candidates)} candidates, "
                f"expected exactly {journey.expected_candidate_count}. Every expected "
                "scope key was found, so this is over- or under-grouping rather than a "
                "missed detection."
            ),
        )

    unexpected = [k for k in actual if k not in expected]
    note = f" (plus unexpected: {unexpected})" if unexpected else ""
    return SpecJourneyResult(
        scenario_id,
        journey.spec_id,
        JourneyStage.COMPLETE,
        expected,
        actual,
        (
            f"spec {journey.spec_id} surfaced {expected} from {run.matched_docs} matching "
            f"documents, with no model call{note}"
        ),
    )


__all__ = ["SpecJourneyResult", "score_spec_journey"]
