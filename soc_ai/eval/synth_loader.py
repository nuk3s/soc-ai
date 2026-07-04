"""YAML scenario loader for synthetic-TP eval.

Reads ``soc_ai/eval/synth_scenarios/*.yaml`` into validated
:class:`Scenario` objects. Downstream modules (render, ingest, score)
consume these typed objects rather than parsing YAML themselves.

The schema is documented in ``soc_ai/eval/synth_scenarios/README.md``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Tier = Literal["easy", "medium", "hard"]
# ``inconclusive`` kept in sync with soc_ai.agent.triage.Verdict (the
# self-consistency vote's split outcome). No scenario should DECLARE it as
# ground truth, but the scorer buckets it like needs_more_info (a non-decision).
Verdict = Literal["true_positive", "false_positive", "needs_more_info", "inconclusive"]

# MITRE ATT&CK technique IDs: T<4 digits>, optionally .<3 digits> for sub-technique.
_ATTACK_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


class ExpectedAction(BaseModel):
    """One rubric assertion about an action the system should recommend."""

    model_config = ConfigDict(extra="forbid")

    kind: str
    target_field: str | None = None
    reason_contains_any: list[str] = Field(default_factory=list)


class GroundTruth(BaseModel):
    """The grading rubric for one scenario."""

    model_config = ConfigDict(extra="forbid")

    verdict: Verdict
    confidence_min: float = Field(ge=0.0, le=1.0)
    required_citation_kinds: list[str] = Field(default_factory=list)
    expected_actions: list[ExpectedAction] = Field(default_factory=list)
    expected_field_reconciliation: bool = False


class EventTemplate(BaseModel):
    """One ECS-shaped event to render and ingest.

    Exactly one event per scenario must have ``is_triage_target=True`` —
    that's the alert the triage harness samples. Supporting events
    (Zeek conn, ssl, dns, ...) join via ``network.community_id``.
    """

    model_config = ConfigDict(extra="forbid")

    index: str
    time_offset_seconds: int = 0
    is_triage_target: bool = False
    fields: dict[str, Any]

    @field_validator("index")
    @classmethod
    def _index_must_start_with_logs_synth(cls, v: str) -> str:
        if not v.startswith("logs-synth-"):
            raise ValueError(
                f"index must start with 'logs-synth-' (got {v!r}); "
                f"synth pollution kill-switch depends on this prefix"
            )
        return v


class Scenario(BaseModel):
    """A complete synthetic-TP scenario.

    Loaded from one ``*.yaml`` file in ``soc_ai/eval/synth_scenarios/``.
    Renderer + ingester + scorer consume the typed object.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    version: int = Field(ge=1)
    tier: Tier
    story: str
    attack: list[str]
    sigma_refs: list[str] = Field(default_factory=list)
    ground_truth: GroundTruth
    events: list[EventTemplate]
    rubric_notes: str = ""

    @field_validator("attack")
    @classmethod
    def _attack_ids_match_mitre_pattern(cls, v: list[str]) -> list[str]:
        for tid in v:
            if not _ATTACK_ID_RE.match(tid):
                raise ValueError(
                    f"ATT&CK technique id {tid!r} does not match pattern T<4 digits>[.<3 digits>]"
                )
        return v

    @model_validator(mode="after")
    def _exactly_one_triage_target(self) -> Scenario:
        targets = [e for e in self.events if e.is_triage_target]
        if len(targets) != 1:
            raise ValueError(
                f"scenario {self.id!r} has {len(targets)} events with "
                f"is_triage_target=True; want exactly one triage target"
            )
        return self


def load_scenario_file(path: Path) -> Scenario:
    """Load and validate one scenario YAML.

    Raises ``ValueError`` if the scenario's declared ``id`` does not
    match the filename stem (caught early — file moves and id renames
    must stay in sync).
    """
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    scenario = Scenario.model_validate(raw)
    if scenario.id != path.stem:
        raise ValueError(
            f"scenario id {scenario.id!r} does not match filename stem {path.stem!r} in {path}"
        )
    return scenario


def load_all_scenarios(scenarios_dir: Path) -> list[Scenario]:
    """Load every ``*.yaml`` scenario in ``scenarios_dir``.

    Returns scenarios sorted by id for deterministic iteration.
    Non-yaml files (e.g. ``README.md``) are ignored.
    """
    paths = sorted(scenarios_dir.glob("*.yaml"))
    return [load_scenario_file(p) for p in paths]


_TIER_SELECTORS = {"easy", "medium", "hard", "all"}


def select_scenarios(scenarios: list[Scenario], *, selector: str) -> list[Scenario]:
    """Resolve a CLI-style selector into a list of scenarios.

    Selectors:
    - ``easy`` / ``medium`` / ``hard`` — all scenarios in that tier
    - ``all`` — every scenario in the catalogue
    - comma-separated explicit ids — exactly those scenarios

    Raises ``KeyError`` if any explicit id is not present.
    """
    tokens = [t.strip() for t in selector.split(",") if t.strip()]
    if len(tokens) == 1 and tokens[0] in _TIER_SELECTORS:
        only = tokens[0]
        if only == "all":
            return list(scenarios)
        return [s for s in scenarios if s.tier == only]
    by_id = {s.id: s for s in scenarios}
    missing = [t for t in tokens if t not in by_id]
    if missing:
        raise KeyError(f"unknown scenario id(s): {missing}")
    return [by_id[t] for t in tokens]
