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


class HuntJourney(BaseModel):
    """What a correct hunt JOURNEY looks like for this scenario.

    Optional on :class:`Scenario`: absent means the scenario is single-alert
    only, which is most of the catalogue as shipped.
    """

    model_config = ConfigDict(extra="forbid")

    objective: str
    """The plain-English objective to run the hunt with."""

    expected_cited_event_ids: list[str] = Field(min_length=1)
    """Scenario-local event ids a correct finding should cite. At least one.

    Events carry no id field, so ids here are event ``index`` values — the
    natural scenario-local identifier (Elasticsearch ``_id`` values only
    exist after ingest). Each must name an event in the scenario's own
    ``events`` list; the loader rejects anything else.

    REQUIRED, with a floor of one, because an empty list makes the citation
    half of the rubric vacuous — every finding "cites everything expected", so
    a journey can reach COMPLETE on the promoted verdict alone. Required
    rather than defaulted: Pydantic does not validate defaults, so a
    ``default_factory=list`` beside ``min_length=1`` would refuse an explicit
    ``[]`` while admitting the same vacuous rubric spelled by omission.
    """

    expected_promoted_verdict: Verdict
    """The verdict the promoted investigation should reach."""


class SpecJourney(BaseModel):
    """What a correct DECLARATIVE hunt looks like for this scenario.

    The catalogue was built entirely around a triage target: every scenario
    opens with an alert, and the journey rubric starts at an LLM hunt. That
    shape cannot express the case proactive hunting exists for — an attack that
    produces real telemetry and no alert at all. The identity chain on the
    development range is exactly that, and Security Onion's own rules saw two
    of its five techniques, both of them late.

    A scenario carrying this block declares which spec should fire on it, on
    which entity, and how many candidates. That half is scored with no model
    call at all, which also means a spec regression is diagnosable: if the spec
    did not fire there is no point asking why the hunt agent missed the finding.
    """

    model_config = ConfigDict(extra="forbid")

    spec_id: str
    """The catalog spec expected to fire (``soc_ai/hunting/catalog/<id>.yaml``)."""

    expected_scope_keys: list[str] = Field(min_length=1)
    """The scope keys a correct run should surface, e.g. the account name.

    Floor of one for the same reason ``expected_cited_event_ids`` has one: an
    empty list makes the assertion vacuous, and every run trivially satisfies
    it.
    """

    expected_candidate_count: int | None = None
    """Exact candidate count, when it is a fact worth pinning. ``None`` means
    "at least one per expected scope key" and is the right default for a spec
    whose count depends on how many documents the render happens to emit."""


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
    hunt_journey: HuntJourney | None = None
    spec_journey: SpecJourney | None = None

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
    def _at_most_one_triage_target(self) -> Scenario:
        """One triage target, or none if the scenario declares a spec journey.

        Was "exactly one", which made the catalogue structurally incapable of
        expressing the thing proactive hunting is for: an attack that produces
        real telemetry and never becomes an alert. Every scenario therefore
        opened with a ``suricata.alert``, and a no-alert scenario was not a
        gap in the catalogue so much as a gap in the schema.

        Zero is admitted ONLY alongside ``spec_journey``. Without it a
        target-less scenario would be unscoreable by anything — the triage
        harness has no alert to sample and the hunt journey has no verdict to
        promote — so it would render perfectly and measure nothing, which this
        catalogue has produced before.
        """
        targets = [e for e in self.events if e.is_triage_target]
        if len(targets) > 1:
            raise ValueError(
                f"scenario {self.id!r} has {len(targets)} events with "
                f"is_triage_target=True; want at most one triage target"
            )
        if not targets and self.spec_journey is None:
            raise ValueError(
                f"scenario {self.id!r} has no triage target and no spec_journey. A "
                "scenario with neither cannot be scored by anything: there is no alert "
                "for the triage harness to sample and no spec expectation to check, so "
                "it would render perfectly and measure nothing."
            )
        return self

    @model_validator(mode="after")
    def _no_same_as_triage_without_a_triage_target(self) -> Scenario:
        """``{{ same_as_triage }}`` needs a triage target to resolve against.

        The renderer raises on this, but at render time, which on a batch run is
        after the scenario has been selected and the plant has begun. Catching it
        at load makes it a file-is-wrong error instead of a run-failed one.
        """
        if any(e.is_triage_target for e in self.events):
            return self
        offenders = [
            e.index
            for e in self.events
            if any(isinstance(v, str) and "same_as_triage" in v for v in e.fields.values())
        ]
        if offenders:
            raise ValueError(
                f"scenario {self.id!r} has no triage target but uses "
                f"'{{{{ same_as_triage }}}}' in {offenders}; there is no triage "
                "community_id for it to resolve to"
            )
        return self

    @model_validator(mode="after")
    def _spec_journey_needs_events_outside_the_alert(self) -> Scenario:
        """A spec journey over nothing but its own triage alert proves nothing.

        The point of the declarative catalog is that it reads telemetry the
        alert queue never carried. A scenario whose only event IS the alert
        would let a spec "fire" on the very document a triage run would have
        been handed anyway.
        """
        if self.spec_journey is None:
            return self
        non_alert = [e for e in self.events if not e.is_triage_target]
        if not non_alert:
            raise ValueError(
                f"scenario {self.id!r} declares a spec_journey but every event is the "
                "triage target; a spec firing on the alert itself demonstrates nothing "
                "about hunting beyond the alert queue"
            )
        return self

    @model_validator(mode="after")
    def _journey_cites_only_events_that_exist(self) -> Scenario:
        # A typo'd id would silently make the journey unscoreable — the
        # scorer would look for an event that does not exist and report a
        # false failure. Event ids are event ``index`` values.
        if self.hunt_journey is None:
            return self
        known = {e.index for e in self.events}
        unknown = [i for i in self.hunt_journey.expected_cited_event_ids if i not in known]
        if unknown:
            raise ValueError(
                f"scenario {self.id!r} hunt_journey cites unknown event id(s) "
                f"{unknown}; known ids (event indices): {sorted(known)}"
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


def triage_scenarios(scenarios: list[Scenario]) -> list[Scenario]:
    """The alert-driven population: the instrument the triage harness measures.

    A ``spec_journey`` scenario has no triage target by design, so the harness
    would have no alert to sample. Handing it one anyway does not fail loudly;
    it scores as a miss, which silently DEPRESSES recall with a scenario that
    was never triageable. Those scenarios are scored by
    :mod:`soc_ai.eval.spec_journey` instead, and the two populations are never
    pooled — the same rule the precision/recall scorer already applies to real
    versus synthetic strata.
    """
    return [s for s in scenarios if s.spec_journey is None]


def spec_scenarios(scenarios: list[Scenario]) -> list[Scenario]:
    """The declarative population: telemetry that never becomes an alert."""
    return [s for s in scenarios if s.spec_journey is not None]


def select_scenarios(scenarios: list[Scenario], *, selector: str) -> list[Scenario]:
    """Resolve a CLI-style selector into a list of scenarios.

    Selectors:
    - ``easy`` / ``medium`` / ``hard`` — all TRIAGE scenarios in that tier
    - ``all`` — every TRIAGE scenario in the catalogue
    - comma-separated explicit ids — exactly those scenarios, whichever
      population they belong to

    The tier and ``all`` selectors resolve over :func:`triage_scenarios` only.
    A caller naming a ``spec_journey`` scenario explicitly gets it, because an
    explicit id is an explicit request; a caller sweeping ``all`` is running the
    triage harness and must not be handed a scenario with no alert in it.

    Raises ``KeyError`` if any explicit id is not present.
    """
    tokens = [t.strip() for t in selector.split(",") if t.strip()]
    if len(tokens) == 1 and tokens[0] in _TIER_SELECTORS:
        only = tokens[0]
        triage = triage_scenarios(scenarios)
        if only == "all":
            return triage
        return [s for s in triage if s.tier == only]
    by_id = {s.id: s for s in scenarios}
    missing = [t for t in tokens if t not in by_id]
    if missing:
        raise KeyError(f"unknown scenario id(s): {missing}")
    return [by_id[t] for t in tokens]
