"""Structured-output + validator-annotated shapes for the detection bridge.

:class:`SigmaDraft` is the drafter agent's (Task 2) structured output: the
deployable Sigma rule (``sigma_yaml``), the equivalent OQL detection logic
that drives the deterministic would-have-fired dry run (``oql``), and the
grounding rationale. ``extra="forbid"`` keeps a drifting model from smuggling
extra keys past validation. The trailing three fields (``validator_note``,
``schema_ok``, ``dry_run``) are never set by the model — only the
deterministic validators in :mod:`soc_ai.detection.validators` (Task 3) set
them, via ``model_copy(update=...)``, mirroring
:func:`soc_ai.agent.hunt_gates._validate_hunt_findings`.

:class:`DryRunResult` is the would-have-fired evidence nested under
``SigmaDraft.dry_run``.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class DryRunResult(BaseModel):
    """Deterministic 'would-have-fired' evidence — set by the validator, never the model."""

    ran: bool
    hit_count: int = 0
    total_is_lower_bound: bool = False
    sample_ids: list[str] = Field(default_factory=list)
    window_days: int = 30
    error: str | None = None


class SigmaDraft(BaseModel):
    """A drafted detection: the deployable Sigma rule + the OQL that IS its dry-run logic."""

    model_config = ConfigDict(extra="forbid")

    # max_length on every model-authored field: an over-long value is rejected
    # at parse time, so the structured-output retry loop corrects a runaway
    # model instead of a giant draft flowing downstream. oql's 2048 matches
    # query_events_oql's _MAX_OQL_LEN (the same ceiling the HTTP q params use).
    title: str = Field(description="Short rule title, ≤ 80 chars.", max_length=200)
    sigma_yaml: str = Field(
        description="A complete Sigma rule as YAML. logsource + detection + condition.",
        max_length=16384,
    )
    oql: str = Field(
        description=(
            "The SAME detection logic as an OQL query (the dry-run vehicle). "
            "No | count — the validator adds it."
        ),
        max_length=2048,
    )
    rationale: str = Field(
        description=(
            "2-4 sentences: what this fires on and why the finding's evidence justifies it."
        ),
        max_length=2000,
    )
    # Set by validators, never the model:
    validator_note: str | None = None
    schema_ok: bool | None = None
    dry_run: DryRunResult | None = None
