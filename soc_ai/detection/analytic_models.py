"""A drafted analytic: a catalog spec the model wrote from a confirmed finding."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from soc_ai.detection.models import DryRunResult


class AnalyticDraft(BaseModel):
    """The model's output. Validated by parse_spec before anything stores it."""

    model_config = ConfigDict(extra="forbid")

    spec_yaml: str = Field(
        description=(
            "One catalog analytic as YAML: id, title, description, level, "
            "scope_field, scope_kind, precondition, detection, false_positives."
        ),
        max_length=12000,
    )
    rationale: str = Field(
        description="2 to 4 sentences. What it fires on and which evidence justifies it.",
        max_length=2000,
    )


class Generalization(BaseModel):
    """What the generalization check found on the draft the route returns.

    ``pinned`` holds one sentence per pin. Empty means the analytic describes a
    behaviour. ``retried`` says the model rewrote the draft once.
    """

    pinned: list[str] = []
    retried: bool = False


class AnalyticDraftOut(BaseModel):
    """What the route returns: the stored candidate and its dry run."""

    analytic_id: str
    spec_yaml: str
    rationale: str
    dry_run: DryRunResult
    # ``candidate`` once stored. ``preview`` for a draft the route did not store.
    status: str = "candidate"
    # What the draft could not read, in the analyst's words. A slow grid
    # leaves the draft to the stored finding, and the note says so.
    notes: list[str] = []
    # None when the check found nothing on the first draft.
    generalization: Generalization | None = None
