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


class AnalyticDraftOut(BaseModel):
    """What the route returns: the stored candidate and its dry run."""

    analytic_id: str
    spec_yaml: str
    rationale: str
    dry_run: DryRunResult
    status: str = "candidate"
