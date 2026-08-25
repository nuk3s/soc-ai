"""Tests for the detection-bridge models (:mod:`soc_ai.detection.models`).

Pins the two structured-output/validator-annotated shapes the detection
drafter (Task 2) and the deterministic validators (Task 3) build on:

* :class:`~soc_ai.detection.models.SigmaDraft` — the drafter's structured
  output. ``extra="forbid"`` so a drifting model can't smuggle extra keys
  past validation; the validator-set fields (``validator_note``,
  ``schema_ok``, ``dry_run``) default to ``None`` because the model never
  sets them — only :mod:`soc_ai.detection.validators` does.
* :class:`~soc_ai.detection.models.DryRunResult` — the would-have-fired
  evidence nested under ``SigmaDraft.dry_run``.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from soc_ai.detection.models import DryRunResult, SigmaDraft


def _draft(**overrides: object) -> SigmaDraft:
    fields: dict[str, object] = {
        "title": "Zerologon NetrServerAuthenticate3 anomaly",
        "sigma_yaml": (
            "title: Zerologon NetrServerAuthenticate3 anomaly\n"
            "logsource:\n"
            "  category: dce_rpc\n"
            "detection:\n"
            "  selection:\n"
            "    dce_rpc.operation: NetrServerAuthenticate3\n"
            "  condition: selection\n"
        ),
        "oql": "event.dataset:zeek.dce_rpc AND zeek.dce_rpc.operation:NetrServerAuthenticate3",
        "rationale": (
            "The finding's citations show repeated NetrServerAuthenticate3 calls from "
            "a single source host, which is the Zerologon authentication-bypass pattern. "
            "Keying on the operation name is specific to the observed evidence."
        ),
    }
    fields.update(overrides)
    return SigmaDraft(**fields)  # type: ignore[arg-type]


def test_sigma_draft_validator_fields_default_none() -> None:
    draft = _draft()
    assert draft.validator_note is None
    assert draft.schema_ok is None
    assert draft.dry_run is None


def test_sigma_draft_content_fields_roundtrip() -> None:
    draft = _draft()
    assert draft.title == "Zerologon NetrServerAuthenticate3 anomaly"
    assert "NetrServerAuthenticate3" in draft.sigma_yaml
    assert "NetrServerAuthenticate3" in draft.oql
    assert draft.rationale


def test_sigma_draft_extra_forbid_rejects_unknown_key() -> None:
    with pytest.raises(ValidationError):
        _draft(deploy_now=True)


def test_dry_run_result_requires_ran_and_has_defaults() -> None:
    result = DryRunResult(ran=True)
    assert result.ran is True
    assert result.hit_count == 0
    assert result.total_is_lower_bound is False
    assert result.sample_ids == []
    assert result.window_days == 30
    assert result.error is None


def test_dry_run_result_ran_is_required() -> None:
    with pytest.raises(ValidationError):
        DryRunResult()  # type: ignore[call-arg]


def test_sigma_draft_model_dump_json_roundtrips() -> None:
    draft = _draft(
        dry_run=DryRunResult(ran=True, hit_count=4, sample_ids=["a", "b"]),
        schema_ok=True,
        validator_note="ok",
    )
    dumped = draft.model_dump(mode="json")
    restored = SigmaDraft.model_validate(dumped)
    assert restored == draft


@pytest.mark.parametrize(
    ("field", "limit"),
    [
        ("title", 200),
        ("oql", 2048),
        ("rationale", 2000),
        ("sigma_yaml", 16384),
    ],
)
def test_sigma_draft_over_long_field_is_rejected(field: str, limit: int) -> None:
    """Each model-authored field has a hard length cap, so a runaway model gets
    a structured-output retry instead of a giant draft flowing downstream."""
    with pytest.raises(ValidationError):
        _draft(**{field: "x" * (limit + 1)})


def test_sigma_draft_field_at_limit_is_accepted() -> None:
    """Exactly at the cap is fine — the cap rejects only the over-long case."""
    draft = _draft(rationale="x" * 2000)
    assert len(draft.rationale) == 2000


def test_sigma_draft_nests_dry_run_result() -> None:
    draft = _draft(dry_run=DryRunResult(ran=True, hit_count=4, sample_ids=["a", "b"]))
    assert draft.dry_run is not None
    assert draft.dry_run.ran is True
    assert draft.dry_run.hit_count == 4
    assert draft.dry_run.sample_ids == ["a", "b"]
    assert draft.dry_run.total_is_lower_bound is False
    assert draft.dry_run.window_days == 30
