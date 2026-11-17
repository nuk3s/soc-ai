"""A hunt finding states its stage (recommendation 7, H3).

The rule that a finding restates a campaign compares the stage of the finding
with the stage that the campaign reached. ``HuntFinding`` gains one optional
field, ``stage``. The normalizer of the triage report folds it to one of the
five values, or drops it. No other field of the hunt report changes.
"""

from __future__ import annotations

import pytest
from soc_ai.agent.hunt import HuntFinding, HuntReport
from soc_ai.campaigns.types import STAGES


@pytest.mark.parametrize(
    ("raw", "kept"),
    [
        ("access", "access"),
        (" Action. ", "action"),
        ("MOVEMENT", "movement"),
        ("lateral movement", None),
        ("exfiltration", None),
        ("", None),
        (None, None),
        (3, None),
    ],
)
def test_the_stage_folds_to_one_of_five_values_or_drops(raw: object, kept: str | None) -> None:
    finding = HuntFinding.model_validate({"title": "t", "detail": "d", "stage": raw})

    assert finding.stage == kept


def test_a_finding_with_no_stage_reads_none_and_keeps_its_old_shape() -> None:
    finding = HuntFinding(title="t", detail="d")

    assert finding.stage is None
    old = {"narrative": "n", "findings": [{"title": "t", "detail": "d"}]}
    assert HuntReport.model_validate(old).findings[0].stage is None


def test_the_schema_names_the_five_stages_and_no_other_field_changes() -> None:
    schema = HuntFinding.model_json_schema()
    description = str(schema["properties"]["stage"]["description"])

    for stage in STAGES:
        assert f"{stage}:" in description
    assert set(HuntFinding.model_fields) == {
        "title",
        "detail",
        "severity",
        "category",
        "hosts",
        "citations",
        "stage",
        "validator_note",
    }
    # Negative control: the schema still forbids a field that it does not know.
    with pytest.raises(ValueError, match="extra"):
        HuntFinding.model_validate({"title": "t", "detail": "d", "phase": "access"})
