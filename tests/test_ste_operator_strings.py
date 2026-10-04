"""Strings an operator reads, built at runtime, carry no em dash or en dash.

The prose gate in ``test_prose_style.py`` counts the dashes in the source. A
string assembled at runtime can still carry one from a value it joins, so the
surfaces the 2026-10-01 dogfood read on a live screen are built here and read
back. Each one carried a dash before this sweep.
"""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from soc_ai.agent import hunt_gates
from soc_ai.api.agent_tools import _CATALOG
from soc_ai.api.data_sources import collect_data_sources
from soc_ai.api.schemas import LivenessResponse
from soc_ai.tools.tuning_heuristic import assess

DASH = re.compile("[—–]")


def test_healthz_checks_line_has_no_dash() -> None:
    checks = LivenessResponse.model_fields["checks"].default
    assert not DASH.search(checks), checks
    assert checks.startswith("None.")


# Every branch of the tuning heuristic: (alert_count, fp, tp, nmi, override_fp,
# triaged, is_burst).
_TUNING_CASES = [
    (500, 100, 3, 0, 0, 103, False),  # caught real signal
    (1531, 0, 0, 0, 5, 0, True),  # burst + analyst overrides
    (1531, 0, 0, 0, 0, 0, True),  # burst
    (3, 0, 0, 0, 5, 0, False),  # below floor + overrides
    (3, 0, 0, 0, 0, 0, False),  # below floor
    (500, 1, 0, 0, 5, 1, False),  # thin trend + overrides
    (500, 1, 0, 0, 0, 1, False),  # thin trend
    (1067, 53, 0, 0, 0, 53, False),  # confident mute
    (60, 30, 0, 0, 5, 30, False),  # under the bar + overrides
    (60, 30, 0, 0, 0, 30, False),  # under the bar
]


@pytest.mark.parametrize("case", _TUNING_CASES)
def test_detection_tuning_reason_has_no_dash(case: tuple[Any, ...]) -> None:
    count, fp, tp, nmi, override_fp, triaged, burst = case
    _noisy, _rec, reason = assess(count, fp, tp, nmi, override_fp, triaged=triaged, is_burst=burst)
    assert not DASH.search(reason), reason


def test_agent_tool_descriptions_have_no_dash() -> None:
    dashed = [t.name for t in _CATALOG if DASH.search(t.description)]
    assert not dashed, dashed


def test_data_source_names_and_notes_have_no_dash(tmp_path: Path) -> None:
    settings = SimpleNamespace(
        blocklist_data_dir=tmp_path,
        maxmind_data_dir=tmp_path,
        cloud_prefix_data_dir=tmp_path,
        maxmind_license_key=None,
        misp_url="",
        misp_api_key=None,
        allow_online_enrichment=True,
        greynoise_api_key=None,
        shodan_api_key=None,
    )
    for source in collect_data_sources(settings):  # type: ignore[arg-type]
        assert not DASH.search(source.name), source.name
        assert not DASH.search(source.note or ""), source.note


def test_hunt_validator_notes_say_what_happened() -> None:
    notes = (
        hunt_gates._UNRESOLVED_NOTE,
        hunt_gates._HIGH_NO_CITE_NOTE,
        hunt_gates._ALERT_ONLY_NOTE,
    )
    for note in notes:
        assert not DASH.search(note), note
        assert "Post-validator" not in note
        assert note[0].isupper(), note
