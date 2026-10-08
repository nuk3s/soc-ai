"""The "How this flows" chart: two copies, one picture, the words of the controls.

The console serves ``frontend/src/assets/hunting-flow.svg`` in the drawer the
"How this flows" link opens. The docs embed ``docs/img/hunting-flow.svg``. The
owner asked what the difference between hunt and promote is (2026-10-07), and
the chart named "Promote" on three arrows after the button changed. These tests
keep the two copies identical and keep the chart on the words of the controls.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CONSOLE_COPY = REPO_ROOT / "frontend" / "src" / "assets" / "hunting-flow.svg"
DOCS_COPY = REPO_ROOT / "docs" / "img" / "hunting-flow.svg"


def _chart() -> str:
    return CONSOLE_COPY.read_text(encoding="utf-8")


def test_the_two_copies_are_identical() -> None:
    assert CONSOLE_COPY.read_bytes() == DOCS_COPY.read_bytes()


def test_the_chart_uses_the_words_of_the_controls() -> None:
    chart = _chart()
    for word in ("Hunt this lead", "Open an investigation", "Hit", "Needs you"):
        assert word in chart, word


def test_the_chart_draws_the_alert_path_beside_the_sweep_path() -> None:
    chart = _chart()
    assert "THE SWEEP PATH" in chart
    assert "THE ALERT PATH" in chart
    for box in ("Alert", "Investigation", "Verdict", "Action in Security Onion"):
        assert f">{box}<" in chart, box


def test_the_chart_names_no_retired_control() -> None:
    # Negative control: the word the owner could not tell from "Hunt".
    chart = _chart()
    assert "Promote" not in chart
    assert "promote" not in chart


def test_the_chart_carries_no_dash_and_no_ellipsis() -> None:
    chart = _chart()
    for mark in ("\u2014", "\u2013", "\u2026", "..."):
        assert mark not in chart, repr(mark)
