"""The "How this flows" chart: two copies, one picture, the words of the controls.

The console serves ``frontend/src/assets/hunting-flow.svg`` in the drawer the
"How this flows" link opens. The docs embed ``docs/img/hunting-flow.svg``. The
owner asked what the difference between hunt and promote is (2026-10-07), and
the chart named "Promote" on three arrows after the button changed. These tests
keep the two copies identical and keep the chart on the words of the controls.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CONSOLE_COPY = REPO_ROOT / "frontend" / "src" / "assets" / "hunting-flow.svg"
DOCS_COPY = REPO_ROOT / "docs" / "img" / "hunting-flow.svg"


def _chart() -> str:
    return CONSOLE_COPY.read_text(encoding="utf-8")


def test_the_two_copies_are_identical() -> None:
    assert CONSOLE_COPY.read_bytes() == DOCS_COPY.read_bytes()


def test_the_chart_uses_the_words_of_the_console() -> None:
    # The two verbs ("Hunt this lead", "Open an investigation") left the chart
    # on 2026-11-16. The definition lines under the chart carry them.
    chart = _chart()
    for word in ("Hit", "Needs you", "Campaign", "Your decision on a campaign"):
        assert word in chart, word


def test_the_chart_draws_the_alert_path_beside_the_sweep_path() -> None:
    chart = _chart()
    assert "THE SWEEP PATH" in chart
    assert "THE ALERT PATH" in chart
    for box in ("Alert", "Investigation", "Verdict", "Campaign", "Action in Security Onion"):
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


def test_the_chart_uses_the_console_definitions() -> None:
    # Dogfood 2026-10-19, V1-S2: the chart kept the older definitions and
    # named the "Overview tile". The console says "Dashboard", "An analytic is
    # one written detection" and "A hit is one match of one analytic".
    chart = _chart()
    for words in (
        "One written detection.",
        "One match of one analytic",
        "One search of the grid",
        "the Dashboard",
        "each threat finding that names an entity",
    ):
        assert words in chart, words


def test_the_chart_states_the_leads_and_hunts_of_a_campaign() -> None:
    # Leads and hunts of a campaign (2026-11-16): a lead of a campaign waits on
    # it, a change of a campaign starts at most one hunt in 24 hours, a hunt
    # reads the open campaigns, and a finding that a campaign holds gets no
    # investigation of its own.
    chart = _chart()
    for words in (
        "A lead of a campaign waits on",
        "a change starts",
        "one in 24 hours",
        "It reads the open campaigns.",
        "unless a campaign holds it",
        # One Security Onion case for a campaign (part C).
        "Open one case: one Security Onion",
        "holds at most",
        "an investigation in no campaign recommends",
    ):
        assert words in chart, words


def test_the_chart_states_no_retired_claim() -> None:
    # Negative control: a hunt investigates its threat findings, and two
    # findings can share one investigation. The chart said every finding.
    chart = _chart()
    for words in (
        "Overview",
        "detection logic",
        "not finished until",
        "its own investigation",
        "investigates each one",
        ">each finding<",
        # Review of 2026-11-14: the console has no Agree control, only a press
        # on a finding writes an observation, and a hunt finding can start a
        # campaign.
        "Agree",
        "agree",
        "a threat finding writes an observation",
        "starts none",
        ">Two verbs<",
    ):
        assert words not in chart, words


def test_the_chart_uses_no_retired_word() -> None:
    # An investigation is no "run" and no "member", the network is no
    # "estate", and the user-facing word is "type".
    words = " ".join(re.findall(r"<text[^>]*>([^<]*)</text>", _chart()))
    for word in ("run", "runs", "member", "members", "estate", "kind"):
        assert not re.search(rf"\b{word}\b", words, re.IGNORECASE), word
