"""Fixes from the second UI dogfood (2026-09-17), pinned.

Each of these was a screen reading wrong while the data behind it was right.
"""

from __future__ import annotations

from types import SimpleNamespace

from soc_ai.api.webui.routes_hunts import _hunt_outcome
from soc_ai.api.webui.routes_investigations import _note_or_none
from soc_ai.hunting.findings import plain_error
from soc_ai.hunting.prior_sweep import _phrase
from soc_ai.hunting.weight import Kind

_GAP_FAILED = {"title": "DCSync: could not run", "category": "visibility_gap", "severity": "medium"}
_GAP_BLIND = {"title": "DCSync: no telemetry", "category": "visibility_gap", "severity": "medium"}
_THREAT = {"title": "DCSync from a workstation", "category": "threat", "severity": "high"}


# --- Hunts list: a hunt that never ran is not "Complete · 1 finding" ----------


def test_a_failed_run_is_not_a_complete_hunt_with_a_finding() -> None:
    assert _hunt_outcome("complete", [_GAP_FAILED]) == (0, "failed")


def test_no_telemetry_is_a_gap_not_a_clean_result() -> None:
    assert _hunt_outcome("complete", [_GAP_BLIND]) == (0, "gap")


def test_threat_findings_are_counted_and_gaps_are_not() -> None:
    assert _hunt_outcome("complete", [_THREAT, _GAP_FAILED]) == (1, "threats")


def test_an_empty_complete_hunt_is_clean() -> None:
    assert _hunt_outcome("complete", []) == (0, "clean")


def test_outcome_is_blank_until_the_hunt_completes() -> None:
    assert _hunt_outcome("running", [_THREAT]) == (1, "")
    assert _hunt_outcome("error", [_GAP_FAILED]) == (0, "")


def test_non_dict_findings_do_not_crash_the_row() -> None:
    assert _hunt_outcome("complete", ["garbage", None, _THREAT]) == (1, "threats")


# --- The exception text is not the sentence an analyst should read -----------


def test_a_timeout_reads_as_a_sentence_with_its_stage() -> None:
    raw = "precondition: ConnectionTimeout caused by TimeoutError(...)"
    assert (
        plain_error(raw) == "The data source did not answer in time during the precondition query."
    )


def test_an_unknown_error_passes_through_unchanged() -> None:
    assert plain_error("detection: KeyError('nope')") == "detection: KeyError('nope')"
    assert plain_error(None) == ""


# --- "Post-validator override — null" ------------------------------------------


def test_the_string_null_is_not_a_validator_note() -> None:
    assert _note_or_none("null") is None
    assert _note_or_none(" None ") is None
    assert _note_or_none("") is None
    assert _note_or_none(None) is None
    assert _note_or_none("verdict lowered: the pivot cited no document") == (
        "verdict lowered: the pivot cited no document"
    )


# --- Headlines in the analyst's words, not the data model's ---------------------


def _dep(dimension: str, member: object, count: int) -> SimpleNamespace:
    return SimpleNamespace(dimension=dimension, member=member, observed_count=count)


def _rate_dep(dimension: str, member: str, *, value: float, median: float) -> SimpleNamespace:
    return SimpleNamespace(
        dimension=dimension,
        member=member,
        observed_count=int(value),
        observed_value=value,
        baseline_median=median,
        ratio=value / median,
    )


def test_novelty_names_the_noun_and_counts_in_words() -> None:
    text = _phrase(Kind.NOVEL_DESTINATION, _dep("peers_out", "10.0.0.5", 3))
    assert text == "new outbound peer for this host: 10.0.0.5. The sweep saw it 3 times"
    assert "x3" not in text and "peers_out" not in text


def test_off_hours_names_the_hour_not_the_cell() -> None:
    text = _phrase(Kind.OFF_HOURS, _dep("active_hours", 3, 12))
    assert "03:00 UTC" in text and "cell" not in text


def test_rate_departures_state_the_numbers_instead_of_far_above() -> None:
    """ "Far above" described a 13 % move, over a median nobody could see.

    The observation said one median and the profile panel said another for the
    same cell. The sentence now carries the rate, the median and the multiple,
    so the reader can judge the distance instead of taking the word for it.
    """
    up = _rate_dep("connection_rate", "work", value=2446.0, median=2216.0)
    down = _rate_dep("connection_rate", "off", value=12.0, median=240.0)
    assert _phrase(Kind.ABOVE_BASELINE, up) == (
        "The connection rate during working hours is 2446 per hour. "
        "The median is 2216 per hour. That is 1.1 times the median"
    )
    assert _phrase(Kind.BELOW_BASELINE, down) == (
        "The connection rate during off-hours is 12 per hour. "
        "The median is 240 per hour. That is 0.1 times the median"
    )
    assert "far above" not in _phrase(Kind.ABOVE_BASELINE, up)
    assert "cell" not in _phrase(Kind.BELOW_BASELINE, down)


# --- Rows written by an older build read in today's words -----------------------


def test_legacy_summaries_are_reworded_on_the_way_out() -> None:
    from soc_ai.hunting.wording import reword_legacy_summary

    hour = (
        "active at hour 23 — outside this entity's measured hours (7 events)"
        " — against a baseline of 15 over 8d"
    )
    assert reword_legacy_summary(hour) == (
        "active around 23:00 UTC. This host is not normally active then (7 events)."
        " The baseline holds 15 values over 8 days."
    )
    above = "connection_rate in the off cell is far ABOVE its own median (129/h)"
    assert reword_legacy_summary(above) == (
        "connection rate during off-hours is far above this host's own median (129/h)"
    )
    cell = "connection rate around off has collapsed against this host's own median (2/h)"
    assert reword_legacy_summary(cell) == (
        "connection rate during off-hours has collapsed against this host's own median (2/h)"
    )
    assert reword_legacy_summary("novel peers_out: 10.0.0.5 x3") == (
        "new outbound peer for this host: 10.0.0.5. The sweep saw it 3 times"
    )
    assert reword_legacy_summary(None) is None
    today = "new DNS name for this host: a.example. The sweep saw it once"
    assert reword_legacy_summary(today) == today


def test_the_colon_free_legacy_headline_reads_as_a_sentence() -> None:
    """The host page showed "novel connection_rate off x2782".

    An earlier build wrote the headline with no colon, so the rewording missed
    it entirely and the data model was on the screen. The rate is not a novel
    member either: 2782 is the rate itself.
    """
    from soc_ai.hunting.wording import reword_legacy_summary

    assert reword_legacy_summary(
        "novel connection_rate off x2782 — against a baseline of 3 over 13d"
    ) == (
        "The connection rate during off-hours is 2782 per hour. "
        "The baseline holds 3 values over 13 days."
    )
    assert reword_legacy_summary("novel served_ports 445 x9") == (
        "new served port for this host: 445. The sweep saw it 9 times"
    )


def test_the_legacy_seen_and_baseline_tails_become_sentences() -> None:
    from soc_ai.hunting.wording import reword_legacy_summary

    row = (
        "new outbound peer for this host: 10.0.0.5 (seen 3 times)"
        " — against a baseline of 15 over 8d"
    )
    assert reword_legacy_summary(row) == (
        "new outbound peer for this host: 10.0.0.5. The sweep saw it 3 times. "
        "The baseline holds 15 values over 8 days."
    )
    assert reword_legacy_summary("a thing (seen once) — against a baseline of 1 over 1d") == (
        "a thing. The sweep saw it once. The baseline holds 1 value over 1 day."
    )
