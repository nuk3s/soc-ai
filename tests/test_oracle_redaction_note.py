"""The Oracle panel's redaction note, which took the whole detail page down.

Reported from production: opening an investigation answered 500. The traceback
ended in pydantic rejecting ``OracleOut.redactionNote``::

    Input should be a valid string
    [type=string_type, input_value={'IP': 1, 'HOST': 2}, input_type=dict]

A producer/consumer disagreement, not a grid problem. ``redaction_summary()``
(soc_ai/oracle/sanitize.py) returns per-category COUNTS — a ``dict[str, int]``
that deliberately never carries the redacted values — and the orchestrator
records it verbatim in the ``oracle_adjudication`` payload. ``_build_oracle``
then handed that dict to a field declared ``str | None``.

The shape of the bug is worth remembering: an empty dict is falsy, so the old
``redacted = bool(redaction)`` guard made the page work fine right up until
redaction had real work to do. Every run where the guard actually replaced
something — the runs an analyst most wants to read — was unopenable, and the
failure was a 500 on the whole page rather than a missing badge.
"""

from __future__ import annotations

from typing import Any

import pytest
from soc_ai.api.webui._timeline import _build_oracle, _redaction_note


class _Event:
    """The two attributes ``_build_oracle`` reads off an event row."""

    def __init__(self, kind: str, payload: dict[str, Any] | None) -> None:
        self.kind = kind
        self.payload = payload


def _events(redaction: Any) -> list[_Event]:
    return [
        _Event("oracle_escalation", {"reason": "low confidence", "local_verdict": "suspicious"}),
        _Event(
            "oracle_adjudication",
            {
                "oracle_verdict": "true_positive",
                "oracle_model": "test-model",
                "redaction": redaction,
            },
        ),
    ]


def test_the_production_payload_builds_instead_of_500ing() -> None:
    """The exact input from the reported traceback: {'IP': 1, 'HOST': 2}.

    This is the regression. Before the fix ``_build_oracle`` raised
    ``ValidationError`` here, which surfaced as an unhandled 500 on
    ``GET /api/v1/investigations/{id}`` — no Oracle panel, no page.
    """
    oracle = _build_oracle(_events({"IP": 1, "HOST": 2}))

    assert oracle is not None
    assert oracle.redacted is True
    # Singular and plural both agree with their count, and the counts survive:
    # "2 hostnames" is the fact the analyst needs to judge what went off-box.
    assert oracle.redactionNote == "1 IP address and 2 hostnames redacted before the second opinion"


def test_nothing_redacted_claims_nothing() -> None:
    """An empty summary must not grow a note — and must not claim redaction.

    The negative control. A fix that always produced a note would pass the test
    above while telling every analyst their data was redacted when it was not.
    """
    for empty in ({}, None):
        oracle = _build_oracle(_events(empty))
        assert oracle is not None
        assert oracle.redacted is False
        assert oracle.redactionNote is None


def test_a_zero_count_is_not_a_redaction() -> None:
    """``{"IP": 0}`` records that nothing was replaced, so it owes no note."""
    oracle = _build_oracle(_events({"IP": 0}))
    assert oracle is not None
    assert oracle.redacted is False
    assert oracle.redactionNote is None


@pytest.mark.parametrize(
    ("summary", "expected"),
    [
        ({"IP": 1}, "1 IP address redacted before the second opinion"),
        ({"HOST": 3}, "3 hostnames redacted before the second opinion"),
        (
            {"USER": 1, "EMAIL": 1},
            "1 username and 1 email address redacted before the second opinion",
        ),
        (
            {"IP": 2, "HOST": 1, "MAC": 4},
            "2 IP addresses, 1 hostname and 4 MAC addresses redacted before the second opinion",
        ),
    ],
)
def test_every_sanitizer_category_reads_as_english(summary: dict[str, int], expected: str) -> None:
    """One, two and three-plus categories each join correctly."""
    assert _redaction_note(summary) == expected


def test_an_unknown_category_still_counts() -> None:
    """A category added to the sanitizer later must not silently vanish.

    Falling back to the raw key keeps a new redaction type visible in the
    console the day it ships, rather than the day someone updates this map.
    """
    assert _redaction_note({"PASSPORT": 2}) == "2 passports redacted before the second opinion"


@pytest.mark.parametrize("weird", [["IP"], 7, True, object()])
def test_an_unreadable_record_never_takes_the_page_down(weird: Any) -> None:
    """Total by construction.

    This renders payloads written by arbitrarily old versions of the agent. A
    note that cannot be phrased is a cosmetic loss; an exception here is the
    whole investigation page. So anything truthy but unreadable degrades to a
    plain statement rather than raising.
    """
    note = _redaction_note(weird)
    assert isinstance(note, str) and note


def test_a_legacy_string_record_is_passed_through() -> None:
    """Older payloads that already stored a sentence keep rendering it."""
    assert _redaction_note("credentials redacted") == "credentials redacted"
    assert _redaction_note("   ") is None
