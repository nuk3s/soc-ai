"""The statistic sentences the hunt reads match the ones the console shows.

The backend writes the subject block of a lead hunt from
``soc_ai.hunting.wording.statistic_sentence``. The console states the same
statistics from ``frontend/src/lib/statistics.ts``, and
``frontend/src/lib/statistics.test.ts`` pins the same strings there.
"""

from __future__ import annotations

import pytest
from soc_ai.hunting.wording import (
    estate_sentence,
    peer_sentence,
    scope_sentence,
    statistic_sentence,
)


@pytest.mark.parametrize(
    ("statistic", "value", "baseline", "sentence"),
    [
        (
            "documents",
            6,
            2,
            "6 documents in the recent window. The set it is new to holds 2 members.",
        ),
        ("documents", 1, None, "1 document matched."),
        ("hour_documents", 14, 0, "14 documents in an hour with no activity in the baseline."),
        ("estate_hosts", 0, 40, "0 of 40 profiled hosts hold this member."),
        ("estate_hosts", 1, 40, "1 of 40 profiled hosts holds this member."),
        (
            "hosts_departing",
            3,
            1,
            "3 hosts gained this member in one sweep. 1 host held it before.",
        ),
        (
            "residual_z",
            90,
            100,
            "A residual z of 90 against an expected 100 per hour for that hour of the week.",
        ),
        ("peer_share", 0, 5, "0 of 5 peers in the role hold this member."),
        (
            "plane_documents",
            0,
            412,
            "0 documents on the silent plane in the silent hours. "
            "The baseline expects 412 in those hours.",
        ),
        (
            "chain_minutes",
            3.5,
            2,
            "The attempt came 3.5 minutes after the session. "
            "The host held 2 learned outbound edges.",
        ),
        (
            "chain_minutes",
            1,
            1,
            "The attempt came 1 minute after the session. The host held 1 learned outbound edge.",
        ),
        ("something_new", 2.5, 1, "something_new 2.5 against a baseline of 1."),
    ],
)
def test_each_statistic_reads_as_the_console_reads_it(
    statistic: str, value: float, baseline: float | None, sentence: str
) -> None:
    assert statistic_sentence(statistic, value, baseline) == sentence


def test_a_row_with_no_statistic_states_nothing() -> None:
    assert statistic_sentence(None, None, None) == ""
    assert statistic_sentence("documents", None, 2) == ""


def test_the_peer_group_reads_in_words() -> None:
    assert peer_sentence(0, 5, "server") == "None of the 5 server peers holds it"
    assert peer_sentence(1, 5, "server") == "1 of the 5 server peers holds it"
    assert peer_sentence(3, 6, None) == "3 of the 6 peers hold it"


def test_the_estate_and_the_spread_read_in_words() -> None:
    assert estate_sentence(0, 4) == "None of the 4 profiled hosts holds it"
    assert estate_sentence(1, 4) == "1 of 4 profiled hosts holds it"
    assert estate_sentence(3, 40) == "3 of 40 profiled hosts hold it"
    assert (
        scope_sentence("served_ports", "4444", hosts=3, holders=1)
        == "3 hosts gained the served port 4444 in one sweep. 1 host held it before"
    )
    assert scope_sentence("served_ports", "4444", hosts=3, holders=None) == (
        "3 hosts gained the served port 4444 in one sweep"
    )
