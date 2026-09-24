"""Imports must not silently become the baseline.

The numbers behind this module, measured on the development range 2026-09-04:
19,604,032 of 23,055,409 documents carry ``import.id``, 5,839 more carry a
``replayed-corpus`` tag, and live telemetry is 3,456,959 — 15% of the grid.
A novelty or rarity test run without this filter is measuring an imported EVTX
corpus and a replayed cloud corpus, not the network.
"""

from __future__ import annotations

from typing import Any

import pytest
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.tools._provenance import (
    ANY,
    LIVE,
    count_imports,
    denominator_note,
    imported_filter,
    imports_note,
    provenance_must_not,
)


def test_live_excludes_both_markers() -> None:
    clauses = provenance_must_not(LIVE)
    assert {"exists": {"field": "import.id"}} in clauses
    assert {"term": {"tags": "replayed-corpus"}} in clauses


def test_any_excludes_nothing() -> None:
    """Retro-hunting a newly published indicator must see full retention."""
    assert provenance_must_not(ANY) == []


def test_live_is_the_default() -> None:
    """A caller that has not thought about provenance gets the safe population."""
    assert provenance_must_not() == provenance_must_not(LIVE)


def test_an_unknown_value_narrows_rather_than_widens() -> None:
    """A typo in a spec's ``provenance:`` field must not admit backfill.

    Failing toward LIVE costs a missed finding. Failing toward ANY costs a
    baseline computed over someone else's network, which is worse because it is
    silent.
    """
    assert provenance_must_not("livee") == provenance_must_not(LIVE)
    assert provenance_must_not("") == provenance_must_not(LIVE)


def test_an_operator_can_name_their_own_replay_tag() -> None:
    clauses = provenance_must_not(LIVE, extra_replay_tags=("lab-training-set",))
    assert {"term": {"tags": "lab-training-set"}} in clauses
    assert {"term": {"tags": "replayed-corpus"}} in clauses


def test_the_clauses_are_valid_elasticsearch_must_not_shape() -> None:
    """Spliced straight into a bool query, so every clause must be a single-key dict."""
    for clause in provenance_must_not(LIVE, extra_replay_tags=("x",)):
        assert isinstance(clause, dict)
        assert len(clause) == 1
        assert next(iter(clause)) in {"exists", "term"}


def test_so_own_import_tag_is_not_matched_redundantly() -> None:
    """``tags:import`` sits on the same documents ``import.id`` already covers.

    Matching both would make the clause redundant rather than stronger, and on
    this grid the two counts differ (19,247,287 vs 19,604,032), so treating them
    as interchangeable would misstate which one is authoritative.
    """
    clauses = provenance_must_not(LIVE)
    assert {"term": {"tags": "import"}} not in clauses


# ---------------------------------------------------------------------------
# The disclosure half. A filter that narrows a denominator without saying so
# is the same defect wearing a different coat, so the exclusion and the sentence
# describing it are built in one place and tested together.
# ---------------------------------------------------------------------------


def test_the_complement_selects_exactly_what_live_excludes() -> None:
    """The two must partition one population, or the probe measures a third thing.

    Built from the same clause list rather than a second hand-written one, so
    adding a replay tag cannot teach the exclusion about a marker the probe
    still does not know.
    """
    clauses = provenance_must_not(LIVE, extra_replay_tags=("lab-training-set",))
    inner = imported_filter(extra_replay_tags=("lab-training-set",))["bool"]
    assert inner["should"] == clauses
    assert inner["minimum_should_match"] == 1


def test_the_note_says_which_population_without_needing_a_paragraph() -> None:
    """It has to fit inside a one-line summary or it will not be carried there."""
    assert "live telemetry only" in denominator_note(LIVE)
    assert "imported" in denominator_note(ANY)
    assert denominator_note() == denominator_note(LIVE)


def test_an_unmeasured_backfill_is_never_reported_as_no_backfill() -> None:
    """Three outcomes, three sentences. The dangerous collapse is None into zero.

    A probe that failed and a grid that holds nothing produce the same absent
    number, and reporting them alike restores the ambiguity the probe exists to
    resolve — while sounding certain about it.
    """
    assert imports_note(0) == ""
    assert "could not be measured" in imports_note(None)
    assert "40000" in imports_note(40_000)
    assert imports_note(None) != imports_note(0)


class _FakeElastic:
    def __init__(self, result: EsSearchResult | Exception) -> None:
        self._result = result
        self.calls: list[dict[str, Any]] = []

    async def search(self, index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        self.calls.append({"index": index, "query": query, **kwargs})
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


@pytest.mark.asyncio
async def test_the_probe_asks_about_the_callers_own_question() -> None:
    """It wraps the caller's query rather than replacing it.

    A bare count of every import on the grid would answer a question nobody
    asked: the number that matters is how many imported documents match THIS
    host, THIS rule, in THIS window.
    """
    base = {"bool": {"must": [{"term": {"source.ip": "10.0.0.5"}}]}}
    elastic = _FakeElastic(EsSearchResult(total=7, took_ms=1))

    assert await count_imports(elastic, "logs-*", base) == 7

    sent = elastic.calls[0]["query"]["bool"]
    assert sent["must"] == [base]
    assert sent["filter"] == [imported_filter()]
    assert elastic.calls[0]["size"] == 0
    assert elastic.calls[0]["track_total_hits"] is True


@pytest.mark.asyncio
async def test_a_failed_probe_returns_none_and_does_not_raise() -> None:
    """Every caller is a tool that already promised not to raise.

    An unmeasured import count is a missing sentence, not a failed answer, so
    the failure degrades the disclosure rather than the result.
    """
    elastic = _FakeElastic(RuntimeError("all shards failed"))
    assert await count_imports(elastic, "logs-*", {"match_all": {}}) is None
