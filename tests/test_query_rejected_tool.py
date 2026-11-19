"""The model reads why the grid rejected a query, and a hunt does not call it an outage.

Production, 2026-11-19: 19 tool results of one campaign hunt read "The Security
Onion grid did not answer this query" on a grid that was up. Each was a query
that was wrong for the type of a field. The model never saw the reason, so it
varied the query six times and wrote that the question "cannot be answered".

These tests drive the tool boundary (:func:`soc_ai.agent.toolset._tool_error`
and the registered ``t_query_events_oql``) and the hunt evidence gate with the
seven reasons the production grid returned. The negative controls pin the path
the change must NOT touch: a real partial read stays ``grid_unavailable``.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import patch

import elasticsearch as es
import pytest
from pydantic_ai.models.test import TestModel
from soc_ai.agent.hunt import HUNT_SYSTEM_PROMPT, build_hunt_agent
from soc_ai.agent.toolset import (
    GRID_UNAVAILABLE_REASON,
    QUERY_REJECTED_REASON,
    _is_grid_unavailable,
    _tool_error,
)
from soc_ai.api.hunt_runner import _grid_tool_outcomes
from soc_ai.config import Settings
from soc_ai.hunting.step_words import translate_tool_error
from soc_ai.so_client.elastic import GridPartialResultsError, GridQueryRejectedError
from soc_ai.store import leads

from tests.test_hunt_outage_report import QUIET_REPORT, _call_and_return, _ctx, _run_recorded

_TOTAL = 612

# (failed shards, reason, words the hint must hold) for each production reason.
_CASES: dict[str, tuple[int, str, tuple[str, ...]]] = {
    "prefix_on_ip": (
        97,
        "query_shard_exception: Can only use prefix queries on keyword, text and wildcard "
        "fields - not on [destination.ip] which is of type [ip]",
        ("destination.ip", "IP field", "CIDR", '"192.0.2.0/24"'),
    ),
    "date_with_a_space": (
        168,
        "query_shard_exception: failed to create query: failed to parse date field "
        "[2026-10-28 22:44] with format [strict_date_optional_time||epoch_millis]",
        ("ISO 8601", "UTC", "2026-10-28T22:44:00Z"),
    ),
    "sort_network_bytes": (
        3,
        "query_shard_exception: No mapping found for [network.bytes] in order to sort on",
        ("network.bytes", "sortby"),
    ),
    "sort_orig_bytes": (
        15,
        "query_shard_exception: No mapping found for [zeek.conn.orig_bytes] in order to sort on",
        ("zeek.conn.orig_bytes", "sortby"),
    ),
    "groupby_text": (
        3,
        "illegal_argument_exception: match_only_text fields do not support sorting and "
        "aggregations",
        ("text field", "groupby", "keyword field"),
    ),
    "text_on_a_number": (
        2,
        'query_shard_exception: failed to create query: For input string: "TXT"',
        ("number", '"TXT"'),
    ),
    "date_math_ms": (
        339,
        "parse_exception: operator not supported for date math [-1728000ms]",
        ("now-20d", "no unit ms"),
    ),
}


def _rejected(case: str) -> GridQueryRejectedError:
    failed, reason, _words = _CASES[case]
    return GridQueryRejectedError(
        f"partial search results from logs-*: {failed} of {_TOTAL} shards failed ({reason}).",
        shards_failed=failed,
        shards_total=_TOTAL,
        reason=reason,
    )


def _partial_read() -> GridPartialResultsError:
    return GridPartialResultsError(
        "partial search results from logs-*: 2 of 612 shards failed "
        "(no_shard_available_action_exception: recovering).",
        shards_failed=2,
        shards_total=_TOTAL,
        reason="no_shard_available_action_exception: recovering",
    )


# ---------------------------------------------------------------------------
# The tool result
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", sorted(_CASES))
def test_the_model_reads_the_reason_and_the_hint(case: str) -> None:
    failed, reason, words = _CASES[case]
    result = _tool_error(_rejected(case))

    assert result["error"] is True
    assert result["type"] == "GridQueryRejectedError"
    assert result["reason"] == QUERY_REJECTED_REASON
    message = result["message"]
    assert "grid is up" in message
    assert f"{failed} of {_TOTAL} shards" in message
    assert reason in message
    # The result is unknown, never empty, and the next step is a corrected query.
    assert "UNKNOWN" in message
    assert "not an empty" in message
    assert "Correct the query" in message
    for word in words:
        assert word in result["hint"], (case, word, result["hint"])


def test_a_reason_of_another_shape_gets_the_reason_and_no_hint() -> None:
    exc = GridQueryRejectedError(
        "partial", shards_failed=1, shards_total=4, reason="parsing_exception: [bool] malformed"
    )
    result = _tool_error(exc)
    assert result["reason"] == QUERY_REJECTED_REASON
    assert "[bool] malformed" in result["message"]
    assert "hint" not in result


def test_the_reason_text_loses_the_synthetic_index_spelling() -> None:
    exc = GridQueryRejectedError(
        "partial",
        shards_failed=1,
        shards_total=4,
        reason="query_shard_exception: failed to create query on [.ds-logs-synth-zeek-conn-1]",
    )
    encoded = json.dumps(_tool_error(exc))
    assert "logs-synth" not in encoded
    assert ".ds-logs-zeek-conn-1" in encoded


def test_a_rejected_query_is_no_grid_failure() -> None:
    assert _is_grid_unavailable(_rejected("prefix_on_ip")) is False


def test_a_real_partial_read_stays_grid_unavailable() -> None:
    """Negative control: the grid did not answer, and the model is told so."""
    exc = _partial_read()
    assert _is_grid_unavailable(exc) is True
    result = _tool_error(exc)
    assert result["reason"] == GRID_UNAVAILABLE_REASON
    assert "hint" not in result
    assert "no_shard_available" not in result["message"]


def test_the_registered_tool_hands_the_model_the_reason(settings_kratos: Settings) -> None:
    """Through the real registered tool on the real hunt agent: the wrapping
    (dedup, guard, clamp) keeps the reason and the hint."""

    async def _go() -> Any:
        agent = build_hunt_agent(
            TestModel(call_tools=["t_query_events_oql"], custom_output_args=QUIET_REPORT),
            _ctx(settings_kratos),
            system_prompt=HUNT_SYSTEM_PROMPT.format(objective="hunt for beaconing"),
        )
        with patch("soc_ai.agent.toolset.query_events_oql", side_effect=_rejected("prefix_on_ip")):
            return await agent.run("hunt for beaconing")

    result = asyncio.run(_go())
    returns = [
        p
        for m in result.all_messages()
        for p in getattr(m, "parts", [])
        if getattr(p, "part_kind", None) == "tool-return"
        and getattr(p, "tool_name", "") == "t_query_events_oql"
    ]
    assert returns, "the tool never ran"
    content = returns[0].content
    assert isinstance(content, dict)
    assert content["reason"] == QUERY_REJECTED_REASON
    assert "which is of type [ip]" in content["message"]
    assert "CIDR" in content["hint"]


# ---------------------------------------------------------------------------
# The counts of a hunt and of a lead
# ---------------------------------------------------------------------------


def test_the_hunt_count_files_a_rejected_query_as_a_rejection() -> None:
    rejected = _tool_error(_rejected("date_with_a_space"))
    partial = _tool_error(_partial_read())
    results = [
        {"tool_name": "t_query_events_oql", "result": rejected},
        {"tool_name": "t_query_events_oql", "result": rejected},
        {"tool_name": "t_query_events_oql", "result": partial},
    ]
    assert _grid_tool_outcomes(results) == (0, 1, 2)


def test_a_hunt_whose_only_failures_are_rejected_queries_stays_complete(
    settings_kratos: Settings,
) -> None:
    """Rejected queries beside an answered query: the hunt read the grid."""
    rejected = _tool_error(_rejected("prefix_on_ip"))
    nodes = (
        _call_and_return("t_query_events_oql", "c1", rejected)
        + _call_and_return("t_query_events_oql", "c2", rejected)
        + _call_and_return("t_query_events_oql", "c3", {"total": 0, "hits": []})
    )
    hunt = _run_recorded(settings_kratos, nodes, QUIET_REPORT)
    assert hunt.status == "complete"


def test_a_hunt_of_rejected_queries_only_is_not_called_a_grid_outage(
    settings_kratos: Settings,
) -> None:
    """It read nothing, so it is degraded. The words blame the queries."""
    rejected = _tool_error(_rejected("prefix_on_ip"))
    nodes = _call_and_return("t_query_events_oql", "c1", rejected) + _call_and_return(
        "t_query_events_oql", "c2", _tool_error(_rejected("date_math_ms"))
    )
    hunt = _run_recorded(settings_kratos, nodes, QUIET_REPORT)
    assert hunt.status == "error"
    gaps = [f for f in (hunt.report or {})["findings"] if f["category"] == "visibility_gap"]
    note = (gaps[0]["validator_note"] or "").lower()
    assert "rejected" in note
    assert GRID_UNAVAILABLE_REASON.replace("_", " ") not in note


def test_a_hunt_with_a_real_partial_read_is_still_a_grid_outage(
    settings_kratos: Settings,
) -> None:
    """Negative control: a partial read beside a rejected query is an outage."""
    nodes = _call_and_return(
        "t_query_events_oql", "c1", _tool_error(_rejected("prefix_on_ip"))
    ) + _call_and_return("t_query_events_oql", "c2", _tool_error(_partial_read()))
    hunt = _run_recorded(settings_kratos, nodes, QUIET_REPORT)
    assert hunt.status == "error"
    gaps = [f for f in (hunt.report or {})["findings"] if f["category"] == "visibility_gap"]
    assert GRID_UNAVAILABLE_REASON.replace("_", " ") in (gaps[0]["validator_note"] or "").lower()


def test_a_rejected_query_holds_no_lead() -> None:
    """The lead settle rule: a query error does not keep a lead open."""
    assert leads._QUERY_REJECTED == QUERY_REJECTED_REASON
    assert leads._grid_failed(_tool_error(_rejected("prefix_on_ip"))) is False
    # A tool that returns its own exception name, with no reason.
    assert leads._grid_failed({"error": True, "type": "GridQueryRejectedError"}) is False
    # Negative control: a partial read still holds the lead.
    assert leads._grid_failed(_tool_error(_partial_read())) is True
    assert leads._grid_failed({"error": True, "type": "GridPartialResultsError"}) is True


def test_the_hunt_page_says_that_the_grid_rejected_the_query() -> None:
    message = _tool_error(_rejected("prefix_on_ip"))["message"]
    assert translate_tool_error(message) == "The grid rejected the query. The result is unknown."
    # Negative control: the grid failure keeps its words.
    grid = _tool_error(es.ConnectionTimeout("timed out"))["message"]
    assert translate_tool_error(grid) == (
        "The grid did not answer this query. The result is unknown."
    )
