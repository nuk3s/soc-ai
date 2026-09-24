"""Two different questions, two different windows.

A centred window is the right shape for "what happened around this alert": the
minutes before it explain the setup, the minutes after it show what followed.
It is the wrong shape for "how often does this happen", and that was the only
shape the event query tool had. A 1440-minute request became twelve hours before
the anchor and twelve after, and for a live alert the forward half holds nothing,
so every prevalence question was answered over half the span it asked for.

Measured on the range on 2026-09-07 against the deployed tool, anchored on a
real alert at 13:02:04Z:

    question                          reported   actual
    system.auth, grid-wide, 24h             504     1061
    system.auth, one host, 48h               81      113

Counting the grid over the effective half-windows reproduces 504 and 81 exactly,
which is what rules out coincidence. Nothing downstream caught it: the citation
validator checks document identifiers, not arithmetic.

The fix is a second question rather than a different answer to the first one.
``window_mode="around"`` keeps the centred window, unchanged, and stays the
default; ``window_mode="before"`` counts the whole requested span backwards from
the anchor. The result now also carries the window it actually searched, so a
number the model prints can be checked against the span it came from.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.tools.query_events import query_events_oql

ANCHOR = datetime(2026, 9, 7, 13, 2, 4, tzinfo=UTC)


def _make_elastic(settings: Settings, response: dict[str, Any]) -> tuple[ElasticClient, MagicMock]:
    elastic = ElasticClient(settings)
    fake_es = MagicMock()
    fake_es.search = AsyncMock(return_value=response)
    elastic._client = fake_es  # type: ignore[attr-defined]
    return elastic, fake_es


def _range_filter(fake_es: MagicMock) -> dict[str, str]:
    body = fake_es.search.call_args.kwargs["body"]
    rng: dict[str, str] = body["query"]["bool"]["filter"][0]["range"]["@timestamp"]
    return rng


@pytest.mark.asyncio
async def test_a_lookback_question_gets_the_whole_span_it_asked_for(
    settings_kratos: Settings,
) -> None:
    """1440 minutes means 1440 minutes, all of them behind the anchor."""
    elastic, fake_es = _make_elastic(settings_kratos, {"took": 0, "hits": {"total": 0, "hits": []}})

    await query_events_oql(
        "event.dataset:system.auth | count",
        elastic=elastic,
        settings=settings_kratos,
        time_range_minutes=1440,
        time_anchor=ANCHOR,
        window_mode="before",
    )

    rng = _range_filter(fake_es)
    assert rng["gte"] == "2026-09-06T13:02:04+00:00"
    assert rng["lte"] == "2026-09-07T13:02:04+00:00"


@pytest.mark.asyncio
async def test_the_around_the_alert_window_is_still_symmetric(
    settings_kratos: Settings,
) -> None:
    """Negative control, and the one that matters most.

    "What happened around this alert" is a legitimate question and the centred
    window is its correct answer. It stays the default, and it stays symmetric:
    if this test ever passes only because the window moved, the fix has broken
    the use it was told not to break.
    """
    elastic, fake_es = _make_elastic(settings_kratos, {"took": 0, "hits": {"total": 0, "hits": []}})

    await query_events_oql(
        "host.name:foo",
        elastic=elastic,
        settings=settings_kratos,
        time_range_minutes=60,
        time_anchor=ANCHOR,
    )

    rng = _range_filter(fake_es)
    assert rng["gte"] == "2026-09-07T12:32:04+00:00"
    assert rng["lte"] == "2026-09-07T13:32:04+00:00"


@pytest.mark.asyncio
async def test_an_explicit_around_request_is_the_same_as_the_default(
    settings_kratos: Settings,
) -> None:
    elastic, fake_es = _make_elastic(settings_kratos, {"took": 0, "hits": {"total": 0, "hits": []}})

    await query_events_oql(
        "host.name:foo",
        elastic=elastic,
        settings=settings_kratos,
        time_range_minutes=60,
        time_anchor=ANCHOR,
        window_mode="around",
    )

    rng = _range_filter(fake_es)
    assert rng["gte"] == "2026-09-07T12:32:04+00:00"
    assert rng["lte"] == "2026-09-07T13:32:04+00:00"


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["around", "before"])
async def test_an_unanchored_call_still_counts_back_from_now(
    settings_kratos: Settings, mode: str
) -> None:
    """With no alert there is nothing to centre on, so both modes look back.

    The CLI and WebUI paths pass no anchor and already got the full span; the
    new parameter must not disturb them.
    """
    elastic, fake_es = _make_elastic(settings_kratos, {"took": 0, "hits": {"total": 0, "hits": []}})

    await query_events_oql(
        "host.name:foo",
        elastic=elastic,
        settings=settings_kratos,
        time_range_minutes=120,
        time_anchor=None,
        window_mode=mode,  # type: ignore[arg-type]
    )

    rng = _range_filter(fake_es)
    assert rng["gte"] == "now-120m"
    assert rng["lte"] == "now"


@pytest.mark.asyncio
async def test_an_unknown_window_mode_is_refused(settings_kratos: Settings) -> None:
    """A typo must not silently fall through to the centred window."""
    elastic, _ = _make_elastic(settings_kratos, {"took": 0, "hits": {"total": 0, "hits": []}})

    with pytest.raises(ValueError, match="window_mode"):
        await query_events_oql(
            "host.name:foo",
            elastic=elastic,
            settings=settings_kratos,
            time_anchor=ANCHOR,
            window_mode="last",  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_the_result_says_which_span_it_counted_over(settings_kratos: Settings) -> None:
    """A count with no span attached gets the span the reader assumed.

    This is the same reasoning as ``counted``: the number is only meaningful
    next to what produced it, and the reader here is a model that has already
    been shown to print "12 in the last 24 hours".
    """
    elastic, _ = _make_elastic(settings_kratos, {"took": 0, "hits": {"total": 12, "hits": []}})

    result = await query_events_oql(
        "event.dataset:system.auth | count",
        elastic=elastic,
        settings=settings_kratos,
        time_range_minutes=1440,
        time_anchor=ANCHOR,
    )

    assert result.window is not None
    assert result.window["mode"] == "around"
    assert result.window["gte"] == "2026-09-07T01:02:04+00:00"
    assert result.window["lte"] == "2026-09-08T01:02:04+00:00"
    assert result.window["minutes_before_anchor"] == 720
    assert result.window["minutes_after_anchor"] == 720
    # The half-window has to be said in words, not left to be derived from two
    # ISO timestamps by the reader who got this wrong in the first place.
    assert "720" in result.window["note"]
    assert "window_mode" in result.window["note"]


@pytest.mark.asyncio
async def test_a_lookback_result_says_so_without_the_correction(
    settings_kratos: Settings,
) -> None:
    elastic, _ = _make_elastic(settings_kratos, {"took": 0, "hits": {"total": 20, "hits": []}})

    result = await query_events_oql(
        "event.dataset:system.auth | count",
        elastic=elastic,
        settings=settings_kratos,
        time_range_minutes=1440,
        time_anchor=ANCHOR,
        window_mode="before",
    )

    assert result.window is not None
    assert result.window["mode"] == "before"
    assert result.window["minutes_before_anchor"] == 1440
    assert result.window["minutes_after_anchor"] == 0
    assert "window_mode" not in result.window["note"]


@pytest.mark.asyncio
async def test_an_unanchored_result_names_the_clock_it_used(settings_kratos: Settings) -> None:
    elastic, _ = _make_elastic(settings_kratos, {"took": 0, "hits": {"total": 3, "hits": []}})

    result = await query_events_oql(
        "host.name:foo",
        elastic=elastic,
        settings=settings_kratos,
        time_range_minutes=120,
    )

    assert result.window is not None
    assert result.window["mode"] == "now_relative"
    assert result.window["gte"] == "now-120m"
    assert result.window["lte"] == "now"
