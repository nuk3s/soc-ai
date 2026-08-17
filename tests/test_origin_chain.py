"""``origin_chain`` — "who was driving this host?" (incident 2026-08-05).

soc-ai attributed SSH probing to internal host 192.168.10.202 and stopped there.
It had, in the indices it was already querying, 15 events showing
192.168.20.226 opening an SSH session TO .202 ninety seconds earlier —
including a ``zeek.ssh`` record. It called ``t_host_summary`` on .202 twice and
still never asked the question an entry-level analyst asks on reflex: *who is on
this box?*

``host_summary`` cannot answer it. Its ``top_peers`` is a volume-ranked
aggregation over a 24h window, so a two-second SSH session is invisible next to
7,000 routine events — and it carries no ordering, so "immediately before"
cannot be expressed. This tool is the missing primitive: remote-access sessions
INBOUND to a host, ordered, windowed on what preceded the activity.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
from soc_ai.tools.origin_chain import origin_chain

ANCHOR = datetime(2026, 8, 5, 11, 34, 21, tzinfo=UTC)


def _hit(ts: str, src: str, dst: str, dataset: str = "zeek.ssh", port: int = 22) -> dict[str, Any]:
    return {
        "_source": {
            "@timestamp": ts,
            "event": {"dataset": dataset},
            "source": {"ip": src},
            "destination": {"ip": dst, "port": port},
        }
    }


def _es(hits: list[dict[str, Any]]) -> AsyncMock:
    es = AsyncMock()
    es.search.return_value = type(
        "R", (), {"hits": hits, "total": len(hits), "raw": {"hits": {"hits": hits}}}
    )()
    return es


class _Settings:
    events_index_pattern = "logs-*"
    es_request_timeout_s = 30


async def test_surfaces_the_inbound_session_that_preceded_the_activity() -> None:
    """The incident, replayed: .226 SSH'd to .202 90s before .202 acted."""
    es = _es(
        [
            _hit("2026-08-05T11:32:45.426Z", "192.168.20.226", "192.168.10.202"),
            _hit("2026-08-05T11:32:59.016Z", "192.168.20.226", "192.168.10.202"),
        ]
    )
    result = await origin_chain(
        "192.168.10.202", elastic=es, settings=_Settings(), time_anchor=ANCHOR
    )

    assert result["observations"] is True
    assert result["inbound_sessions"], "the driving session must be surfaced"
    first = result["inbound_sessions"][0]
    assert first["source_ip"] == "192.168.20.226"
    assert first["dataset"] == "zeek.ssh"
    # The operative fact: something was on this host before it acted.
    assert "192.168.20.226" in result["summary"]
    assert result["closest_preceding"]["source_ip"] == "192.168.20.226"
    # Closest session is 11:32:59 -> 82s before the 11:34:21 anchor. (The 96s
    # figure from the incident write-up is the FIRST probe at 11:32:45; the
    # driver is the nearest one.)
    assert result["closest_preceding"]["seconds_before"] == pytest.approx(82, abs=2)


async def test_absence_is_a_real_answer_not_an_error() -> None:
    """No inbound session means the host acted on its own — that CHANGES the
    verdict, so it must read as a finding, not an empty shrug."""
    result = await origin_chain(
        "192.168.10.202", elastic=_es([]), settings=_Settings(), time_anchor=ANCHOR
    )
    assert result["observations"] is False
    assert result["inbound_sessions"] == []
    assert result["closest_preceding"] is None
    assert "no inbound" in result["summary"].lower()


async def test_only_inbound_remote_access_counts() -> None:
    """Outbound sessions FROM the host are not origin evidence — including them
    would let the host's own activity masquerade as its driver."""
    es = _es(
        [
            _hit("2026-08-05T11:32:45Z", "192.168.20.226", "192.168.10.202"),
            _hit("2026-08-05T11:33:00Z", "192.168.10.202", "192.168.10.253"),  # outbound
        ]
    )
    result = await origin_chain(
        "192.168.10.202", elastic=es, settings=_Settings(), time_anchor=ANCHOR
    )
    srcs = [s["source_ip"] for s in result["inbound_sessions"]]
    assert srcs == ["192.168.20.226"]


async def test_sessions_are_time_ordered_and_closest_wins() -> None:
    es = _es(
        [
            _hit("2026-08-05T11:20:00Z", "10.0.0.9", "192.168.10.202"),
            _hit("2026-08-05T11:32:45Z", "192.168.20.226", "192.168.10.202"),
        ]
    )
    result = await origin_chain(
        "192.168.10.202", elastic=es, settings=_Settings(), time_anchor=ANCHOR
    )
    assert [s["source_ip"] for s in result["inbound_sessions"]] == [
        "10.0.0.9",
        "192.168.20.226",
    ]
    # Closest preceding is the likely driver, not the earliest.
    assert result["closest_preceding"]["source_ip"] == "192.168.20.226"


async def test_es_failure_returns_clean_error_dict() -> None:
    """Read-tool robustness contract: never raise into the agent loop."""
    es = AsyncMock()
    es.search.side_effect = RuntimeError("es down")
    result = await origin_chain(
        "192.168.10.202", elastic=es, settings=_Settings(), time_anchor=ANCHOR
    )
    assert result["error"] is True
    assert "es down" in result["message"]


async def test_query_targets_the_host_as_destination_over_remote_access() -> None:
    """Guard the query shape: destination==ip (inbound) and remote-access
    datasets only — the two constraints that make the answer meaningful."""
    es = _es([])
    await origin_chain("192.168.10.202", elastic=es, settings=_Settings(), time_anchor=ANCHOR)
    body = es.search.await_args.kwargs
    q = str(body.get("query"))
    assert "192.168.10.202" in q
    assert "destination.ip" in q
    assert "ssh" in q.lower()


# ── Registration + doctrine (the capability is useless if never invoked) ─────


def test_tool_is_registered_for_the_investigator() -> None:
    """A tool the agent cannot call is not a fix."""
    import inspect

    from soc_ai.agent import toolset

    src = inspect.getsource(toolset)
    assert "async def t_origin_chain" in src
    assert "origin_chain(" in src


def test_investigator_doctrine_requires_the_pivot_before_attribution() -> None:
    """The 2026-08-05 failure was not a missing tool — host_summary was called
    twice. It was a missing STEP. Pin the instruction that makes it mandatory."""
    from soc_ai.agent.prompts import INVESTIGATOR_PROMPT

    p = INVESTIGATOR_PROMPT
    assert "t_origin_chain" in p
    # The obligation must be stated as a precondition of attribution.
    assert "before" in p.lower() and "waypoint" in p.lower()
    # And the empty case must be framed as a finding, not a dead end.
    assert "autonomously" in p.lower()
