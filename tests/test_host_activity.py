"""Tests for the live host-activity queries (``soc_ai/webui/host_activity.py``).

The host page reads identity from the dossier (swept, cached, survives a down
grid) and activity from here (straight off the grid, every load). These tests
pin the second half of that split: the peer list is a MERGE of two directional
sub-aggregations from a single search, and the honest-absence cases — no peers,
no host logs — have to stay distinguishable from "we did not look".

The fake Elasticsearch returns real :class:`EsSearchResult` objects and routes on
the aggregation names the module asks for, so a test fails if the module stops
asking the question the fixture answers.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from elastic_transport import TransportError
from soc_ai.config import Settings
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.webui.host_activity import (
    MAX_PEERS,
    MAX_USERS,
    LatestInvestigation,
    fetch_host_activity,
)
from sqlalchemy.exc import SQLAlchemyError

_IP = "192.168.10.202"

# One host's zeek.conn pass: it originates a lot to the NAS (192.168.10.40),
# answers that same peer on ssh (so the merged direction is "both"), and makes
# two lonely outbound connections to 192.168.20.226 — the shape a beacon has
# before anything has alerted on it.
_CONN_AGG: dict[str, Any] = {
    "out": {
        "doc_count": 902,
        "peers": {
            "buckets": [
                {
                    "key": "192.168.10.40",
                    "doc_count": 900,
                    "ports": {
                        "buckets": [
                            {"key": 445, "doc_count": 800},
                            {"key": 2049, "doc_count": 100},
                        ]
                    },
                },
                {
                    "key": "192.168.20.226",
                    "doc_count": 2,
                    "ports": {"buckets": [{"key": 4444, "doc_count": 2}]},
                },
            ]
        },
    },
    "in": {
        "doc_count": 30,
        "peers": {
            "buckets": [
                {
                    "key": "192.168.10.40",
                    "doc_count": 30,
                    "ports": {"buckets": [{"key": 22, "doc_count": 30}]},
                }
            ]
        },
    },
    "volume": {
        "buckets": [
            {"key_as_string": "2026-08-08T10:00:00.000Z", "key": 1786298400000, "doc_count": 0},
            {"key_as_string": "2026-08-08T11:00:00.000Z", "key": 1786302000000, "doc_count": 612},
            {"key_as_string": "2026-08-08T12:00:00.000Z", "key": 1786305600000, "doc_count": 320},
        ]
    },
}


def _truncate_recent(
    detections: dict[str, Any] | None, requested: dict[str, Any]
) -> dict[str, Any] | None:
    """Cut the alerting-peer buckets to the terms ``size`` the module asked for.

    Elasticsearch returns at most ``size`` buckets, so a fake that handed back
    every bucket regardless would make the agg width untestable — and the width
    is exactly what decides whether a real alerting peer can go unflagged.
    """
    if not detections:
        return detections
    recent = (requested.get("recent") or {}).get("aggs") or {}
    out: dict[str, Any] = {"recent": dict(detections["recent"])}
    for side in ("src", "dst"):
        if side not in out["recent"]:
            continue
        cap = int(((recent.get(side) or {}).get("terms") or {}).get("size", 10))
        buckets = sorted(
            out["recent"][side].get("buckets", []),
            key=lambda b: int(b.get("doc_count") or 0),
            reverse=True,
        )
        out["recent"][side] = {"buckets": buckets[:cap]}
    return out


class _FakeConnElastic:
    """An ElasticClient stand-in that answers each sub-query by its agg names."""

    def __init__(
        self,
        conn_agg: dict[str, Any],
        *,
        detections: dict[str, Any] | None = None,
        alerts_total: int = 0,
        auth: dict[str, Any] | None = None,
        auth_total: int = 0,
        latency_s: float = 0.0,
    ) -> None:
        self._conn = conn_agg
        self._detections = detections
        self._alerts_total = alerts_total
        self._auth = auth
        self._auth_total = auth_total
        self._latency_s = latency_s
        self.searches: list[dict[str, Any]] = []
        # Issue/return order, so a test can tell concurrent from sequential:
        # three "start" entries before the first "end" can only be a fan-out.
        self.timeline: list[str] = []

    async def search(
        self,
        index: str,
        query: dict[str, Any],
        *,
        size: int = 100,
        from_: int = 0,
        sort: list[dict[str, Any]] | None = None,
        source: list[str] | bool | None = None,
        aggs: dict[str, Any] | None = None,
        track_total_hits: bool | None = None,
    ) -> EsSearchResult:
        self.searches.append({"index": index, "query": query, "aggs": aggs, "size": size})
        names = set(aggs or {})
        label = next((n for n in ("volume", "recent", "users") if n in names), "other")
        self.timeline.append(f"start:{label}")
        if self._latency_s:
            await asyncio.sleep(self._latency_s)
        self.timeline.append(f"end:{label}")
        if "volume" in names:
            volume = self._conn.get("volume", {}).get("buckets", [])
            conn_total = sum(b["doc_count"] for b in volume)
            return EsSearchResult(total=conn_total, took_ms=1, aggregations=self._conn)
        if "recent" in names:
            return EsSearchResult(
                total=self._alerts_total,
                took_ms=1,
                aggregations=_truncate_recent(self._detections, aggs or {}),
            )
        if "users" in names:
            return EsSearchResult(total=self._auth_total, took_ms=1, aggregations=self._auth)
        return EsSearchResult(total=0, took_ms=1)


@pytest.mark.asyncio
async def test_fetch_host_activity_returns_top_peers_and_volume(
    settings_kratos: Settings,
) -> None:
    es = _FakeConnElastic(_CONN_AGG)
    act = await fetch_host_activity(es, settings_kratos, _IP, range="24h")  # type: ignore[arg-type]

    assert act.peers[0].ip == "192.168.10.40"
    assert act.peers[0].direction in ("out", "both")
    assert len(act.peers) <= MAX_PEERS
    assert act.volume and act.volume[0].events >= 0


@pytest.mark.asyncio
async def test_peers_carry_merged_direction_and_ports(settings_kratos: Settings) -> None:
    """A peer this host both calls and answers is "both", with BOTH sets of ports.

    The two directions are separate sub-aggregations of one search, so a peer
    that appears in each arrives twice; a module that took the first bucket and
    stopped would report the NAS as outbound-only and lose the ssh service it
    answers on — the direction is the whole point of the peer row.
    """
    es = _FakeConnElastic(_CONN_AGG)
    act = await fetch_host_activity(es, settings_kratos, _IP, range="24h")  # type: ignore[arg-type]

    nas = next(p for p in act.peers if p.ip == "192.168.10.40")
    assert nas.direction == "both"
    assert nas.events == 930  # 900 originated + 30 answered
    assert set(nas.ports) == {445, 2049, 22}
    quiet = next(p for p in act.peers if p.ip == "192.168.20.226")
    assert quiet.direction == "out"
    # Busiest first: two connections must not outrank nine hundred.
    assert [p.ip for p in act.peers] == ["192.168.10.40", "192.168.20.226"]


@pytest.mark.asyncio
async def test_peers_and_volume_come_from_one_search(settings_kratos: Settings) -> None:
    """Peers + volume cost ONE round trip — this endpoint runs on every page load."""
    es = _FakeConnElastic(_CONN_AGG)
    await fetch_host_activity(es, settings_kratos, _IP, range="24h")  # type: ignore[arg-type]

    conn = [s for s in es.searches if "volume" in set(s["aggs"] or {})]
    assert len(conn) == 1
    assert conn[0]["size"] == 0
    assert conn[0]["index"] == settings_kratos.events_index_pattern


@pytest.mark.asyncio
async def test_volume_buckets_to_the_range(settings_kratos: Settings) -> None:
    """24h is an hourly histogram; 7d is a daily one — 168 hourly bars is a smear."""
    es = _FakeConnElastic(_CONN_AGG)
    await fetch_host_activity(es, settings_kratos, _IP, range="24h")  # type: ignore[arg-type]
    hourly = es.searches[0]["aggs"]["volume"]["date_histogram"]
    assert hourly["calendar_interval"] == "hour"

    es2 = _FakeConnElastic(_CONN_AGG)
    await fetch_host_activity(es2, settings_kratos, _IP, range="7d")  # type: ignore[arg-type]
    daily = es2.searches[0]["aggs"]["volume"]["date_histogram"]
    assert daily["calendar_interval"] == "day"


@pytest.mark.asyncio
async def test_a_host_is_not_its_own_peer(settings_kratos: Settings) -> None:
    """A same-address flow must not list the host as a peer of itself.

    zeek.conn does record flows whose two endpoints are the same address, and
    both directional sub-aggs then bucket the host itself. The alert lane
    already discards it; without the same rule here the peer table opens with a
    row pointing back at the page you are standing on.
    """
    self_flow = {
        "out": {
            "peers": {
                "buckets": [
                    {
                        "key": _IP,
                        "doc_count": 40,
                        "ports": {"buckets": [{"key": 9000, "doc_count": 40}]},
                    },
                    {"key": "192.168.10.40", "doc_count": 5, "ports": {"buckets": []}},
                ]
            }
        },
        "in": {"peers": {"buckets": [{"key": _IP, "doc_count": 40, "ports": {"buckets": []}}]}},
        "volume": {"buckets": []},
    }
    es = _FakeConnElastic(self_flow)
    act = await fetch_host_activity(es, settings_kratos, _IP, range="24h")  # type: ignore[arg-type]

    assert [p.ip for p in act.peers] == ["192.168.10.40"]


@pytest.mark.asyncio
async def test_a_silent_host_is_empty_not_an_error(settings_kratos: Settings) -> None:
    """No zeek.conn for this address answers empty. "Quiet" is a real answer."""
    es = _FakeConnElastic({"out": {"peers": {"buckets": []}}, "in": {"peers": {"buckets": []}}})
    act = await fetch_host_activity(es, settings_kratos, _IP, range="24h")  # type: ignore[arg-type]

    assert act.peers == []
    assert act.volume == []
    assert act.peers_truncated is False
    assert act.users_truncated is False


@pytest.mark.asyncio
async def test_peers_truncated_says_the_cut_happened_not_that_it_might_have(
    settings_kratos: Settings,
) -> None:
    """The flag compares the PRE-cut merged length against the cap.

    The frontend used to re-infer truncation from a copied cap constant
    (``len(peers) >= 12``), which goes quietly false the day the constant
    moves — and reads a host with exactly twelve peers as a cut list. The wire
    now states it: True only when peers actually fell off the end.
    """

    def _agg(n: int) -> dict[str, Any]:
        return {
            "out": {
                "peers": {
                    "buckets": [
                        {
                            "key": f"192.168.30.{i}",
                            "doc_count": 500 - i,
                            "ports": {"buckets": [{"key": 443, "doc_count": 500 - i}]},
                        }
                        for i in range(1, n + 1)
                    ]
                }
            },
            "in": {"peers": {"buckets": []}},
            "volume": {"buckets": []},
        }

    # Exactly at the cap: a full page, not a cut one.
    act = await fetch_host_activity(  # type: ignore[arg-type]
        _FakeConnElastic(_agg(MAX_PEERS)), settings_kratos, _IP, range="24h"
    )
    assert len(act.peers) == MAX_PEERS
    assert act.peers_truncated is False

    # One over: the thirteenth peer fell off, and the wire says so.
    act = await fetch_host_activity(  # type: ignore[arg-type]
        _FakeConnElastic(_agg(MAX_PEERS + 1)), settings_kratos, _IP, range="24h"
    )
    assert len(act.peers) == MAX_PEERS
    assert act.peers_truncated is True


@pytest.mark.asyncio
async def test_users_truncated_marks_a_cut_account_list(settings_kratos: Settings) -> None:
    """Same contract on the user lane: True only when an account fell off."""

    def _auth(n: int) -> dict[str, Any]:
        return {
            "users": {
                "buckets": [
                    {
                        "key": f"user-{i:02d}",
                        "doc_count": 100 - i,
                        "last": {"value_as_string": "2026-08-08T12:00:00Z"},
                    }
                    for i in range(1, n + 1)
                ]
            }
        }

    act = await fetch_host_activity(  # type: ignore[arg-type]
        _FakeConnElastic(_CONN_AGG, auth=_auth(MAX_USERS), auth_total=100),
        settings_kratos,
        _IP,
        range="24h",
    )
    assert act.users is not None and len(act.users) == MAX_USERS
    assert act.users_truncated is False

    act = await fetch_host_activity(  # type: ignore[arg-type]
        _FakeConnElastic(_CONN_AGG, auth=_auth(MAX_USERS + 1), auth_total=110),
        settings_kratos,
        _IP,
        range="24h",
    )
    assert act.users is not None and len(act.users) == MAX_USERS
    assert act.users_truncated is True

    # No auth documents at all: nothing was cut, because there was no list.
    act = await fetch_host_activity(  # type: ignore[arg-type]
        _FakeConnElastic(_CONN_AGG), settings_kratos, _IP, range="24h"
    )
    assert act.users is None
    assert act.users_truncated is False


# ---------------------------------------------------------------------------
# B2 — peer names, alerted edges, users, alert count
# ---------------------------------------------------------------------------

# A detection in the window whose flow is (this host, 192.168.20.226) — the
# beacon-shaped peer, now with something fired on it.
_DET_AGG: dict[str, Any] = {
    "recent": {
        "doc_count": 3,
        "src": {
            "buckets": [
                {"key": _IP, "doc_count": 3},
                {"key": "192.168.20.226", "doc_count": 1},
            ]
        },
        "dst": {"buckets": [{"key": "192.168.20.226", "doc_count": 3}]},
    }
}

_AUTH_AGG: dict[str, Any] = {
    "users": {
        "buckets": [
            {
                "key": "svc-backup",
                "doc_count": 41,
                "last": {"value_as_string": "2026-08-08T12:04:11.000Z"},
            },
            {
                "key": "root",
                "doc_count": 6,
                "last": {"value_as_string": "2026-08-08T09:31:02.000Z"},
            },
            # ES emits an empty-name bucket for auth lines with no account on
            # them; it is not a user and must not render as one.
            {"key": "", "doc_count": 12, "last": {"value_as_string": "2026-08-08T08:00:00.000Z"}},
        ]
    }
}


class _FakeDossierStore:
    """The route's batch peer-name lookup, without a database."""

    def __init__(self, names: dict[str, str]) -> None:
        self._names = names
        self.asked: list[list[str]] = []

    async def names_for(self, ips: list[str]) -> dict[str, str]:
        self.asked.append(list(ips))
        return {ip: name for ip, name in self._names.items() if ip in set(ips)}


@pytest.mark.asyncio
async def test_activity_flags_alerted_peers_and_names_them(settings_kratos: Settings) -> None:
    es = _FakeConnElastic(_CONN_AGG, detections=_DET_AGG, alerts_total=4)
    store = _FakeDossierStore({"192.168.10.40": "nas-1"})
    act = await fetch_host_activity(  # type: ignore[arg-type]
        es, settings_kratos, _IP, range="7d", dossier_lookup=store.names_for
    )

    nas = next(p for p in act.peers if p.ip == "192.168.10.40")
    assert nas.hostname == "nas-1"
    assert nas.alerted is False
    bad = next(p for p in act.peers if p.ip == "192.168.20.226")
    assert bad.alerted is True
    assert act.alerts_7d >= 1


@pytest.mark.asyncio
async def test_peer_names_are_one_batched_lookup(settings_kratos: Settings) -> None:
    """One call carrying every peer — never a per-row query behind the panel."""
    es = _FakeConnElastic(_CONN_AGG)
    store = _FakeDossierStore({"192.168.10.40": "nas-1"})
    await fetch_host_activity(  # type: ignore[arg-type]
        es, settings_kratos, _IP, range="24h", dossier_lookup=store.names_for
    )

    assert len(store.asked) == 1
    assert set(store.asked[0]) == {"192.168.10.40", "192.168.20.226"}


@pytest.mark.asyncio
async def test_alert_count_is_seven_days_even_on_the_24h_view(
    settings_kratos: Settings,
) -> None:
    """``alerts_7d`` means seven days whatever the peer table is showing.

    The alerted FLAG is scoped to the range the analyst picked (an edge that
    fired last Tuesday is not what this 24h table is about), so the two live in
    one search: a 7-day query whose peer terms sit under an in-range filter.
    """
    es = _FakeConnElastic(_CONN_AGG, detections=_DET_AGG, alerts_total=4)
    await fetch_host_activity(es, settings_kratos, _IP, range="24h")  # type: ignore[arg-type]

    det = next(s for s in es.searches if "recent" in set(s["aggs"] or {}))
    ranges = [
        f["range"]["@timestamp"]["gte"]
        for f in det["query"]["bool"]["filter"]
        if "range" in f and "@timestamp" in f["range"]
    ]
    assert ranges == ["now-7d"]
    assert det["aggs"]["recent"]["filter"]["range"]["@timestamp"]["gte"] == "now-24h"


@pytest.mark.asyncio
async def test_the_alerted_intersection_is_wide_enough_to_not_lie(
    settings_kratos: Settings,
) -> None:
    """The alerted flag must not fail toward "clean".

    A peer is flagged by intersecting the connection table against a terms agg
    of alerting addresses. A host being scanned — exactly the host someone opens
    this page for — can have hundreds of distinct alerting peers over 7 days,
    and any displayed peer outside that agg renders ``alerted: False``: a real
    security signal silently downgraded to "nothing here". The merged peer list
    is at most twelve, so the intersection is the only place this can go wrong
    and a wide terms agg is the cheap side of the trade.
    """
    es = _FakeConnElastic(_CONN_AGG, detections=_DET_AGG, alerts_total=4)
    await fetch_host_activity(es, settings_kratos, _IP, range="24h")  # type: ignore[arg-type]

    recent = next(s for s in es.searches if "recent" in set(s["aggs"] or {}))["aggs"]["recent"]
    for side in ("src", "dst"):
        assert recent["aggs"][side]["terms"]["size"] >= 200, recent["aggs"][side]


@pytest.mark.asyncio
async def test_a_peer_alerting_beyond_the_display_cap_is_still_flagged(
    settings_kratos: Settings,
) -> None:
    """A quiet peer that alerted stays flagged even behind hundreds of noisier
    alerting addresses — the flag is an intersection, not a ranking."""
    loud = [{"key": f"192.168.99.{n}", "doc_count": 500 - n} for n in range(1, 200)]
    noisy = {
        "recent": {
            "src": {"buckets": list(loud)},
            # The beacon peer is the QUIETEST alerting address, so a ranked cut
            # drops it first — and it is the one the analyst needs to see.
            "dst": {"buckets": [*loud, {"key": "192.168.20.226", "doc_count": 1}]},
        }
    }
    es = _FakeConnElastic(_CONN_AGG, detections=noisy, alerts_total=900)
    act = await fetch_host_activity(es, settings_kratos, _IP, range="24h")  # type: ignore[arg-type]

    assert next(p for p in act.peers if p.ip == "192.168.20.226").alerted is True


@pytest.mark.asyncio
@pytest.mark.parametrize("extra_on", [True, False])
async def test_alert_scope_tracks_the_alerts_console_source_switch(
    settings_kratos: Settings, extra_on: bool
) -> None:
    """The alert count is scoped by the SAME sources the alerts console uses.

    ``webui_extra_detections`` widens the console beyond Suricata to Sigma and
    ATTACK notices. If this lane stopped following that switch, a host page and
    the console would disagree about how many alerts a machine has — the exact
    drift the shared ``build_filter`` call exists to prevent, and the branch
    most likely to rot because nothing else reads it.
    """
    settings = settings_kratos.model_copy(update={"webui_extra_detections": extra_on})
    es = _FakeConnElastic(_CONN_AGG, detections=_DET_AGG, alerts_total=4)
    await fetch_host_activity(es, settings, _IP, range="24h")  # type: ignore[arg-type]

    det = next(s for s in es.searches if "recent" in set(s["aggs"] or {}))
    rendered = json.dumps(det["query"])
    assert ("sigma.alert" in rendered) is extra_on
    assert ("zeek.notice" in rendered) is extra_on


@pytest.mark.asyncio
async def test_activity_users_null_without_host_logs(settings_kratos: Settings) -> None:
    es = _FakeConnElastic(_CONN_AGG)  # no system.auth for this ip
    act = await fetch_host_activity(es, settings_kratos, _IP, range="24h")  # type: ignore[arg-type]

    assert act.users is None  # honest "needs host logs" state


@pytest.mark.asyncio
async def test_activity_lists_users_when_the_host_ships_auth_logs(
    settings_kratos: Settings,
) -> None:
    es = _FakeConnElastic(_CONN_AGG, auth=_AUTH_AGG, auth_total=59)
    act = await fetch_host_activity(es, settings_kratos, _IP, range="24h")  # type: ignore[arg-type]

    assert act.users is not None
    assert [u.name for u in act.users] == ["svc-backup", "root"]
    assert act.users[0].events == 41
    assert act.users[0].last_seen == "2026-08-08T12:04:11.000Z"


@pytest.mark.asyncio
async def test_accounts_differing_only_by_whitespace_are_one_user(
    settings_kratos: Settings,
) -> None:
    """Trimmed names must MERGE, not both survive as separate rows.

    A real grid stores a handful of auth lines whose ``user.name`` carries a
    leading space, so the terms agg returns "root" and " root" as two buckets.
    Trimming each in isolation renders the same account twice with two different
    counts, which reads as two accounts.
    """
    _EARLIER, _LATER = "2026-08-08T09:00:00Z", "2026-08-08T12:00:00Z"
    padded = {
        "users": {
            "buckets": [
                {"key": "root", "doc_count": 40, "last": {"value_as_string": _EARLIER}},
                {"key": " root", "doc_count": 2, "last": {"value_as_string": _LATER}},
            ]
        }
    }
    es = _FakeConnElastic(_CONN_AGG, auth=padded, auth_total=42)
    act = await fetch_host_activity(es, settings_kratos, _IP, range="24h")  # type: ignore[arg-type]

    assert act.users is not None
    assert [u.name for u in act.users] == ["root"]
    assert act.users[0].events == 42
    # The newest sighting across both spellings, not whichever bucket sorted first.
    assert act.users[0].last_seen == _LATER


@pytest.mark.asyncio
async def test_auth_logs_with_no_named_account_are_empty_not_null(
    settings_kratos: Settings,
) -> None:
    """Host logs that name nobody is ``[]`` — a finding, not a coverage gap.

    ``None`` is reserved for "this machine ships no auth logs at all". Folding
    the two together would tell the analyst to go install an agent on a host
    that already has one.
    """
    es = _FakeConnElastic(_CONN_AGG, auth={"users": {"buckets": []}}, auth_total=17)
    act = await fetch_host_activity(es, settings_kratos, _IP, range="24h")  # type: ignore[arg-type]

    assert act.users == []


@pytest.mark.asyncio
async def test_users_are_withheld_on_an_address_several_agents_claim(
    settings_kratos: Settings,
) -> None:
    """A shared address must not list another machine's accounts as this host's.

    ``host.ip`` is an ARRAY of every address a machine can see on itself, so a
    docker bridge gateway (``172.17.0.1``), a hypervisor bridge or an address
    DHCP recycled inside the window is reported by several agents at once — four
    of them for one bridge address on the network this was built against. The
    auth documents matching ``host.ip: <that address>`` then come from four
    different machines, and folding their ``user.name`` buckets together puts
    other people's logins on this host's page.

    THE UNIQUE-CLAIM RULE (see :class:`~soc_ai.dossier.types.AgentInventory`) is
    what the dossier's hostlog lane already applies to the same question, and the
    identity lane of this very page resolves to no name at all for a contested
    address. The user list has to agree with it.
    """
    shared = {
        "agents": {
            "buckets": [{"key": "pve01", "doc_count": 30}, {"key": "nas-1", "doc_count": 9}]
        },
        "users": {
            "buckets": [
                {
                    "key": "root",
                    "doc_count": 30,
                    "last": {"value_as_string": "2026-08-08T12:00:00Z"},
                }
            ]
        },
    }
    es = _FakeConnElastic(_CONN_AGG, auth=shared, auth_total=39)
    act = await fetch_host_activity(es, settings_kratos, _IP, range="24h")  # type: ignore[arg-type]

    assert act.users is None


@pytest.mark.asyncio
async def test_users_survive_when_exactly_one_agent_claims_the_address(
    settings_kratos: Settings,
) -> None:
    """The gate is CONTENTION, not the presence of an agent name."""
    claimed = {
        "agents": {"buckets": [{"key": "ws-1", "doc_count": 59}]},
        "users": _AUTH_AGG["users"],
    }
    es = _FakeConnElastic(_CONN_AGG, auth=claimed, auth_total=59)
    act = await fetch_host_activity(es, settings_kratos, _IP, range="24h")  # type: ignore[arg-type]

    assert act.users is not None
    assert [u.name for u in act.users] == ["svc-backup", "root"]


@pytest.mark.asyncio
async def test_the_unique_claim_gate_rides_the_search_that_already_runs(
    settings_kratos: Settings,
) -> None:
    """The gate is a sub-agg of the auth pass — not a fourth round trip.

    The rule is the dossier's; the network-wide inventory that normally answers
    it is not. ``collect_agent_inventory`` costs a dataset probe plus a grid-wide
    ``host.name`` aggregation carrying a ``top_hits`` document per machine — two
    more searches on a page that runs three, sized to the whole network to
    answer one question about one address. Asking the auth documents themselves
    who wrote them is the same question, scoped to the window the analyst picked.
    """
    es = _FakeConnElastic(_CONN_AGG, auth=_AUTH_AGG, auth_total=59)
    await fetch_host_activity(es, settings_kratos, _IP, range="24h")  # type: ignore[arg-type]

    assert len(es.searches) == 3
    auth = next(s for s in es.searches if "users" in set(s["aggs"] or {}))
    assert auth["aggs"]["agents"]["terms"]["field"] == "host.name"


@pytest.mark.asyncio
async def test_latest_investigation_comes_from_the_injected_lookup(
    settings_kratos: Settings,
) -> None:
    """The store lookup is injected, so this module never reaches into the DB."""
    seen: list[str] = []

    async def _lookup(ip: str) -> LatestInvestigation | None:
        seen.append(ip)
        return LatestInvestigation(id="01J0INV", verdict="tp", ts="2026-08-07T22:10:00Z")

    es = _FakeConnElastic(_CONN_AGG)
    act = await fetch_host_activity(  # type: ignore[arg-type]
        es, settings_kratos, _IP, range="24h", investigation_lookup=_lookup
    )

    assert seen == [_IP]
    assert act.latest_investigation is not None
    assert act.latest_investigation.verdict == "tp"


@pytest.mark.asyncio
async def test_activity_costs_three_searches(settings_kratos: Settings) -> None:
    """Conn, detections, auth — and nothing else. This runs on every page load."""
    es = _FakeConnElastic(_CONN_AGG, detections=_DET_AGG, alerts_total=4)
    await fetch_host_activity(es, settings_kratos, _IP, range="24h")  # type: ignore[arg-type]

    assert len(es.searches) == 3
    assert all(s["size"] == 0 for s in es.searches)


@pytest.mark.asyncio
async def test_the_three_searches_run_concurrently(settings_kratos: Settings) -> None:
    """All three are issued before any returns.

    They are fully independent, and the route runs them under ONE
    ``webui_grid_timeout_s`` budget. Awaited in series that budget is spent
    serially — a slow conn pass eats the allowance of the two behind it and the
    page times out on a grid that answered every query inside its limit.
    """
    es = _FakeConnElastic(_CONN_AGG, detections=_DET_AGG, alerts_total=4, latency_s=0.05)
    await fetch_host_activity(es, settings_kratos, _IP, range="24h")  # type: ignore[arg-type]

    # Deliberately an ORDERING assertion, not a stopwatch: three "start" entries
    # before the first "end" can only be a fan-out, and it stays true on a
    # loaded runner where a wall-clock margin would flake.
    assert es.timeline[:3] == [
        "start:volume",
        "start:recent",
        "start:users",
    ], es.timeline


@pytest.mark.asyncio
async def test_a_failing_search_still_reports_its_own_error(settings_kratos: Settings) -> None:
    """Fanning out must not swap the exception the route degrades on.

    ``asyncio.gather`` collects every outcome, so the failure that reaches the
    caller has to be chosen deliberately — the connection pass is the panel's
    spine and its error is the one worth reporting.
    """

    class _ConnFails(_FakeConnElastic):
        async def search(self, *args: Any, **kwargs: Any) -> EsSearchResult:
            if "volume" in set(kwargs.get("aggs") or {}):
                raise TransportError("connection refused")
            return await super().search(*args, **kwargs)

    es = _ConnFails(_CONN_AGG, detections=_DET_AGG, alerts_total=4)
    with pytest.raises(TransportError):
        await fetch_host_activity(es, settings_kratos, _IP, range="24h")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# A DATABASE failure must not be reported as a down grid
# ---------------------------------------------------------------------------
#
# Both injected lookups are database-backed and both are cosmetic: a peer's name
# and a link to the newest investigation. The route degrades only
# `TransportError`/`TimeoutError`/`OqlValidationError`, so an exception out of
# either one used to leave the route with a bare 500 — and the page then renders
# its grid-unavailable card, telling the analyst Security Onion is down when the
# grid answered every query and the DATABASE is what failed.


@pytest.mark.asyncio
async def test_a_failing_peer_name_lookup_costs_names_and_nothing_else(
    settings_kratos: Settings,
) -> None:
    """A broken peer-name lookup leaves the peers, unnamed. It is enrichment."""

    async def _names(ips: list[str]) -> dict[str, str]:
        raise SQLAlchemyError("connection pool exhausted")

    es = _FakeConnElastic(_CONN_AGG, detections=_DET_AGG, alerts_total=4)
    act = await fetch_host_activity(  # type: ignore[arg-type]
        es, settings_kratos, _IP, range="24h", dossier_lookup=_names
    )

    assert [p.ip for p in act.peers] == ["192.168.10.40", "192.168.20.226"]
    assert all(p.hostname is None for p in act.peers)
    # Everything the grid DID answer survives the database failure.
    assert act.alerts_7d == 4
    assert next(p for p in act.peers if p.ip == "192.168.20.226").alerted is True
    assert act.volume


@pytest.mark.asyncio
async def test_a_failing_investigation_lookup_costs_the_link_and_nothing_else(
    settings_kratos: Settings,
) -> None:
    """A broken investigation lookup leaves the panel, without its link."""

    async def _latest(ip: str) -> LatestInvestigation | None:
        raise SQLAlchemyError("no such table: investigations")

    es = _FakeConnElastic(_CONN_AGG, detections=_DET_AGG, alerts_total=4)
    act = await fetch_host_activity(  # type: ignore[arg-type]
        es, settings_kratos, _IP, range="24h", investigation_lookup=_latest
    )

    assert act.latest_investigation is None
    assert [p.ip for p in act.peers] == ["192.168.10.40", "192.168.20.226"]
    assert act.alerts_7d == 4


@pytest.mark.asyncio
async def test_a_cancelled_peer_name_lookup_is_not_swallowed(
    settings_kratos: Settings,
) -> None:
    """The degrade is for FAILURES, not for the route's own timeout.

    ``asyncio.timeout`` cancels the whole call and converts that cancellation to
    a ``TimeoutError`` at the context boundary — which is how this endpoint
    answers 503. A degrade that caught ``BaseException`` would eat the
    cancellation, return a partial panel, and leave the route's timeout with
    nothing to convert.
    """

    async def _names(ips: list[str]) -> dict[str, str]:
        raise asyncio.CancelledError

    es = _FakeConnElastic(_CONN_AGG)
    with pytest.raises(asyncio.CancelledError):
        await fetch_host_activity(  # type: ignore[arg-type]
            es, settings_kratos, _IP, range="24h", dossier_lookup=_names
        )
