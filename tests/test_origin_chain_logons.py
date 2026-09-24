"""``origin_chain`` reads Windows network logons (2026-09-19 accuracy mission).

The range's DCSync, as stored: the attacker box logged ``localuser`` on to the
domain controller over NTLM (event 4624, logon type 3, ``source.ip`` = the
attacker) 70 ms before the three 4662 replication events under the same logon
id. The tool answered with the lab's WinRM management session from the router
instead. A 4624 carries the host in ``host.ip`` and the origin in
``source.ip``; no remote-access port and no Zeek dataset is involved, so the
first query shape never saw it. The model then read the router as the driver
and the alert as provisioning, and four of six runs ended needs_more_info on a
true positive.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

from soc_ai.tools.origin_chain import origin_chain

DC = "10.20.30.11"
ATTACKER = "10.20.99.5"
ROUTER = "10.20.30.254"
DC_ANCHOR = datetime(2026, 9, 4, 16, 36, 12, tzinfo=UTC)


class _Settings:
    events_index_pattern = "logs-*"
    es_request_timeout_s = 30


def _es(hits: list[dict[str, Any]]) -> AsyncMock:
    es = AsyncMock()
    es.search.return_value = type(
        "R", (), {"hits": hits, "total": len(hits), "raw": {"hits": {"hits": hits}}}
    )()
    return es


def _flow(ts: str, src: str, dst: str, port: int = 5985) -> dict[str, Any]:
    return {
        "_source": {
            "@timestamp": ts,
            "event": {"dataset": "endpoint.events.network"},
            "source": {"ip": src},
            "destination": {"ip": dst, "port": port},
        }
    }


def _logon(
    ts: str,
    src: str | None,
    user: str,
    logon_type: str = "3",
    logon_id: str = "0x1dbb59b",
) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "@timestamp": ts,
        "event": {"dataset": "system.security", "code": "4624"},
        "host": {"ip": [DC], "name": "dc01"},
        "user": {"name": user},
        "winlog": {
            "event_data": {
                "LogonType": logon_type,
                "TargetLogonId": logon_id,
                "AuthenticationPackageName": "NTLM",
            }
        },
    }
    if src:
        doc["source"] = {"ip": src}
    return {"_source": doc}


async def test_a_windows_network_logon_names_the_host_that_drove_the_account() -> None:
    """The DCSync, replayed: the NTLM logon from the attacker box is the
    closest preceding session, and the session names the account."""
    es = _es(
        [
            _logon("2026-09-04T16:35:51.122Z", ATTACKER, "localuser"),
            _flow("2026-09-04T16:23:47.891Z", ROUTER, DC),
        ]
    )
    out = await origin_chain(DC, elastic=es, settings=_Settings(), time_anchor=DC_ANCHOR)
    assert out["observations"] is True
    closest = out["closest_preceding"]
    assert closest["source_ip"] == ATTACKER
    assert closest["user"] == "localuser"
    assert closest["logon_type"] == "3"
    assert closest["logon_id"] == "0x1dbb59b"
    assert "localuser" in out["summary"]
    assert ATTACKER in out["summary"]


async def test_the_query_asks_for_windows_logons_that_carry_an_origin() -> None:
    """Guard the second query branch: a 4624 on this host with a source
    address, and the inbound remote-access branch still there beside it."""
    es = _es([])
    await origin_chain(DC, elastic=es, settings=_Settings(), time_anchor=DC_ANCHOR)
    q = str(es.search.await_args.kwargs.get("query"))
    assert "host.ip" in q
    assert "4624" in q
    assert "source.ip" in q
    assert "LogonType" in q
    assert "destination.ip" in q


async def test_the_newest_sessions_survive_a_busy_window() -> None:
    """A busy host has more sessions in the window than the tool returns.
    The newest ones are the ones that can have driven the activity, so the
    query asks for the newest first, and the answer still reads in time
    order."""
    es = _es(
        [
            _logon("2026-09-04T16:35:51.122Z", ATTACKER, "localuser"),
            _flow("2026-09-04T16:23:47.891Z", ROUTER, DC),
        ]
    )
    out = await origin_chain(DC, elastic=es, settings=_Settings(), time_anchor=DC_ANCHOR)
    assert es.search.await_args.kwargs.get("sort") == [{"@timestamp": "desc"}]
    times = [s["timestamp"] for s in out["inbound_sessions"]]
    assert times == sorted(times)
    assert out["closest_preceding"]["source_ip"] == ATTACKER


async def test_a_logon_with_no_origin_address_is_not_a_session() -> None:
    """Service and local logons (Advapi, Negotiate, no source.ip) are the bulk
    of a domain controller's 4624s. None of them says who drove the box."""
    es = _es([_logon("2026-09-04T16:35:00.000Z", None, "localuser")])
    out = await origin_chain(DC, elastic=es, settings=_Settings(), time_anchor=DC_ANCHOR)
    assert out["observations"] is False


async def test_a_logon_from_the_host_itself_is_not_a_session() -> None:
    """The direction invariant holds for logons too: the host logging an
    account on from its own address did not drive itself."""
    es = _es([_logon("2026-09-04T16:35:00.000Z", DC, "localuser")])
    out = await origin_chain(DC, elastic=es, settings=_Settings(), time_anchor=DC_ANCHOR)
    assert out["observations"] is False


async def test_a_flow_session_still_reads_as_before() -> None:
    """NEGATIVE CONTROL: the original answer shape for a flow is unchanged."""
    es = _es([_flow("2026-09-04T16:23:47.891Z", ROUTER, DC)])
    out = await origin_chain(DC, elastic=es, settings=_Settings(), time_anchor=DC_ANCHOR)
    session = out["inbound_sessions"][0]
    assert session["source_ip"] == ROUTER
    assert session["destination_port"] == 5985
    assert session["dataset"] == "endpoint.events.network"
    assert "user" not in session


async def test_a_noisy_domain_controller_still_shows_every_driver() -> None:
    """A domain controller logs hundreds of network logons in half an hour,
    nearly all of them one machine account re-authenticating. Each driver
    takes one slot, and the count says how often it appeared."""
    hits = [_logon("2026-09-04T16:35:51.122Z", ATTACKER, "localuser")]
    for i in range(120):
        hits.append(
            _logon(
                f"2026-09-04T16:{20 + i // 10:02d}:{i % 60:02d}.000Z",
                "10.20.30.21",
                "WS01$",
                logon_id="0x1",
            )
        )
    es = _es(hits)
    out = await origin_chain(DC, elastic=es, settings=_Settings(), time_anchor=DC_ANCHOR)
    assert es.search.await_args.kwargs.get("size") >= 100
    sources = [(s["source_ip"], s.get("user")) for s in out["inbound_sessions"]]
    assert sources == [("10.20.30.21", "WS01$"), (ATTACKER, "localuser")]
    assert out["inbound_sessions"][0]["events_in_window"] == 120
    assert out["closest_preceding"]["source_ip"] == ATTACKER


async def test_a_loopback_logon_is_not_a_driver() -> None:
    """The host's own service traffic logs as a network logon from 127.0.0.1
    or ::1. It says nothing about who drove the box."""
    es = _es(
        [
            _logon("2026-09-04T16:35:00.000Z", "127.0.0.1", "DC01$"),
            _logon("2026-09-04T16:34:00.000Z", "::1", "DC01$"),
        ]
    )
    out = await origin_chain(DC, elastic=es, settings=_Settings(), time_anchor=DC_ANCHOR)
    assert out["observations"] is False
    q = str(es.search.await_args.kwargs.get("query"))
    assert "127.0.0.1" in q


async def test_the_newest_event_of_a_repeating_driver_is_the_one_reported() -> None:
    """Whatever order the page arrives in, the pair's newest event is the one
    that could have driven the activity."""
    es = _es(
        [
            _flow("2026-09-04T16:10:00.000Z", ROUTER, DC),
            _flow("2026-09-04T16:30:00.000Z", ROUTER, DC),
            _flow("2026-09-04T16:20:00.000Z", ROUTER, DC),
        ]
    )
    out = await origin_chain(DC, elastic=es, settings=_Settings(), time_anchor=DC_ANCHOR)
    assert len(out["inbound_sessions"]) == 1
    only = out["inbound_sessions"][0]
    assert only["timestamp"] == "2026-09-04T16:30:00.000Z"
    assert only["events_in_window"] == 3
