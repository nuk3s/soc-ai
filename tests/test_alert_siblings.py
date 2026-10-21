"""Alert groups that share a flow, and the cases a group is on (dogfood 2026-10-19).

R2-I9 and R2-D9. On the range an SQL injection alert and a Geoserver alert
shared one ``network.community_id`` and showed as two unrelated rows. The
NTLMv1 group (a false positive) and the WMIExec group (a true positive) fired
2.6 s apart between the same two hosts, and neither row named the other. One
attack sequence carried opposite verdicts with no pointer.

V3-N1 and V3-N5. The first read cut each pair at the 10 groups with the most
alerts, so the two 1-alert groups of that pair named nobody. It linked two
groups when their spans of alert times overlapped, so a scan 28 minutes away
was a "sibling" of NTLMv1, and 50 of 64 rows of a 90 day window had a chip.

R2-I2. The escalate confirm said a group was "already on a case" and named no
case. The row marker had no link.

The rule tests plant alerts in a grid double that evaluates the request
(tests/doc_grid.py). Every positive test has a negative control beside it, and
each control sits on the path a loose rule would take.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.so_client.elastic import ElasticClient, EsSearchResult
from soc_ai.store import escalations as esc_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.webui import alert_siblings as sib
from soc_ai.webui.alert_siblings import GroupRef

from tests.doc_grid import DocGrid, alert, burst

_SQLI = "ET WEB_SERVER Possible SQL Injection (exec) in HTTP URI"
_GEO = "ET WEB_SPECIFIC_APPS Geoserver Unsafe jxpath Evaluation RCE Attempt"
_NTLM = "ET INFO NTLMv1 Session Setup Response - Challenge"
_WMI = "ET INFO Suspected Impacket WMIExec Activity"
_SCAN = "ET SCAN Suspicious inbound to MSSQL port 1433"
_NMAP = "ET SCAN Nmap Scripting Engine User-Agent Detected"
_RDP = "ET SCAN MS Terminal Server Traffic on Non-standard Port"
_LATERAL = "ET INFO Possible Lateral Movement - File Creation Request"
_NTP = "ET INFO NTP traffic on a fixed port"

_ATTACKER = "192.0.2.40"
_VICTIM = "192.0.2.20"
_OTHER = "192.0.2.30"

_SECOND = timedelta(seconds=1)
_MINUTE = timedelta(minutes=1)


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _rule(name: str) -> GroupRef:
    return sib.group_ref("suricata", name)


def _read(grid: DocGrid, settings: Settings, time_range: str = "24h") -> sib.SiblingIndex:
    """One page read of the window, against the double."""
    return asyncio.run(
        sib.fetch_sibling_index(
            grid,  # type: ignore[arg-type]
            settings,
            time_range=time_range,
            abs_from=None,
            abs_to=None,
            time_zone=None,
        )
    )


def _names(index: sib.SiblingIndex, name: str) -> set[str]:
    return {r.name for r in index.links(_rule(name))}


# ── R2-I9: the community id signal ───────────────────────────────────────────


def test_two_rules_on_one_community_id_are_siblings(settings_kratos: Settings) -> None:
    t = _now() - timedelta(hours=1)
    grid = DocGrid(
        [
            alert(t, rule=_SQLI, src="198.51.100.77", dst=_VICTIM, community_id="1:abc="),
            alert(
                t + 30 * _MINUTE,
                rule=_GEO,
                src="198.51.100.77",
                dst=_VICTIM,
                community_id="1:abc=",
            ),
        ]
    )

    index = _read(grid, settings_kratos)

    assert index.links(_rule(_SQLI)) == {_rule(_GEO): {"flow"}}
    assert index.links(_rule(_GEO)) == {_rule(_SQLI): {"flow"}}


def test_a_flow_with_one_rule_links_nothing(settings_kratos: Settings) -> None:
    """NEGATIVE CONTROL. Many alerts of one rule on one flow are one group."""
    t = _now() - timedelta(hours=1)
    grid = DocGrid(list(burst(t, 5, _SECOND, rule=_SQLI, community_id="1:abc=")))

    index = _read(grid, settings_kratos)

    assert index.links(_rule(_SQLI)) == {}


def test_a_zeek_notice_and_a_rule_on_one_flow_are_siblings(settings_kratos: Settings) -> None:
    t = _now() - timedelta(hours=1)
    grid = DocGrid(
        [
            alert(t, rule=_WMI, community_id="1:wmi="),
            alert(
                t + _SECOND,
                dataset="zeek.notice",
                note="ATTACK::Lateral_Movement",
                community_id="1:wmi=",
            ),
        ]
    )

    index = _read(grid, settings_kratos)

    assert index.links(_rule(_WMI)) == {
        sib.group_ref("notice", "ATTACK::Lateral_Movement"): {"flow"}
    }


# ── The flow signal has a time bound ────────────────────────────────────────

_DAY = timedelta(days=1)
_HOUR = timedelta(hours=1)


def test_two_groups_on_one_community_id_three_days_apart_do_not_link(
    settings_kratos: Settings,
) -> None:
    """NEGATIVE CONTROL. A community id is a hash of the five-tuple. NTP from
    port 123 to port 123 repeats it every day, so one id is not one session."""
    t = _now() - 4 * _DAY
    grid = DocGrid(
        [
            alert(t, rule=_SQLI, src=_OTHER, dst=_VICTIM, community_id="1:ntp="),
            alert(t + 3 * _DAY, rule=_GEO, src=_OTHER, dst=_VICTIM, community_id="1:ntp="),
        ]
    )

    index = _read(grid, settings_kratos, time_range="7d")

    assert index.links(_rule(_SQLI)) == {}
    assert not index.partial(_rule(_SQLI))


def test_two_groups_on_one_community_id_fifty_minutes_apart_link(
    settings_kratos: Settings,
) -> None:
    t = _now() - 3 * _HOUR
    grid = DocGrid(
        [
            alert(t, rule=_SQLI, community_id="1:abc="),
            alert(t + 50 * _MINUTE, rule=_GEO, community_id="1:abc="),
        ]
    )

    assert _read(grid, settings_kratos).links(_rule(_SQLI)) == {_rule(_GEO): {"flow"}}


def test_the_flow_bound_reads_the_alert_times_inside_two_long_spans(
    settings_kratos: Settings,
) -> None:
    """The two groups repeat one id over days, and their spans overlap. A
    rule on the spans would link them. Only an alert of each within the hour
    links them."""
    t = _now() - 5 * _DAY
    base = [
        alert(t, rule=_SQLI, community_id="1:ntp="),
        alert(t + 3 * _DAY, rule=_SQLI, community_id="1:ntp="),
        alert(t + 36 * _HOUR, rule=_GEO, community_id="1:ntp="),
        alert(t + 48 * _HOUR, rule=_GEO, community_id="1:ntp="),
    ]
    near = DocGrid([*base, alert(t + 36 * _HOUR + 50 * _MINUTE, rule=_SQLI, community_id="1:ntp=")])
    far = DocGrid([*base, alert(t + 36 * _HOUR + 61 * _MINUTE, rule=_SQLI, community_id="1:ntp=")])

    assert _read(near, settings_kratos, "7d").links(_rule(_SQLI)) == {_rule(_GEO): {"flow"}}
    # NEGATIVE CONTROL. One hour and one minute apart.
    far_index = _read(far, settings_kratos, "7d")
    assert far_index.links(_rule(_SQLI)) == {}
    assert not far_index.partial(_rule(_SQLI))


def test_a_flow_over_the_slot_budget_claims_no_unsure_link(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Past the budget the first and last alert of each group decide. A flow
    link they cannot decide is left out and marked partial."""
    monkeypatch.setattr(sib, "SLOT_BUDGET", 1)
    t = _now() - 5 * _DAY
    grid = DocGrid(
        [
            alert(t, rule=_SQLI, community_id="1:ntp="),
            alert(t + 36 * _HOUR + 50 * _MINUTE, rule=_SQLI, community_id="1:ntp="),
            alert(t + 3 * _DAY, rule=_SQLI, community_id="1:ntp="),
            alert(t + 36 * _HOUR, rule=_GEO, community_id="1:ntp="),
            alert(t + 48 * _HOUR, rule=_GEO, community_id="1:ntp="),
            # NEGATIVE CONTROL. The first and last alerts decide this flow.
            alert(t, rule=_NTLM, community_id="1:smb="),
            alert(t + 10 * _MINUTE, rule=_WMI, community_id="1:smb="),
        ]
    )

    index = _read(grid, settings_kratos, "7d")

    assert index.links(_rule(_SQLI)) == {}
    assert index.partial(_rule(_SQLI))
    assert index.partial(_rule(_GEO))
    assert index.links(_rule(_NTLM)) == {_rule(_WMI): {"flow"}}
    assert not index.partial(_rule(_NTLM))


# ── V3-N1, V3-N5: the hosts signal is exact ─────────────────────────────────


def _range_pair(t: datetime) -> list[dict[str, Any]]:
    """The range pair: 13 groups on one pair of hosts.

    NTLMv1 and WMIExec hold one alert each, 2.6 s apart, in opposite
    directions. Nine lateral-movement groups hold up to 1,531 alerts, from 10
    minutes after them. The Nmap scan fired 15 minutes before. The terminal
    server scan fired 25 minutes before and 20 minutes after, so its span
    covers NTLMv1 while no alert of it comes near.
    """
    docs: list[dict[str, Any]] = [
        alert(t, rule=_NTLM, src=_VICTIM, dst=_ATTACKER),
        alert(t + timedelta(seconds=2.6), rule=_WMI, src=_ATTACKER, dst=_VICTIM),
        *burst(
            t - 15 * _MINUTE, 20, timedelta(milliseconds=5), rule=_NMAP, src=_ATTACKER, dst=_VICTIM
        ),
        *burst(t - 25 * _MINUTE, 30, _SECOND, rule=_RDP, src=_ATTACKER, dst=_VICTIM),
        *burst(t + 20 * _MINUTE, 30, _SECOND, rule=_RDP, src=_ATTACKER, dst=_VICTIM),
    ]
    for i, count in enumerate((1531, 276, 13, 11, 10, 6, 5, 5, 4)):
        docs += burst(
            t + (10 + i / 4) * _MINUTE,
            count,
            timedelta(milliseconds=50),
            rule=f"{_LATERAL} {i}",
            src=_ATTACKER,
            dst=_VICTIM,
        )
    return docs


def test_two_one_alert_groups_on_a_busy_pair_name_each_other(settings_kratos: Settings) -> None:
    """V3-N1. The read cut the pair at its 10 biggest groups, and NTLMv1 and
    WMIExec hold one alert each."""
    t = _now() - timedelta(hours=2)
    index = _read(DocGrid(_range_pair(t)), settings_kratos)

    assert index.links(_rule(_NTLM)) == {_rule(_WMI): {"hosts"}}
    assert index.links(_rule(_WMI)) == {_rule(_NTLM): {"hosts"}}
    assert not index.partial(_rule(_NTLM))


def test_a_group_fifteen_minutes_away_is_not_a_sibling(settings_kratos: Settings) -> None:
    """NEGATIVE CONTROL. The Nmap scan fired 15 minutes before NTLMv1."""
    t = _now() - timedelta(hours=2)
    index = _read(DocGrid(_range_pair(t)), settings_kratos)

    assert _NMAP not in _names(index, _NTLM)
    assert _NMAP not in _names(index, _WMI)
    assert index.links(_rule(_NMAP)) == {}


def test_a_span_that_covers_an_alert_with_no_alert_near_it_is_not_a_sibling(
    settings_kratos: Settings,
) -> None:
    """NEGATIVE CONTROL, V3-N5. The terminal server scan fired 25 minutes
    before and 20 minutes after NTLMv1. The two spans overlap, and the first
    read linked them on that."""
    t = _now() - timedelta(hours=2)
    index = _read(DocGrid(_range_pair(t)), settings_kratos)

    assert _RDP not in _names(index, _NTLM)
    assert _RDP not in _names(index, _WMI)


def test_the_busy_groups_of_the_pair_name_each_other(settings_kratos: Settings) -> None:
    t = _now() - timedelta(hours=2)
    index = _read(DocGrid(_range_pair(t)), settings_kratos)

    assert _names(index, f"{_LATERAL} 0") == {f"{_LATERAL} {i}" for i in range(1, 9)}


def test_more_than_ten_groups_on_one_pair_all_name_each_other(settings_kratos: Settings) -> None:
    """Fourteen groups within one minute on one pair. Each names the other 13."""
    t = _now() - timedelta(hours=1)
    rules = [f"ET TEST rule {i:02d}" for i in range(14)]
    docs = [
        alert(t + i * 3 * _SECOND, rule=r, src=_ATTACKER, dst=_VICTIM) for i, r in enumerate(rules)
    ]
    # One big group far away pushes nothing out.
    docs += burst(t + 30 * _MINUTE, 400, _SECOND, rule=_SCAN, src=_ATTACKER, dst=_VICTIM)

    index = _read(DocGrid(docs), settings_kratos)

    for r in rules:
        assert _names(index, r) == set(rules) - {r}
    assert index.links(_rule(_SCAN)) == {}


def test_two_alerts_just_under_five_minutes_apart_inside_two_long_spans_link(
    settings_kratos: Settings,
) -> None:
    """The spans overlap and no first or last alert is near another. Only the
    alert times inside the spans decide."""
    t = _now() - timedelta(hours=3)
    a = "ET POLICY long-lived A"
    b = "ET POLICY long-lived B"
    base = [
        alert(t, rule=a, src=_ATTACKER, dst=_VICTIM),
        alert(t + 60 * _MINUTE, rule=a, src=_ATTACKER, dst=_VICTIM),
        alert(t + 30 * _MINUTE, rule=b, src=_VICTIM, dst=_ATTACKER),
        alert(t + 40 * _MINUTE, rule=b, src=_VICTIM, dst=_ATTACKER),
    ]
    near = DocGrid([*base, alert(t + 25 * _MINUTE + _SECOND, rule=a, src=_ATTACKER, dst=_VICTIM)])
    far = DocGrid([*base, alert(t + 25 * _MINUTE - _SECOND, rule=a, src=_ATTACKER, dst=_VICTIM)])

    assert _read(near, settings_kratos).links(_rule(a)) == {_rule(b): {"hosts"}}
    # NEGATIVE CONTROL. Five minutes and one second apart.
    far_index = _read(far, settings_kratos)
    assert far_index.links(_rule(a)) == {}
    assert not far_index.partial(_rule(a))


def test_the_rule_holds_at_exactly_five_minutes(settings_kratos: Settings) -> None:
    t = _now() - timedelta(hours=1)
    inside = DocGrid(
        [
            alert(t, rule=_NTLM, src=_ATTACKER, dst=_VICTIM),
            alert(t + sib.SIBLING_SPAN, rule=_WMI, src=_ATTACKER, dst=_VICTIM),
        ]
    )
    outside = DocGrid(
        [
            alert(t, rule=_NTLM, src=_ATTACKER, dst=_VICTIM),
            alert(t + sib.SIBLING_SPAN + _SECOND, rule=_WMI, src=_ATTACKER, dst=_VICTIM),
        ]
    )

    assert _read(inside, settings_kratos).links(_rule(_NTLM)) == {_rule(_WMI): {"hosts"}}
    assert _read(outside, settings_kratos).links(_rule(_NTLM)) == {}


def test_other_hosts_at_the_same_time_are_not_siblings(settings_kratos: Settings) -> None:
    """NEGATIVE CONTROL. The same second, two different pairs that share one host."""
    t = _now() - timedelta(hours=1)
    grid = DocGrid(
        [
            alert(t, rule=_NTLM, src=_ATTACKER, dst=_VICTIM),
            alert(t, rule=_WMI, src=_ATTACKER, dst=_OTHER),
        ]
    )

    assert _read(grid, settings_kratos).links(_rule(_NTLM)) == {}


def test_both_signals_on_one_sibling_are_named_once(settings_kratos: Settings) -> None:
    t = _now() - timedelta(hours=1)
    grid = DocGrid(
        [
            alert(t, rule=_SQLI, src="203.0.113.77", dst=_VICTIM, community_id="1:abc="),
            alert(t, rule=_GEO, src="203.0.113.77", dst=_VICTIM, community_id="1:abc="),
        ]
    )

    assert _read(grid, settings_kratos).links(_rule(_SQLI)) == {_rule(_GEO): {"flow", "hosts"}}


def test_a_group_never_lists_itself(settings_kratos: Settings) -> None:
    """The same rule in both directions of a pair, and twice on a flow."""
    t = _now() - timedelta(hours=1)
    grid = DocGrid(
        [
            alert(t, rule=_SQLI, src=_ATTACKER, dst=_VICTIM, community_id="1:abc="),
            alert(t, rule=_SQLI, src=_VICTIM, dst=_ATTACKER, community_id="1:abc="),
            alert(t, rule=_GEO, src="203.0.113.9", dst="203.0.113.8", community_id="1:abc="),
        ]
    )

    index = _read(grid, settings_kratos)

    assert _rule(_SQLI) not in index.links(_rule(_SQLI))
    assert index.links(_rule(_SQLI)) == {_rule(_GEO): {"flow"}}


def test_an_alert_outside_the_window_links_nothing(settings_kratos: Settings) -> None:
    """NEGATIVE CONTROL. WMIExec sits two days back, outside the 24 h window."""
    t = _now() - timedelta(hours=1)
    grid = DocGrid(
        [
            alert(t, rule=_NTLM, src=_ATTACKER, dst=_VICTIM),
            alert(t - timedelta(days=2), rule=_WMI, src=_ATTACKER, dst=_VICTIM),
        ]
    )

    assert _read(grid, settings_kratos).links(_rule(_NTLM)) == {}


def test_the_query_reads_the_window_without_the_page_filters(settings_kratos: Settings) -> None:
    """A sibling stays a sibling when the analyst hides acknowledged alerts or
    filters by severity. The NTLMv1 false positive was auto-acknowledged."""
    query = sib.sibling_query(
        settings_kratos, time_range="24h", abs_from=None, abs_to=None, time_zone=None
    )
    text = repr(query)

    assert "event.acknowledged" not in text
    assert "event.severity_label" not in text
    assert "now-24h" in text


# ── The cost of the read ─────────────────────────────────────────────────────


def test_a_window_with_no_shared_pair_or_flow_costs_one_search(settings_kratos: Settings) -> None:
    t = _now() - timedelta(hours=1)
    grid = DocGrid(
        [
            alert(t, rule=_NTLM, src=_ATTACKER, dst=_VICTIM, community_id="1:a="),
            alert(t, rule=_WMI, src=_OTHER, dst=_VICTIM, community_id="1:b="),
        ]
    )

    index = _read(grid, settings_kratos)

    assert len(grid.searches) == 1
    assert index.links(_rule(_NTLM)) == {}
    assert not index.partial(_rule(_NTLM))


def test_a_shared_flow_costs_one_more_search_for_its_groups(settings_kratos: Settings) -> None:
    """The candidate read counts the groups of each flow. The names come in
    the second search, for the flows that hold two groups or more."""
    t = _now() - timedelta(hours=1)
    grid = DocGrid(
        [
            alert(t, rule=_NTLM, src=_ATTACKER, dst=_VICTIM, community_id="1:a="),
            alert(t, rule=_WMI, src=_OTHER, dst=_VICTIM, community_id="1:a="),
            *burst(t, 3, _SECOND, rule=_SCAN, src=_OTHER, dst=_ATTACKER, community_id="1:b="),
        ]
    )

    index = _read(grid, settings_kratos)

    assert len(grid.searches) == 2
    assert index.links(_rule(_NTLM)) == {_rule(_WMI): {"flow"}}
    # The second search reads the shared flow only.
    second = repr(grid.searches[1]["query"])
    assert "1:a=" in second and "1:b=" not in second


def test_many_flows_of_one_group_cost_no_cut(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """NEGATIVE CONTROL. Busy flows of one rule each pass the candidate cap
    of flows with names. The count read lists them all, so the list is whole."""
    monkeypatch.setattr(sib, "FLOW_CANDIDATES", 1)
    t = _now() - timedelta(hours=1)
    docs = [
        alert(t, rule=_SQLI, community_id="1:a="),
        alert(t, rule=_GEO, community_id="1:a="),
    ]
    for i in range(20):
        docs += burst(t, 3, _SECOND, rule=_SCAN, community_id=f"1:busy{i}=")

    index = _read(DocGrid(docs), settings_kratos)

    assert not index.partial(_rule(_SQLI))
    assert index.links(_rule(_SQLI)) == {_rule(_GEO): {"flow"}}


def test_more_shared_flows_than_the_cap_are_partial(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sib, "FLOW_CANDIDATES", 1)
    t = _now() - timedelta(hours=1)
    grid = DocGrid(
        [
            alert(t, rule=_SQLI, community_id="1:a="),
            alert(t, rule=_GEO, community_id="1:a="),
            alert(t, rule=_NTLM, community_id="1:b="),
            alert(t, rule=_WMI, community_id="1:b="),
        ]
    )

    assert _read(grid, settings_kratos).partial(_rule(_SQLI))


def test_a_shared_pair_costs_one_more_search_for_its_alert_times(
    settings_kratos: Settings,
) -> None:
    t = _now() - timedelta(hours=2)
    grid = DocGrid(_range_pair(t))

    _read(grid, settings_kratos)

    assert len(grid.searches) == 2
    # The second search reads the shared pairs only.
    second = repr(grid.searches[1]["query"])
    assert _ATTACKER in second and _VICTIM in second


def test_a_failed_second_read_claims_no_link_and_says_the_list_is_partial(
    settings_kratos: Settings,
) -> None:
    t = _now() - timedelta(hours=2)
    docs = [
        *_range_pair(t),
        alert(t, rule=_SQLI, src="198.51.100.77", dst=_OTHER, community_id="1:abc="),
        alert(t, rule=_GEO, src="198.51.100.77", dst=_OTHER, community_id="1:abc="),
    ]
    grid = DocGrid(docs, fail_from=2)

    index = _read(grid, settings_kratos)

    assert index.links(_rule(_SQLI)) == {}
    assert index.links(_rule(_NTLM)) == {}
    # Every row says the list can be partial.
    assert index.partial(_rule(_NTLM))
    assert index.partial(_rule(_SQLI))
    assert index.degraded


# ── Partial: a cap that cuts the data says so ───────────────────────────────


def test_a_pair_over_the_slot_budget_claims_no_unsure_link(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The grid reads the alert times of a pair only while the read stays
    small. Past the budget the first and last alert of each group decide, and
    a link they cannot decide is left out and marked partial."""
    monkeypatch.setattr(sib, "SLOT_BUDGET", 1)
    t = _now() - timedelta(hours=3)
    a = "ET POLICY long-lived A"
    b = "ET POLICY long-lived B"
    grid = DocGrid(
        [
            alert(t, rule=a, src=_ATTACKER, dst=_VICTIM),
            alert(t + 25 * _MINUTE + _SECOND, rule=a, src=_ATTACKER, dst=_VICTIM),
            alert(t + 60 * _MINUTE, rule=a, src=_ATTACKER, dst=_VICTIM),
            alert(t + 30 * _MINUTE, rule=b, src=_ATTACKER, dst=_VICTIM),
            alert(t + 40 * _MINUTE, rule=b, src=_ATTACKER, dst=_VICTIM),
            # Its first alert is 2 s after the last alert of A. The first and
            # the last alerts decide that link.
            alert(t + 60 * _MINUTE + 2 * _SECOND, rule=_WMI, src=_ATTACKER, dst=_VICTIM),
            # NEGATIVE CONTROL. A pair inside the budget is not partial.
            alert(t, rule=_SQLI, src=_OTHER, dst=_VICTIM),
            alert(t + _SECOND, rule=_GEO, src=_OTHER, dst=_VICTIM),
        ]
    )

    index = _read(grid, settings_kratos)

    assert index.links(_rule(a)) == {_rule(_WMI): {"hosts"}}
    assert index.partial(_rule(a))
    assert index.partial(_rule(b))
    assert not index.partial(_rule(_WMI))
    assert not index.partial(_rule(_SQLI))
    assert index.links(_rule(_SQLI)) == {_rule(_GEO): {"hosts"}}


def test_a_pair_with_more_groups_than_the_read_lists_is_partial(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sib, "PAIR_MEMBERS", 3)
    t = _now() - timedelta(hours=1)
    rules = [f"ET TEST rule {i}" for i in range(5)]
    grid = DocGrid(
        [alert(t + i * _SECOND, rule=r, src=_ATTACKER, dst=_VICTIM) for i, r in enumerate(rules)]
    )

    index = _read(grid, settings_kratos)

    assert all(index.partial(_rule(r)) for r in rules)


def test_pairs_cut_in_both_views_are_partial(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sib, "PAIR_SOURCES", 1)
    monkeypatch.setattr(sib, "PAIR_PEERS", 1)
    t = _now() - timedelta(hours=1)
    grid = DocGrid(
        [
            alert(t, rule=_NTLM, src=_ATTACKER, dst=_VICTIM),
            alert(t, rule=_WMI, src=_ATTACKER, dst=_VICTIM),
            alert(t, rule=_SQLI, src=_OTHER, dst="192.0.2.31"),
            alert(t, rule=_GEO, src="192.0.2.31", dst=_OTHER),
        ]
    )

    index = _read(grid, settings_kratos)

    assert index.partial(_rule(_NTLM))


def test_a_scan_cut_in_one_view_is_whole_in_the_other(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """NEGATIVE CONTROL. A scan of four hosts passes the destination cap of
    its source. The view by destination holds each pair whole."""
    monkeypatch.setattr(sib, "PAIR_PEERS", 2)
    t = _now() - timedelta(hours=1)
    docs = [alert(t, rule=_NMAP, src=_ATTACKER, dst=f"198.51.100.{i}") for i in range(1, 5)]
    docs.append(alert(t + _SECOND, rule=_SCAN, src="198.51.100.4", dst=_ATTACKER))

    index = _read(DocGrid(docs), settings_kratos)

    assert not index.partial(_rule(_NMAP))
    assert index.links(_rule(_NMAP)) == {_rule(_SCAN): {"hosts"}}


def test_flows_cut_with_shared_flows_left_out_are_partial(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sib, "FLOW_BUCKETS", 1)
    t = _now() - timedelta(hours=1)
    grid = DocGrid(
        [
            alert(t, rule=_SQLI, community_id="1:a="),
            alert(t, rule=_GEO, community_id="1:a="),
            alert(t, rule=_NTLM, community_id="1:b="),
            alert(t, rule=_WMI, community_id="1:b="),
        ]
    )

    assert _read(grid, settings_kratos).partial(_rule(_SQLI))


def test_a_cut_flow_of_one_rule_still_marks_the_list_partial(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The flows come ordered by their group count, but each shard orders by
    its own count. A flow of a Suricata rule and a Zeek notice holds one group
    on each shard and can fall off both. So any flow the cap leaves out marks
    the lists partial, even one that looks like one group."""
    monkeypatch.setattr(sib, "FLOW_BUCKETS", 2)
    t = _now() - timedelta(hours=1)
    grid = DocGrid(
        [
            alert(t, rule=_SQLI, community_id="1:a="),
            alert(t, rule=_GEO, community_id="1:a="),
            *burst(t, 2, _SECOND, rule=_NTLM, community_id="1:b="),
            *burst(t, 2, _SECOND, rule=_WMI, community_id="1:c="),
        ]
    )

    # The last flow kept holds one group. That says nothing about the flow
    # left out on a grid of many shards.
    assert _read(grid, settings_kratos).partial(_rule(_SQLI))


def test_flows_of_one_alert_cost_no_cut(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """NEGATIVE CONTROL. A flow with one alert cannot hold two groups. The
    read leaves it out of the flows, and its absence cuts nothing."""
    monkeypatch.setattr(sib, "FLOW_BUCKETS", 1)
    t = _now() - timedelta(hours=1)
    grid = DocGrid(
        [
            alert(t, rule=_SQLI, community_id="1:a="),
            alert(t, rule=_GEO, community_id="1:a="),
            alert(t, rule=_NTLM, community_id="1:b="),
            alert(t, rule=_WMI, community_id="1:c="),
            alert(t, rule=_SCAN, community_id="1:d="),
        ]
    )

    index = _read(grid, settings_kratos)

    assert not index.partial(_rule(_SQLI))
    assert index.links(_rule(_SQLI)) == {_rule(_GEO): {"flow"}}


def test_two_unnamed_datasets_on_one_pair_link(settings_kratos: Settings) -> None:
    """An alert with no rule name is named by its dataset. Two such groups
    on one pair counted as one group and never reached the group read."""
    t = _now() - timedelta(hours=1)
    grid = DocGrid(
        [
            alert(t, dataset="opencanary.events", src=_ATTACKER, dst=_VICTIM),
            alert(t + 3 * _SECOND, dataset="endpoint.alerts", src=_ATTACKER, dst=_VICTIM),
        ]
    )

    index = _read(grid, settings_kratos)

    assert index.links(sib.GroupRef("unnamed", "opencanary.events")) == {
        sib.GroupRef("unnamed", "endpoint.alerts"): {"hosts"}
    }


def test_the_reads_ask_for_a_complete_answer(settings_kratos: Settings) -> None:
    """A read that lost a shard misses groups and cannot tell. It must raise,
    so the list is no data or partial and never a false "complete"."""
    seen: list[dict[str, Any]] = []
    grid = DocGrid(_range_pair(_now() - timedelta(hours=2)))
    plain = grid.search

    async def _search(index: str, query: Any, **kwargs: Any) -> EsSearchResult:
        seen.append(kwargs)
        return await plain(index, query, **kwargs)

    grid.search = _search  # type: ignore[method-assign]
    _read(grid, settings_kratos)

    assert len(seen) == 2
    assert all(k.get("require_complete") is True for k in seen)


# ── Route: the row carries the siblings, at most two searches per page ──────


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as c:
            yield c


def _run(client: TestClient, *, alert: str, rule: str, verdict: str) -> str:
    async def _go() -> str:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            inv = await inv_svc.create(
                db, alert_es_id=alert, started_by="tester", rule_name=rule, kind="suricata"
            )
            await inv_svc.finalize(db, inv.id, status="complete", verdict=verdict, confidence=0.8)
            return str(inv.id)

    return asyncio.run(_go())


def _page_bucket(
    name: str,
    *,
    escalated_ids: tuple[str, ...] = (),
    escalated: int | None = None,
    latest: datetime | None = None,
) -> dict[str, Any]:
    bucket: dict[str, Any] = {
        "key": name,
        "doc_count": 2,
        "latest": {
            "hits": {
                "hits": [
                    {
                        "_id": f"latest-{name}",
                        "_source": {
                            "@timestamp": (latest or _now() - _MINUTE).isoformat(),
                            "event": {"dataset": "suricata.alert"},
                        },
                    }
                ]
            }
        },
    }
    if escalated_ids:
        bucket["escalated"] = {
            "doc_count": len(escalated_ids) if escalated is None else escalated,
            "ids": {"hits": {"hits": [{"_id": i} for i in escalated_ids]}},
        }
    return bucket


class _Grid:
    """A grid double: canned page rows, and the sibling read from documents."""

    def __init__(
        self,
        page: list[dict[str, Any]],
        docs: list[dict[str, Any]] | None = None,
        *,
        sibling_error: BaseException | None = None,
        case_links: dict[str, str] | None = None,
    ) -> None:
        self.page = page
        self.docs = DocGrid(docs or [])
        self.sibling_error = sibling_error
        self.case_links = case_links or {}
        self.calls: list[str] = []

    async def __call__(self, index: str, query: Any, **kwargs: Any) -> EsSearchResult:
        aggs = kwargs.get("aggs") or {}
        if "flows" in aggs or any(k in aggs for k in sib.GROUP_READ_AGGS):
            self.calls.append("siblings" if "flows" in aggs else "sibling-times")
            if self.sibling_error is not None:
                raise self.sibling_error
            return await self.docs.search(index, query, **kwargs)
        if "by_alert" in aggs:
            self.calls.append("cases")
            return EsSearchResult(
                total=0,
                took_ms=1,
                aggregations={
                    "by_alert": {
                        "buckets": [
                            {
                                "key": alert,
                                "first_case": {
                                    "hits": {
                                        "hits": [{"_source": {"so_related": {"caseId": case}}}]
                                    }
                                },
                            }
                            for alert, case in self.case_links.items()
                        ]
                    }
                },
            )
        self.calls.append("page")
        if "rules" in aggs and "unnamed" in aggs:
            return EsSearchResult(
                total=len(self.page), took_ms=1, aggregations={"rules": {"buckets": self.page}}
            )
        return EsSearchResult(total=0, took_ms=1, aggregations={"rules": {"buckets": []}})


def _get(client: TestClient, grid: _Grid, params: str = "?range=24h&links=true") -> dict[str, Any]:
    with patch.object(ElasticClient, "search", AsyncMock(side_effect=grid.__call__)):
        res = client.get("/api/v1/alerts" + params)
    assert res.status_code == 200, res.text
    return {g["name"]: g for g in res.json()["groups"]}


def _ntlm_and_wmi(t: datetime) -> list[dict[str, Any]]:
    return [
        alert(t, rule=_NTLM, src=_VICTIM, dst=_ATTACKER),
        alert(t + 3 * _SECOND, rule=_WMI, src=_ATTACKER, dst=_VICTIM),
        alert(t + timedelta(hours=2), rule=_SCAN, src=_ATTACKER, dst=_VICTIM),
    ]


def test_the_row_names_its_siblings_and_their_verdicts(client: TestClient) -> None:
    _run(client, alert="ev-ntlm", rule=_NTLM, verdict="false_positive")
    _run(client, alert="ev-wmi", rule=_WMI, verdict="true_positive")
    t = _now() - timedelta(hours=3)
    grid = _Grid([_page_bucket(_NTLM), _page_bucket(_WMI), _page_bucket(_SCAN)], _ntlm_and_wmi(t))

    rows = _get(client, grid)

    ntlm = rows[_NTLM]
    assert ntlm["siblingCount"] == 1
    assert ntlm["siblingsPartial"] is False
    [wmi] = ntlm["siblings"]
    assert wmi["name"] == _WMI
    assert wmi["kind"] == "suricata"
    assert wmi["verdict"] == "true_positive"
    assert wmi["signals"] == ["hosts"]
    assert wmi["invId"]
    assert [s["verdict"] for s in rows[_WMI]["siblings"]] == ["false_positive"]
    # NEGATIVE CONTROL. A group two hours away on the same pair is no
    # sibling, and says so with an empty list.
    assert rows[_SCAN]["siblings"] == []
    assert rows[_SCAN]["siblingCount"] == 0


def test_a_sibling_off_the_page_still_carries_its_verdict(client: TestClient) -> None:
    """The NTLMv1 false positive was auto-acknowledged, so a page that hides
    acknowledged alerts does not list it. The WMIExec row still names it."""
    _run(client, alert="ev-ntlm", rule=_NTLM, verdict="false_positive")
    t = _now() - timedelta(hours=1)
    grid = _Grid(
        [_page_bucket(_WMI)],
        [
            alert(t, rule=_WMI, community_id="1:abc="),
            alert(t + 30 * _MINUTE, rule=_NTLM, community_id="1:abc="),
        ],
    )

    rows = _get(client, grid, "?range=24h&hide_acked=true&links=true")

    [ntlm] = rows[_WMI]["siblings"]
    assert ntlm["name"] == _NTLM
    assert ntlm["verdict"] == "false_positive"
    assert ntlm["signals"] == ["flow"]


def test_the_siblings_cost_at_most_two_searches_for_the_whole_page(client: TestClient) -> None:
    """Thirty groups, never one search per group."""
    page = [_page_bucket(f"ET TEST rule {i}") for i in range(30)]
    t = _now() - timedelta(hours=1)
    docs = [
        alert(t + i * _SECOND, rule=f"ET TEST rule {i}", src=_ATTACKER, dst=_VICTIM)
        for i in range(30)
    ]

    plain = _Grid(page)
    _get(client, plain, "?range=24h")
    linked = _Grid(page, docs)
    rows = _get(client, linked)

    assert linked.calls.count("siblings") == 1
    assert linked.calls.count("sibling-times") == 1
    assert len(linked.calls) == len(plain.calls) + 2
    assert rows["ET TEST rule 1"]["siblingCount"] == 29


def test_a_page_that_asks_for_no_links_pays_for_none(client: TestClient) -> None:
    """NEGATIVE CONTROL. The Dashboard and the needs-you count read the same
    route and ask for no links."""
    grid = _Grid([_page_bucket(_SQLI, escalated_ids=("e-1",))])

    rows = _get(client, grid, "?range=24h")

    assert "siblings" not in grid.calls
    assert "cases" not in grid.calls
    assert rows[_SQLI]["siblings"] is None
    assert rows[_SQLI]["siblingsPartial"] is None
    assert rows[_SQLI]["cases"] == []


@pytest.mark.parametrize(
    "error",
    [TimeoutError(), RuntimeError("too_many_buckets_exception")],
    ids=["timeout", "grid-error"],
)
def test_a_failed_sibling_read_leaves_the_page_whole(
    client: TestClient, error: BaseException
) -> None:
    grid = _Grid([_page_bucket(_SQLI), _page_bucket(_GEO)], sibling_error=error)

    rows = _get(client, grid)

    assert set(rows) == {_SQLI, _GEO}
    assert rows[_SQLI]["siblings"] is None
    assert rows[_SQLI]["siblingCount"] is None


def test_a_slow_sibling_read_ends_at_the_grid_timeout(
    client: TestClient, settings_kratos: Settings
) -> None:
    """The page answers. The sibling read stops at the grid budget."""

    class _Slow(_Grid):
        async def __call__(self, index: str, query: Any, **kwargs: Any) -> EsSearchResult:
            if "flows" in (kwargs.get("aggs") or {}):
                self.calls.append("siblings")
                await asyncio.sleep(30)
            return await super().__call__(index, query, **kwargs)

    settings_kratos.webui_grid_timeout_s = 1
    grid = _Slow([_page_bucket(_SQLI)])

    rows = _get(client, grid)

    assert rows[_SQLI]["siblings"] is None


def test_a_sibling_read_that_cannot_build_its_query_leaves_the_page_whole(
    client: TestClient,
) -> None:
    """NEGATIVE CONTROL. The read builds its query before the cache lookup. A
    failure there must not fail the page."""
    grid = _Grid([_page_bucket(_SQLI)])

    with patch.object(sib, "sibling_query", side_effect=ValueError("bad alert filter")):
        rows = _get(client, grid)

    assert rows[_SQLI]["siblings"] is None
    assert "siblings" not in grid.calls


def test_a_muted_sibling_is_not_listed(client: TestClient) -> None:
    """NEGATIVE CONTROL. The feed hides a muted rule, so its row cannot be
    linked."""
    from soc_ai.store import detection_overrides as override_svc

    async def _mute() -> None:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            await override_svc.create(db, rule_name=_GEO, created_by="tester")

    asyncio.run(_mute())
    t = _now() - timedelta(hours=1)
    grid = _Grid(
        [_page_bucket(_SQLI)],
        [alert(t, rule=_SQLI, community_id="1:abc="), alert(t, rule=_GEO, community_id="1:abc=")],
    )

    rows = _get(client, grid)

    assert rows[_SQLI]["siblings"] == []


def test_the_row_says_when_its_sibling_list_can_be_partial(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sib, "PAIR_MEMBERS", 2)
    t = _now() - timedelta(hours=1)
    rules = [f"ET TEST rule {i}" for i in range(4)]
    grid = _Grid(
        [_page_bucket(r) for r in rules],
        [alert(t + i * _SECOND, rule=r, src=_ATTACKER, dst=_VICTIM) for i, r in enumerate(rules)],
    )

    rows = _get(client, grid)

    assert all(rows[r]["siblingsPartial"] is True for r in rules)


# ── The poll reads the siblings once a minute ───────────────────────────────


def test_the_poll_does_not_rerun_the_sibling_read(client: TestClient) -> None:
    """The Alerts screen polls every 10 s. The sibling read ran on each poll of
    each tab, at up to 1.2 s a read."""
    t = _now() - timedelta(hours=3)
    grid = _Grid([_page_bucket(_NTLM), _page_bucket(_WMI)], _ntlm_and_wmi(t))

    first = _get(client, grid)
    for params in (
        "?range=24h&links=true",
        "?range=24h&links=true&hide_acked=true",
        "?range=24h&links=true&severity=high",
    ):
        again = _get(client, grid, params)
        assert again[_NTLM]["siblings"] == first[_NTLM]["siblings"]

    assert grid.calls.count("siblings") == 1
    assert grid.calls.count("sibling-times") == 1
    # The page itself still reads the grid on every poll.
    assert grid.calls.count("page") >= 4


def test_a_new_window_reads_the_siblings_again(client: TestClient) -> None:
    t = _now() - timedelta(hours=3)
    grid = _Grid([_page_bucket(_NTLM), _page_bucket(_WMI)], _ntlm_and_wmi(t))

    _get(client, grid)
    _get(client, grid, "?range=7d&links=true")

    assert grid.calls.count("siblings") == 2


def test_the_sibling_read_runs_again_after_a_minute(client: TestClient) -> None:
    t = _now() - timedelta(hours=3)
    grid = _Grid([_page_bucket(_NTLM), _page_bucket(_WMI)], _ntlm_and_wmi(t))

    _get(client, grid)
    cache: sib.SiblingCache = client.app.state.sibling_cache  # type: ignore[attr-defined]
    start = cache.clock()
    cache.clock = lambda: start + sib.SIBLING_CACHE_TTL.total_seconds() + 1
    _get(client, grid)

    assert grid.calls.count("siblings") == 2


def test_a_row_with_an_alert_newer_than_the_kept_read_says_partial(client: TestClient) -> None:
    """The page reads its rows on each poll and keeps the sibling read for a
    minute. A row whose newest alert came after the read can have a sibling
    the read did not see."""
    t = _now() - timedelta(hours=3)
    grid = _Grid([_page_bucket(_NTLM), _page_bucket(_WMI)], _ntlm_and_wmi(t))
    _get(client, grid)

    grid.page = [
        _page_bucket(_NTLM, latest=datetime.now(UTC) + 5 * _SECOND),
        _page_bucket(_WMI),
    ]
    rows = _get(client, grid)

    assert grid.calls.count("siblings") == 1
    assert rows[_NTLM]["siblingsPartial"] is True
    # NEGATIVE CONTROL. A row with no newer alert keeps its whole list.
    assert rows[_WMI]["siblingsPartial"] is False


def test_a_failed_sibling_read_is_kept_for_a_short_time(client: TestClient) -> None:
    """A slow grid must not get a new read on every poll of every tab. A
    failed read stands for SIBLING_RETRY, and the next poll after it reads
    again."""
    t = _now() - timedelta(hours=3)
    grid = _Grid([_page_bucket(_NTLM)], _ntlm_and_wmi(t), sibling_error=TimeoutError())

    _get(client, grid)
    grid.sibling_error = None
    soon = _get(client, grid)
    cache: sib.SiblingCache = client.app.state.sibling_cache  # type: ignore[attr-defined]
    start = cache.clock()
    cache.clock = lambda: start + sib.SIBLING_RETRY.total_seconds() + 1
    later = _get(client, grid)

    assert soon[_NTLM]["siblings"] is None
    assert later[_NTLM]["siblingCount"] == 1
    assert grid.calls.count("siblings") == 2


def test_a_degraded_sibling_read_is_kept_for_a_short_time(client: TestClient) -> None:
    """The group read failed. The empty read stands for SIBLING_RETRY,
    and the next poll after it reads again."""
    t = _now() - timedelta(hours=3)
    grid = _Grid([_page_bucket(_NTLM), _page_bucket(_WMI)], _ntlm_and_wmi(t))
    grid.docs.fail_from = 2

    first = _get(client, grid)
    grid.docs.fail_from = None
    soon = _get(client, grid)
    cache: sib.SiblingCache = client.app.state.sibling_cache  # type: ignore[attr-defined]
    start = cache.clock()
    cache.clock = lambda: start + sib.SIBLING_RETRY.total_seconds() + 1
    later = _get(client, grid)

    assert first[_NTLM]["siblingsPartial"] is True
    assert soon[_NTLM]["siblingsPartial"] is True
    assert later[_NTLM]["siblingsPartial"] is False
    assert grid.calls.count("siblings") == 2


def test_two_reads_of_one_window_at_once_share_one_search() -> None:
    """Two tabs that poll one window at the same moment run one read."""
    cache = sib.SiblingCache()
    calls = 0
    gate = asyncio.Event()

    async def _load() -> sib.SiblingIndex | None:
        nonlocal calls
        calls += 1
        await gate.wait()
        return sib.SiblingIndex()

    async def _go() -> list[sib.SiblingIndex | None]:
        first = asyncio.ensure_future(cache.read("w", _load))
        second = asyncio.ensure_future(cache.read("w", _load))
        await asyncio.sleep(0)
        gate.set()
        return [await first, await second]

    a, b = asyncio.run(_go())

    assert calls == 1
    assert a is b is not None


def test_a_page_that_stops_does_not_stop_the_shared_read() -> None:
    """NEGATIVE CONTROL. One tab closes while the read runs. The other tab
    still gets the read, and the cache keeps it."""
    cache = sib.SiblingCache()
    gate = asyncio.Event()

    async def _load() -> sib.SiblingIndex | None:
        await gate.wait()
        return sib.SiblingIndex()

    async def _go() -> sib.SiblingIndex | None:
        first = asyncio.ensure_future(cache.read("w", _load))
        second = asyncio.ensure_future(cache.read("w", _load))
        await asyncio.sleep(0)
        first.cancel()
        gate.set()
        got = await second
        assert await cache.read("w", _load) is got
        return got

    assert asyncio.run(_go()) is not None


# ── R2-I2: the cases a group is on ──────────────────────────────────────────


def _ledger(client: TestClient, alert: str, case: str) -> None:
    async def _go() -> None:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            await esc_svc.claim(db, [alert], actor="tester")
            await esc_svc.record_case(db, alert, case)

    asyncio.run(_go())


def test_the_row_carries_the_case_its_alert_is_on(client: TestClient) -> None:
    _ledger(client, "e-tor", "case-tor-1")
    grid = _Grid([_page_bucket("ET TOR Known Tor Exit Node Traffic", escalated_ids=("e-tor",))])

    rows = _get(client, grid)

    assert rows["ET TOR Known Tor Exit Node Traffic"]["cases"] == [
        {"id": "case-tor-1", "url": "https://so.example.com/#/case/case-tor-1"}
    ]
    # The ledger answered for every alert, so the grid was not asked.
    assert "cases" not in grid.calls


def test_a_case_opened_in_security_onion_comes_from_the_grid(client: TestClient) -> None:
    """The ledger holds the cases soc-ai opened. Security Onion's case links
    answer for a case the analyst opened in its own console."""
    grid = _Grid(
        [_page_bucket("ET TOR Known Tor Exit Node Traffic", escalated_ids=("e-so",))],
        case_links={"e-so": "case-so-7"},
    )

    rows = _get(client, grid)

    assert [c["id"] for c in rows["ET TOR Known Tor Exit Node Traffic"]["cases"]] == ["case-so-7"]
    assert grid.calls.count("cases") == 1


def test_a_group_with_no_escalated_alert_carries_no_case(client: TestClient) -> None:
    """NEGATIVE CONTROL. A ledger case of another group's alert stays there."""
    _ledger(client, "e-other", "case-other")
    grid = _Grid([_page_bucket(_SQLI)])

    rows = _get(client, grid)

    assert rows[_SQLI]["cases"] == []
    assert "cases" not in grid.calls


def test_the_cases_of_one_group_are_named_once_each(client: TestClient) -> None:
    _ledger(client, "e-1", "case-a")
    _ledger(client, "e-2", "case-a")
    _ledger(client, "e-3", "case-b")
    grid = _Grid([_page_bucket(_SQLI, escalated_ids=("e-1", "e-2", "e-3"))])

    rows = _get(client, grid)

    assert [c["id"] for c in rows[_SQLI]["cases"]] == ["case-a", "case-b"]


def test_the_row_says_when_its_cases_cover_every_escalated_alert(client: TestClient) -> None:
    _ledger(client, "e-1", "case-a")
    _ledger(client, "e-2", "case-a")
    grid = _Grid([_page_bucket(_SQLI, escalated_ids=("e-1", "e-2"))])

    rows = _get(client, grid)

    assert rows[_SQLI]["casesComplete"] is True


@pytest.mark.parametrize(
    ("ids", "escalated"),
    [(("e-1",), 40), (("e-1", "e-2"), None)],
    ids=["more-alerts-than-ids", "an-id-with-no-case"],
)
def test_a_partial_case_list_is_not_called_complete(
    client: TestClient, ids: tuple[str, ...], escalated: int | None
) -> None:
    """NEGATIVE CONTROL. The row reads the ids of the newest escalated alerts
    only, and an alert can be on a case nobody can name."""
    _ledger(client, "e-1", "case-a")
    grid = _Grid([_page_bucket(_SQLI, escalated_ids=ids, escalated=escalated)])

    rows = _get(client, grid)

    assert [c["id"] for c in rows[_SQLI]["cases"]] == ["case-a"]
    assert rows[_SQLI]["casesComplete"] is False


# ── R2-D9: the investigation page names the same siblings ───────────────────


def _alert_run(
    client: TestClient,
    *,
    rule: str,
    verdict: str,
    at: datetime | None,
    src: str = _ATTACKER,
    dst: str = _VICTIM,
    community_id: str | None = "1:wmi=",
    kind: str = "suricata",
) -> str:
    """A complete run whose stored alert context names the flow and the time."""

    async def _go() -> str:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            inv = await inv_svc.create(
                db, alert_es_id=f"ev-{rule}", started_by="tester", rule_name=rule, kind=kind
            )
            await inv_svc.set_alert_fields(
                db, inv.id, src_ip=src, dest_ip=dst, community_id=community_id
            )
            alert: dict[str, Any] = {"rule_name": rule, "source_ip": src, "destination_ip": dst}
            if at is not None:
                alert["timestamp"] = at.isoformat()
            await inv_svc.append_events(
                db, inv.id, [{"kind": "enriched_alert_context", "payload": {"alert": alert}}]
            )
            await inv_svc.finalize(db, inv.id, status="complete", verdict=verdict, confidence=0.7)
            return str(inv.id)

    return asyncio.run(_go())


def _siblings(client: TestClient, grid: DocGrid, inv_id: str) -> dict[str, Any]:
    with patch.object(ElasticClient, "search", AsyncMock(side_effect=grid.search)):
        res = client.get("/api/v1/alerts/siblings", params={"inv_id": inv_id})
    assert res.status_code == 200, res.text
    body: dict[str, Any] = res.json()
    return body


def _report_flow(at: datetime) -> list[dict[str, Any]]:
    """The WMIExec alert of the report, and what lies around it."""
    return [
        alert(at, rule=_WMI, src=_ATTACKER, dst=_VICTIM, community_id="1:wmi="),
        alert(at - timedelta(seconds=2.6), rule=_NTLM, src=_VICTIM, dst=_ATTACKER),
        alert(at + 50 * _MINUTE, rule=_GEO, src=_OTHER, dst=_VICTIM, community_id="1:wmi="),
        # NEGATIVE CONTROLS. The same pair six minutes later, another pair in
        # the same second, and the same community id 70 minutes before and
        # three days after.
        alert(at + 6 * _MINUTE, rule=_NMAP, src=_ATTACKER, dst=_VICTIM),
        alert(at, rule=_SCAN, src=_ATTACKER, dst=_OTHER),
        alert(at - 70 * _MINUTE, rule=_NTP, src=_OTHER, dst=_VICTIM, community_id="1:wmi="),
        alert(at + timedelta(days=3), rule=_NTP, src=_OTHER, dst=_VICTIM, community_id="1:wmi="),
    ]


def test_the_report_names_the_opposite_verdict_on_its_flow(client: TestClient) -> None:
    at = _now() - timedelta(days=3)
    wmi = _alert_run(client, rule=_WMI, verdict="true_positive", at=at)
    _alert_run(client, rule=_NTLM, verdict="false_positive", at=at - timedelta(seconds=2.6))
    grid = DocGrid(_report_flow(at))

    body = _siblings(client, grid, wmi)

    by_name = {s["name"]: s for s in body["siblings"]}
    assert set(by_name) == {_NTLM, _GEO}
    assert by_name[_NTLM]["verdict"] == "false_positive"
    assert by_name[_NTLM]["signals"] == ["hosts"]
    assert by_name[_NTLM]["invId"]
    assert by_name[_GEO]["verdict"] == "untriaged"
    assert by_name[_GEO]["signals"] == ["flow"]
    assert body["siblingCount"] == 2
    assert body["partial"] is False
    assert body["reason"] is None
    # One search, anchored on the alert.
    assert len(grid.searches) == 1


def test_the_report_obeys_the_flow_bound(client: TestClient) -> None:
    """The report names a group on its community id only within the hour of
    its alert, as the row does."""
    at = _now() - timedelta(days=4)
    wmi = _alert_run(client, rule=_WMI, verdict="true_positive", at=at)

    body = _siblings(client, DocGrid(_report_flow(at)), wmi)

    names = {s["name"] for s in body["siblings"]}
    assert _GEO in names
    assert _NTP not in names
    assert body["partial"] is False


def test_the_report_names_the_window_its_read_covered(client: TestClient) -> None:
    """The Show link of the report opens the Alerts list on that window."""
    at = _now() - timedelta(days=3)
    wmi = _alert_run(client, rule=_WMI, verdict="true_positive", at=at)

    body = _siblings(client, DocGrid(_report_flow(at)), wmi)

    lo = datetime.fromisoformat(body["windowFrom"].replace("Z", "+00:00"))
    hi = datetime.fromisoformat(body["windowTo"].replace("Z", "+00:00"))
    assert lo == at - sib.FLOW_SPAN
    assert hi == at + sib.FLOW_SPAN


def test_the_report_names_every_group_near_its_alert(
    client: TestClient,
) -> None:
    """V3-N1 on the report. Twelve groups within a minute of the alert."""
    at = _now() - timedelta(days=1)
    wmi = _alert_run(client, rule=_WMI, verdict="true_positive", at=at)
    rules = [f"ET TEST rule {i:02d}" for i in range(12)]
    docs = [alert(at, rule=_WMI, src=_ATTACKER, dst=_VICTIM)]
    docs += [
        alert(at + i * _SECOND, rule=r, src=_VICTIM, dst=_ATTACKER) for i, r in enumerate(rules)
    ]
    docs += burst(
        at - 4 * _MINUTE, 500, timedelta(milliseconds=100), rule=_SCAN, src=_ATTACKER, dst=_VICTIM
    )

    body = _siblings(client, DocGrid(docs), wmi)

    assert body["siblingCount"] == 13
    assert body["partial"] is False


def test_a_report_with_more_groups_than_the_read_lists_is_partial(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sib, "PAIR_MEMBERS", 3)
    at = _now() - timedelta(days=1)
    wmi = _alert_run(client, rule=_WMI, verdict="true_positive", at=at)
    docs = [
        alert(at + i * _SECOND, rule=f"ET TEST rule {i}", src=_ATTACKER, dst=_VICTIM)
        for i in range(6)
    ]

    body = _siblings(client, DocGrid(docs), wmi)

    assert body["partial"] is True


def test_a_report_never_lists_its_own_detection(client: TestClient) -> None:
    """NEGATIVE CONTROL. The alert of the report is on its own flow."""
    at = _now() - timedelta(hours=1)
    wmi = _alert_run(client, rule=_WMI, verdict="true_positive", at=at)
    grid = DocGrid(
        list(burst(at, 3, _SECOND, rule=_WMI, src=_ATTACKER, dst=_VICTIM, community_id="1:wmi="))
    )

    body = _siblings(client, grid, wmi)

    assert body["siblings"] == []
    assert body["siblingCount"] == 0


def test_a_run_with_no_time_claims_no_sibling_and_says_partial(client: TestClient) -> None:
    """Without an alert time neither leg has an anchor: both rules measure
    from the alert. The list claims nothing and says it can be partial."""
    wmi = _alert_run(client, rule=_WMI, verdict="true_positive", at=None)
    grid = DocGrid(_report_flow(_now() - timedelta(minutes=10)))

    body = _siblings(client, grid, wmi)

    assert body["siblings"] == []
    assert body["partial"] is True
    assert grid.searches == []


def test_a_run_with_no_hosts_misses_no_host_sibling(client: TestClient) -> None:
    """NEGATIVE CONTROL. An alert with no pair of addresses has no host leg
    to lose."""
    at = _now() - timedelta(hours=2)
    wmi = _alert_run(client, rule=_WMI, verdict="true_positive", at=at, src="", dst="")

    body = _siblings(client, DocGrid(_report_flow(at)), wmi)

    assert [s["name"] for s in body["siblings"]] == [_GEO]
    assert body["partial"] is False


def test_a_hunt_run_has_no_flow_to_share(client: TestClient) -> None:
    hunt = _alert_run(
        client, rule="Lead 12 on 192.0.2.10", verdict="true_positive", at=_now(), kind="lead"
    )
    grid = DocGrid([])

    body = _siblings(client, grid, hunt)

    assert body["siblings"] is None
    assert body["reason"] == "no_alert"
    assert grid.searches == []


def test_a_failed_read_says_the_grid_did_not_answer(client: TestClient) -> None:
    wmi = _alert_run(client, rule=_WMI, verdict="true_positive", at=_now())

    body = _siblings(client, DocGrid([], fail_from=1, error=TimeoutError()), wmi)

    assert body["siblings"] is None
    assert body["reason"] == "grid"


def test_an_unknown_run_is_a_404(client: TestClient) -> None:
    with patch.object(ElasticClient, "search", AsyncMock()):
        res = client.get("/api/v1/alerts/siblings", params={"inv_id": "01NOSUCHRUN"})
    assert res.status_code == 404
