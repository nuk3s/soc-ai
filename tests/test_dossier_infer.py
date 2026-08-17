"""Tests for the pure host-dossier classifier (:mod:`soc_ai.dossier.infer`).

The classifier is the heart of the dossier: it turns one window of observations
about one IP into the durable answer to "what IS this host?". It is pure — no
Elasticsearch, no database, no LLM, no clock — so every rule below is driven
from a hand-built :class:`HostObservations` rather than a live grid.

The load-bearing properties, each with its own test:

* **Role precedence is ordered, and the order matters.** A hypervisor also
  answers 22 and 443; a domain controller also answers 445. First match wins,
  and the rows are ordered most-specific-first so the specific evidence is not
  swallowed by the generic "it serves something" rule.
* **One inbound connection is never a role.** ``host_summary._guess_role``
  promotes a host to "server" off a single inbound packet on a service port;
  that trigger is deliberately NOT inherited here. A laptop that accepted one
  SSH connection is a laptop.
* **Two OS families stay two.** A NAT gateway or a hypervisor bridging guests
  legitimately shows Apple AND Windows telemetry on one address. The honest
  answer is "mixed" (``os=None``, weak), never a coin-flip collapse to one.
* **Nothing is stamped with the clock.** ``Fact.observed_at`` comes from the
  observation set, so a build over a historical window concludes what was true
  then instead of looking freshly confirmed forever.

The motivating case is ``192.168.10.202``: soc-ai attributed SSH probing to it
while believing it was "an internal host". It answers on tcp/8006 + tcp/8007 —
it is a Proxmox hypervisor, and the dossier has to say so.
"""

from __future__ import annotations

import ast
import inspect
from datetime import UTC, datetime
from typing import Any

from soc_ai.dossier import infer
from soc_ai.dossier.infer import ROLE_VOCABULARY, infer_host_facts
from soc_ai.dossier.types import DOSSIER_FIELDS, AgentSelfReport, HostObservations

HOST_IP = "192.168.10.202"


def _match_role_literals() -> set[str]:
    """Every role string a `_match_role` branch returns, pulled from the source.

    The roles are bare literals scattered through `_match_role` and its helpers,
    so the guard reads the AST rather than a hand-kept copy (which would be a new
    twin). A role return is either ``return "role", strength, evidence`` (a tuple
    whose first element is a string) or a forwarded ``return dc`` (covered by the
    helper's own returns), so collecting the leading string of every tuple return
    across the four role functions catches them all.
    """
    role_funcs = {
        "_match_role",
        "_match_domain_controller",
        "_match_iot",
        "_match_workstation",
    }
    tree = ast.parse(inspect.getsource(infer))
    roles: set[str] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.FunctionDef) and node.name in role_funcs):
            continue
        for sub in ast.walk(node):
            if isinstance(sub, ast.Return) and isinstance(sub.value, ast.Tuple) and sub.value.elts:
                head = sub.value.elts[0]
                if isinstance(head, ast.Constant) and isinstance(head.value, str):
                    roles.add(head.value)
    return roles


def test_role_vocabulary_covers_every_match_role_literal() -> None:
    literals = _match_role_literals()
    # The rules really do return roles — a scan that found nothing would pass
    # vacuously and hide a broken extractor.
    assert {"hypervisor", "domain_controller", "server", "workstation"} <= literals
    missing = literals - set(ROLE_VOCABULARY)
    assert not missing, f"_match_role returns roles absent from ROLE_VOCABULARY: {sorted(missing)}"
    # `unknown` is never a `_match_role` return — it is `_infer_role`'s fallback —
    # but it IS a value the field can hold, so the vocabulary must carry it.
    assert "unknown" in ROLE_VOCABULARY


# Deliberately old: every assertion about `observed_at` is really an assertion
# that the value did not come from `datetime.now()`, and a 2019 window makes a
# clock leak impossible to miss.
FIRST_SEEN = datetime(2019, 3, 1, 8, 0, tzinfo=UTC)
LAST_SEEN = datetime(2019, 3, 15, 21, 30, tzinfo=UTC)
RECORD_SEEN_ISO = "2019-03-15T20:15:00Z"
RECORD_SEEN = datetime(2019, 3, 15, 20, 15, tzinfo=UTC)

DEBIAN_BANNER = "SSH-2.0-OpenSSH_9.6p1 Debian-3"
WINDOWS_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
MAC_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"

APPLE_DOMAINS = ["gdmf.apple.com", "gateway.icloud.com"]
WINDOWS_DOMAINS = ["dns.msftncsi.com", "ctldl.windowsupdate.com"]


def _obs(**overrides: Any) -> HostObservations:
    """A HostObservations with sane, above-the-floor defaults."""
    base: dict[str, Any] = {
        "ip": HOST_IP,
        "total_events": 500,
        "first_seen": FIRST_SEEN,
        "last_seen": LAST_SEEN,
    }
    base.update(overrides)
    return HostObservations(**base)


def _ports(*pairs: tuple[int, int]) -> list[dict[str, Any]]:
    """Terms-agg bucket pairs in the ``[{value, count}]`` shape the collector emits."""
    return [{"value": port, "count": count} for port, count in pairs]


def _scanned(*pairs: tuple[int, int]) -> dict[str, Any]:
    """Observation overrides for a host that was PROBED on these ports, not used.

    A zeek.conn record is written for a connection ATTEMPT, so a scanned host
    accumulates responder ports it never answered on. The byte percentiles are
    the host-level proof of that: it returned nothing, on anything, all window.
    """
    return {
        "resp_ports": _ports(*pairs),
        "resp_bytes_p50": 0.0,
        "resp_bytes_p95": 0.0,
        "resp_peer_count": 1,
        "resp_hours": 1,
    }


def _domains(*names: str) -> list[dict[str, Any]]:
    return [{"value": name, "count": 3} for name in names]


# ---------------------------------------------------------------------------
# Role — one test per row of the ordered table, plus the two precedence cases
# the ordering exists for.
# ---------------------------------------------------------------------------


def test_proxmox_hypervisor_is_the_motivating_case() -> None:
    # 192.168.10.202 answering on tcp/8006 (PVE) + tcp/8007 (PBS). soc-ai once
    # attributed SSH probing to this host while believing it was just "an
    # internal host"; the dossier has to name it a hypervisor.
    obs = _obs(
        resp_ports=_ports((8006, 2100), (8007, 1200), (22, 112)),
        resp_peer_count=4,
        resp_hours=19,
        orig_peer_count=3,
    )
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value == "hypervisor"
    assert role.strength == "strong"
    assert role.confidence == 0.9
    assert role.source == "behaviour"
    # The evidence names the matched port set, the conn volume, the peer
    # cardinality and the hour spread — not just a label. The volume is the
    # MATCHED ports' (2,100 + 1,200), not the host's whole responder total: a
    # verdict about tcp/8006 that quotes tcp/22's traffic is quoting a number
    # that had nothing to do with the call.
    assert role.evidence == [
        "responds on tcp/8006, tcp/8007 — 3,300 zeek.conn records "
        "from 4 distinct peers across 19 hours (from behaviour)"
    ]
    assert role.observed_at == LAST_SEEN


def test_hypervisor_beats_the_ssh_and_https_it_also_serves() -> None:
    # A hypervisor answers 22 and 443 like any Linux server. If the generic
    # server rule ran first, the specific signal would be lost.
    obs = _obs(
        resp_ports=_ports((22, 400), (443, 900), (8006, 2100)),
        resp_peer_count=6,
        resp_hours=20,
    )
    assert infer_host_facts(obs, min_events=20)["role"].value == "hypervisor"


def test_hypervisor_without_sustained_traffic_is_weak() -> None:
    # One peer in one hour on tcp/8006 is a port scan hit as easily as a
    # console login — the call stands, the confidence does not.
    obs = _obs(resp_ports=_ports((8006, 9)), resp_peer_count=1, resp_hours=1)
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value == "hypervisor"
    assert role.strength == "weak"
    assert role.confidence == 0.5


def test_domain_controller_from_core_port_set() -> None:
    obs = _obs(
        resp_ports=_ports((88, 800), (389, 640), (636, 40)),
        resp_peer_count=25,
        resp_hours=24,
    )
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value == "domain_controller"
    assert role.strength == "strong"
    assert "tcp/88" in role.evidence[0]
    # _DC_EXTRA (636 here) corroborates; it is never the trigger on its own.
    assert any("636" in line for line in role.evidence)


def test_domain_controller_beats_the_smb_it_also_serves() -> None:
    # 445 is in the general-server set. A DC serves it too.
    obs = _obs(
        resp_ports=_ports((88, 800), (389, 640), (445, 5000)),
        resp_peer_count=30,
        resp_hours=24,
    )
    assert infer_host_facts(obs, min_events=20)["role"].value == "domain_controller"


def test_domain_controller_from_kerberos_traffic_to_this_host() -> None:
    # Kerberos on 88 with the host as the destination: clients authenticate TO
    # a KDC, so direction is what separates the DC from its clients.
    obs = _obs(
        resp_ports=_ports((88, 900)),
        resp_peer_count=12,
        resp_hours=18,
        windows_identity=(
            {
                "dataset": "zeek.kerberos",
                "realm": "LAB.EXAMPLE",
                "source_ip": "192.168.10.40",
                "destination_ip": HOST_IP,
                "timestamp": RECORD_SEEN_ISO,
            },
        ),
    )
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value == "domain_controller"
    assert any("kerberos" in line for line in role.evidence)


def test_domain_controller_from_drsuapi_endpoint() -> None:
    # DRSUAPI is directory replication — only a DC answers it. Without this
    # disjunct the host reads as a plain SMB server.
    obs = _obs(
        resp_ports=_ports((445, 4000)),
        resp_peer_count=9,
        resp_hours=20,
        windows_identity=(
            {
                "dataset": "zeek.dce_rpc",
                "dce_rpc_endpoint": "drsuapi",
                "source_ip": "192.168.10.41",
                "destination_ip": HOST_IP,
                "timestamp": RECORD_SEEN_ISO,
            },
        ),
    )
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value == "domain_controller"
    assert any("drsuapi" in line for line in role.evidence)


def test_dce_rpc_endpoint_on_a_peer_does_not_make_this_host_a_dc() -> None:
    # Same endpoint, but this host is the ORIGINATOR — it is a domain member
    # talking to a DC, not the DC.
    obs = _obs(
        resp_ports=_ports((445, 4000)),
        resp_peer_count=9,
        resp_hours=20,
        orig_peer_count=2,
        windows_identity=(
            {
                "dataset": "zeek.dce_rpc",
                "dce_rpc_endpoint": "drsuapi",
                "source_ip": HOST_IP,
                "destination_ip": "192.168.10.10",
                "timestamp": RECORD_SEEN_ISO,
            },
        ),
    )
    assert infer_host_facts(obs, min_events=20)["role"].value == "server"


def test_security_appliance_from_elastic_ports() -> None:
    obs = _obs(
        resp_ports=_ports((9200, 15000), (5601, 300), (443, 200)),
        resp_peer_count=8,
        resp_hours=24,
    )
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value == "security_appliance"
    assert role.strength == "strong"


def test_security_appliance_from_syslog_only_is_weak() -> None:
    # udp/514 alone is a log sink; it could equally be a router's own syslog
    # listener, so the weak set never reaches strong.
    obs = _obs(resp_ports=_ports((514, 9000)), resp_peer_count=30, resp_hours=24)
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value == "security_appliance"
    assert role.strength == "weak"


def test_network_device_from_snmp() -> None:
    obs = _obs(resp_ports=_ports((161, 4000), (22, 30)), resp_peer_count=3, resp_hours=24)
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value == "network_device"
    assert role.strength == "strong"


def test_network_device_from_dhcp_service_is_weak() -> None:
    # Answering on 67 makes it the DHCP server — a router or a small appliance.
    obs = _obs(resp_ports=_ports((67, 800), (123, 400)), resp_peer_count=20, resp_hours=24)
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value == "network_device"
    assert role.strength == "weak"


def test_iot_from_printer_ports() -> None:
    obs = _obs(
        resp_ports=_ports((9100, 40), (631, 12), (5353, 300)),
        resp_peer_count=3,
        resp_hours=9,
        orig_peer_count=2,
    )
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value == "iot"
    assert role.strength == "strong"


def test_iot_weak_when_only_the_chatty_discovery_ports_qualify() -> None:
    obs = _obs(
        resp_ports=_ports((5353, 900), (1900, 400)),
        resp_peer_count=4,
        resp_hours=20,
        orig_peer_count=3,
    )
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value == "iot"
    assert role.strength == "weak"


def test_iot_is_refused_when_a_desktop_user_agent_is_present() -> None:
    # A laptop sharing a printer is not a printer. Without the UA guard the
    # narrow port set would carry the classification on its own.
    obs = _obs(
        resp_ports=_ports((9100, 40), (631, 12)),
        resp_peer_count=3,
        resp_hours=9,
        orig_peer_count=2,
        user_agents=(MAC_UA,),
    )
    assert infer_host_facts(obs, min_events=20)["role"].value != "iot"


def test_server_from_general_service_ports() -> None:
    obs = _obs(
        resp_ports=_ports((80, 4000), (443, 9000)),
        resp_peer_count=14,
        resp_hours=24,
    )
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value == "server"
    assert role.strength == "strong"


def test_server_is_weak_without_sustained_multi_peer_traffic() -> None:
    # Real service ports, but one peer inside one hour: the port set qualifies,
    # the pattern does not.
    obs = _obs(resp_ports=_ports((443, 60)), resp_peer_count=1, resp_hours=1)
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value == "server"
    assert role.strength == "weak"


def test_one_inbound_ssh_connection_is_never_a_server() -> None:
    # THE anti-regression test. `host_summary._guess_role` returns "server" off
    # a single inbound hit on a well-known port; a laptop that accepted one SSH
    # connection would be filed as a server forever.
    obs = _obs(
        resp_ports=_ports((22, 1)),
        resp_peer_count=1,
        resp_hours=1,
        orig_peer_count=11,
        user_agents=(MAC_UA,),
    )
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value != "server"
    assert role.value == "workstation"


def test_workstation_strong_with_os_corroboration() -> None:
    obs = _obs(
        resp_ports=[],
        resp_peer_count=0,
        resp_hours=0,
        orig_peer_count=42,
        user_agents=(MAC_UA,),
    )
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value == "workstation"
    assert role.strength == "strong"
    assert "42 distinct peers" in role.evidence[0]


def test_workstation_weak_without_os_corroboration() -> None:
    obs = _obs(resp_ports=[], orig_peer_count=9)
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value == "workstation"
    assert role.strength == "weak"


def test_unknown_when_nothing_qualifies() -> None:
    obs = _obs(resp_ports=_ports((443, 1)), orig_peer_count=2)
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value == "unknown"
    assert role.strength == "none"
    assert role.confidence == 0.0
    # Absence is a real answer, and it has to say why.
    assert role.evidence
    assert "no qualifying responder" in role.evidence[0]


def test_min_events_floor_emits_identity_but_role_unknown() -> None:
    # Seven events cannot support a behavioural conclusion. Identity signals
    # are first-party announcements and stand on their own.
    obs = _obs(
        total_events=7,
        resp_ports=_ports((8006, 4)),
        resp_peer_count=2,
        resp_hours=3,
        dhcp=({"hostname": "pve01", "source_ip": HOST_IP, "timestamp": RECORD_SEEN_ISO},),
    )
    facts = infer_host_facts(obs, min_events=20)
    assert facts["role"].value == "unknown"
    assert facts["role"].confidence == 0.0
    assert facts["role"].evidence == ["insufficient telemetry: 7 events in window (< 20)"]
    assert facts["hostname"].value == "pve01"
    assert facts["hostname"].strength == "strong"


# ---------------------------------------------------------------------------
# Role — a port only counts once it was ANSWERED. zeek.conn logs attempts, so
# every rule below is otherwise reachable by scanning the host.
# ---------------------------------------------------------------------------


def test_a_scanned_host_offers_no_services_and_has_no_role() -> None:
    # A sweep writes a zeek.conn record per probe, so counting records alone
    # lets an attacker hand the host any port set they like.
    obs = _obs(**_scanned((8006, 2), (22, 4), (3389, 3), (445, 6)), orig_peer_count=0)
    facts = infer_host_facts(obs, min_events=20)
    assert facts["role"].value == "unknown"
    assert facts["services_offered"].value_json == []
    assert facts["management_plane"].value == "no"


def test_scanning_tcp_8006_twice_does_not_make_a_hypervisor() -> None:
    # The worst version of the same bug: two probes at the Proxmox port and the
    # dossier tells the analyst this workstation is a hypervisor, at 0.9.
    obs = _obs(**_scanned((8006, 2), (8007, 2)))
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value != "hypervisor"
    assert role.value == "unknown"


def test_per_port_answered_counts_decide_which_ports_qualify() -> None:
    # When the collector measures the answered subset per port, that is the
    # number a service is proved by: 900 refused probes at 8006 is not a
    # hypervisor, and 40 answered sessions on 443 is a server.
    obs = _obs(
        resp_ports=[
            {"value": 8006, "count": 900, "answered": 0},
            {"value": 443, "count": 50, "answered": 40},
        ],
        resp_peer_count=6,
        resp_hours=20,
    )
    facts = infer_host_facts(obs, min_events=20)
    assert facts["role"].value == "server"
    assert [entry["port"] for entry in facts["services_offered"].value_json] == [443]


def test_a_named_zeek_service_proves_the_host_answered_something() -> None:
    # A UDP log sink returns no bytes at all, so the byte percentiles alone
    # would file a real syslog server as never having answered anything. Zeek
    # only names a service once an analyzer matched the payload.
    obs = _obs(
        resp_ports=_ports((514, 9000)),
        resp_bytes_p50=0.0,
        resp_bytes_p95=0.0,
        resp_peer_count=30,
        resp_hours=24,
        services=[{"value": "syslog", "count": 9000}],
    )
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value == "security_appliance"


def test_a_busy_server_under_a_scan_keeps_the_ports_it_answers() -> None:
    # The other side of the gate. A server whose median responder connection
    # returned nothing — it is being swept, and most attempts are refusals — has
    # still plainly answered somebody, and the p95 says so. Reading a zero
    # MEDIAN as "answered nothing" would retract the role of every scanned
    # server on the grid, which is the network-wide version of this bug.
    obs = _obs(
        resp_ports=_ports((443, 9000)),
        resp_bytes_p50=0.0,
        resp_bytes_p95=48000.0,
        resp_peer_count=20,
        resp_hours=24,
    )
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value == "server"
    assert role.strength == "strong"


def test_a_nan_byte_percentile_is_not_read_as_silence() -> None:
    # An empty ES percentile bucket comes back as NaN, and every comparison
    # against NaN is False — including `> 0`. Read as "returned nothing", it
    # would blank the role of every host whose byte field went unmapped.
    obs = _obs(
        resp_ports=_ports((8006, 2100), (8007, 1200)),
        resp_bytes_p50=float("nan"),
        resp_bytes_p95=float("nan"),
        resp_peer_count=4,
        resp_hours=19,
    )
    assert infer_host_facts(obs, min_events=20)["role"].value == "hypervisor"


def test_a_squid_proxy_on_3128_is_not_a_hypervisor() -> None:
    # tcp/3128 is Squid's default port long before it is Proxmox's SPICE proxy,
    # and the hypervisor row runs first, so a forward proxy used to be filed as
    # a hypervisor at strong confidence and no later row could correct it.
    obs = _obs(resp_ports=_ports((3128, 5000)), resp_peer_count=12, resp_hours=20)
    facts = infer_host_facts(obs, min_events=20)
    assert facts["role"].value != "hypervisor"
    # …nor is a proxy port an administrative surface.
    assert facts["management_plane"].value == "no"


def test_3128_corroborates_a_genuine_proxmox_port() -> None:
    # Alongside tcp/8006 it IS the SPICE proxy, and the evidence should say so.
    obs = _obs(resp_ports=_ports((8006, 2100), (3128, 400)), resp_peer_count=4, resp_hours=19)
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value == "hypervisor"
    assert "tcp/3128" in role.evidence[0]


def test_a_strong_verdict_is_not_earned_by_traffic_on_other_ports() -> None:
    # Three connections at tcp/8006 inside a window whose 12 peers and 24 hours
    # are all HTTPS. The row still matches — but the sustained gate belongs to
    # the traffic that matched it, not to the busiest thing the host does.
    obs = _obs(
        resp_ports=_ports((443, 9000), (8006, 3)),
        resp_peer_count=12,
        resp_hours=24,
    )
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value == "hypervisor"
    assert role.strength == "weak"
    assert role.confidence == 0.5


def test_per_port_peers_and_hours_earn_the_strong_verdict() -> None:
    # With the matched port measured directly, the same shape is strong on its
    # own evidence rather than on the host's aggregate.
    obs = _obs(
        resp_ports=[
            {"value": 8006, "count": 300, "peers": 4, "hours": 19},
            {"value": 443, "count": 9000, "peers": 40, "hours": 24},
        ],
        resp_peer_count=41,
        resp_hours=24,
    )
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value == "hypervisor"
    assert role.strength == "strong"


def test_the_server_peer_floor_counts_peers_on_the_matched_ports() -> None:
    # Four connections on tcp/443 next to a busy non-role port. The host has 25
    # peers; none of them are provably the service's.
    obs = _obs(
        resp_ports=_ports((12345, 20000), (443, 4)),
        resp_peer_count=25,
        resp_hours=24,
    )
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value == "server"
    assert role.strength == "weak"


def test_a_windows_workstation_answering_smb_callbacks_is_still_a_workstation() -> None:
    # Ordinary domain-fleet behaviour: 135/445 callbacks answered a handful of
    # times. Requiring the qualifying set to be EMPTY sent this host to the
    # server row — or to "unknown", which is worse than no dossier at all.
    obs = _obs(
        resp_ports=_ports((445, 6), (135, 4)),
        resp_peer_count=2,
        resp_hours=3,
        orig_peer_count=12,
        user_agents=(WINDOWS_UA,),
    )
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value == "workstation"
    assert role.strength == "strong"
    assert any("tcp/445" in line for line in role.evidence)


def test_a_file_server_serving_smb_to_the_fleet_is_still_a_server() -> None:
    # The other side of the same line: the callback ports are also what a file
    # server answers, so serving them TO A FLEET has to stay a server.
    obs = _obs(
        resp_ports=_ports((445, 9000)),
        resp_peer_count=25,
        resp_hours=24,
        orig_peer_count=8,
        user_agents=(WINDOWS_UA,),
    )
    role = infer_host_facts(obs, min_events=20)["role"]
    assert role.value == "server"
    assert role.strength == "strong"


# ---------------------------------------------------------------------------
# OS — the ladder, the two-family rule, and the disagreement string.
# ---------------------------------------------------------------------------


def test_ssh_server_banner_names_the_distribution() -> None:
    # The headless-Linux case: no User-Agent, no vendor DNS telemetry, and the
    # banner says Debian outright. `host_summary` never reads it.
    obs = _obs(
        ssh_banners=(
            {
                "server": DEBIAN_BANNER,
                "source_ip": "192.168.10.40",
                "destination_ip": HOST_IP,
                "timestamp": RECORD_SEEN_ISO,
            },
        )
    )
    facts = infer_host_facts(obs, min_events=20)
    assert facts["os_family"].value == "linux"
    assert facts["os_family"].source == "banner"
    assert facts["os_family"].strength == "strong"
    assert facts["os_detail"].value == "debian"
    assert facts["os_family"].observed_at == RECORD_SEEN


def test_ssh_client_banner_from_a_peer_is_not_this_host_s_os() -> None:
    # The client banner belongs to the ORIGINATOR. Reading it without the
    # direction attributes the peer's OS to this host.
    obs = _obs(
        ssh_banners=(
            {
                "client": "SSH-2.0-OpenSSH_for_Windows_8.1",
                "server": DEBIAN_BANNER,
                "source_ip": "192.168.10.40",
                "destination_ip": HOST_IP,
                "timestamp": RECORD_SEEN_ISO,
            },
        )
    )
    assert infer_host_facts(obs, min_events=20)["os_family"].value == "linux"


def test_this_host_s_own_client_banner_is_read_when_it_originates() -> None:
    obs = _obs(
        ssh_banners=(
            {
                "client": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3",
                "server": "SSH-2.0-OpenSSH_for_Windows_8.1",
                "source_ip": HOST_IP,
                "destination_ip": "192.168.10.50",
                "timestamp": RECORD_SEEN_ISO,
            },
        )
    )
    facts = infer_host_facts(obs, min_events=20)
    assert facts["os_family"].value == "linux"
    assert facts["os_detail"].value == "ubuntu"


def test_banner_beats_user_agent_beats_telemetry_hint() -> None:
    # The full ladder in one observation set, all three agreeing on family.
    obs = _obs(
        ssh_banners=(
            {"server": DEBIAN_BANNER, "destination_ip": HOST_IP, "timestamp": RECORD_SEEN_ISO},
        ),
        user_agents=("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",),
        dns_queries=_domains("deb.debian.org", "archive.ubuntu.com"),
    )
    os_family = infer_host_facts(obs, min_events=20)["os_family"]
    assert os_family.value == "linux"
    assert os_family.source == "banner"
    # The weaker signals are retained rather than dropped — the reader can see
    # everything the call was made from.
    joined = " ".join(os_family.evidence)
    # The banner evidence names the DIRECTION it was read from, not just "ssh".
    assert "ssh-server-banner" in joined
    assert "user-agent" in joined
    assert "telemetry-domains" in joined


def test_user_agent_beats_the_telemetry_hint_when_there_is_no_banner() -> None:
    obs = _obs(user_agents=(MAC_UA,), dns_queries=_domains(*APPLE_DOMAINS))
    facts = infer_host_facts(obs, min_events=20)
    assert facts["os_family"].value == "apple"
    assert facts["os_family"].source == "telemetry"
    assert facts["os_detail"].value == "macOS"


def test_iphone_user_agent_is_not_a_mac() -> None:
    # `classify_user_agent`'s ordering is reused, not reimplemented: every
    # mobile-Safari UA carries "like Mac OS X".
    ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15"
    facts = infer_host_facts(_obs(user_agents=(ua,)), min_events=20)
    assert facts["os_family"].value == "apple"
    assert facts["os_detail"].value == "iPhone"


def test_two_os_families_stay_mixed_instead_of_collapsing() -> None:
    # A hypervisor bridging guests, or a NAT gateway. Picking one family here
    # is worse than saying "mixed".
    obs = _obs(dns_queries=_domains(*APPLE_DOMAINS), sni=_domains(*WINDOWS_DOMAINS))
    os_family = infer_host_facts(obs, min_events=20)["os_family"]
    assert os_family.value is None
    assert os_family.strength == "weak"
    assert os_family.confidence == 0.5
    joined = " ".join(os_family.evidence)
    assert "apple.com" in joined or "icloud.com" in joined
    assert "msftncsi.com" in joined or "windowsupdate.com" in joined
    # No detail can be claimed for a mixed verdict.
    assert infer_host_facts(obs, min_events=20)["os_detail"].value is None


def test_two_user_agent_families_stay_mixed_too() -> None:
    # Same rule, same reason, other signal: a NAT gateway or a hypervisor
    # bridging guests shows Windows AND Apple User-Agents on one address.
    # Taking the first UA collapses that to a coin flip at strong confidence.
    obs = _obs(user_agents=(WINDOWS_UA, MAC_UA))
    facts = infer_host_facts(obs, min_events=20)
    assert facts["os_family"].value is None
    assert facts["os_family"].strength == "weak"
    assert facts["os_detail"].value is None
    joined = " ".join(facts["os_family"].evidence)
    assert "Windows NT 10.0" in joined
    assert "Mac OS X" in joined


def test_mixed_user_agents_do_not_defer_to_a_weaker_telemetry_guess() -> None:
    # The mixed verdict outranks the rung below it: vendor telemetry naming one
    # family does not resolve two families seen on the wire.
    obs = _obs(user_agents=(WINDOWS_UA, MAC_UA), dns_queries=_domains(*WINDOWS_DOMAINS))
    assert infer_host_facts(obs, min_events=20)["os_family"].value is None


def test_a_first_party_banner_still_beats_mixed_user_agents() -> None:
    # Mixed UAs are what a host FORWARDS; the SSH banner is what it IS.
    obs = _obs(
        ssh_banners=(
            {"server": DEBIAN_BANNER, "destination_ip": HOST_IP, "timestamp": RECORD_SEEN_ISO},
        ),
        user_agents=(WINDOWS_UA, MAC_UA),
    )
    os_family = infer_host_facts(obs, min_events=20)["os_family"]
    assert os_family.value == "linux"
    # …and the reader is told the traffic said two other things.
    assert os_family.conflict is not None
    assert "user-agent=mixed" in os_family.conflict


def test_a_second_user_agent_in_the_same_family_is_not_a_disagreement() -> None:
    # An iPhone and a Mac on one address are one family; `classify_user_agent`'s
    # specific-device-first ordering still picks the device for os_detail.
    iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15"
    facts = infer_host_facts(_obs(user_agents=(iphone, MAC_UA)), min_events=20)
    assert facts["os_family"].value == "apple"
    assert facts["os_detail"].value == "iPhone"


def test_os_family_disagreement_is_named_not_dropped() -> None:
    obs = _obs(
        ssh_banners=(
            {"server": DEBIAN_BANNER, "destination_ip": HOST_IP, "timestamp": RECORD_SEEN_ISO},
        ),
        user_agents=(WINDOWS_UA,),
    )
    os_family = infer_host_facts(obs, min_events=20)["os_family"]
    # The stronger source still wins the value…
    assert os_family.value == "linux"
    # …and the loser is stated, with both sides and their raw signals.
    assert os_family.conflict is not None
    assert "OS family disagreement" in os_family.conflict
    assert "banner=linux" in os_family.conflict
    assert "user-agent=windows" in os_family.conflict


def test_no_os_signal_emits_an_explicit_none() -> None:
    # A field that was evaluated and produced nothing still reports — that is
    # what lets the store retract a value that has gone away.
    facts = infer_host_facts(_obs(), min_events=20)
    assert facts["os_family"].value is None
    assert facts["os_family"].strength == "none"
    assert facts["os_detail"].value is None


def test_bare_openssh_banner_does_not_invent_linux() -> None:
    # OpenSSH runs on Linux, BSD, macOS and Windows. A banner with no
    # distribution token is not evidence of a family.
    obs = _obs(ssh_banners=({"server": "SSH-2.0-OpenSSH_9.6", "destination_ip": HOST_IP},))
    assert infer_host_facts(obs, min_events=20)["os_family"].value is None


# ---------------------------------------------------------------------------
# Hostname — source-major precedence across the WHOLE observation set.
# ---------------------------------------------------------------------------


def test_hostname_prefers_dhcp_across_the_whole_observation_set() -> None:
    # `host_summary._resolve_hostname` loops documents first and sources
    # second, so whichever document sorted first decides. Here the PTR answer
    # comes first in the set and still loses to the DHCP announcement.
    obs = _obs(
        ptr_name="ptr-name.example",
        host_names=("HOSTLOG-NAME",),
        windows_identity=(
            {"dataset": "zeek.ntlm", "hostname": "PVE01-NTLM", "source_ip": HOST_IP},
        ),
        dhcp=({"hostname": "pve01", "source_ip": HOST_IP, "timestamp": RECORD_SEEN_ISO},),
    )
    hostname = infer_host_facts(obs, min_events=20)["hostname"]
    assert hostname.value == "pve01"
    assert hostname.source == "banner"
    assert hostname.strength == "strong"
    assert hostname.evidence[0] == "pve01 (from dhcp)"
    joined = " ".join(hostname.evidence)
    assert "(from ntlm)" in joined
    assert "(from dns-ptr)" in joined
    assert "(from host.name)" in joined


def test_hostname_from_ntlm_when_there_is_no_dhcp() -> None:
    # `ntlm.hostname` is the CLIENT's machine name, so it is this host's only
    # when this host originated the negotiation.
    obs = _obs(
        windows_identity=(
            {
                "dataset": "zeek.ntlm",
                "hostname": "WS-4471",
                "source_ip": HOST_IP,
                "destination_ip": "192.168.10.10",
                "timestamp": RECORD_SEEN_ISO,
            },
        ),
        ptr_name="ws-4471.example",
    )
    hostname = infer_host_facts(obs, min_events=20)["hostname"]
    assert hostname.value == "WS-4471"
    assert hostname.strength == "strong"


def test_hostname_from_smb_announcement_is_weak() -> None:
    obs = _obs(
        windows_identity=(
            {
                "dataset": "zeek.smb_mapping",
                "smb_host_name": "FILES01",
                "source_ip": "192.168.10.40",
                "destination_ip": HOST_IP,
            },
        )
    )
    hostname = infer_host_facts(obs, min_events=20)["hostname"]
    assert hostname.value == "FILES01"
    assert hostname.strength == "weak"
    assert hostname.source == "banner"


def test_hostname_from_ptr_is_telemetry_and_weak() -> None:
    hostname = infer_host_facts(_obs(ptr_name="gw.lab.example"), min_events=20)["hostname"]
    assert hostname.value == "gw.lab.example"
    assert hostname.source == "telemetry"
    assert hostname.strength == "weak"


def test_ntlm_hostname_belongs_to_the_client_not_to_the_server() -> None:
    # THE Windows-identity direction bug: `ntlm.hostname` is the machine name
    # the CLIENT announces, and `ntlm.server_nb_computer_name` is the server's.
    # Attaching both to whichever host the record was found under renames a file
    # server after the last laptop that authenticated to it.
    obs = _obs(
        windows_identity=(
            {
                "dataset": "zeek.ntlm",
                "hostname": "LAPTOP-VISITOR",
                "server_nb": "FILES01",
                "source_ip": "192.168.10.40",
                "destination_ip": HOST_IP,
                "timestamp": RECORD_SEEN_ISO,
            },
        )
    )
    hostname = infer_host_facts(obs, min_events=20)["hostname"]
    assert hostname.value == "FILES01"
    assert "LAPTOP-VISITOR" not in " ".join(hostname.evidence)


def test_the_peers_server_name_is_not_this_clients_hostname() -> None:
    # Mirror image: this host originated, so the NetBIOS computer name in the
    # record is the server it talked to.
    obs = _obs(
        windows_identity=(
            {
                "dataset": "zeek.ntlm",
                "hostname": "LAPTOP-VISITOR",
                "server_nb": "FILES01",
                "source_ip": HOST_IP,
                "destination_ip": "192.168.10.10",
                "timestamp": RECORD_SEEN_ISO,
            },
        )
    )
    hostname = infer_host_facts(obs, min_events=20)["hostname"]
    assert hostname.value == "LAPTOP-VISITOR"
    assert "FILES01" not in " ".join(hostname.evidence)


def test_an_smb_host_name_is_not_attributed_to_the_client_side() -> None:
    obs = _obs(
        windows_identity=(
            {
                "dataset": "zeek.smb_mapping",
                "smb_host_name": "FILES01",
                "source_ip": HOST_IP,
                "destination_ip": "192.168.10.10",
            },
        )
    )
    assert infer_host_facts(obs, min_events=20)["hostname"].value is None


def test_a_windows_identity_record_with_no_endpoints_names_nobody() -> None:
    # Without a side, there is no host to attribute the name to. A wrong
    # hostname is worse than none: it is what an analyst pivots on.
    obs = _obs(
        windows_identity=({"dataset": "zeek.ntlm", "hostname": "WS-4471", "server_nb": "DC01"},)
    )
    assert infer_host_facts(obs, min_events=20)["hostname"].value is None


def test_hostname_rejects_ip_literals_junk_and_stubs() -> None:
    obs = _obs(
        dhcp=({"hostname": HOST_IP, "source_ip": HOST_IP},),  # host.name carrying the address
        windows_identity=({"dataset": "zeek.ntlm", "hostname": "WORKGROUP"},),
        host_names=("ab",),  # too short to be a name
        ptr_name="\\x01\\x02__MSBROWSE__\\x02",
    )
    hostname = infer_host_facts(obs, min_events=20)["hostname"]
    assert hostname.value is None
    assert hostname.strength == "none"


# ---------------------------------------------------------------------------
# MAC
# ---------------------------------------------------------------------------


def test_mac_is_normalized_and_carries_its_oui_prefix() -> None:
    obs = _obs(
        dhcp=(
            {
                "hostname": "pve01",
                "mac": "AA-BB-CC-DD-EE-FF",
                "source_ip": HOST_IP,
                "timestamp": RECORD_SEEN_ISO,
            },
        )
    )
    mac = infer_host_facts(obs, min_events=20)["mac"]
    assert mac.value == "aa:bb:cc:dd:ee:ff"
    assert mac.value_json == {"mac": "aa:bb:cc:dd:ee:ff", "oui": "aa:bb:cc"}
    assert mac.source == "banner"
    assert mac.strength == "strong"
    assert mac.evidence == ["aa:bb:cc:dd:ee:ff (from dhcp)"]


def test_mac_accepts_the_cisco_dotted_form_from_a_non_dhcp_record() -> None:
    obs = _obs(windows_identity=({"dataset": "zeek.ntlm", "mac": "aabb.ccdd.eeff"},))
    mac = infer_host_facts(obs, min_events=20)["mac"]
    assert mac.value == "aa:bb:cc:dd:ee:ff"
    assert mac.evidence == ["aa:bb:cc:dd:ee:ff (from host.mac)"]


def test_mac_ignores_broadcast_and_all_zero_addresses() -> None:
    obs = _obs(
        dhcp=({"mac": "ff:ff:ff:ff:ff:ff", "source_ip": HOST_IP},),
        windows_identity=({"dataset": "zeek.ntlm", "mac": "00:00:00:00:00:00"},),
    )
    assert infer_host_facts(obs, min_events=20)["mac"].value is None


# ---------------------------------------------------------------------------
# Domain membership
# ---------------------------------------------------------------------------


def test_domain_membership_prefers_ntlm_over_kerberos_over_dhcp() -> None:
    obs = _obs(
        dhcp=({"domain": "dhcp.example", "source_ip": HOST_IP},),
        windows_identity=(
            {"dataset": "zeek.kerberos", "realm": "KRB.EXAMPLE", "destination_ip": HOST_IP},
            {"dataset": "zeek.ntlm", "domain": "CORP", "timestamp": RECORD_SEEN_ISO},
        ),
    )
    membership = infer_host_facts(obs, min_events=20)["domain_membership"]
    assert membership.value == "CORP"
    assert membership.source == "banner"
    assert membership.strength == "strong"
    assert membership.evidence[0] == "CORP (from ntlm)"


def test_domain_membership_from_dhcp_alone_is_weak() -> None:
    obs = _obs(dhcp=({"domain": "lab.example", "source_ip": HOST_IP},))
    membership = infer_host_facts(obs, min_events=20)["domain_membership"]
    assert membership.value == "lab.example"
    assert membership.strength == "weak"


def test_workgroup_is_not_a_domain_membership() -> None:
    # WORKGROUP is the Windows default for a host that joined nothing.
    obs = _obs(windows_identity=({"dataset": "zeek.ntlm", "domain": "WORKGROUP"},))
    membership = infer_host_facts(obs, min_events=20)["domain_membership"]
    assert membership.value is None
    assert membership.strength == "none"


# ---------------------------------------------------------------------------
# is_static_addressed — three-valued, because "no DHCP data" is not "static".
# ---------------------------------------------------------------------------


def test_a_dhcp_lease_means_the_address_is_not_static() -> None:
    obs = _obs(
        available_datasets=frozenset({"zeek.conn", "zeek.dhcp"}),
        dhcp=({"hostname": "wks-12", "source_ip": HOST_IP, "timestamp": RECORD_SEEN_ISO},),
    )
    fact = infer_host_facts(obs, min_events=20)["is_static_addressed"]
    assert fact.value == "no"
    assert fact.strength == "strong"


def test_no_lease_on_a_grid_that_carries_dhcp_means_static_weak() -> None:
    obs = _obs(available_datasets=frozenset({"zeek.conn", "zeek.dhcp"}))
    fact = infer_host_facts(obs, min_events=20)["is_static_addressed"]
    assert fact.value == "yes"
    assert fact.strength == "weak"


def test_no_dhcp_dataset_reports_the_signal_as_unavailable() -> None:
    # THE failure this three-valued field exists to prevent: a grid with no
    # zeek.dhcp would otherwise report the whole network as statically addressed.
    obs = _obs(available_datasets=frozenset({"zeek.conn", "zeek.dns"}))
    fact = infer_host_facts(obs, min_events=20)["is_static_addressed"]
    assert fact.value is None
    assert fact.evidence == ["signal unavailable on this grid (no zeek.dhcp dataset)"]


def test_below_the_event_floor_static_addressing_is_not_claimed() -> None:
    obs = _obs(total_events=4, available_datasets=frozenset({"zeek.conn", "zeek.dhcp"}))
    fact = infer_host_facts(obs, min_events=20)["is_static_addressed"]
    assert fact.value is None


# ---------------------------------------------------------------------------
# services_offered / management_plane / activity_profile
# ---------------------------------------------------------------------------


def test_services_offered_carries_the_structured_port_list() -> None:
    obs = _obs(
        resp_ports=_ports((443, 900), (22, 40)),
        resp_peer_count=5,
        resp_hours=12,
        services=[{"value": "ssl", "count": 900}, {"value": "ssh", "count": 40}],
    )
    services = infer_host_facts(obs, min_events=20)["services_offered"]
    assert services.value_json == [
        {"port": 443, "proto": "tcp", "count": 900, "service": None},
        {"port": 22, "proto": "tcp", "count": 40, "service": None},
    ]
    assert services.value == "tcp/443, tcp/22"
    assert services.source == "behaviour"
    assert services.strength == "strong"
    # The Zeek service names are observed per-host, not per-port, so they are
    # reported as evidence rather than mapped onto a port they may not belong to.
    assert any("ssl" in line and "ssh" in line for line in services.evidence)


def test_services_offered_is_empty_when_the_host_only_originates() -> None:
    services = infer_host_facts(_obs(orig_peer_count=8), min_events=20)["services_offered"]
    assert services.value is None
    assert services.value_json == []
    assert services.strength == "none"


def test_services_offered_applies_the_minimum_hits_floor() -> None:
    # One packet at tcp/8006 is a stray, and the role rules already treat it as
    # one. Publishing it as an offered service contradicts them on the same
    # screen — and "serves tcp/8006" is what a reader acts on.
    obs = _obs(
        resp_ports=_ports((443, 900), (8006, 1)),
        resp_peer_count=5,
        resp_hours=12,
    )
    services = infer_host_facts(obs, min_events=20)["services_offered"]
    assert [entry["port"] for entry in services.value_json] == [443]
    assert services.value == "tcp/443"


def test_services_offered_is_not_strong_when_every_port_is_a_stray() -> None:
    obs = _obs(resp_ports=_ports((8006, 1), (22, 1)), resp_peer_count=1, resp_hours=1)
    services = infer_host_facts(obs, min_events=20)["services_offered"]
    assert services.value is None
    assert services.value_json == []
    assert services.strength == "none"
    assert services.confidence == 0.0


def test_management_plane_lists_the_admin_ports_it_answers() -> None:
    obs = _obs(
        resp_ports=_ports((8006, 2100), (22, 400), (443, 900)),
        resp_peer_count=4,
        resp_hours=19,
    )
    plane = infer_host_facts(obs, min_events=20)["management_plane"]
    assert plane.value == "yes"
    assert plane.value_json == [22, 8006]
    assert plane.source == "behaviour"


def test_management_plane_is_no_when_nothing_administrative_answers() -> None:
    obs = _obs(resp_ports=_ports((80, 400), (443, 900)), resp_peer_count=6, resp_hours=20)
    plane = infer_host_facts(obs, min_events=20)["management_plane"]
    assert plane.value == "no"
    assert plane.value_json == []


def test_activity_profile_flags_outbound_remote_access() -> None:
    # This is the field that turns "host did X" into "host did X, which it has
    # never done before".
    obs = _obs(
        orig_ports=_ports((22, 12), (443, 4000)),
        orig_peer_count=9,
        hour_of_day={9: 120, 10: 400, 14: 300, 22: 5},
        orig_bytes_p50=1200.0,
        orig_bytes_p95=90000.0,
        ja3_distinct=3,
    )
    fact = infer_host_facts(obs, min_events=20)["activity_profile"]
    profile = fact.value_json
    assert profile is not None
    assert profile["initiates_remote_access"] is True
    assert profile["remote_access_ports"] == [22]
    assert profile["busiest_hours"] == [10, 14, 9]
    assert profile["hour_of_day"] == {9: 120, 10: 400, 14: 300, 22: 5}
    assert profile["orig_bytes_p50"] == 1200.0
    assert profile["distinct_ja3"] == 3
    assert fact.source == "behaviour"
    assert fact.strength == "strong"


def test_activity_profile_records_the_absence_of_remote_access() -> None:
    obs = _obs(orig_ports=_ports((443, 4000)), orig_peer_count=9, hour_of_day={3: 40})
    profile = infer_host_facts(obs, min_events=20)["activity_profile"].value_json
    assert profile is not None
    assert profile["initiates_remote_access"] is False
    assert profile["remote_access_ports"] == []


# ---------------------------------------------------------------------------
# Malformed input — the collector never raises, so it can hand over anything.
# ---------------------------------------------------------------------------


def test_unparseable_port_buckets_are_skipped_not_fatal() -> None:
    # A grid with a text-mapped port field, or a reduced-agg fallback, produces
    # buckets the classifier has to survive rather than raise on.
    obs = _obs(
        resp_ports=[
            {"value": "8006", "count": 2100},  # numeric string
            {"value": "not-a-port", "count": 40},
            {"value": None, "count": 12},
            {"value": 99999, "count": 5},  # out of range
            {"count": 3},  # no key at all
        ],
        resp_peer_count=4,
        resp_hours=19,
    )
    facts = infer_host_facts(obs, min_events=20)
    assert facts["role"].value == "hypervisor"
    assert facts["services_offered"].value == "tcp/8006"


def test_a_record_timestamp_may_already_be_a_datetime() -> None:
    obs = _obs(dhcp=({"hostname": "wks-12", "source_ip": HOST_IP, "timestamp": RECORD_SEEN},))
    assert infer_host_facts(obs, min_events=20)["hostname"].observed_at == RECORD_SEEN


def test_an_unparseable_record_timestamp_falls_back_to_the_window() -> None:
    obs = _obs(dhcp=({"hostname": "wks-12", "source_ip": HOST_IP, "timestamp": "not-a-date"},))
    assert infer_host_facts(obs, min_events=20)["hostname"].observed_at == LAST_SEEN


def test_a_dhcp_record_without_address_fields_is_still_this_host_s_lease() -> None:
    # The collector already scoped the search to this host, so a record that
    # carries no address field is ours by construction.
    obs = _obs(
        available_datasets=frozenset({"zeek.dhcp"}),
        dhcp=({"hostname": "wks-12"},),
    )
    facts = infer_host_facts(obs, min_events=20)
    assert facts["hostname"].value == "wks-12"
    assert facts["is_static_addressed"].value == "no"


def test_an_ssh_banner_with_no_endpoints_is_not_attributed_to_this_host() -> None:
    # A document carrying neither endpoint IP says nothing about which side this
    # host was. Reading the SERVER banner anyway stamps the peer's OS on a host
    # that was only ever an SSH client.
    obs = _obs(ssh_banners=({"server": DEBIAN_BANNER, "timestamp": RECORD_SEEN_ISO},))
    facts = infer_host_facts(obs, min_events=20)
    assert facts["os_family"].value is None
    assert facts["os_family"].strength == "none"


def test_a_dhcp_server_does_not_wear_its_clients_lease() -> None:
    # This host is the DHCP SERVER: the transaction was addressed TO it. Taking
    # the record as its own lease gives the server the client's name and MAC and
    # reports the server's static address as dynamically assigned.
    obs = _obs(
        available_datasets=frozenset({"zeek.dhcp"}),
        resp_ports=_ports((67, 800)),
        resp_peer_count=20,
        resp_hours=24,
        dhcp=(
            {
                "hostname": "wks-12",
                "mac": "aa:bb:cc:dd:ee:ff",
                "destination_ip": HOST_IP,
                "timestamp": RECORD_SEEN_ISO,
            },
        ),
    )
    facts = infer_host_facts(obs, min_events=20)
    assert facts["hostname"].value is None
    assert facts["mac"].value is None
    assert facts["is_static_addressed"].value == "yes"


def test_an_explicit_assigned_address_decides_whose_lease_it_is() -> None:
    # When the collector can read the lease itself, it outranks packet
    # direction: a relayed or proxied transaction is still not our lease.
    obs = _obs(
        available_datasets=frozenset({"zeek.dhcp"}),
        dhcp=(
            {"hostname": "wks-12", "assigned_ip": "192.168.10.77", "source_ip": HOST_IP},
            {"hostname": "pve01", "assigned_ip": HOST_IP, "source_ip": "192.168.10.1"},
        ),
    )
    facts = infer_host_facts(obs, min_events=20)
    assert facts["hostname"].value == "pve01"
    assert facts["is_static_addressed"].value == "no"


def test_only_the_peers_client_banner_yields_no_os_for_this_host() -> None:
    # This host answered the session, so the client banner in the record is the
    # peer's. With no server banner there is simply nothing to read.
    obs = _obs(
        ssh_banners=(
            {
                "client": "SSH-2.0-OpenSSH_for_Windows_8.1",
                "source_ip": "192.168.10.40",
                "destination_ip": HOST_IP,
            },
        )
    )
    assert infer_host_facts(obs, min_events=20)["os_family"].value is None


def test_an_unclassifiable_user_agent_is_skipped_not_fatal() -> None:
    # `curl/8.4` names no OS. The next UA in the (newest-first) list decides.
    obs = _obs(user_agents=("curl/8.4.0", MAC_UA))
    assert infer_host_facts(obs, min_events=20)["os_family"].value == "apple"


def test_a_smart_tv_user_agent_names_a_device_not_an_os_family() -> None:
    # `classify_user_agent` labels it, but there is no OS family behind the
    # label — so it neither sets os_family nor disqualifies the IoT verdict.
    obs = _obs(
        resp_ports=_ports((8009, 300), (5353, 200)),
        resp_peer_count=3,
        resp_hours=14,
        orig_peer_count=4,
        user_agents=("Mozilla/5.0 (SMART-TV; Linux; Tizen 6.0) AppleWebKit/537.36",),
    )
    facts = infer_host_facts(obs, min_events=20)
    assert facts["role"].value == "iot"
    assert facts["os_family"].value is None


def test_a_telemetry_only_windows_host_has_no_version_detail() -> None:
    # os_hint's "windows" label IS the family; there is nothing more specific to
    # claim, and the detail field says so rather than repeating the family.
    obs = _obs(sni=_domains(*WINDOWS_DOMAINS))
    facts = infer_host_facts(obs, min_events=20)
    assert facts["os_family"].value == "windows"
    assert facts["os_detail"].value is None
    assert facts["os_detail"].strength == "none"


# ---------------------------------------------------------------------------
# Cross-cutting contracts
# ---------------------------------------------------------------------------


def test_criticality_and_policy_notes_are_never_inferred() -> None:
    # Only the operator lane ever populates these. A telemetry-derived
    # criticality would be an unsourced assertion about an asset.
    obs = _obs(
        resp_ports=_ports((8006, 2100), (8007, 1200)),
        resp_peer_count=4,
        resp_hours=19,
        dhcp=({"hostname": "pve01", "mac": "aa:bb:cc:dd:ee:ff", "source_ip": HOST_IP},),
    )
    facts = infer_host_facts(obs, min_events=20)
    assert "criticality" not in facts
    assert "policy_notes" not in facts


def test_only_known_dossier_fields_are_emitted() -> None:
    facts = infer_host_facts(_obs(), min_events=20)
    assert set(facts) <= set(DOSSIER_FIELDS)
    # Every emitted Fact is keyed by its own field name.
    assert all(name == fact.field for name, fact in facts.items())


def test_observed_at_never_comes_from_the_clock() -> None:
    # A build over a historical window must conclude what was true THEN. A fact
    # stamped with the build time looks freshly confirmed forever, which is
    # exactly how the resolver loses the ability to spot a stale belief.
    obs = _obs(
        resp_ports=_ports((8006, 2100), (22, 400)),
        resp_peer_count=4,
        resp_hours=19,
        orig_ports=_ports((22, 4)),
        orig_peer_count=6,
        hour_of_day={10: 400},
        user_agents=(MAC_UA,),
        dns_queries=_domains(*APPLE_DOMAINS),
        available_datasets=frozenset({"zeek.conn", "zeek.dhcp"}),
        dhcp=(
            {
                "hostname": "pve01",
                "mac": "aa:bb:cc:dd:ee:ff",
                "domain": "lab.example",
                "source_ip": HOST_IP,
                "timestamp": RECORD_SEEN_ISO,
            },
        ),
        ssh_banners=(
            {"server": DEBIAN_BANNER, "destination_ip": HOST_IP, "timestamp": RECORD_SEEN_ISO},
        ),
    )
    facts = infer_host_facts(obs, min_events=20)
    stamps = {fact.observed_at for fact in facts.values()}
    assert stamps <= {None, FIRST_SEEN, LAST_SEEN, RECORD_SEEN}
    # And nothing landed anywhere near "now".
    assert all(stamp is None or stamp.year == 2019 for stamp in stamps)


def test_an_empty_observation_set_still_evaluates_every_inferable_field() -> None:
    # The store needs a Fact even when a field produced nothing: that is what
    # refreshes `inferred_last_run_at` and drives retraction.
    facts = infer_host_facts(HostObservations(ip=HOST_IP), min_events=20)
    inferable = tuple(f for f in DOSSIER_FIELDS if f not in ("criticality", "policy_notes"))
    assert set(facts) == set(inferable)


# ---------------------------------------------------------------------------
# The hostlog rung — what an agent ON the machine reported.
#
# Until host logs shipped, this rung of the ladder was a docstring: the dossier
# could describe 192.168.10.202 from the wire but could not NAME it, which is
# how an incident report ended up talking about "an internal host" that was in
# fact the hypervisor the pivot ran through. An agent's self-report is a machine
# naming itself, so it outranks anything announced on the wire — and every fact
# it produces is stamped with the AGENT's clock, never the builder's.
# ---------------------------------------------------------------------------

AGENT_SEEN = datetime(2019, 3, 15, 22, 15, tzinfo=UTC)
AGENT_FIRST = datetime(2019, 3, 2, 6, 0, tzinfo=UTC)

# host.os as a filebeat agent reports it on a Debian-family machine. The kernel
# is the interesting part: it is the only field that says "Proxmox" out loud.
DEBIAN_OS = {
    "name": "Debian GNU/Linux",
    "family": "debian",
    "version": "13 (trixie)",
    "kernel": "7.0.12-1-pve",
    "platform": "debian",
    "type": "linux",
}
WINDOWS_OS = {
    "name": "Windows Server 2022 Datacenter",
    "family": "windows",
    "version": "10.0",
    "kernel": "10.0.20348.2461",
    "platform": "windows",
    "type": "windows",
}


def _agent(**overrides: Any) -> AgentSelfReport:
    """A self-report with the fields every filebeat document carries."""
    base: dict[str, Any] = {
        "host_name": "pve-a",
        "os": dict(DEBIAN_OS),
        "macs": ("52-54-00-12-34-56",),
        "architecture": "x86_64",
        "agent_type": "filebeat",
        "agent_version": "9.3.7",
        "ips": (HOST_IP,),
        "doc_count": 14024,
        "first_report": AGENT_FIRST,
        "last_report": AGENT_SEEN,
    }
    base.update(overrides)
    return AgentSelfReport(**base)


def _dhcp_named(name: str) -> dict[str, Any]:
    return {"hostname": name, "source_ip": HOST_IP, "timestamp": RECORD_SEEN_ISO}


def test_a_self_reported_hostname_outranks_a_banner_hostname() -> None:
    # The disagreement is live on the incident host: DHCP announced one name,
    # the agent on the machine reports another. `hostlog` is the higher rung —
    # a machine naming itself beats a name a DHCP client asked for.
    obs = _obs(agent_report=_agent(), dhcp=(_dhcp_named("pve01"),))

    fact = infer_host_facts(obs, min_events=20)["hostname"]

    assert fact.value == "pve-a"
    assert fact.source == "hostlog"
    assert fact.strength == "strong"
    assert fact.confidence == 0.9
    # The loser is kept: a host with two names is worth seeing, not worth
    # silently resolving.
    assert fact.evidence == [
        "pve-a (self-reported, filebeat 9.3.7, last 2019-03-15T22:15:00+00:00)",
        "pve01 (from dhcp)",
    ]
    # The agent's clock, not the builder's and not the DHCP record's.
    assert fact.observed_at == AGENT_SEEN


def test_a_self_reported_hostname_stands_alone_when_the_wire_says_nothing() -> None:
    # The quiet machine: a handful of auth events, nothing to announce on the
    # network. Naming it is the entire point of the lane.
    obs = _obs(
        ip="192.168.60.226",
        total_events=0,
        agent_report=_agent(host_name="quiet-vm", ips=("192.168.60.226",)),
    )

    fact = infer_host_facts(obs, min_events=20)["hostname"]

    assert fact.value == "quiet-vm"
    assert fact.source == "hostlog"


def test_a_contended_address_names_the_agents_arguing_over_it() -> None:
    # Four machines report the same Docker bridge gateway. No identity is
    # attributed — and the dossier says why, rather than looking like an address
    # nobody has ever reported.
    obs = _obs(
        ip="172.17.0.1",
        agent_report=None,
        agent_ip_claimants=("buildbox", "registry-a", "sensor", "workbench"),
    )

    fact = infer_host_facts(obs, min_events=20)["hostname"]

    assert fact.value is None
    assert fact.strength == "none"
    assert any("4 host-log agents claim 172.17.0.1" in line for line in fact.evidence)
    assert any("buildbox, registry-a, sensor, workbench" in line for line in fact.evidence)


def test_a_contention_note_is_kept_beside_a_name_the_wire_did_supply() -> None:
    # A banner name still wins the field — but the reader is told the hostlog
    # lane was withheld rather than empty.
    obs = _obs(
        ip="172.17.0.1",
        dhcp=(_dhcp_named("pve01"),),
        agent_ip_claimants=("buildbox", "registry-a"),
    )

    fact = infer_host_facts(obs, min_events=20)["hostname"]

    assert fact.value == "pve01"
    assert fact.source == "banner"
    assert any("2 host-log agents claim" in line for line in fact.evidence)


def test_os_family_and_detail_come_from_the_agents_own_os_struct() -> None:
    obs = _obs(agent_report=_agent())

    facts = infer_host_facts(obs, min_events=20)

    family, detail = facts["os_family"], facts["os_detail"]
    # The coarse family the rest of the dossier speaks — NOT ECS's
    # `host.os.family`, which says "debian" and would make every Debian-family
    # machine disagree with every SSH banner that says "linux".
    assert family.value == "linux"
    assert family.source == "hostlog"
    assert family.strength == "strong"
    assert family.observed_at == AGENT_SEEN
    assert detail.value == "Debian GNU/Linux 13 (trixie), kernel 7.0.12-1-pve"
    assert detail.source == "hostlog"
    assert detail.evidence == [
        "Debian GNU/Linux 13 (trixie), kernel 7.0.12-1-pve "
        "(self-reported, filebeat 9.3.7, last 2019-03-15T22:15:00+00:00)"
    ]


def test_a_self_reported_os_outranks_the_ssh_banner_and_keeps_the_disagreement() -> None:
    # The banner is the strongest signal the WIRE has; the machine's own answer
    # is still better. A family-level disagreement is named, never resolved by
    # silently preferring one side.
    obs = _obs(
        agent_report=_agent(os=dict(WINDOWS_OS), host_name="win-a"),
        ssh_banners=(
            {"server": DEBIAN_BANNER, "destination_ip": HOST_IP, "timestamp": RECORD_SEEN_ISO},
        ),
    )

    family = infer_host_facts(obs, min_events=20)["os_family"]

    assert family.value == "windows"
    assert family.source == "hostlog"
    assert family.conflict is not None
    assert "hostlog=windows" in family.conflict
    assert "banner=linux" in family.conflict


def test_a_single_reported_mac_is_the_hosts_hardware_address() -> None:
    obs = _obs(agent_report=_agent(macs=("52-54-00-12-34-56",)))

    fact = infer_host_facts(obs, min_events=20)["mac"]

    # Normalised to the stored spelling; the agent writes hyphenated uppercase.
    assert fact.value == "52:54:00:12:34:56"
    assert fact.value_json == {"mac": "52:54:00:12:34:56", "oui": "52:54:00"}
    assert fact.source == "hostlog"
    assert fact.observed_at == AGENT_SEEN


def test_many_reported_macs_are_never_guessed_between() -> None:
    # A hypervisor reports its uplink alongside every bridge and veth it owns,
    # in no stable order and with no way to pair one with an address. Picking
    # "the first" would publish a random veth as the machine's hardware address
    # AND flip the identity fingerprint from sweep to sweep.
    obs = _obs(agent_report=_agent(macs=("52-54-00-12-34-56", "0A-11-22-33-44-55")))

    fact = infer_host_facts(obs, min_events=20)["mac"]

    assert fact.value is None
    assert fact.strength == "none"
    assert any("2 hardware addresses" in line for line in fact.evidence)


def test_an_ambiguous_agent_mac_leaves_the_dhcp_lease_in_charge() -> None:
    obs = _obs(
        agent_report=_agent(macs=("52-54-00-12-34-56", "0A-11-22-33-44-55")),
        dhcp=({**_dhcp_named("pve01"), "mac": "aa:bb:cc:dd:ee:ff"},),
    )

    fact = infer_host_facts(obs, min_events=20)["mac"]

    assert fact.value == "aa:bb:cc:dd:ee:ff"
    assert fact.source == "banner"


def test_an_os_struct_with_no_recognisable_family_still_yields_the_detail() -> None:
    # A family this dossier has no vocabulary for must not pollute the field —
    # but "what it says it runs" is still true and still worth recording.
    obs = _obs(agent_report=_agent(os={"name": "Plan 9", "type": "plan9", "version": "4"}))

    facts = infer_host_facts(obs, min_events=20)

    assert facts["os_family"].value is None
    assert any("Plan 9 4" in line for line in facts["os_detail"].evidence)


def test_the_hostlog_lane_is_inert_without_a_self_report() -> None:
    # A grid with no host logs must classify exactly as it did before the lane
    # existed: the banner wins the name, and nothing mentions an agent.
    obs = _obs(dhcp=(_dhcp_named("pve01"),))

    fact = infer_host_facts(obs, min_events=20)["hostname"]

    assert (fact.value, fact.source) == ("pve01", "banner")
    assert fact.evidence == ["pve01 (from dhcp)"]


# ---------------------------------------------------------------------------
# The DNS-name lane — the `telemetry` rung, below the machine's own account.
# ---------------------------------------------------------------------------

DNS_SEEN = datetime(2019, 3, 15, 19, 45, tzinfo=UTC)
DNS_EVIDENCE = "40 A/AAAA answers over the window"


def test_a_dns_consensus_name_becomes_the_hostname_at_the_telemetry_rung() -> None:
    # The lane's whole purpose: a host running no agent and announcing nothing
    # on the wire still has a name, because the network resolved one for it.
    obs = _obs(
        ip="192.168.10.50",
        total_events=0,
        dns_name="ws-1.lab.internal",
        dns_name_evidence=DNS_EVIDENCE,
        dns_name_observed_at=DNS_SEEN,
    )

    fact = infer_host_facts(obs, min_events=20)["hostname"]

    assert fact.value == "ws-1.lab.internal"
    assert fact.source == "telemetry"
    assert "40 A/AAAA answers" in fact.evidence[0]
    # The newest answer that named the address, never the build clock — this
    # host has no network sighting to fall back on.
    assert fact.observed_at == DNS_SEEN


def test_a_dns_name_is_confident_enough_to_survive_the_resolvers_floor() -> None:
    # A consensus that a strict majority of hundreds of answers agreed on is not
    # a guess. `weak` here would mean 0.5, under the default
    # `dossier_min_confidence` of 0.6 — the resolver would answer
    # "low_confidence" for every host this lane names, and the entire lane would
    # be invisible on every screen while looking wired up in the store.
    obs = _obs(dns_name="ws-1.lab.internal", dns_name_evidence=DNS_EVIDENCE)

    fact = infer_host_facts(obs, min_events=20)["hostname"]

    assert fact.strength == "strong"
    assert fact.confidence == 0.9


def test_a_self_reported_name_outranks_the_dns_name_for_the_same_host() -> None:
    # The ladder, not a tiebreak: an address can be re-pointed at a new machine
    # without that machine ever knowing, so what a resolver hands out never beats
    # what the machine says it is.
    obs = _obs(dns_name="pve-a-dns.lab.internal", agent_report=_agent())

    fact = infer_host_facts(obs, min_events=20)["hostname"]

    assert fact.value == "pve-a"
    assert fact.source == "hostlog"
    # The loser is kept: a host with two names is worth seeing.
    assert any("pve-a-dns.lab.internal" in line for line in fact.evidence)


def test_a_dhcp_name_outranks_the_dns_name_for_the_same_host() -> None:
    obs = _obs(dns_name="pve-a-dns.lab.internal", dhcp=(_dhcp_named("pve01"),))

    fact = infer_host_facts(obs, min_events=20)["hostname"]

    assert (fact.value, fact.source) == ("pve01", "banner")


def test_a_dns_consensus_outranks_a_ptr_answer_inside_the_telemetry_rung() -> None:
    # Both name the ADDRESS rather than the machine, so both are telemetry — but
    # one is a majority over the window's answers and the other is a single
    # record, and a contested consensus was already withheld upstream.
    obs = _obs(
        dns_name="ws-1.lab.internal",
        dns_name_evidence=DNS_EVIDENCE,
        ptr_name="stale.lab.internal",
        host_names=("proxy.lab.internal",),
    )

    fact = infer_host_facts(obs, min_events=20)["hostname"]

    assert fact.value == "ws-1.lab.internal"
    assert [line for line in fact.evidence if "stale" in line], "the PTR answer is kept"


def test_the_dns_lane_is_inert_without_a_consensus_name() -> None:
    # A grid with no DNS telemetry, or an address whose names tied, must
    # classify exactly as it did before the lane existed.
    obs = _obs(dhcp=(_dhcp_named("pve01"),))

    fact = infer_host_facts(obs, min_events=20)["hostname"]

    assert fact.evidence == ["pve01 (from dhcp)"]


def test_a_withheld_dns_name_is_explained_rather_than_looking_like_no_signal() -> None:
    # The failure this pins: a host whose ONLY name signal was a tied DNS
    # consensus used to report "no hostname signal in window" — wrong twice
    # over, because DNS is a signal and this one was withheld, not absent.
    obs = _obs(
        ip="192.168.10.50",
        total_events=0,
        dns_name_withheld="2 names tie for 192.168.10.50",
    )

    fact = infer_host_facts(obs, min_events=20)["hostname"]

    assert fact.value is None
    assert any("2 names tie" in line for line in fact.evidence)


def test_the_no_signal_line_names_dns_among_the_sources_it_checked() -> None:
    # The line enumerates what was looked at, so a source missing from it reads
    # as a source that was never consulted.
    obs = _obs()

    fact = infer_host_facts(obs, min_events=20)["hostname"]

    assert "DNS" in fact.evidence[0]


def test_a_withheld_dns_note_is_kept_beside_a_name_the_wire_did_supply() -> None:
    # The banner name still wins the field — but the reader is told the DNS lane
    # was withheld rather than empty, exactly as the hostlog lane does.
    obs = _obs(
        dhcp=(_dhcp_named("pve01"),),
        dns_name_withheld="vpn.lab.internal answers for 2 addresses of one family",
    )

    fact = infer_host_facts(obs, min_events=20)["hostname"]

    assert (fact.value, fact.source) == ("pve01", "banner")
    assert any("answers for 2 addresses" in line for line in fact.evidence)


# ---------------------------------------------------------------------------
# Candidate visibility — a name the resolver would HIDE must not shadow one it
# would show.
# ---------------------------------------------------------------------------


def _smb_named(name: str) -> dict[str, Any]:
    """An SMB host announcement ANSWERED by this host — a `banner`/weak name."""
    return {
        "dataset": "zeek.smb_mapping",
        "smb_host_name": name,
        "source_ip": "192.168.10.40",
        "destination_ip": HOST_IP,
    }


def test_a_weak_smb_name_does_not_shadow_a_visible_dns_name() -> None:
    # THE Windows-heavy failure mode this section pins: the SMB share name
    # (`banner`/weak, 0.5) used to win on rung alone, then fall under
    # `dossier_min_confidence` (0.6) at read time — the field rendered BLANK
    # while a 0.9 DNS consensus sat discarded in the evidence.
    obs = _obs(
        windows_identity=(_smb_named("FILES01"),),
        dns_name="files-1.lab.internal",
        dns_name_evidence=DNS_EVIDENCE,
        dns_name_observed_at=DNS_SEEN,
    )

    fact = infer_host_facts(obs, min_events=20, min_confidence=0.6)["hostname"]

    assert fact.value == "files-1.lab.internal"
    assert fact.source == "telemetry"
    assert fact.confidence == 0.9
    # Winner first, and the shadowed weak claim stays on the record — a host
    # with two names is worth seeing, not worth silently resolving.
    assert fact.evidence[0].startswith("files-1.lab.internal")
    assert any("FILES01" in line for line in fact.evidence)


def test_a_weak_high_rung_name_above_the_floor_still_wins_the_ladder() -> None:
    # The symmetric case: the ladder is NOT repealed. With the floor at 0.5 the
    # SMB name would render (the resolver's gate is `confidence < floor`), so
    # the higher rung keeps the field over the stronger telemetry name.
    obs = _obs(
        windows_identity=(_smb_named("FILES01"),),
        dns_name="files-1.lab.internal",
        dns_name_evidence=DNS_EVIDENCE,
    )

    fact = infer_host_facts(obs, min_events=20, min_confidence=0.5)["hostname"]

    assert (fact.value, fact.source) == ("FILES01", "banner")
    assert fact.confidence == 0.5


def test_with_every_name_below_the_floor_the_ladder_still_orders_them() -> None:
    # Nothing would render either way, so visibility has nothing to say and the
    # stored belief keeps the old rule: highest rung wins, and the resolver
    # reports `low_confidence` rather than asserting either name.
    obs = _obs(
        windows_identity=(_smb_named("FILES01"),),
        ptr_name="stale.lab.internal",
    )

    fact = infer_host_facts(obs, min_events=20, min_confidence=0.6)["hostname"]

    assert (fact.value, fact.source) == ("FILES01", "banner")
    assert fact.strength == "weak"
    assert any("stale.lab.internal" in line for line in fact.evidence)
