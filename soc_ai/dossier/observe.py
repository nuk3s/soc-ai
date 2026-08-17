"""Host-dossier collector: everything one IP did in one window, in ~7 searches.

This is the only I/O in :mod:`soc_ai.dossier`. It turns an IP into a
:class:`~soc_ai.dossier.types.HostObservations` snapshot and concludes nothing —
the classifier is a pure function of what comes back from here, so every role
rule stays testable from a hand-built observation set.

Shape of the collection:

* **One network-wide pass per SWEEP** (:func:`collect_agent_inventory`, ``size=0``)
  carries the host-log agents' self-reports: every machine that ships
  ``system.auth`` / ``system.syslog``, its name, OS, MACs and the addresses it
  claims. Network-wide because the answer does not vary by address — and because
  attribution needs the WHOLE network's claims before any single address can be
  attributed (see :class:`~soc_ai.dossier.types.AgentInventory`).
* **One more network-wide pass per SWEEP** (:func:`collect_dns_names`, ``size=0``)
  carries what the network's own DNS answers call each internal address. It is
  the only lane that reaches a host running no agent and announcing nothing:
  ``zeek.dns`` is where the names of the machines the other lanes cannot see are.
* **One multi-agg pass** (``size=0``) carries the volume signals: responder and
  originator port sets, peer cardinality, the hour spread, byte percentiles, the
  datasets this host appears in. These are what separate a hypervisor from a
  laptop that once answered an SSH connection.
* **Six targeted searches** carry identity: DHCP lease, SSH banner, Windows
  (NTLM/Kerberos/SMB/DCE-RPC) announcements, Zeek software, HTTP/TLS endpoint
  fields, and the PTR name. Each is ``size=20`` sorted **newest-first** — the
  opposite of ``host_summary``'s oldest-first 200-doc sample, because a dossier
  reports what a host IS now and the name it announced 14 days ago is history.

Three failure modes drove the design, all of them silent:

1. **A dual-mapped field aggregated under the wrong name returns zero buckets,
   not an error.** ``zeek.dns.query`` is mapped-but-empty on a modern SO grid, so
   a hardcoded agg would conclude "this host makes no DNS queries" and the
   dossier would be confidently wrong. Every dual-mapped field therefore goes
   through :func:`soc_ai.so_client.fields.resolve_agg_field`; only canonical ECS
   (``@timestamp``, ``event.dataset``, ``source.ip``, ``destination.ip``,
   ``destination.port``) is spelled inline.
2. **A missing dataset looks exactly like a missing signal.** A grid with no
   ``zeek.dhcp`` yields no lease for every host on it, which reads as
   "statically addressed" for the entire network. So the grid's dataset inventory
   is collected first, a targeted search whose datasets are all absent is
   skipped, and :attr:`HostObservations.available_datasets` lets the classifier
   say "signal unavailable on this grid" instead. When the inventory itself is
   unavailable, nothing is gated — an inventory outage must not be able to
   retract the network's hostnames.
3. **One bad agg 400s the whole pass.** ``resolve_agg_field``'s exists-probe
   proves a field has data, not that it is aggregatable; a ``terms`` agg on a
   text-mapped field fails the entire multi-agg search. The pass is retried once
   with the optional aggregations stripped, keeping the ports/peers/hours that
   the role rules actually need.

Never raises. Every sub-query has its own ``try``/``except`` that appends to
:attr:`HostObservations.errors` and leaves its slice empty — a partial
observation set is still a usable one, and the build proceeds on whatever came
back.
"""

from __future__ import annotations

import ipaddress
import logging
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from soc_ai.config import Settings
from soc_ai.dossier.types import (
    AgentInventory,
    AgentSelfReport,
    DnsNameClaim,
    DnsNameInventory,
    HostObservations,
    identity_bearing_ip,
)
from soc_ai.so_client import fields, inventory
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.fields import first_present, get_dotted
from soc_ai.tools.host_summary import (
    _agg_time,
    _base_host_query,
    _bucket_pairs,
    _first_str,
    _looks_like_ip,
)
from soc_ai.tools.query_events import _build_time_filter

_LOGGER = logging.getLogger(__name__)

# Docs per targeted identity search. Small on purpose: the aggregations carry
# the volume, these hits only carry the newest few announcements.
_SAMPLE_SIZE = 20

# Newest-first. A dossier states what a host is NOW.
_NEWEST_FIRST: list[dict[str, Any]] = [{"@timestamp": {"order": "desc"}}]

# Aggregation bucket caps. Ports are wide (a hypervisor answers on many), names
# wider still (the DNS/SNI sets feed the OS hint), datasets narrow.
_PORT_AGG_SIZE = 50
_DATASET_AGG_SIZE = 30
_SERVICE_AGG_SIZE = 20
_DOMAIN_AGG_SIZE = 50
_NAME_AGG_SIZE = 100

# Fields every identity record carries, whatever the search. The endpoints are
# not decoration: an SSH banner or a DCE-RPC endpoint attributes to the wrong
# host without knowing which side of the connection this host was on — and the
# same is true of the MAC, which is why every projection carries all three
# spellings of it (see :func:`_directional_mac`).
_ENVELOPE: tuple[str, ...] = (
    "@timestamp",
    "event.dataset",
    "source.ip",
    "destination.ip",
    *fields.HOST_MAC,
)

# (record key, ECS-first candidate list) per targeted search. The record keys
# are the vocabulary the classifier reads; the candidate lists are the ONLY
# place a raw field name is spelled.
_Reads = tuple[tuple[str, tuple[str, ...]], ...]

_DHCP_READS: _Reads = (
    ("hostname", fields.DHCP_HOSTNAME),
    ("mac", fields.DHCP_MAC),
    ("client_fqdn", fields.DHCP_CLIENT_FQDN),
    ("domain", fields.DHCP_DOMAIN),
)
_SSH_READS: _Reads = (
    ("client", fields.SSH_CLIENT),
    ("server", fields.SSH_SERVER),
    ("version", fields.SSH_VERSION),
    ("direction", fields.SSH_DIRECTION),
)
# Keys are unprefixed because the record is already namespaced by its search:
# within a Windows-identity record, "hostname" can only be the NTLM one and
# "realm" can only be the Kerberos one. This is the vocabulary
# ``soc_ai.dossier.infer`` reads by name.
_WINDOWS_READS: _Reads = (
    ("hostname", fields.NTLM_HOSTNAME),
    ("domain", fields.NTLM_DOMAIN),
    ("server_nb", fields.NTLM_SERVER_NB),
    ("kerberos_client", fields.KERBEROS_CLIENT),
    ("realm", fields.KERBEROS_REALM),
    ("smb_host_name", fields.SMB_HOST_NAME),
    ("smb_mapping_service", fields.SMB_MAPPING_SERVICE),
    ("dce_rpc_endpoint", fields.DCE_RPC_ENDPOINT),
)
_SOFTWARE_READS: _Reads = (
    ("name", fields.SOFTWARE_NAME),
    ("version", fields.SOFTWARE_VERSION),
    ("software_type", fields.SOFTWARE_TYPE),
)
_ENDPOINT_READS: _Reads = (
    ("user_agent", fields.HTTP_USER_AGENT),
    # Canonical ECS, no dual mapping, so it is spelled inline.
    ("host_name", ("host.name",)),
)
_PTR_READS: _Reads = (("answer", fields.DNS_RESOLVED_IP),)

# Datasets per targeted search, in the order they are searched.
_DHCP_DATASETS = ("zeek.dhcp",)
_SSH_DATASETS = ("zeek.ssh",)
_WINDOWS_DATASETS = ("zeek.ntlm", "zeek.kerberos", "zeek.smb_mapping", "zeek.dce_rpc")
_SOFTWARE_DATASETS = ("zeek.software",)
_ENDPOINT_DATASETS = ("zeek.http", "zeek.ssl")

# --- the network agent inventory (the `hostlog` rung) ------------------------
#
# The datasets an on-host log shipper writes. Both carry the full `host.*` /
# `agent.*` envelope on every document, which is the whole point: a machine
# that ships its auth log also tells us its name, its OS, its kernel, its MACs
# and the addresses it holds — the fields no amount of wire telemetry can give.
_HOSTLOG_DATASETS: tuple[str, ...] = ("system.auth", "system.syslog")

# Machines per network, and addresses per machine. The host cap is generous
# because an agent-shipping network is bounded by installs, not by traffic; the
# address cap is small because a host with 40 addresses is a container host and
# the extras are bridges that will lose the claim test anyway.
_AGENT_HOST_AGG_SIZE = 500
_AGENT_IP_AGG_SIZE = 40

# Projected out of the newest document per machine. `host.os` is taken as a
# whole object: os_detail renders whichever of name/version/kernel exist, and a
# grid that adds a key should not need a schema change to carry it.
_AGENT_READS: tuple[str, ...] = (
    "@timestamp",
    "host.name",
    "host.ip",
    "host.mac",
    "host.architecture",
    "host.os",
    "agent.type",
    "agent.version",
)
_AGENT_OS_KEYS: tuple[str, ...] = ("name", "family", "version", "kernel", "platform", "type")

# --- the network DNS-name inventory (the `telemetry` rung) -------------------
#
# The dataset that names the rest of the network. `hostlog` only reaches machines
# running a log agent — 13 of them against ~134 dossier rows on the network this
# was built for — and DHCP could not fill the gap because the server does not log
# its leases. `zeek.dns` did: ~38,000 answer documents every 6 hours, 553 distinct
# names pointing INSIDE the network over a 14-day window.
_DNS_DATASETS: tuple[str, ...] = ("zeek.dns",)

# Query names per network, and internal answer addresses per name. The name cap is
# generous because it is the only bound on a lane whose input is every name the
# network resolved; the address cap is small because a name answering for more
# than a handful of internal addresses is a service record rather than a host's
# name, and the per-address consensus weighs it against everything else claiming
# those addresses anyway.
_DNS_NAME_AGG_SIZE = 2000
_DNS_ANSWER_AGG_SIZE = 5

# Answer fields ECS types as `ip`, where a CIDR is a matchable term and the pass
# can be narrowed server-side. Spelled as the PROPERTY rather than as
# `DNS_RESOLVED_IP[0]`: the candidate list is ordered by preference, and
# reordering it must not silently change the shape of this query.
_IP_TYPED_ANSWER_FIELDS: frozenset[str] = frozenset({"dns.resolved_ip"})


@dataclass(frozen=True)
class _AggFields:
    """The dual-mapped field names resolved for THIS deployment.

    Seven names, seven cheap cached probes. Everything else the multi-agg pass
    touches is canonical ECS and needs no resolution.
    """

    service: str
    resp_bytes: str
    orig_bytes: str
    ja3: str
    reg_domain: str
    dns_query: str
    sni: str


@dataclass(frozen=True)
class _Identity:
    """The six targeted searches' output, before it becomes a HostObservations."""

    dhcp: tuple[dict[str, Any], ...] = ()
    ssh_banners: tuple[dict[str, Any], ...] = ()
    windows_identity: tuple[dict[str, Any], ...] = ()
    software: tuple[dict[str, Any], ...] = ()
    user_agents: tuple[str, ...] = ()
    host_names: tuple[str, ...] = ()
    ptr_name: str | None = None


def reverse_zone(ip: str) -> str | None:
    """The ``in-addr.arpa`` / ``ip6.arpa`` name for ``ip``, or ``None``.

    ``reverse_zone("192.168.10.202") == "202.10.168.192.in-addr.arpa"``. Exact
    and cheap: the PTR lookup is a ``term`` query on the DNS query name, never a
    wildcard scan over the whole DNS dataset.
    """
    try:
        return ipaddress.ip_address(ip.strip()).reverse_pointer
    except ValueError:
        return None


async def collect_host_observations(
    ip: str,
    *,
    elastic: ElasticClient,
    settings: Settings,
    window_hours: int,
    time_anchor: datetime | None = None,
    agent_inventory: AgentInventory | None = None,
    dns_names: DnsNameInventory | None = None,
) -> HostObservations:
    """Gather one host's observations over ``window_hours``. Never raises.

    Args:
        ip: the host to observe. A non-IP returns an errored (but valid) empty
            observation set rather than raising — the caller is a sweep over
            aggregation buckets and one bad key must not abort the pass.
        elastic: client for the SO ES cluster.
        settings: app settings (uses ``events_index_pattern``).
        window_hours: lookback width. With ``time_anchor`` set the window is
            CENTERED on the anchor, per ``query_events._build_time_filter``.
        time_anchor: anchor the window on this timestamp instead of now, so a
            build over a historical window concludes what was true then.
        agent_inventory: the network's host-log self-reports, collected ONCE per
            sweep by :func:`collect_agent_inventory` and handed to every host —
            the answer is network-wide, so re-deriving it here would be one extra
            aggregation per address for an identical result. Omitted (the
            default) the hostlog rung simply contributes nothing.
        dns_names: what the network's DNS answers call each internal address,
            collected ONCE per sweep by :func:`collect_dns_names` and handed down
            the same way. Omitted, the DNS lane contributes nothing.

    Returns:
        A :class:`HostObservations`. Absence of data is a clean, empty result —
        never an error — and any sub-query failure lands in ``errors`` with the
        rest of the collection intact.
    """
    if reverse_zone(ip) is None:
        return HostObservations(ip=ip, errors=(f"invalid IP: {ip!r}",))

    index = settings.events_index_pattern
    # A zero/negative window would build a nonsense range filter; clamp rather
    # than reject, since the caller is a scheduled job reading a hot setting.
    minutes = max(1, window_hours) * 60
    errors: list[str] = []

    agg_fields = await _resolve_agg_fields(elastic, index)
    available = await _available_datasets(elastic, settings, minutes)
    total, aggs = await _run_main_pass(
        elastic, index, ip=ip, minutes=minutes, anchor=time_anchor, f=agg_fields, errors=errors
    )
    identity = await _collect_identity(
        elastic,
        index,
        ip=ip,
        minutes=minutes,
        anchor=time_anchor,
        available=available,
        dns_query_field=agg_fields.dns_query,
        errors=errors,
    )

    agent_report, agent_claimants = (agent_inventory or AgentInventory()).for_ip(ip)
    # ONE pass over the claim list, not one per field read off it.
    dns = (dns_names or DnsNameInventory()).resolve(ip)

    responder = aggs.get("responder") or {}
    originator = aggs.get("originator") or {}
    return HostObservations(
        ip=ip,
        total_events=total,
        first_seen=_agg_datetime(aggs.get("first_seen")),
        last_seen=_agg_datetime(aggs.get("last_seen")),
        resp_ports=_bucket_pairs(responder.get("ports")),
        orig_ports=_bucket_pairs(originator.get("ports")),
        resp_peer_count=_cardinality(responder.get("peers")),
        orig_peer_count=_cardinality(originator.get("peers")),
        resp_hours=len((responder.get("hours") or {}).get("buckets") or []),
        services=_bucket_pairs(responder.get("services")),
        datasets=_bucket_pairs(aggs.get("datasets")),
        hour_of_day=_fold_hour_of_day(aggs.get("activity")),
        orig_bytes_p50=_percentile(originator.get("bytes"), 50),
        orig_bytes_p95=_percentile(originator.get("bytes"), 95),
        resp_bytes_p50=_percentile(responder.get("bytes"), 50),
        resp_bytes_p95=_percentile(responder.get("bytes"), 95),
        registered_domains=_bucket_pairs(aggs.get("reg_domains")),
        dns_queries=_bucket_pairs(aggs.get("dns_queries")),
        sni=_bucket_pairs(aggs.get("sni")),
        ja3_distinct=_cardinality(originator.get("ja3")),
        user_agents=identity.user_agents,
        dhcp=identity.dhcp,
        ssh_banners=identity.ssh_banners,
        windows_identity=identity.windows_identity,
        software=identity.software,
        host_names=identity.host_names,
        ptr_name=identity.ptr_name,
        available_datasets=available,
        agent_report=agent_report,
        agent_ip_claimants=agent_claimants,
        dns_name=dns.name,
        dns_name_evidence=dns.evidence,
        dns_name_withheld=dns.withheld,
        dns_name_observed_at=dns.observed_at,
        errors=tuple(errors),
    )


# ---------------------------------------------------------------------------
# The network agent inventory — one aggregation for every self-reporting machine
# ---------------------------------------------------------------------------


async def collect_agent_inventory(
    *,
    elastic: ElasticClient,
    settings: Settings,
    window_hours: int,
    time_anchor: datetime | None = None,
) -> AgentInventory:
    """Every machine shipping host logs, and the addresses each one claims.

    ONE ``size=0`` aggregation for the whole network, run once per sweep rather
    than once per host: the answer does not vary by address, and the per-host
    version would cost an extra aggregation for every dossier built.

    Shape: a ``host.name`` terms agg, each bucket carrying a ``host.ip`` terms
    agg (the claim list), min/max ``@timestamp`` (the reporting window), and a
    size-1 newest-first ``top_hits`` (the self-report). The identity fields come
    out of that ONE document on purpose — it is a coherent snapshot, so the name,
    the kernel and the agent version in it belong to the same moment, and none of
    those fields has to be provably aggregatable for the pass to work. (A
    ``terms`` agg on a text-mapped field 400s the whole search; that is what
    ``_run_main_pass`` carries a reduced-agg retry for.)

    Gated on the grid's own dataset inventory: when neither host-log dataset is
    present, this issues NO query and returns an empty inventory, so a
    network-only deployment pays nothing and behaves exactly as it did before
    the lane existed. An inventory that is empty because discovery FAILED is
    "unknown" rather than "absent" and the pass still runs — the same rule
    :func:`_present_datasets` applies to the identity searches, and for the same
    reason: an inventory outage must not be able to retract the network's names.

    Never raises. A failed aggregation returns an empty inventory carrying the
    reason, which the classifier reads as "no self-report" — an absence, not a
    retraction.
    """
    minutes = max(1, window_hours) * 60
    available = await _available_datasets(elastic, settings, minutes)
    present = _present_datasets(_HOSTLOG_DATASETS, available)
    if not present:
        _LOGGER.debug("dossier: no host-log datasets on this grid — hostlog lane is idle")
        return AgentInventory()

    query: dict[str, Any] = {
        "bool": {
            "filter": [
                _build_time_filter(minutes, time_anchor),
                {"terms": {"event.dataset": list(present)}},
            ],
            # Same kill-switch as every other dossier query: a synthetic-eval
            # fixture that reached an asset record would be durable,
            # prompt-injected context about a real machine.
            "must_not": [{"exists": {"field": "synth.scenario_id"}}],
        }
    }
    try:
        result = await elastic.search(
            settings.events_index_pattern, query, size=0, aggs=_agent_aggs()
        )
    except Exception as exc:
        _LOGGER.warning("dossier: agent inventory failed: %s", exc)
        return AgentInventory(errors=(f"agent inventory failed: {exc}",))

    buckets = ((result.aggregations or {}).get("hosts") or {}).get("buckets") or []
    reports = [report for bucket in buckets if (report := _agent_report(bucket)) is not None]
    return AgentInventory.from_reports(reports)


def _agent_aggs() -> dict[str, Any]:
    return {
        "hosts": {
            "terms": {"field": "host.name", "size": _AGENT_HOST_AGG_SIZE},
            "aggs": {
                "ips": {"terms": {"field": "host.ip", "size": _AGENT_IP_AGG_SIZE}},
                # The reporting window, not the build time: an agent-only host
                # takes its dossier lifetime from these.
                "first_report": {"min": {"field": "@timestamp"}},
                "last_report": {"max": {"field": "@timestamp"}},
                "latest": {
                    "top_hits": {
                        "size": 1,
                        "sort": _NEWEST_FIRST,
                        "_source": list(_AGENT_READS),
                    }
                },
            },
        }
    }


def _agent_report(bucket: Mapping[str, Any]) -> AgentSelfReport | None:
    """One ``host.name`` bucket → the machine's newest self-report.

    A bucket whose key is not a usable name is dropped rather than raised on:
    the network-wide pass sees whatever the grid happens to hold.
    """
    name = _first_str(bucket.get("key"))
    if not name:
        return None
    hits = ((bucket.get("latest") or {}).get("hits") or {}).get("hits") or []
    source: Mapping[str, Any] = (hits[0].get("_source") or {}) if hits else {}
    os_struct = {
        key: text
        for key in _AGENT_OS_KEYS
        if (text := _first_str(get_dotted(source, f"host.os.{key}"))) is not None
    }
    return AgentSelfReport(
        host_name=name,
        os=os_struct,
        macs=_ordered_unique(_as_list(get_dotted(source, "host.mac"))),
        architecture=_first_str(get_dotted(source, "host.architecture")),
        agent_type=_first_str(get_dotted(source, "agent.type")),
        agent_version=_first_str(get_dotted(source, "agent.version")),
        # The claim list comes from the terms agg, not from the newest document:
        # an address the machine held earlier in the window is still a claim, and
        # counting it can only make the contention test stricter.
        ips=_ordered_unique(b.get("key") for b in (bucket.get("ips") or {}).get("buckets") or ()),
        doc_count=int(bucket.get("doc_count") or 0),
        first_report=_agg_datetime(bucket.get("first_report")),
        last_report=_agg_datetime(bucket.get("last_report")),
    )


def _as_list(value: Any) -> list[Any]:
    """An ES field that may be scalar or array, always as a list."""
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


# ---------------------------------------------------------------------------
# The network DNS-name inventory — one aggregation for every name the net resolved
# ---------------------------------------------------------------------------


async def collect_dns_names(
    *,
    elastic: ElasticClient,
    settings: Settings,
    window_hours: int,
    cidrs: Sequence[Any] = (),
    time_anchor: datetime | None = None,
) -> DnsNameInventory:
    """What the network's own DNS answers call each internal address.

    ONE ``size=0`` aggregation for the whole network, run once per sweep beside
    :func:`collect_agent_inventory` and for the same reason: the answer does not
    vary by address, so a per-host version would cost an extra aggregation per
    dossier for an identical result.

    Shape: a terms agg over the QUERY name (``dns.query.name`` — the name that
    was asked for; the ANSWER is ``dns.resolved_ip``), each bucket carrying a
    terms agg over the addresses that name resolved to, each of those carrying
    min/max ``@timestamp``. One (name, address) bucket is one
    :class:`~soc_ai.dossier.types.DnsNameClaim`, and the majority rule that turns
    a pile of claims into a name lives in
    :class:`~soc_ai.dossier.types.DnsNameInventory` — nothing is concluded here.

    The lane exists because the ``hostlog`` rung only names machines that run a
    log agent. On the network this was built against that was 13 of them, against
    ~134 dossier rows, and the operator's complaint was that hostname was blank
    almost everywhere. DHCP could not help — the server does not log its leases —
    but ``zeek.dns`` carried ~38,000 answer documents every 6 hours, and 553
    distinct names pointing INSIDE the network over a 14-day window.

    Args:
        elastic: client for the SO ES cluster.
        settings: app settings (uses ``events_index_pattern``).
        window_hours: lookback width, the sweep's own dossier window.
        cidrs: the operator's definition of "internal", the SAME list the network
            census scopes itself with. Empty means undefined, and the pass does
            not run at all: a name lane scoped to the whole internet would write
            CDN edge names into asset records.
        time_anchor: anchor the window here instead of now, so a build over a
            historical window concludes what was true then.

    Returns:
        A :class:`DnsNameInventory`. Never raises — a failed or truncated pass
        comes back empty (or short) with the reason in ``errors``, which the
        classifier reads as an absence of evidence rather than a retraction.
    """
    if not cidrs:
        _LOGGER.debug("dossier: no internal CIDRs — the DNS name lane cannot be scoped")
        return DnsNameInventory()
    nets = list(cidrs)

    minutes = max(1, window_hours) * 60
    available = await _available_datasets(elastic, settings, minutes)
    present = _present_datasets(_DNS_DATASETS, available)
    if not present:
        _LOGGER.debug("dossier: no DNS dataset on this grid — the name lane is idle")
        return DnsNameInventory()

    index = settings.events_index_pattern
    # Both dual-mapped, and both silent when guessed wrong: a `terms` agg on the
    # spelling this grid does not populate returns zero buckets, not an error,
    # and the whole network would read as "DNS names nothing".
    name_field = await fields.resolve_agg_field(elastic, index, fields.DNS_QUERY)
    answer_field = await fields.resolve_agg_field(elastic, index, fields.DNS_RESOLVED_IP)

    query: dict[str, Any] = {
        "bool": {
            "filter": [
                _build_time_filter(minutes, time_anchor),
                {"terms": {"event.dataset": list(present)}},
                _internal_answer_clause(answer_field, nets),
            ],
            # The same kill-switch as every other dossier query: a synthetic-eval
            # fixture that reached an asset record would be durable,
            # prompt-injected context about a real machine.
            "must_not": [{"exists": {"field": "synth.scenario_id"}}],
        }
    }
    try:
        result = await elastic.search(
            index, query, size=0, aggs=_dns_aggs(name_field, answer_field)
        )
    except Exception as exc:
        _LOGGER.warning("dossier: DNS name pass failed: %s", exc)
        return DnsNameInventory(errors=(f"DNS name pass failed: {exc}",))

    return _dns_inventory(
        (result.aggregations or {}).get("names") or {},
        nets,
        narrowed=answer_field in _IP_TYPED_ANSWER_FIELDS,
    )


def _internal_answer_clause(field: str, nets: list[Any]) -> dict[str, Any]:
    """Narrow the pass to answers pointing INTO the network, where the field can.

    ECS types ``dns.resolved_ip`` as ``ip``, so a CIDR is a matchable term on it
    and the public half of the grid's DNS traffic never enters the aggregation at
    all. That is the difference between 553 name buckets and 4,221 on the network
    this was measured against — and terms fall off the end of ``size`` by DOC
    COUNT, so an un-narrowed pass drops the LEAST-queried names first. Those are
    the quiet printer and the appliance nobody has context for, which is exactly
    what this lane exists to name.

    The legacy spelling (``zeek.dns.answers``) is a KEYWORD holding raw answer
    strings, where a CIDR matches nothing whatsoever and does so silently. That
    grid gets the wide pass instead: :func:`_dns_claim` applies the same gate
    client-side, and it is the authority either way.
    """
    if field in _IP_TYPED_ANSWER_FIELDS:
        return {"terms": {field: [str(net) for net in nets]}}
    return {"exists": {"field": field}}


def _dns_aggs(name_field: str, answer_field: str) -> dict[str, Any]:
    return {
        "names": {
            "terms": {"field": name_field, "size": _DNS_NAME_AGG_SIZE},
            "aggs": {
                "ips": {
                    "terms": {"field": answer_field, "size": _DNS_ANSWER_AGG_SIZE},
                    "aggs": {
                        # The span of answers, not the build clock: a DNS-only
                        # host takes its census lifetime and its Fact timestamp
                        # from these two.
                        "first_answer": {"min": {"field": "@timestamp"}},
                        "last_answer": {"max": {"field": "@timestamp"}},
                    },
                }
            },
        }
    }


def _dns_inventory(agg: Mapping[str, Any], nets: list[Any], *, narrowed: bool) -> DnsNameInventory:
    """Fold the query-name buckets into claims, internal answers only.

    Names are NOT folded here: :class:`DnsNameClaim` normalises its own address
    and name on construction, so a hand-built inventory and a collected one
    behave identically.
    """
    claims: list[DnsNameClaim] = []
    dropped_answers = 0
    for bucket in agg.get("buckets") or []:
        answers = (bucket.get("ips") or {}).get("buckets") or []
        # Accounted for BEFORE the name is judged: a bucket this collector cannot
        # use still had addresses fall off the end of its inner agg, and skipping
        # the tally with the bucket is how "both caps have to account for it"
        # quietly stops being true.
        dropped_answers += int((bucket.get("ips") or {}).get("sum_other_doc_count") or 0)
        name = _first_str(bucket.get("key"))
        if not name:
            continue
        for answer in answers:
            claim = _dns_claim(name, answer, nets)
            if claim is not None:
                claims.append(claim)
    return DnsNameInventory(
        claims=tuple(claims),
        # Truncation is a NOTE, not a failure: a hit cap is a healthy-but-capped
        # pass, and folding it into `errors` made every sweep report an error
        # count. `errors` stays for a pass that actually broke.
        notes=_dns_truncation(agg, dropped_answers, narrowed=narrowed),
    )


def _dns_claim(name: str, bucket: Mapping[str, Any], nets: list[Any]) -> DnsNameClaim | None:
    """One (name, answer address) bucket → a claim, or ``None`` for an outside answer.

    Two gates, both narrowing: :func:`identity_bearing_ip` drops what cannot name
    a machine however often it is answered (a sinkhole's ``0.0.0.0``, loopback,
    link-local), and ``_is_internal_ip`` drops everything outside the operator's
    own definition of the network. The second is the census's gate verbatim — two
    jobs disagreeing about which addresses are ours is how one of them ends up
    describing the internet.
    """
    # Lazy: `discovery` pulls in the identifier store and its own ES helpers, and
    # this import exists only to keep the two jobs' "is this address ours" answer
    # literally the same function. `soc_ai.dossier` sits BELOW `soc_ai.enrichment`
    # — importing upward at module scope drags the store into every importer of
    # the collector, and `infer` keeps the same import lazy for the same reason.
    from soc_ai.enrichment.discovery import _is_internal_ip  # noqa: PLC0415

    ip = identity_bearing_ip(bucket.get("key"))
    if ip is None or not _is_internal_ip(ip, nets):
        return None
    return DnsNameClaim(
        ip=ip,
        name=name,
        answers=int(bucket.get("doc_count") or 0),
        first_answer=_agg_datetime(bucket.get("first_answer")),
        last_answer=_agg_datetime(bucket.get("last_answer")),
    )


def _dns_truncation(
    agg: Mapping[str, Any], dropped_answers: int, *, narrowed: bool
) -> tuple[str, ...]:
    """Say so when either cap hit its limit instead of dropping addresses quietly.

    ``sum_other_doc_count`` is Elasticsearch's only signal that terms fell off
    the end of ``size``, and they fall off by doc count — so what goes is the
    least-answered ones. A short result is indistinguishable from an address DNS
    never named, and the sweep records both of these on the run row where an
    operator can see the ceiling rather than trust a quietly incomplete inventory.

    The inner cap matters most on the LEGACY answer field, where the pass cannot
    be narrowed to internal answers server-side (see
    :func:`_internal_answer_clause`): a name whose public answers fill the top
    ``_DNS_ANSWER_AGG_SIZE`` buckets pushes its internal one out of the result
    entirely, and the host it would have named just never appears.
    """
    notes: list[str] = []
    dropped_names = int(agg.get("sum_other_doc_count") or 0)
    if dropped_names:
        # On the WIDE pass the count includes every public name the network
        # resolved — 4,221 against a 2,000 cap on the grid this was measured on —
        # so it overflows every sweep whether or not anything internal was lost.
        # A run-row warning that is always on stops being read, so the wide path
        # says what it actually knows instead of claiming an impact it cannot see.
        notes.append(
            f"the DNS name pass truncated at {_DNS_NAME_AGG_SIZE} name buckets "
            f"({dropped_names} answer(s) in names that did not fit); the names "
            "dropped are the least-queried ones"
            if narrowed
            else f"the DNS name pass ran wide (this grid's answer field cannot be "
            f"narrowed to internal answers) and truncated at {_DNS_NAME_AGG_SIZE} "
            f"name buckets; {dropped_names} answer(s) did not fit, mostly public "
            "names — internal impact unknown"
        )
    if dropped_answers:
        notes.append(
            f"the DNS name pass truncated at {_DNS_ANSWER_AGG_SIZE} addresses per "
            f"name ({dropped_answers} answer(s) in addresses that did not fit); "
            "an internal address can be crowded out by a name's public answers"
        )
    return tuple(notes)


# ---------------------------------------------------------------------------
# Field + dataset resolution
# ---------------------------------------------------------------------------


async def _resolve_agg_fields(elastic: ElasticClient, index: str) -> _AggFields:
    """Resolve every dual-mapped aggregation field for this deployment.

    ``resolve_agg_field`` never raises and caches per (index, candidates), so
    this costs at most seven exists-probes per TTL for the whole network sweep.
    """
    return _AggFields(
        service=await fields.resolve_agg_field(elastic, index, fields.CONN_SERVICE),
        resp_bytes=await fields.resolve_agg_field(elastic, index, fields.CONN_RESP_BYTES),
        orig_bytes=await fields.resolve_agg_field(elastic, index, fields.CONN_ORIG_BYTES),
        ja3=await fields.resolve_agg_field(elastic, index, fields.SSL_JA3),
        reg_domain=await fields.resolve_agg_field(elastic, index, fields.DNS_REGISTERED_DOMAIN),
        dns_query=await fields.resolve_agg_field(elastic, index, fields.DNS_QUERY),
        sni=await fields.resolve_agg_field(elastic, index, fields.SSL_SNI),
    )


async def _available_datasets(
    elastic: ElasticClient, settings: Settings, minutes: int
) -> frozenset[str]:
    """The ``event.dataset`` values this grid carries over the dossier window.

    Uses the dossier's own window rather than the inventory's 24h default: a
    dataset that last appeared four days ago is present on this grid, and
    gating a 14-day build on a 24h inventory would skip it.
    """
    try:
        inv = await inventory.discover_datasets(elastic, settings, window_minutes=minutes)
    except Exception as exc:  # pragma: no cover - discover_datasets swallows its own
        _LOGGER.warning("dossier dataset inventory failed: %s", exc)
        return frozenset()
    return frozenset(inv.dataset_names())


def _present_datasets(datasets: Sequence[str], available: frozenset[str]) -> tuple[str, ...]:
    """Narrow ``datasets`` to those the grid carries; all of them when unknown.

    An EMPTY inventory is "unknown", not "nothing": a discovery failure that
    silently skipped every identity search would retract the hostname of every
    host in the network on one bad sweep.
    """
    if not available:
        return tuple(datasets)
    return tuple(d for d in datasets if d in available)


# ---------------------------------------------------------------------------
# Query 1 — the multi-agg pass
# ---------------------------------------------------------------------------


def _build_aggs(ip: str, f: _AggFields, *, optional: bool = True) -> dict[str, Any]:
    """The multi-agg body. ``optional=False`` is the reduced-agg retry.

    The optional half (services, byte percentiles, JA3 cardinality, and the
    domain/name terms aggs) is everything that aggregates a field whose mapping
    we cannot prove is aggregatable. The mandatory half — ports, peers, hours,
    datasets, first/last seen, the hourly activity histogram — is canonical ECS
    and is what every role rule reads, so it must survive the retry.
    """
    responder_aggs: dict[str, Any] = {
        "ports": {"terms": {"field": "destination.port", "size": _PORT_AGG_SIZE}},
        "peers": {"cardinality": {"field": "source.ip"}},
        "hours": {
            "date_histogram": {
                "field": "@timestamp",
                "calendar_interval": "hour",
                "min_doc_count": 1,
            }
        },
    }
    originator_aggs: dict[str, Any] = {
        "ports": {"terms": {"field": "destination.port", "size": _PORT_AGG_SIZE}},
        "peers": {"cardinality": {"field": "destination.ip"}},
    }
    if optional:
        responder_aggs["services"] = {"terms": {"field": f.service, "size": _SERVICE_AGG_SIZE}}
        responder_aggs["bytes"] = {"percentiles": {"field": f.resp_bytes, "percents": [50, 95]}}
        originator_aggs["bytes"] = {"percentiles": {"field": f.orig_bytes, "percents": [50, 95]}}
        originator_aggs["ja3"] = {"cardinality": {"field": f.ja3}}

    aggs: dict[str, Any] = {
        "first_seen": {"min": {"field": "@timestamp"}},
        "last_seen": {"max": {"field": "@timestamp"}},
        "datasets": {"terms": {"field": "event.dataset", "size": _DATASET_AGG_SIZE}},
        # Direction matters more than anything else here: a port this host
        # ANSWERS on is a service it offers; the same port outbound is a service
        # it consumes. Restricted to zeek.conn because a Suricata alert doc also
        # carries destination.port and would inflate "ports this host serves".
        "responder": {
            "filter": {
                "bool": {
                    "must": [
                        {"term": {"destination.ip": ip}},
                        {"term": {"event.dataset": "zeek.conn"}},
                    ]
                }
            },
            "aggs": responder_aggs,
        },
        "originator": {
            "filter": {
                "bool": {
                    "must": [
                        {"term": {"source.ip": ip}},
                        {"term": {"event.dataset": "zeek.conn"}},
                    ]
                }
            },
            "aggs": originator_aggs,
        },
        # Hour-of-day is folded from this client-side: scripting is disabled on
        # hardened grids, so no painless hour-extraction agg.
        "activity": {
            "date_histogram": {
                "field": "@timestamp",
                "calendar_interval": "hour",
                "min_doc_count": 1,
            }
        },
    }
    if optional:
        aggs["reg_domains"] = {"terms": {"field": f.reg_domain, "size": _DOMAIN_AGG_SIZE}}
        aggs["dns_queries"] = {"terms": {"field": f.dns_query, "size": _NAME_AGG_SIZE}}
        aggs["sni"] = {"terms": {"field": f.sni, "size": _NAME_AGG_SIZE}}
    return aggs


async def _run_main_pass(
    elastic: ElasticClient,
    index: str,
    *,
    ip: str,
    minutes: int,
    anchor: datetime | None,
    f: _AggFields,
    errors: list[str],
) -> tuple[int, dict[str, Any]]:
    """Run the multi-agg pass, retrying ONCE with the optional aggs stripped.

    Returns ``(total_events, aggregations)``; ``(0, {})`` when both attempts
    fail. The retry exists because a ``terms`` agg on a text-mapped field 400s
    the entire search: ``resolve_agg_field``'s exists-probe proves the field has
    data, not that the mapping allows aggregating it.
    """
    for optional in (True, False):
        try:
            result = await elastic.search(
                index,
                _base_host_query(ip, minutes, anchor),
                size=0,
                aggs=_build_aggs(ip, f, optional=optional),
                track_total_hits=True,
            )
        except Exception as exc:
            if optional:
                errors.append(f"reduced-agg fallback: {exc}")
                continue
            errors.append(f"multi-agg pass failed: {exc}")
            return 0, {}
        return result.total, result.aggregations or {}
    return 0, {}


# ---------------------------------------------------------------------------
# Queries 2-7 — targeted identity searches
# ---------------------------------------------------------------------------


async def _collect_identity(
    elastic: ElasticClient,
    index: str,
    *,
    ip: str,
    minutes: int,
    anchor: datetime | None,
    available: frozenset[str],
    dns_query_field: str,
    errors: list[str],
) -> _Identity:
    """The six identity searches, each skipped when its datasets are absent."""

    async def _search(datasets: Sequence[str], reads: _Reads) -> tuple[dict[str, Any], ...]:
        present = _present_datasets(datasets, available)
        if not present:
            _LOGGER.debug("dossier: skipping %s for %s — not on this grid", datasets, ip)
            return ()
        return await _search_records(
            elastic,
            index,
            ip=ip,
            query=_dataset_query(ip, minutes, anchor, present),
            reads=reads,
            label="/".join(present),
            errors=errors,
        )

    dhcp = await _search(_DHCP_DATASETS, _DHCP_READS)
    ssh_banners = await _search(_SSH_DATASETS, _SSH_READS)
    windows_identity = await _search(_WINDOWS_DATASETS, _WINDOWS_READS)
    software = await _search(_SOFTWARE_DATASETS, _SOFTWARE_READS)
    endpoint = await _search(_ENDPOINT_DATASETS, _ENDPOINT_READS)
    ptr_name = await _resolve_ptr_name(
        elastic,
        index,
        ip=ip,
        minutes=minutes,
        anchor=anchor,
        dns_query_field=dns_query_field,
        errors=errors,
    )
    return _Identity(
        dhcp=dhcp,
        ssh_banners=ssh_banners,
        windows_identity=windows_identity,
        software=software,
        # HTTP/TLS records are flattened to the two strings the classifier
        # reads; HostObservations has no slot for the records themselves, so a
        # MAC seen only on an HTTP document does not survive this step.
        user_agents=_ordered_unique(r.get("user_agent") for r in endpoint),
        host_names=_ordered_unique(r.get("host_name") for r in endpoint),
        ptr_name=ptr_name,
    )


def _dataset_query(
    ip: str, minutes: int, anchor: datetime | None, datasets: Sequence[str]
) -> dict[str, Any]:
    """``_base_host_query`` plus a dataset filter.

    The base is imported verbatim from ``host_summary``: it is the one place
    that gets the either-endpoint predicate AND the synthetic-eval kill-switch
    (``must_not exists synth.scenario_id``) right, and a synth fixture leaking
    into an asset record would be a durable, prompt-injected lie.
    """
    query = _base_host_query(ip, minutes, anchor)
    clause: dict[str, Any] = (
        {"term": {"event.dataset": datasets[0]}}
        if len(datasets) == 1
        else {"terms": {"event.dataset": list(datasets)}}
    )
    query["bool"]["must"].append(clause)
    return query


async def _search_records(
    elastic: ElasticClient,
    index: str,
    *,
    ip: str,
    query: dict[str, Any],
    reads: _Reads,
    label: str,
    errors: list[str],
) -> tuple[dict[str, Any], ...]:
    """Run one targeted search and normalise its hits into identity records."""
    try:
        result = await elastic.search(
            index,
            query,
            size=_SAMPLE_SIZE,
            sort=_NEWEST_FIRST,
            source=_projection(reads),
        )
    except Exception as exc:
        errors.append(f"{label} search failed: {exc}")
        return ()
    return tuple(_record(hit.get("_source") or {}, reads, ip=ip) for hit in result.hits)


async def _resolve_ptr_name(
    elastic: ElasticClient,
    index: str,
    *,
    ip: str,
    minutes: int,
    anchor: datetime | None,
    dns_query_field: str,
    errors: list[str],
) -> str | None:
    """The newest reverse-DNS name for ``ip``, or ``None``.

    Deliberately host-filter-free: a PTR lookup is made BY A RESOLVER, so the
    host under investigation is neither endpoint of the DNS packet. The query
    is an exact ``term`` on the reverse zone, so it stays cheap. An answer that
    is itself an IP is rejected — that is a mapping artefact, not a name.
    """
    zone = reverse_zone(ip)
    if zone is None:
        return None
    query: dict[str, Any] = {
        "bool": {
            "must": [{"term": {dns_query_field: zone}}],
            "filter": [_build_time_filter(minutes, anchor)],
            "must_not": [{"exists": {"field": "synth.scenario_id"}}],
        }
    }
    try:
        result = await elastic.search(
            index,
            query,
            size=_SAMPLE_SIZE,
            sort=_NEWEST_FIRST,
            source=_projection(_PTR_READS),
        )
    except Exception as exc:
        errors.append(f"PTR search failed: {exc}")
        return None
    for hit in result.hits:
        answer = _first_str(first_present(hit.get("_source") or {}, fields.DNS_RESOLVED_IP))
        if answer and not _looks_like_ip(answer):
            return answer.rstrip(".")
    return None


def _projection(reads: _Reads) -> list[str]:
    """``_source`` projection: the envelope plus every candidate name.

    Ordered-unique so the request is stable across calls (and readable in a
    slow-query log).
    """
    projected: dict[str, None] = dict.fromkeys(_ENVELOPE)
    for _key, candidates in reads:
        for candidate in candidates:
            projected.setdefault(candidate, None)
    return list(projected)


def _record(source: Mapping[str, Any], reads: _Reads, *, ip: str) -> dict[str, Any]:
    """One identity record: the envelope, plus whichever reads resolved.

    The envelope keys (``timestamp`` / ``dataset`` / ``source_ip`` /
    ``destination_ip``) are ALWAYS present — the classifier needs the direction
    to attribute a banner to the right end of the connection — while a read that
    found nothing is simply absent, so ``record.get("mac")`` is the only access
    pattern a caller needs.
    """
    record: dict[str, Any] = {
        "timestamp": _parse_ts(get_dotted(source, "@timestamp")),
        "dataset": _first_str(get_dotted(source, "event.dataset")),
        "source_ip": _first_str(get_dotted(source, "source.ip")),
        "destination_ip": _first_str(get_dotted(source, "destination.ip")),
    }
    for key, candidates in reads:
        value = _scalar(first_present(source, candidates))
        if value is not None and value != "":
            record[key] = value
    if "mac" not in record:
        mac = _directional_mac(source, ip)
        if mac:
            record["mac"] = mac
    return record


def _directional_mac(source: Mapping[str, Any], ip: str) -> str | None:
    """This host's own hardware address from a document — never its peer's.

    ``source.mac`` / ``destination.mac`` are per-ENDPOINT fields. Coalescing
    them blindly (as the flat ``HOST_MAC`` candidate order would) stamps the
    peer's address onto this host every time the host sits on the other side of
    the connection, which is a silently wrong identity field — the exact failure
    class the dossier exists to remove. So the endpoint field belonging to the
    OTHER end is dropped before coalescing, leaving per-document ``host.mac``
    (an endpoint agent's own report) as the fallback.
    """
    excluded: set[str] = set()
    if _first_str(get_dotted(source, "source.ip")) != ip:
        excluded.add("source.mac")
    if _first_str(get_dotted(source, "destination.ip")) != ip:
        excluded.add("destination.mac")
    candidates = tuple(c for c in fields.HOST_MAC if c not in excluded)
    return _first_str(_scalar(first_present(source, candidates)))


# ---------------------------------------------------------------------------
# Value normalisation
# ---------------------------------------------------------------------------


def _scalar(value: Any) -> Any:
    """Collapse a multi-valued ES field to its first element."""
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _ordered_unique(values: Iterable[Any]) -> tuple[str, ...]:
    """Non-empty strings, de-duplicated, order preserved (so: newest-first)."""
    seen: dict[str, None] = {}
    for value in values:
        text = _first_str(value)
        if text:
            seen.setdefault(text, None)
    return tuple(seen)


def _parse_ts(value: Any) -> datetime | None:
    """Coerce an ES timestamp (ISO string, epoch-millis, datetime) to UTC-aware.

    Naive values are assumed UTC — every timestamp in the events index is, and a
    naive datetime compared against an aware one raises, which would turn a
    cosmetic mapping quirk into a failed build.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value / 1000.0, UTC)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


def _agg_datetime(agg: dict[str, Any] | None) -> datetime | None:
    """Read a min/max date aggregation as a datetime.

    Prefers ``value_as_string`` (via ``host_summary._agg_time``) and falls back
    to the raw epoch-millis ``value`` for a grid that returns no formatted form.
    """
    parsed = _parse_ts(_agg_time(agg))
    if parsed is not None:
        return parsed
    return _parse_ts((agg or {}).get("value"))


def _cardinality(agg: dict[str, Any] | None) -> int:
    """Read a cardinality aggregation's value (0 when the agg is absent)."""
    value = (agg or {}).get("value")
    return int(value) if isinstance(value, (int, float)) else 0


def _percentile(agg: dict[str, Any] | None, percent: int) -> float | None:
    """Read one percentile out of a percentiles aggregation.

    ES keys the map ``"50.0"``; some versions key it ``"50"``. An empty bucket
    yields ``null`` (or NaN), which is ``None`` here — a host with no byte
    volume must not report a p50 of zero.
    """
    values = (agg or {}).get("values") or {}
    for key in (f"{percent}.0", str(percent)):
        if key in values:
            value = values[key]
            if isinstance(value, (int, float)) and not math.isnan(value):
                return float(value)
            return None
    return None


def _fold_hour_of_day(agg: dict[str, Any] | None) -> dict[int, int]:
    """Fold an hourly date_histogram into 0..23 -> event count.

    Client-side because scripting is disabled on hardened grids, so the obvious
    ``script`` / ``runtime_mappings`` hour extraction is not available.
    """
    hours: dict[int, int] = {}
    for bucket in (agg or {}).get("buckets") or []:
        key = bucket.get("key")
        if not isinstance(key, (int, float)):
            continue
        hour = datetime.fromtimestamp(key / 1000.0, UTC).hour
        hours[hour] = hours.get(hour, 0) + int(bucket.get("doc_count") or 0)
    return hours


__all__ = [
    "collect_agent_inventory",
    "collect_dns_names",
    "collect_host_observations",
    "reverse_zone",
]
