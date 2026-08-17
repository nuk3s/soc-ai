"""The pure host-dossier classifier: one window of observations → what the host IS.

Rules, not a model. :func:`infer_host_facts` takes a
:class:`~soc_ai.dossier.types.HostObservations` and returns one
:class:`~soc_ai.dossier.types.Fact` per inferable field. It touches no
Elasticsearch, no database, no LLM and — deliberately — no clock: every
timestamp it emits comes out of the observation set, so a build over a
historical window concludes what was true *then* rather than looking freshly
confirmed forever. That purity is what makes the whole role table testable from
a hand-built observation set instead of a live grid.

The two behaviours this module exists to fix, both from ``host_summary``:

**Role is a port SET, never a single hit.** ``_guess_role`` promotes a host to
"server" the moment one inbound connection lands on a well-known port, so a
laptop that accepted a single SSH session is filed as a server. Here a port only
counts once it has been ANSWERED at least twice — zeek.conn writes a record for
a connection attempt, so counting records alone lets a port scan hand the host
any role its ports imply — and the confident verdicts additionally require
multiple peers across multiple hours *on the ports that matched the row*, never
on whatever else the host happens to be busy with. The rows are ordered
most-specific-first because the specific evidence is otherwise swallowed: a
hypervisor also answers 22 and 443, and a domain controller also answers 445.
The motivating case is a Proxmox host at ``192.168.10.202`` that soc-ai
treated as "an internal host" while attributing SSH probing to it — it answers
on tcp/8006 and tcp/8007 and the dossier has to say so.

**Provenance is source-major, and the loser is kept.** ``_resolve_hostname``
loops documents first and sources second, so whichever document happened to sort
first decides the name. Here every signal in the window is collected per source,
the ladder (``osquery > hostlog > banner > telemetry > behaviour``) picks the
value among the candidates the resolver would actually show (see
:func:`_rank_candidates`), and the weaker signals stay in the Fact's evidence. A family-level
disagreement — the SSH banner says Linux, the User-Agent says Windows — becomes
an explicit ``conflict`` string naming both sides, because a dossier that
silently dropped one is hiding the case most worth reading.

**The machine's own account of itself wins, when it is unambiguously its.** The
``hostlog`` rung is what an agent running ON the host reported — its name, its
OS struct, its hardware addresses — and it outranks every wire signal because
nothing observed from outside beats a machine naming itself. It is attributed
by the unique-claim rule in
:class:`~soc_ai.dossier.types.AgentInventory`, so an address several agents
report (a container bridge gateway) resolves to NO identity here: the
observation carries the claimant list instead, and the absence is explained
rather than left looking like a host that never reported.

**What the network CALLS a host is worth saying when nothing else names it.**
Most machines run no log agent and announce nothing on the wire, so the rungs
above ``telemetry`` are silent for them and the hostname was simply blank. The
network's own DNS answers are not: a name a strict majority of the window's
answers pointed at an address is emitted at the ``telemetry`` rung, under
everything first-party. It is ``strong`` inside that rung — a majority over
hundreds of answers is not a guess, and an address whose names disagreed was
withheld by :class:`~soc_ai.dossier.types.DnsNameInventory` before it got here —
but it never displaces a name the machine gave for itself.

``criticality`` and ``policy_notes`` are never inferred: no Fact is emitted for
them at all. They are where a deployment's own policy lives ("no interactive
SSH; API-token access only"), which no amount of telemetry can derive.

Fields that were evaluated and produced nothing still return a Fact, with
``strength="none"`` and evidence saying why. That is not noise — it is what
refreshes the store's ``inferred_last_run_at`` and what lets a belief be
retracted when the evidence behind it goes away.
"""

from __future__ import annotations

import dataclasses
import math
import re
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime
from typing import Any

from soc_ai.dossier.resolve import DEFAULT_MIN_CONFIDENCE, below_confidence_floor
from soc_ai.dossier.types import (
    STRENGTH_CONFIDENCE,
    AgentSelfReport,
    Fact,
    HostObservations,
    ProvenanceSource,
    Strength,
    provenance_rank,
)
from soc_ai.tools.host_summary import (
    _first_str,
    _looks_like_ip,
    _os_label_to_family,
    _ua_label_to_family,
    classify_user_agent,
)
from soc_ai.tools.os_hint import os_hint_from_domains

# --- role port sets ---------------------------------------------------------
#
# Membership is what a role IS, not what it happens to serve. Each set is small
# and specific enough that a host answering it is that thing; the generic
# service ports live in `_GENERAL_SERVER` and are consulted last.
_HYPERVISOR: frozenset[int] = frozenset({8006, 8007, 902, 903, 5988, 5989, 16509})
# tcp/3128 is Proxmox's SPICE proxy — and Squid's default port, which is far more
# common. On its own it filed every forward proxy in the network as a hypervisor,
# at strong confidence, from the first row of the table where no later rule could
# correct it. It now only counts as corroboration for a genuine Proxmox port.
_HYPERVISOR_CORROBORATING: frozenset[int] = frozenset({3128})
_DC_CORE: frozenset[int] = frozenset({88, 389})
_DC_EXTRA: frozenset[int] = frozenset({636, 3268, 3269, 53, 445})
_SIEM_STRONG: frozenset[int] = frozenset({9200, 9300, 5601, 5044})
_SIEM_WEAK: frozenset[int] = frozenset({514, 6514, 3000, 4739, 8220})
_NETDEV_STRONG: frozenset[int] = frozenset({161, 179})
_NETDEV_WEAK: frozenset[int] = frozenset({162, 67, 69, 123})
_IOT_STRONG: frozenset[int] = frozenset({9100, 631, 515, 502})
_IOT_WEAK: frozenset[int] = frozenset({1900, 5353, 8009, 554, 1883, 8883, 8123})
_GENERAL_SERVER: frozenset[int] = frozenset(
    {21, 22, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 1433,
     3128, 3306, 3389, 5432, 5985, 5986, 6379, 8080, 8443, 27017}
)  # fmt: skip
# Outbound ports that mean "this host reached for a remote session". The
# activity profile records them so a later investigation can say "and it has
# never done this before" instead of "the host did X".
_REMOTE_ACCESS_OUT: frozenset[int] = frozenset({22, 23, 3389, 5900, 5985, 5986})
# Answering any of these is an administrative surface: the thing an attacker
# wants and the thing a policy note is usually written about.
_MANAGEMENT_PLANE: frozenset[int] = (
    _HYPERVISOR | _SIEM_STRONG | _NETDEV_STRONG | frozenset({22, 623, 3389, 5985, 5986})
)
# DCE-RPC endpoints only a domain controller answers (directory replication,
# netlogon, SAM and LSA remote access).
_DC_RPC_ENDPOINTS: frozenset[str] = frozenset({"drsuapi", "netlogon", "samr", "lsarpc"})

# The classifier's CLOSED role vocabulary — every value `_infer_role` can put on
# the `role` field. The first seven are the roles `_match_role` and its helpers
# return as bare string literals scattered through the rules; `unknown` is the
# fallback `_infer_role` supplies when no rule matches, when the match falls
# below the confidence floor, or when telemetry is under the event floor.
#
# It is a REAL constant precisely so it is not a twin: the frontend used to
# hand-mirror this list with only a comment linking it to `_match_role`, and the
# backend had no constant to mirror. Now the vocabulary lives here, the API
# exposes it on `/dossiers/summary`, and the host filter and declare datalist
# read it from the wire with the frontend list as a fallback. A test
# (`test_role_vocabulary_covers_every_match_role_literal`) asserts every role a
# `_match_role` branch returns is a member, so a new role rule that forgets to
# extend this fails loudly rather than shipping a value no surface can offer.
# Sorted so the wire order is stable.
ROLE_VOCABULARY: tuple[str, ...] = (
    "domain_controller",
    "hypervisor",
    "iot",
    "network_device",
    "security_appliance",
    "server",
    "unknown",
    "workstation",
)

# A port answered once is a stray packet — a scan hit, a misdirected retry, a
# single inbound session. Two answers is the floor for calling it a service.
_MIN_PORT_HITS = 2
# Below this share of the host's answered responder traffic, the port set that
# matched a role rule cannot claim the host's peer and hour spread as its own.
# Without it, three connections to tcp/8006 inside a window whose 12 peers and 24
# hours are all HTTPS earned a STRONG hypervisor verdict off traffic that had
# nothing to do with tcp/8006. The absolute floor is the other half of the same
# rule: a low-volume management port on a busy server is still a real service, so
# a set with this many answered connections stands on its own volume.
_MATCHED_SHARE_FLOOR = 0.05
_MATCHED_VOLUME_FLOOR = 100
# "Sustained" = seen from more than one peer, in more than one hour. This is the
# line between a service and an incident, and it is what separates a strong
# verdict from a weak one on every behavioural row.
_MIN_SUSTAINED_PEERS = 2
_MIN_SUSTAINED_HOURS = 2
# A general-purpose server serves several clients. Three is deliberately low —
# a lab file server has few — but it stops a two-host backup pair reading as one.
_MIN_SERVER_PEERS = 3
# A workstation is defined by breadth of outbound contact, not by what it serves.
_MIN_WORKSTATION_PEERS = 5
# An IoT device talks to its vendor and a controller, not to the internet at
# large; past this the narrow listening profile is not enough to call it one.
_MAX_IOT_PEERS = 20

# Ports are rendered as ``tcp/8006`` throughout, matching the dossier's evidence
# convention. The responder aggregation is a terms agg on ``destination.port``
# over ``zeek.conn`` and carries no transport breakdown, so the label is an
# assumption: a UDP-only responder (a DHCP server on 67) reads as ``tcp/67``.
# The role rules treat those ports as signals regardless of transport, so the
# classification is unaffected; only the rendering is imprecise.
_PROTO = "tcp"

# How many responder ports to record in `services_offered`.
_MAX_SERVICES = 20
# Hostnames shorter than this are parsing artifacts, not names.
_HOSTNAME_MIN_LEN = 3
# Raw signal strings (User-Agents especially) are long; a conflict string has to
# stay readable in a prompt block and a UI chip.
_MAX_SIGNAL_CHARS = 80

# SSH banner → OS, the strongest signal a headless Linux host emits. A banner
# like ``SSH-2.0-OpenSSH_9.6p1 Debian-3`` names the distribution outright on a
# machine with no User-Agent and no vendor DNS telemetry — the exact
# 192.168.10.202 case, and a signal `host_summary` never reads.
#
# Matching is plain case-insensitive substring: distribution names are
# distinctive, and word boundaries fail on the real banners (``\bWindows\b``
# does not match ``OpenSSH_for_Windows_8.1`` because ``_`` is a word character).
# Order matters — a Raspbian or Ubuntu banner also carries "Debian" lineage in
# some builds, so the specific distribution is tried first.
#
# A banner with no distribution token yields NOTHING. OpenSSH runs on Linux,
# BSD, macOS and Windows; concluding "linux" from a bare ``OpenSSH_9.6`` would
# be the os_hint module's BPFDoor mistake in a new place.
# --- the hostlog rung -------------------------------------------------------
#
# How an agent's self-report is named in evidence ("the concrete signal") as
# opposed to on the ladder ("hostlog", the rung).
_HOSTLOG_LABEL = "host-agent"

# --- the DNS-name lane ------------------------------------------------------
#
# How a DNS consensus is named in evidence, as opposed to on the ladder
# (`telemetry`, the rung it shares with a PTR answer and a proxy's host.name).
_DNS_LABEL = "dns"

# ECS `host.os` → the coarse family the REST of this module speaks (the
# vocabulary `_ua_label_to_family` / `_os_label_to_family` produce). Read from
# `os.type` first, then `os.platform`, then `os.family`.
#
# The order matters and the mapping is not the identity: ECS `host.os.family` is
# "debian" on a Debian-derived machine and "redhat" on a Fedora one, while every
# other source in this module says "linux". Publishing ECS's spelling at the
# hostlog rung would make the agent DISAGREE with the SSH banner on every Linux
# host in the network — a conflict string on each one, about nothing. An os.type
# this table does not know yields NO family (the lower rungs keep the field)
# rather than a made-up one.
_HOSTLOG_OS_FAMILY: dict[str, str] = {
    "linux": "linux",
    "windows": "windows",
    "macos": "apple",
    "darwin": "apple",
    "ios": "apple",
    "android": "android",
    "freebsd": "freebsd",
}
# In the order they are consulted; see above.
_HOSTLOG_OS_FAMILY_KEYS: tuple[str, ...] = ("type", "platform", "family")

_SSH_OS_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile("raspbian", re.IGNORECASE), "linux", "raspbian"),
    (re.compile("ubuntu", re.IGNORECASE), "linux", "ubuntu"),
    (re.compile("debian", re.IGNORECASE), "linux", "debian"),
    (re.compile("alpine", re.IGNORECASE), "linux", "alpine"),
    (re.compile(r"red\s*hat|rhel", re.IGNORECASE), "linux", "red hat"),
    (re.compile("centos", re.IGNORECASE), "linux", "centos"),
    (re.compile("suse", re.IGNORECASE), "linux", "suse"),
    (re.compile("freebsd", re.IGNORECASE), "freebsd", "freebsd"),
    (re.compile("windows", re.IGNORECASE), "windows", "windows"),
)


def infer_host_facts(
    obs: HostObservations, *, min_events: int, min_confidence: float = DEFAULT_MIN_CONFIDENCE
) -> dict[str, Fact]:
    """Classify one host from one window of observations.

    Args:
        obs: everything the collector gathered for this IP. Never mutated.
        min_events: the telemetry floor (``settings.dossier_min_events``).
            Below it the behavioural verdict is withheld — ``role`` comes back
            ``unknown`` and the address-assignment call is not made — while the
            identity signals, which are first-party announcements and stand on
            their own, are still emitted.
        min_confidence: the resolver's render floor
            (``settings.dossier_min_confidence``). Nothing is gated on it here —
            the resolver applies it at read time — but candidate SELECTION reads
            it, because a winner below the floor renders as unknown: a weak name
            on a high rung must not shadow a strong name on a lower rung that
            would actually show (see :func:`_rank_candidates`). The default
            mirrors the resolver's, so a caller that cannot supply the knob
            degrades to the documented behaviour rather than a different one.

    Returns:
        A dict keyed by :data:`~soc_ai.dossier.types.DOSSIER_FIELDS` name. Every
        inferable field is present, including the ones that produced nothing
        (``strength="none"``, evidence saying why) — the store needs those to
        refresh its per-field run stamp and to retract a value whose evidence
        has gone away. ``criticality`` and ``policy_notes`` are never present:
        they are operator-only by design.
    """
    ports = _responder_ports(obs)
    qualified = _qualified_ports(ports)
    facts: dict[str, Fact] = {}
    facts["hostname"] = _infer_hostname(obs, min_confidence=min_confidence)
    facts["mac"] = _infer_mac(obs)
    os_family, os_detail = _infer_os(obs)
    facts["os_family"] = os_family
    facts["os_detail"] = os_detail
    facts["role"] = _infer_role(obs, ports=ports, qualified=qualified, floor=min_events)
    facts["services_offered"] = _infer_services(obs, ports=ports)
    facts["management_plane"] = _infer_management_plane(obs, qualified=qualified, floor=min_events)
    facts["domain_membership"] = _infer_domain_membership(obs)
    facts["is_static_addressed"] = _infer_static_addressing(obs, floor=min_events)
    facts["activity_profile"] = _infer_activity_profile(obs, floor=min_events)
    return facts


# ---------------------------------------------------------------------------
# Fact construction
# ---------------------------------------------------------------------------


def _fact(
    field: str,
    *,
    strength: Strength,
    source: ProvenanceSource,
    evidence: list[str],
    value: str | None = None,
    value_json: Any | None = None,
    observed_at: datetime | None = None,
    conflict: str | None = None,
) -> Fact:
    """Build a Fact, deriving the confidence from the strength.

    Confidence is never passed in: the three discrete values in
    :data:`STRENGTH_CONFIDENCE` are the whole vocabulary, and a rule-based
    classifier that invented 0.73 would be claiming a precision it does not have.
    """
    return Fact(
        field=field,
        value=value,
        value_json=value_json,
        confidence=STRENGTH_CONFIDENCE[strength],
        strength=strength,
        source=source,
        evidence=evidence,
        observed_at=observed_at,
        conflict=conflict,
    )


def _evidence(value: str, source: str) -> str:
    """The house evidence convention, verbatim: ``"pve01 (from dhcp)"``."""
    return f"{value} (from {source})"


def _hostlog_evidence(value: str, report: AgentSelfReport) -> str:
    """The hostlog form: ``"blue (self-reported, filebeat 9.3.7, last 2026-08-08T…)"``.

    Says WHO reported and WHEN, because that is the whole difference between
    this rung and the ones below it: a name on the wire is what some packet
    claimed, and this is the machine's own account of itself, timestamped by its
    own agent. An analyst reading "self-reported" knows the answer came from
    inside the host, and the version is what tells them the agent is current.
    """
    bits = ["self-reported"]
    agent = " ".join(part for part in (report.agent_type, report.agent_version) if part)
    if agent:
        bits.append(agent)
    if report.last_report is not None:
        bits.append(f"last {report.last_report.isoformat()}")
    return f"{value} ({', '.join(bits)})"


def _dns_evidence(value: str, detail: str) -> str:
    """The DNS-consensus form: ``"ws-1.lab.internal (from dns, 40 answers …)"``.

    Carries the WEIGHT beside the name, because that is the only thing a DNS
    name has going for it: nobody vouched for it, a majority of the window's
    answers simply agreed. A reader deciding whether to trust it needs to know
    whether that majority was 214 answers or two.
    """
    return _evidence(value, f"dns, {detail}") if detail else _evidence(value, "dns")


def _withheld_dns_note(obs: HostObservations) -> str | None:
    """Why the DNS lane is silent on a CONTESTED address, or ``None``.

    The twin of :func:`_contention_note`, and it exists for the same reason: the
    inventory goes to real trouble to distinguish "nothing named this address"
    from "its names tie" from "its name belongs to a service", and a classifier
    that read only the name would collapse all three back into the same blank.
    Reported even when a higher rung won the field, because "the DNS lane was
    withheld" is a different fact from "DNS had nothing to say" whatever else
    named the host.
    """
    return obs.dns_name_withheld or None


def _contention_note(obs: HostObservations) -> str | None:
    """Why the hostlog lane is silent on a CONTESTED address, or ``None``.

    Several agents reporting the same address is the normal state of a container
    bridge gateway, not an anomaly — but the difference between "nobody has ever
    reported this address" and "four machines claim it and none may have it" is
    the difference between an unknown host and a shared interface, and only one
    of those is worth an analyst's time.
    """
    claimants = obs.agent_ip_claimants
    if len(claimants) < 2:
        return None
    return (
        f"{len(claimants)} host-log agents claim {obs.ip} ({', '.join(sorted(claimants))}) — "
        "no self-reported identity can be attributed to a shared address"
    )


def _floor_evidence(obs: HostObservations, floor: int) -> str:
    return f"insufficient telemetry: {obs.total_events} events in window (< {floor})"


# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------


def _port_pairs(buckets: Sequence[dict[str, Any]]) -> list[tuple[int, int]]:
    """``[{value, count}]`` → ``[(port, count)]``, dropping unparseable keys.

    Order is preserved: the collector hands over terms-agg buckets, which are
    already sorted by count descending, and `services_offered` is rendered in
    that order.
    """
    return [pair for bucket in buckets or () if (pair := _parse_port_bucket(bucket)) is not None]


def _parse_port_bucket(bucket: dict[str, Any]) -> tuple[int, int] | None:
    """One terms bucket → ``(port, count)``, or ``None`` when it is not a port."""
    try:
        port = int(bucket.get("value"))  # type: ignore[arg-type]
        count = int(bucket.get("count") or 0)
    except (TypeError, ValueError):
        return None
    return (port, count) if 0 < port <= 65535 else None


@dataclasses.dataclass(frozen=True)
class _PortObservation:
    """One responder port, with the answered subset separated from the attempts.

    ``conns`` is what the terms agg counted: zeek.conn writes a record for a
    connection ATTEMPT, so a host that was merely port-scanned accumulates
    responder ports it never answered on. ``answered`` is the subset we can show
    the host actually replied to, and it — never ``conns`` — decides whether a
    port is a service.

    ``peers`` and ``hours`` are per-port and optional: they are populated only
    when the collector aggregates them per port, in which case a role verdict is
    gated on the matched port set's own spread instead of the host's aggregate.

    All three are read from optional keys on the terms bucket (``answered``,
    ``peers``, ``hours``) so the classifier improves the moment the collector
    can supply them: an ``answered`` filter sub-agg on ``fields.CONN_STATE`` (or
    ``resp_bytes > 0``), a ``source.ip`` cardinality, and an hourly
    date_histogram, all nested under the responder ``ports`` terms agg. Until
    then the host-wide fallbacks below are what stands between a port scan and a
    role, and they are coarse: they can only see whether the host answered
    ANYTHING, not what it answered on.
    """

    port: int
    conns: int
    answered: int
    peers: int | None = None
    hours: int | None = None


def _bucket_int(bucket: dict[str, Any], key: str) -> int | None:
    """Read an optional integer sub-agg off a terms bucket, or ``None``."""
    raw = bucket.get(key)
    if raw is None or isinstance(raw, bool):
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _answered_nothing(obs: HostObservations) -> bool:
    """True when the window PROVES this host returned nothing to anybody.

    The only host-wide proof the collector currently gathers is the responder
    byte percentile: a p95 of zero means at least 95% of the connections *to*
    this host carried no bytes back — refused, filtered or unanswered. A scanned
    host looks exactly like that, and without this check its probe counts pass
    for service traffic (two probes at tcp/8006 made it a "hypervisor", strong).

    A percentile of ``None`` is "not measured on this grid", not "zero": the
    check reports nothing rather than retracting the role of every host in the
    network on one grid whose byte field is unmapped.

    Zeek service names override it: an analyzer only names a service once it
    matched the traffic, and a UDP log sink answers nothing while being a
    perfectly real service.
    """
    p95 = obs.resp_bytes_p95
    # NaN is what an empty ES percentile bucket yields. It is not a zero, and
    # `NaN > 0` being False is precisely how a comparison-only check would read
    # it as one and drop every port on the host.
    if p95 is None or not math.isfinite(p95) or p95 > 0:
        return False
    return not any(_first_str(bucket.get("value")) for bucket in obs.services)


def _responder_ports(obs: HostObservations) -> list[_PortObservation]:
    """Responder ports in bucket order, with attempts and answers separated."""
    answered_nothing = _answered_nothing(obs)
    out: list[_PortObservation] = []
    for bucket in obs.resp_ports or ():
        parsed = _parse_port_bucket(bucket)
        if parsed is None:
            continue
        port, count = parsed
        measured = _bucket_int(bucket, "answered")
        if measured is not None:
            answered = max(0, min(measured, count))
        else:
            answered = 0 if answered_nothing else count
        out.append(
            _PortObservation(
                port=port,
                conns=count,
                answered=answered,
                peers=_bucket_int(bucket, "peers"),
                hours=_bucket_int(bucket, "hours"),
            )
        )
    return out


def _qualified_ports(ports: Sequence[_PortObservation]) -> set[int]:
    """Responder ports ANSWERED often enough to be a service, not a stray packet."""
    return {row.port for row in ports if row.answered >= _MIN_PORT_HITS}


def _render_ports(ports: Iterable[int]) -> str:
    return ", ".join(f"{_PROTO}/{port}" for port in sorted(ports))


@dataclasses.dataclass(frozen=True)
class _Traffic:
    """The traffic behind one role match: only what landed on the matched ports.

    ``peers`` and ``hours`` are either measured on those ports or borrowed from
    the host aggregate; :attr:`attributed` says which. A borrowed spread that
    cannot be shown to belong to this port set never earns a strong verdict —
    that is the whole point of carrying the flag rather than the number alone.
    """

    ports: frozenset[int]
    conns: int
    peers: int
    hours: int
    attributed: bool

    @property
    def sustained(self) -> bool:
        """Seen from more than one peer, in more than one hour, on THESE ports."""
        return (
            self.attributed
            and self.peers >= _MIN_SUSTAINED_PEERS
            and self.hours >= _MIN_SUSTAINED_HOURS
        )

    @property
    def serves_several_peers(self) -> bool:
        """Enough distinct clients on THESE ports to call it a general server."""
        return self.attributed and self.peers >= _MIN_SERVER_PEERS


def _matched_traffic(
    obs: HostObservations, ports: Sequence[_PortObservation], matched: Iterable[int]
) -> _Traffic:
    """Measure the answered traffic on ``matched``, and decide whose spread it is."""
    selected = frozenset(matched)
    rows = [row for row in ports if row.port in selected]
    conns = sum(row.answered for row in rows)

    measured_peers = [row.peers for row in rows if row.peers is not None]
    measured_hours = [row.hours for row in rows if row.hours is not None]
    if measured_peers or measured_hours:
        # `max`, never `sum`: distinct-peer counts do not add across ports (the
        # same admin hits 8006 and 8007), so the largest is the safe lower bound.
        return _Traffic(
            ports=selected,
            conns=conns,
            peers=max(measured_peers, default=0),
            hours=max(measured_hours, default=0),
            attributed=True,
        )

    total = sum(row.answered for row in ports)
    share = conns / total if total else 0.0
    return _Traffic(
        ports=selected,
        conns=conns,
        peers=obs.resp_peer_count,
        hours=obs.resp_hours,
        attributed=conns >= _MATCHED_VOLUME_FLOOR or share >= _MATCHED_SHARE_FLOOR,
    )


# ---------------------------------------------------------------------------
# Identity-record readers
#
# The collector normalises each targeted search into plain dicts keyed by
# logical name (``hostname``, ``mac``, ``domain``, ``realm``, ``client``,
# ``server``, ``source_ip``, ``destination_ip``, ``timestamp``, …) with values
# already coalesced through `fields.first_present`. Everything below reads them
# defensively with `.get` so a collector that cannot populate a key degrades to
# "no signal" rather than raising.
# ---------------------------------------------------------------------------


def _record_str(record: dict[str, Any], key: str) -> str | None:
    """Read one key as a non-empty string (ES fields arrive as scalars or lists)."""
    return _first_str(record.get(key))


def _record_time(record: dict[str, Any], fallback: datetime | None = None) -> datetime | None:
    """The document timestamp behind a record — never the current time.

    Accepts a real datetime or an ISO-8601 string (what an ES ``_source`` hands
    back, ``Z``-suffixed). Falls back to the caller's value, which is always
    another observation timestamp.
    """
    raw = record.get("timestamp", record.get("@timestamp"))
    if isinstance(raw, datetime):
        return raw
    text = _first_str(raw)
    if text:
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            pass
    return fallback


def _is_dhcp_client(record: dict[str, Any], ip: str) -> bool:
    """True when this DHCP record is a lease held BY *ip*.

    A DHCP server on the grid appears in the same records as the counterparty,
    and the base query matches either endpoint — without this check a DHCP
    server would read as the most dynamically-addressed host in the network,
    wearing its clients' hostnames and MACs.

    That discrimination has to be done on the keys the collector actually emits.
    ``assigned_ip``/``client_ip`` are checked first because an explicit lease
    address beats packet direction (a relayed transaction is still not our
    lease), but the collector projects neither today, so DIRECTION is what does
    the work: in Zeek's aggregated ``dhcp.log`` the originator is the client and
    the responder is the server.

    A record with neither endpoint is still accepted — the collector already
    scoped the search to this host, and dropping it would cost a real lease.
    """
    for key in ("assigned_ip", "client_ip"):
        value = _record_str(record, key)
        if value:
            return value == ip
    source_ip = _record_str(record, "source_ip")
    destination_ip = _record_str(record, "destination_ip")
    if source_ip == ip:
        return True
    return destination_ip != ip


def _dhcp_leases(obs: HostObservations) -> list[dict[str, Any]]:
    return [record for record in obs.dhcp if _is_dhcp_client(record, obs.ip)]


def _originated_by(record: dict[str, Any], ip: str) -> bool:
    """True when *ip* is the connection's originator in this record.

    Unknown is not "us": a record with no endpoints cannot say which side this
    host was, and a name attributed from the wrong side is worse than no name.
    """
    return _record_str(record, "source_ip") == ip


def _answered_by(record: dict[str, Any], ip: str) -> bool:
    """True when *ip* is the connection's responder in this record."""
    return _record_str(record, "destination_ip") == ip


def _identity_records(obs: HostObservations) -> tuple[dict[str, Any], ...]:
    """Every non-DHCP identity record, newest-first as the collector ordered them."""
    return (*obs.windows_identity, *obs.ssh_banners, *obs.software)


# ---------------------------------------------------------------------------
# hostname
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class _NameCandidate:
    """One candidate name from one source, with the evidence line it renders as.

    Candidates are collected across the WHOLE window per source and then ordered
    by source, which is what makes the precedence stable. :attr:`evidence` is
    carried rather than derived because the rungs do not all render the same
    way: a wire signal is ``"pve01 (from dhcp)"``, and a machine's own report
    says who reported it and when.
    """

    name: str
    label: str
    source: ProvenanceSource
    strength: Strength
    evidence: str


def _clean_hostname(value: Any) -> str | None:
    """Normalise a hostname candidate, or reject it.

    Rejects addresses (``host.name`` frequently carries the IP), stubs under
    three characters, and everything ``discovery._junk_host_reason`` knows to be
    a protocol artifact (``WORKGROUP``, ``__MSBROWSE__``, escaped NetBIOS suffix
    bytes, a bare public TLD).
    """
    # Lazy: `discovery` pulls in the identifier store and the ES field helpers,
    # and this module's whole contract is that importing it costs nothing and
    # touches nothing. The rule set is worth sharing; its import graph is not.
    from soc_ai.enrichment.discovery import _junk_host_reason  # noqa: PLC0415

    text = _first_str(value)
    if text is None:
        return None
    text = text.strip().rstrip(".")
    if len(text) < _HOSTNAME_MIN_LEN or _looks_like_ip(text):
        return None
    if _junk_host_reason(text) is not None:
        return None
    return text


def _hostname_candidates(obs: HostObservations) -> list[_NameCandidate]:
    """Every hostname the window offers, strongest source FIRST.

    Source-major, not document-major: the whole observation set is walked per
    source, so a DHCP announcement beats a PTR answer regardless of which
    document happened to sort first. That ordering bug is why
    ``host_summary._resolve_hostname`` returns a different name depending on the
    sample it drew.

    This is the COLLECTION order, not the verdict: :func:`_rank_candidates`
    re-ranks the list so a candidate the resolver would hide cannot shadow one
    it would show. The order here is still load-bearing as the tie-break —
    within one (visibility, rung, strength) class, earlier in this walk wins.
    """
    out: list[_NameCandidate] = []
    seen: set[tuple[str, str]] = set()

    def add(
        raw: Any,
        label: str,
        source: ProvenanceSource,
        strength: Strength,
        evidence: str | None = None,
    ) -> None:
        name = _clean_hostname(raw)
        if name is None or (name, label) in seen:
            return
        seen.add((name, label))
        out.append(
            _NameCandidate(
                name=name,
                label=label,
                source=source,
                strength=strength,
                evidence=evidence if evidence is not None else _evidence(name, label),
            )
        )

    # 0. The machine naming itself. An agent running ON the host reports
    #    `host.name`; nothing on the wire is a better answer to "what is this
    #    machine called", which is why `hostlog` sits above `banner` on the
    #    ladder. Present only for an address exactly one agent claims — a shared
    #    bridge gateway resolves to no identity at all, by construction.
    if obs.agent_report is not None:
        add(
            obs.agent_report.host_name,
            _HOSTLOG_LABEL,
            "hostlog",
            "strong",
            _hostlog_evidence(obs.agent_report.host_name, obs.agent_report),
        )
    # 1. The host's own DHCP announcement — the strongest first-party claim.
    for record in _dhcp_leases(obs):
        add(record.get("hostname"), "dhcp", "banner", "strong")
    # 2. NTLM, read by DIRECTION. `ntlm.hostname` is the machine name the CLIENT
    #    announces and `ntlm.server_nb_computer_name` is the server's, so a
    #    record attaches one name to each END of the connection — not both to
    #    whichever host it was found under. Without the split, a file server gets
    #    renamed after the last laptop that authenticated to it, and a hostname
    #    is what an analyst pivots on.
    for record in obs.windows_identity:
        if _originated_by(record, obs.ip):
            add(record.get("hostname"), "ntlm", "banner", "strong")
        if _answered_by(record, obs.ip):
            add(record.get("server_nb"), "ntlm", "banner", "strong")
    # 3. SMB host announcement — the SERVER's name for itself, so it belongs to
    #    this host only when this host answered. Real, but a share-level name,
    #    hence weak.
    for record in obs.windows_identity:
        if _answered_by(record, obs.ip):
            add(record.get("smb_host_name"), "smb", "banner", "weak")
    # 4. What the network's DNS answers call this address. Telemetry, not a
    #    first-party claim — an address can be re-pointed at a different machine
    #    without that machine ever knowing — but STRONG within the rung, because
    #    it is a majority over every answer in the window rather than one
    #    document, and an address whose names disagree was already withheld
    #    upstream. Weak here would put it under the resolver's confidence floor,
    #    which would make the lane invisible on every screen while looking wired.
    #    Ahead of the two below for the same reason: they are single records.
    if obs.dns_name:
        add(
            obs.dns_name,
            _DNS_LABEL,
            "telemetry",
            "strong",
            _dns_evidence(obs.dns_name, obs.dns_name_evidence),
        )
    # 5. ECS host.name from HTTP/TLS documents: not first-party, often a proxy's.
    for name in obs.host_names:
        add(name, "host.name", "telemetry", "weak")
    # 6. A PTR answer names the address, which is a claim about DNS, not the host.
    add(obs.ptr_name, "dns-ptr", "telemetry", "weak")
    return out


def _rank_candidates(
    candidates: Sequence[_NameCandidate], *, min_confidence: float
) -> list[_NameCandidate]:
    """Candidates in winning order: visibility first, then the ladder, then strength.

    *min_confidence* is the resolver's render floor (``dossier_min_confidence``):
    a winner below it resolves to "unknown" at read time, so a candidate that
    would be INVISIBLE must never shadow one that would show. Ranking by rung
    alone did exactly that — an SMB share name (``banner``/weak, 0.5) beat the
    DNS consensus (``telemetry``/strong, 0.9), fell under the floor, and the
    field rendered blank while the dossier held a perfectly good name. A plain
    (rung, strength) sort does not fix it either: the weak high-rung name still
    wins on rung.

    So the sort key is (would render, rung, strength), descending. Among the
    candidates on one side of the floor the ladder is untouched — a weak banner
    name that WOULD render still beats a strong telemetry name, because the
    machine's own announcement outranks what a resolver hands out — and strength
    breaks ties within a rung. When nothing clears the floor this degrades to
    the old rule exactly: highest rung keeps the (hidden) field. The sort is
    stable, so the collection order (DHCP before NTLM, ``host.name`` before PTR)
    is the final tie-break.

    The floor is read at BUILD time, so a hot-applied change shows up on the
    next sweep; the resolver still applies its own copy at read time, which can
    only hide the stored winner, never resurrect a loser.
    """
    return sorted(
        candidates,
        key=lambda c: (
            below_confidence_floor(STRENGTH_CONFIDENCE[c.strength], min_confidence),
            -provenance_rank(c.source),
            -STRENGTH_CONFIDENCE[c.strength],
        ),
    )


def _infer_hostname(obs: HostObservations, *, min_confidence: float) -> Fact:
    candidates = _rank_candidates(_hostname_candidates(obs), min_confidence=min_confidence)
    # Always last, so they read as footnotes to the names rather than as ones:
    # these say why a lane is SILENT, which is only interesting once the reader
    # knows what the other lanes said.
    notes = [note for note in (_contention_note(obs), _withheld_dns_note(obs)) if note is not None]
    if not candidates:
        # The sources are enumerated, so one missing from the list reads as one
        # that was never consulted — and a host whose only signal was a withheld
        # DNS name reported "no signal" while a note below said otherwise.
        evidence = ["no hostname signal in window (no DHCP, NTLM, SMB, DNS, host.name or PTR)"]
        evidence.extend(notes)
        return _fact("hostname", strength="none", source="banner", evidence=evidence)
    winner = candidates[0]
    observed_at = _hostname_time(obs, winner.label) or obs.last_seen
    # Winner first, then every other name the window offered. A host with two
    # names is worth seeing, not worth silently resolving.
    evidence = [candidate.evidence for candidate in candidates]
    evidence.extend(notes)
    return _fact(
        "hostname",
        value=winner.name,
        strength=winner.strength,
        source=winner.source,
        evidence=evidence,
        observed_at=observed_at,
    )


def _hostname_time(obs: HostObservations, label: str) -> datetime | None:
    """The timestamp of the newest record that could have produced *label*.

    The collector orders identity records newest-first, so the first record of
    the right kind is the freshest confirmation of the name.
    """
    if label == _HOSTLOG_LABEL:
        return obs.agent_report.last_report if obs.agent_report is not None else None
    if label == _DNS_LABEL:
        return obs.dns_name_observed_at
    records: Sequence[dict[str, Any]] = ()
    if label == "dhcp":
        records = _dhcp_leases(obs)
    elif label in ("ntlm", "smb"):
        records = obs.windows_identity
    return _record_time(records[0]) if records else None


# ---------------------------------------------------------------------------
# mac
# ---------------------------------------------------------------------------


def _normalize_mac(value: Any) -> str | None:
    """Any of the three written MAC forms → ``aa:bb:cc:dd:ee:ff``, or ``None``.

    Accepts colon, hyphen and Cisco dotted-quad spellings. The broadcast and
    all-zero addresses are rejected: both appear in DHCP and ARP-adjacent
    records as protocol placeholders, and storing one as a host's hardware
    address would make every such host look like the same machine.
    """
    text = _first_str(value)
    if text is None:
        return None
    digits = re.sub(r"[^0-9a-fA-F]", "", text).lower()
    if len(digits) != 12 or digits in ("0" * 12, "f" * 12):
        return None
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def _infer_mac(obs: HostObservations) -> Fact:
    """The host's hardware address: its agent's report, its DHCP lease, host.mac.

    OUI vendor lookup is deliberately absent: no OUI database is vendored, and
    vendoring one is a data-licensing decision rather than a code decision. The
    prefix is stored so backfilling the vendor name later is a pure lookup.
    """
    agent_mac, ambiguity = _agent_mac(obs)
    if agent_mac is not None and obs.agent_report is not None:
        return _mac_fact(
            agent_mac,
            observed_at=obs.agent_report.last_report,
            source="hostlog",
            evidence=_hostlog_evidence(agent_mac, obs.agent_report),
        )
    for record in _dhcp_leases(obs):
        mac = _normalize_mac(record.get("mac"))
        if mac:
            return _mac_fact(mac, observed_at=_record_time(record, obs.last_seen), label="dhcp")
    for record in _identity_records(obs):
        mac = _normalize_mac(record.get("mac"))
        if mac:
            return _mac_fact(mac, observed_at=_record_time(record, obs.last_seen), label="host.mac")
    evidence = ["no hardware address in window (no DHCP lease, no host.mac)"]
    if ambiguity is not None:
        evidence.append(ambiguity)
    return _fact("mac", strength="none", source="banner", evidence=evidence)


def _agent_mac(obs: HostObservations) -> tuple[str | None, str | None]:
    """The agent's report of THE machine's address — only when there is one.

    ``host.mac`` is an array of every interface the machine can see on itself,
    and on anything running containers or VMs that is a dozen bridge and veth
    addresses with the real uplink somewhere among them. Nothing pairs an entry
    with an address (``host.ip`` and ``host.mac`` are independent arrays of
    different lengths), and the order is the kernel's interface enumeration, not
    a ranking.

    So a multi-address report yields NOTHING here, and says so. Publishing "the
    first one" would be a silently wrong identity field — the failure class
    ``_directional_mac`` exists to prevent — and worse, an unstable one: ``mac``
    is half of the identity fingerprint, so a report whose array order shifted
    between sweeps would stamp ``identity_rebound_at`` and prod the operator
    about a machine swap that never happened.
    """
    report = obs.agent_report
    if report is None:
        return None, None
    macs = sorted({mac for raw in report.macs if (mac := _normalize_mac(raw)) is not None})
    if len(macs) == 1:
        return macs[0], None
    if not macs:
        return None, None
    return None, _evidence(
        f"{report.host_name} reported {len(macs)} hardware addresses "
        "(bridges and virtual interfaces); none can be singled out as the machine's own",
        _HOSTLOG_LABEL,
    )


def _mac_fact(
    mac: str,
    *,
    observed_at: datetime | None,
    label: str | None = None,
    source: ProvenanceSource = "banner",
    evidence: str | None = None,
) -> Fact:
    return _fact(
        "mac",
        value=mac,
        value_json={"mac": mac, "oui": mac[:8]},
        strength="strong",
        source=source,
        evidence=[evidence if evidence is not None else _evidence(mac, label or source)],
        observed_at=observed_at,
    )


# ---------------------------------------------------------------------------
# os_family / os_detail
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class _OsCandidate:
    """One source's answer to the OS question, with the raw signal behind it."""

    family: str | None
    detail: str | None
    strength: Strength
    source: ProvenanceSource
    # How the source is named in a conflict string ("banner"), and in an
    # evidence string ("ssh-banner") — the ladder rung vs the concrete signal.
    label: str
    evidence_label: str
    signal: str
    observed_at: datetime | None
    # True only for the os_hint "two families matched" verdict, which is a real
    # answer ("mixed") rather than an absence.
    mixed: bool = False
    # Set when this rung does not render as "<signal> (from <label>)" — see
    # `_hostlog_evidence`.
    rendered: str | None = None

    @property
    def evidence(self) -> str:
        if self.rendered is not None:
            return self.rendered
        return _evidence(self.signal, self.evidence_label)


def _hostlog_os_candidate(obs: HostObservations) -> _OsCandidate | None:
    """What the machine says it runs, out of the agent's ``host.os`` struct.

    The strongest OS answer there is: the agent read it from the running system
    rather than inferring it from a banner or a telemetry domain. The FAMILY is
    translated into this module's coarse vocabulary (see
    :data:`_HOSTLOG_OS_FAMILY`) — never ECS's, which would have every Debian
    machine "disagreeing" with its own SSH banner — while the DETAIL keeps the
    agent's words verbatim, including the kernel, which is routinely the only
    field that names the distribution's purpose (``…-pve`` on a hypervisor).

    An ``os.type`` this module has no vocabulary for yields no family but keeps
    the detail: "what it says it runs" is still true, and the lower rungs are
    left holding the family rather than being displaced by a guess.
    """
    report = obs.agent_report
    if report is None or not report.os:
        return None
    family = _hostlog_os_family(report.os)
    detail = _hostlog_os_detail(report.os)
    if detail is None and family is None:
        return None
    signal = detail or family or ""
    return _OsCandidate(
        family=family,
        detail=detail,
        strength="strong",
        source="hostlog",
        label="hostlog",
        evidence_label=_HOSTLOG_LABEL,
        signal=signal,
        observed_at=report.last_report,
        rendered=_hostlog_evidence(signal, report),
    )


def _hostlog_os_family(os_struct: dict[str, str]) -> str | None:
    for key in _HOSTLOG_OS_FAMILY_KEYS:
        family = _HOSTLOG_OS_FAMILY.get((os_struct.get(key) or "").strip().casefold())
        if family is not None:
            return family
    return None


def _hostlog_os_detail(os_struct: dict[str, str]) -> str | None:
    """``"Debian GNU/Linux 13 (trixie), kernel 7.0.12-1-pve"`` — whatever exists."""
    name = os_struct.get("name") or os_struct.get("platform")
    version = os_struct.get("version")
    kernel = os_struct.get("kernel")
    head = " ".join(part for part in (name, version) if part)
    parts = [part for part in (head, f"kernel {kernel}" if kernel else None) if part]
    return ", ".join(parts) or None


def _banner_candidate(obs: HostObservations) -> _OsCandidate | None:
    """Parse this host's OWN SSH banner.

    Direction is load-bearing: the client banner belongs to the originator and
    the server banner to the responder, so reading whichever is present would
    attribute the peer's OS to this host on every SSH session it takes part in.

    A document carrying NEITHER endpoint is skipped rather than read as ours.
    Treating it as an inbound session stamped the peer's OS on a host that was
    only ever an SSH client — and "linux, strong, from the banner" is exactly
    the kind of claim an analyst does not re-check.
    """
    for record in obs.ssh_banners:
        source_ip = _record_str(record, "source_ip")
        destination_ip = _record_str(record, "destination_ip")
        ours: list[tuple[str, str]] = []
        if destination_ip == obs.ip:
            server = _record_str(record, "server")
            if server:
                ours.append((server, "ssh-server-banner"))
        if source_ip == obs.ip:
            client = _record_str(record, "client")
            if client:
                ours.append((client, "ssh-client-banner"))
        for banner, evidence_label in ours:
            for pattern, family, detail in _SSH_OS_PATTERNS:
                if pattern.search(banner):
                    return _OsCandidate(
                        family=family,
                        detail=detail,
                        strength="strong",
                        source="banner",
                        label="banner",
                        evidence_label=evidence_label,
                        signal=banner,
                        observed_at=_record_time(record, obs.last_seen),
                    )
    return None


def _ua_candidate(obs: HostObservations) -> _OsCandidate | None:
    """What this host's User-Agents say about its OS — ALL of them, not the first.

    ``classify_user_agent`` is reused rather than reimplemented — its
    specific-device-first ordering is the iPhone-vs-Mac fix, and every mobile
    Safari UA contains ``like Mac OS X``. Labels that name a device without an
    OS family (``Smart TV``, ``PlayStation``) map to no family and are skipped.

    Two families is a real answer, not a tie to be broken. A NAT gateway or a
    hypervisor bridging guests legitimately shows Apple AND Windows UAs on one
    address; returning the first match collapsed that to a coin flip published
    at 0.9. The rule already existed for vendor-telemetry domains — this is the
    same rule on the signal that shows the case most often.
    """
    seen: list[tuple[str, str, str]] = []  # (family, label, raw UA)
    for ua in obs.user_agents:
        label = classify_user_agent(ua)
        if label is None:
            continue
        family = _ua_label_to_family(label)
        if family is None:
            continue
        seen.append((family, label, ua))
    if not seen:
        return None

    family, label, ua = seen[0]
    others = [entry for entry in seen if entry[0] != family]
    if others:
        return _OsCandidate(
            family=None,
            detail=None,
            strength="weak",
            source="telemetry",
            label="user-agent",
            evidence_label="user-agent",
            # One representative UA per family: enough for a reader to see both
            # sides without pasting a whole browser fleet into the evidence.
            signal=f"{ua}, {others[0][2]}",
            observed_at=obs.last_seen,
            mixed=True,
        )
    return _OsCandidate(
        family=family,
        detail=label,
        strength="strong",
        source="telemetry",
        label="user-agent",
        evidence_label="user-agent",
        signal=ua,
        observed_at=obs.last_seen,
    )


def _hint_candidate(obs: HostObservations) -> _OsCandidate | None:
    """Vendor telemetry domains → OS, via the shared os_hint classifier.

    The two-families verdict is preserved verbatim rather than collapsed: a NAT
    gateway or a hypervisor bridging guests legitimately shows Apple AND Windows
    telemetry on one address, and "mixed" is a better answer than a coin flip.
    ``linux`` stays structurally unreachable from absence — os_hint only ever
    sets it from positive distro telemetry.
    """
    domains = [
        name
        for bucket in (*obs.dns_queries, *obs.sni)
        if (name := _first_str(bucket.get("value"))) is not None
    ]
    hint = os_hint_from_domains(domains)
    if hint is None:
        return None
    label = hint["os"]
    family = _os_label_to_family(label) if label else None
    return _OsCandidate(
        family=family,
        # macos/ios narrow the coarse apple family; windows/linux/android do not.
        detail=label if label and label != family else None,
        strength="strong" if hint["confidence"] == "strong" else "weak",
        source="telemetry",
        label="telemetry-domains",
        evidence_label="telemetry-domains",
        signal=", ".join(hint["signals"]),
        observed_at=obs.last_seen,
        mixed=label is None,
    )


def _infer_os(obs: HostObservations) -> tuple[Fact, Fact]:
    """``(os_family, os_detail)`` — the ladder, then the merge.

    The agent's own answer beats the banner beats User-Agent beats telemetry
    hint for the VALUE; the losers stay in the evidence; a family-level
    disagreement is named in ``conflict`` instead of being resolved by
    preference.
    """
    candidates = [
        candidate
        for candidate in (
            _hostlog_os_candidate(obs),
            _banner_candidate(obs),
            _ua_candidate(obs),
            _hint_candidate(obs),
        )
        if candidate is not None
    ]
    evidence = [c.evidence for c in candidates]

    # A "mixed" verdict is an answer, so it competes on the ladder like any
    # other: two families seen on the wire are not resolved by a weaker source
    # naming one of them. Only a HIGHER rung — the host's own banner — outranks it.
    winner = next((c for c in candidates if c.family is not None or c.mixed), None)
    if winner is not None and winner.mixed:
        # Two families on one address. os=None, weak, both families visible.
        return (
            _fact(
                "os_family",
                strength="weak",
                source=winner.source,
                evidence=evidence,
                observed_at=winner.observed_at,
            ),
            _fact(
                "os_detail",
                strength="none",
                source=winner.source,
                evidence=["OS family is mixed — no version detail can be claimed"],
                observed_at=winner.observed_at,
            ),
        )
    if winner is None:
        # No source named a family. A source may still have named the SYSTEM —
        # an agent reporting an OS this module has no family vocabulary for is
        # the only way to get here, and "what it says it runs" is true whether or
        # not the family maps. Dropping it would throw away the better half of a
        # first-party answer to keep a taxonomy tidy.
        detailed = next((c for c in candidates if c.detail is not None), None)
        family_fact = _fact(
            "os_family",
            strength="none",
            source="telemetry",
            evidence=evidence
            or ["no OS signal in window (no SSH banner, no User-Agent, no vendor telemetry)"],
        )
        if detailed is None:
            return family_fact, _fact(
                "os_detail",
                strength="none",
                source="telemetry",
                evidence=["no OS signal in window"],
            )
        return family_fact, _fact(
            "os_detail",
            value=detailed.detail,
            strength=detailed.strength,
            source=detailed.source,
            evidence=[detailed.evidence],
            observed_at=detailed.observed_at,
        )

    conflict = _os_conflict(winner, candidates)
    family_fact = _fact(
        "os_family",
        value=winner.family,
        strength=winner.strength,
        source=winner.source,
        evidence=evidence,
        observed_at=winner.observed_at,
        conflict=conflict,
    )
    if winner.detail is None:
        detail_fact = _fact(
            "os_detail",
            strength="none",
            source=winner.source,
            evidence=[f"OS family {winner.family} identified, but no version detail in the signal"],
            observed_at=winner.observed_at,
        )
    else:
        detail_fact = _fact(
            "os_detail",
            value=winner.detail,
            strength=winner.strength,
            source=winner.source,
            evidence=[winner.evidence],
            observed_at=winner.observed_at,
        )
    return family_fact, detail_fact


def _os_conflict(winner: _OsCandidate, candidates: Sequence[_OsCandidate]) -> str | None:
    """Name a family-level disagreement, or return ``None``.

    The winner still wins the value — the point is that the reader is told the
    other source said something else, and what it was reading when it did. A
    source that saw TWO families is a disagreement of its own and is named
    ``mixed``: the banner decides what the host is, but "the traffic on this
    address is not all from one machine" is the part worth reading.
    """
    losers = [
        c
        for c in candidates
        if c is not winner and (c.mixed or c.family not in (None, winner.family))
    ]
    if not losers:
        return None
    sides = " vs ".join(
        f"{c.label}={c.family or 'mixed'} ({_truncate(c.signal)})" for c in (winner, *losers)
    )
    return f"OS family disagreement: {sides}"


def _truncate(text: str) -> str:
    return text if len(text) <= _MAX_SIGNAL_CHARS else text[:_MAX_SIGNAL_CHARS] + "..."


# ---------------------------------------------------------------------------
# role
# ---------------------------------------------------------------------------


def _infer_role(
    obs: HostObservations, *, ports: Sequence[_PortObservation], qualified: set[int], floor: int
) -> Fact:
    """The ordered role table: first match wins.

    Order is the whole design. A hypervisor answers 22 and 443; a domain
    controller answers 445; a SIEM answers 443. Running the generic "it serves
    something" rule first would file all three as ``server`` and throw away the
    only part of the answer an analyst could not have guessed.
    """
    if obs.total_events < floor:
        return _fact(
            "role",
            value="unknown",
            strength="none",
            source="behaviour",
            evidence=[_floor_evidence(obs, floor)],
            observed_at=obs.last_seen,
        )

    matched = _match_role(obs, ports=ports, qualified=qualified)
    if matched is None:
        return _fact(
            "role",
            value="unknown",
            strength="none",
            source="behaviour",
            evidence=[_unknown_role_evidence(obs, qualified)],
            observed_at=obs.last_seen,
        )
    role, strength, evidence = matched
    return _fact(
        "role",
        value=role,
        strength=strength,
        source="behaviour",
        evidence=evidence,
        observed_at=obs.last_seen,
    )


def _match_role(
    obs: HostObservations, *, ports: Sequence[_PortObservation], qualified: set[int]
) -> tuple[str, Strength, list[str]] | None:
    """Walk the eight rows in order; return ``(role, strength, evidence)``.

    Every row is judged on the traffic that MATCHED it. Reading the host's whole
    responder aggregate instead let one row's verdict be earned by another row's
    traffic — and printed that unrelated volume as its evidence.
    """

    def traffic(matched: Iterable[int]) -> _Traffic:
        return _matched_traffic(obs, ports, matched)

    core = qualified & _HYPERVISOR
    if core:
        # 3128 is only ever corroboration, never the trigger — see _HYPERVISOR.
        matched = core | (qualified & _HYPERVISOR_CORROBORATING)
        hyper = traffic(matched)
        return "hypervisor", _sustained_strength(hyper), [_role_evidence(matched, hyper)]

    dc = _match_domain_controller(obs, qualified=qualified, traffic=traffic)
    if dc is not None:
        return dc

    siem_strong = qualified & _SIEM_STRONG
    if siem_strong:
        siem = traffic(siem_strong)
        return "security_appliance", _sustained_strength(siem), [_role_evidence(siem_strong, siem)]
    siem_weak = qualified & _SIEM_WEAK
    if siem_weak:
        return "security_appliance", "weak", [_role_evidence(siem_weak, traffic(siem_weak))]

    netdev_strong = qualified & _NETDEV_STRONG
    if netdev_strong:
        return "network_device", "strong", [_role_evidence(netdev_strong, traffic(netdev_strong))]
    netdev_weak = qualified & _NETDEV_WEAK
    if netdev_weak:
        return "network_device", "weak", [_role_evidence(netdev_weak, traffic(netdev_weak))]

    iot = _match_iot(obs, qualified=qualified, traffic=traffic)
    if iot is not None:
        return iot

    # Before the generic server row, not after it: 135/139/445 callbacks are
    # ordinary Windows fleet behaviour and every one of them is also a general
    # service port. Running "it serves something" first filed the whole fleet as
    # servers; requiring the qualifying set to be EMPTY blackholed them to
    # "unknown" instead. Neither answer is "workstation", which is what they are.
    workstation = _match_workstation(obs, qualified=qualified, traffic=traffic)
    if workstation is not None:
        return workstation

    server = qualified & _GENERAL_SERVER
    if server:
        served = traffic(server)
        fleet = served.sustained and served.serves_several_peers
        return "server", ("strong" if fleet else "weak"), [_role_evidence(server, served)]

    return None


def _sustained_strength(traffic: _Traffic) -> Strength:
    """Strong only when the MATCHED ports were answered across peers and hours."""
    return "strong" if traffic.sustained else "weak"


def _match_domain_controller(
    obs: HostObservations,
    *,
    qualified: set[int],
    traffic: Callable[[Iterable[int]], _Traffic],
) -> tuple[str, Strength, list[str]] | None:
    """Kerberos + LDAP as a set, or a protocol only a DC speaks.

    The two protocol disjuncts exist because a DC on a quiet grid may only show
    one core port in the window, and because direction is what separates the KDC
    from the clients authenticating to it.
    """
    # Each disjunct contributes its own evidence line, so a non-empty list IS
    # the trigger — there is no way to match this row without saying what on.
    # The directory ports are what the verdict is gated on; when none of them
    # qualify (the DCE-RPC disjunct) the corroborating set carries the traffic.
    directory = traffic((qualified & _DC_CORE) or (qualified & _DC_EXTRA))
    evidence: list[str] = []
    if qualified >= _DC_CORE:
        evidence.append(_role_evidence(_DC_CORE, traffic(_DC_CORE)))
    if 88 in qualified and _has_kerberos_to_host(obs):
        evidence.append(
            _evidence("zeek.kerberos authentication answered by this host", "behaviour")
        )
    endpoint = _dc_rpc_endpoint(obs)
    if endpoint is not None:
        evidence.append(_evidence(f"answers the DCE-RPC endpoint {endpoint}", "behaviour"))
    if not evidence:
        return None

    extra = qualified & _DC_EXTRA
    if extra:
        # Corroboration only — LDAPS/GC/DNS/SMB are served by plenty of hosts
        # that are not domain controllers, so they never trigger the row.
        evidence.append(
            _evidence(f"corroborating directory ports {_render_ports(extra)}", "behaviour")
        )
    return "domain_controller", _sustained_strength(directory), evidence


def _has_kerberos_to_host(obs: HostObservations) -> bool:
    """A Kerberos exchange in which this host was the destination (the KDC)."""
    return any(
        _record_str(record, "dataset") == "zeek.kerberos"
        and _record_str(record, "destination_ip") == obs.ip
        for record in obs.windows_identity
    )


def _dc_rpc_endpoint(obs: HostObservations) -> str | None:
    """A DC-only DCE-RPC endpoint answered BY this host."""
    for record in obs.windows_identity:
        endpoint = (_record_str(record, "dce_rpc_endpoint") or "").lower()
        if endpoint in _DC_RPC_ENDPOINTS and _record_str(record, "destination_ip") == obs.ip:
            return endpoint
    return None


def _match_iot(
    obs: HostObservations,
    *,
    qualified: set[int],
    traffic: Callable[[Iterable[int]], _Traffic],
) -> tuple[str, Strength, list[str]] | None:
    """A narrow appliance profile: it listens for its own protocol and little else.

    The whole qualifying set must fall inside the appliance ports — a host that
    also answers SSH or HTTPS is a computer with a printer port, not a printer —
    and a desktop or mobile User-Agent disqualifies it outright, because a laptop
    sharing a printer would otherwise match.
    """
    if not qualified or not qualified <= (_IOT_STRONG | _IOT_WEAK):
        return None
    if obs.orig_peer_count > _MAX_IOT_PEERS or _ua_candidate(obs) is not None:
        return None
    return (
        "iot",
        ("strong" if qualified & _IOT_STRONG else "weak"),
        [_role_evidence(qualified, traffic(qualified))],
    )


def _match_workstation(
    obs: HostObservations,
    *,
    qualified: set[int],
    traffic: Callable[[Iterable[int]], _Traffic],
) -> tuple[str, Strength, list[str]] | None:
    """Defined by outbound breadth, and by what it does NOT serve.

    This is where ``host_summary._guess_role``'s single-hit trigger is refused:
    a laptop that accepted one SSH session has no qualifying responder port and
    stays a workstation.

    A qualifying port is no longer disqualifying, though. A domain workstation
    answers 135/139/445 callbacks a few times a day, and demanding an empty
    qualifying set sent every one of them to the server row or, when nothing
    matched there, to "unknown". What separates the two is whether those ports
    serve a FLEET: sustained traffic from several distinct peers is a file
    server, a handful of callbacks from one or two is a desktop.
    """
    if obs.orig_peer_count < _MIN_WORKSTATION_PEERS:
        return None
    answered = traffic(qualified)
    if qualified and answered.sustained and answered.serves_several_peers:
        return None
    if qualified:
        evidence = [
            _evidence(
                f"answers only {_render_ports(qualified)} ({answered.conns:,} zeek.conn "
                f"records from {answered.peers} distinct peers) while initiating "
                f"connections to {obs.orig_peer_count} distinct peers",
                "behaviour",
            )
        ]
    else:
        evidence = [
            _evidence(
                "no qualifying responder ports; initiated connections to "
                f"{obs.orig_peer_count} distinct peers",
                "behaviour",
            )
        ]
    os_candidate = _ua_candidate(obs) or _hint_candidate(obs)
    if os_candidate is None or os_candidate.family is None:
        return "workstation", "weak", evidence
    evidence.append(_evidence(os_candidate.signal, os_candidate.evidence_label))
    return "workstation", "strong", evidence


def _role_evidence(ports: Iterable[int], traffic: _Traffic) -> str:
    """The behavioural evidence line: what it answered, how much, from whom, how long.

    Volume, peer cardinality and hour spread are all in the string because each
    one is a different way the same port set can be a false lead — a scan, a
    backup pair, a one-off maintenance window. Every number names the MATCHED
    ports: a verdict about tcp/8006 that quotes tcp/443's volume is quoting a
    number that had nothing to do with the call.

    When the spread could not be attributed to these ports the line says so
    rather than borrowing the host's totals silently.
    """
    head = f"responds on {_render_ports(ports)} — {traffic.conns:,} zeek.conn records"
    if traffic.attributed:
        return _evidence(
            f"{head} from {traffic.peers} distinct peers across {traffic.hours} hours",
            "behaviour",
        )
    return _evidence(
        f"{head}; the host's {traffic.peers} responder peers across "
        f"{traffic.hours} hours are mostly other ports",
        "behaviour",
    )


def _unknown_role_evidence(obs: HostObservations, qualified: set[int]) -> str:
    """Absence is a real answer — say which absence."""
    if qualified:
        return _evidence(
            f"responds on {_render_ports(qualified)} — no role rule matches this port set",
            "behaviour",
        )
    return _evidence(
        "no qualifying responder ports and only "
        f"{obs.orig_peer_count} outbound peers — not enough to classify",
        "behaviour",
    )


# ---------------------------------------------------------------------------
# services_offered / management_plane / activity_profile
# ---------------------------------------------------------------------------


def _infer_services(obs: HostObservations, *, ports: Sequence[_PortObservation]) -> Fact:
    """The ports this host ANSWERS, as structured data for the UI and the tool.

    The same two floors the role table uses apply here, and for the same reason:
    a port reached once is a stray packet and a port that was never answered is
    somebody else's scan. Publishing either as an offered service contradicts
    the role verdict on the same screen — and "serves tcp/8006" is what a reader
    acts on.

    ``service`` is left ``None`` per entry: the collector's Zeek-service
    aggregation is per host, not per port, so mapping a name onto a port would
    be a guess. The observed names go in the evidence instead, where they are
    true.
    """
    pairs = [(row.port, row.answered) for row in ports if row.answered >= _MIN_PORT_HITS]
    pairs = pairs[:_MAX_SERVICES]
    if not pairs:
        return _fact(
            "services_offered",
            value_json=[],
            strength="none",
            source="behaviour",
            evidence=[_evidence("no answered responder connections in window", "behaviour")],
            observed_at=obs.last_seen,
        )
    offered = [port for port, _ in pairs]
    evidence = [_role_evidence(offered, _matched_traffic(obs, ports, offered))]
    names = [name for bucket in obs.services if (name := _first_str(bucket.get("value")))]
    if names:
        evidence.append(_evidence(f"zeek service names in window: {', '.join(names)}", "behaviour"))
    return _fact(
        "services_offered",
        value=_render_ports_in_order(pairs),
        value_json=[
            {"port": port, "proto": _PROTO, "count": count, "service": None}
            for port, count in pairs
        ],
        strength="strong",
        source="behaviour",
        evidence=evidence,
        observed_at=obs.last_seen,
    )


def _render_ports_in_order(pairs: Sequence[tuple[int, int]]) -> str:
    """Ports in bucket order (busiest first), unlike the sorted evidence form."""
    return ", ".join(f"{_PROTO}/{port}" for port, _ in pairs)


def _infer_management_plane(obs: HostObservations, *, qualified: set[int], floor: int) -> Fact:
    """Does this host expose an administrative surface, and on which ports.

    "No" is withheld below the telemetry floor: a handful of events is not
    evidence that an admin interface is absent, and a confident "no" is exactly
    the kind of claim an investigation would lean on.
    """
    exposed = sorted(qualified & _MANAGEMENT_PLANE)
    if exposed:
        return _fact(
            "management_plane",
            value="yes",
            value_json=exposed,
            strength="strong",
            source="behaviour",
            evidence=[
                _evidence(f"management-plane responder on {_render_ports(exposed)}", "behaviour")
            ],
            observed_at=obs.last_seen,
        )
    if obs.total_events < floor:
        return _fact(
            "management_plane",
            value_json=[],
            strength="none",
            source="behaviour",
            evidence=[_floor_evidence(obs, floor)],
            observed_at=obs.last_seen,
        )
    return _fact(
        "management_plane",
        value="no",
        value_json=[],
        strength="weak",
        source="behaviour",
        evidence=[_evidence("no management-plane port answered in window", "behaviour")],
        observed_at=obs.last_seen,
    )


def _infer_activity_profile(obs: HostObservations, *, floor: int) -> Fact:
    """The behavioural baseline: when it is busy, how much it moves, what it reaches for.

    ``initiates_remote_access`` is the field that turns "the host did X" into
    "the host did X, which it has never done before" — the comparison an
    investigation cannot make without a durable record.
    """
    hour_of_day = {int(hour): int(count) for hour, count in obs.hour_of_day.items()}
    busiest = [
        hour for hour, _ in sorted(hour_of_day.items(), key=lambda item: (-item[1], item[0]))[:3]
    ]
    remote = sorted({port for port, _ in _port_pairs(obs.orig_ports)} & _REMOTE_ACCESS_OUT)
    profile: dict[str, Any] = {
        "hour_of_day": hour_of_day,
        "busiest_hours": busiest,
        "orig_bytes_p50": obs.orig_bytes_p50,
        "orig_bytes_p95": obs.orig_bytes_p95,
        "resp_bytes_p50": obs.resp_bytes_p50,
        "resp_bytes_p95": obs.resp_bytes_p95,
        "distinct_ja3": obs.ja3_distinct,
        "initiates_remote_access": bool(remote),
        "remote_access_ports": remote,
    }
    if obs.total_events == 0:
        return _fact(
            "activity_profile",
            value_json=profile,
            strength="none",
            source="behaviour",
            evidence=[_evidence("no events in window", "behaviour")],
        )
    parts = [
        f"busiest hours {', '.join(f'{hour:02d}:00' for hour in busiest)} UTC"
        if busiest
        else "no hourly activity recorded"
    ]
    parts.append(
        f"initiates remote access on {_render_ports(remote)}"
        if remote
        else "no outbound remote access"
    )
    evidence = [
        _evidence(
            f"{obs.total_events:,} events in window across "
            f"{obs.orig_peer_count} outbound and {obs.resp_peer_count} inbound peers",
            "behaviour",
        )
    ]
    if remote:
        evidence.append(
            _evidence(f"initiated outbound {_render_ports(remote)}", "behaviour"),
        )
    return _fact(
        "activity_profile",
        value="; ".join(parts),
        value_json=profile,
        strength="strong" if obs.total_events >= floor else "weak",
        source="behaviour",
        evidence=evidence,
        observed_at=obs.last_seen,
    )


# ---------------------------------------------------------------------------
# domain_membership / is_static_addressed
# ---------------------------------------------------------------------------


def _clean_domain(value: Any) -> str | None:
    """Normalise a domain/realm candidate, or reject it.

    ``WORKGROUP`` is rejected by ``_junk_host_reason`` — which is exactly right
    here: it is the Windows default for a host that joined nothing, so reporting
    it as a domain membership would invert the meaning.
    """
    from soc_ai.enrichment.discovery import _junk_host_reason  # noqa: PLC0415

    text = _first_str(value)
    if text is None:
        return None
    text = text.strip().rstrip(".")
    if len(text) < 2 or _looks_like_ip(text) or _junk_host_reason(text) is not None:
        return None
    return text


def _infer_domain_membership(obs: HostObservations) -> Fact:
    """NTLM domain > Kerberos realm > DHCP domain option."""
    candidates: list[tuple[str, str, Strength, datetime | None]] = []
    for record in obs.windows_identity:
        name = _clean_domain(record.get("domain"))
        if name:
            candidates.append((name, "ntlm", "strong", _record_time(record, obs.last_seen)))
    for record in obs.windows_identity:
        name = _clean_domain(record.get("realm"))
        if name:
            candidates.append((name, "kerberos", "strong", _record_time(record, obs.last_seen)))
    for record in _dhcp_leases(obs):
        # The DHCP domain option is what the SERVER handed out, not what the
        # host joined — a real signal about the network, a weak one about the host.
        name = _clean_domain(record.get("domain"))
        if name:
            candidates.append((name, "dhcp", "weak", _record_time(record, obs.last_seen)))
    if not candidates:
        return _fact(
            "domain_membership",
            strength="none",
            source="banner",
            evidence=["no domain or realm announced in window"],
        )
    value, _label, strength, observed_at = candidates[0]
    return _fact(
        "domain_membership",
        value=value,
        strength=strength,
        source="banner",
        evidence=[_evidence(name, src) for name, src, _, _ in candidates],
        observed_at=observed_at,
    )


def _infer_static_addressing(obs: HostObservations, *, floor: int) -> Fact:
    """Three-valued, because "no DHCP data" is not "statically addressed".

    A grid without ``zeek.dhcp`` yields no lease for any host on it. Read as a
    negative, that silence would report the entire network as statically
    addressed — confidently, and wrongly. So the absence of the dataset is
    reported as an absence of signal.
    """
    leases = _dhcp_leases(obs)
    if leases:
        return _fact(
            "is_static_addressed",
            value="no",
            strength="strong",
            source="banner",
            evidence=[_evidence(f"DHCP lease observed for {obs.ip}", "dhcp")],
            observed_at=_record_time(leases[0], obs.last_seen),
        )
    if "zeek.dhcp" not in obs.available_datasets:
        return _fact(
            "is_static_addressed",
            strength="none",
            source="behaviour",
            evidence=["signal unavailable on this grid (no zeek.dhcp dataset)"],
        )
    if obs.total_events < floor:
        return _fact(
            "is_static_addressed",
            strength="none",
            source="behaviour",
            evidence=[_floor_evidence(obs, floor)],
        )
    return _fact(
        "is_static_addressed",
        value="yes",
        strength="weak",
        source="behaviour",
        evidence=[
            _evidence("no DHCP lease in window on a grid that carries zeek.dhcp", "behaviour")
        ],
        observed_at=obs.last_seen,
    )
