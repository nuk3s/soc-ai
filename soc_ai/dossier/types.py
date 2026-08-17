"""Shared types for the host dossier: what was observed, and what was concluded.

The dossier answers "what IS this host?" from telemetry Security Onion already
has. Its two halves are split deliberately:

* :class:`HostObservations` is everything the collector gathered for one IP —
  aggregation buckets, identity records, byte percentiles, which datasets the
  grid even carries. It holds no conclusions.
* :class:`AgentSelfReport` and :class:`AgentInventory` are the network-wide half
  of the same collection: what each machine's own log agent says it is, and the
  rule deciding which addresses may carry that identity. Network-wide because
  attribution is a question about the WHOLE network's claims, not one host's.
* :class:`DnsNameClaim` and :class:`DnsNameInventory` are the other network-wide
  lane, one rung lower: what the network's DNS answers call each address, and
  the majority rule deciding which of several names an address actually goes by.
* :class:`Fact` is one concluded field, with the evidence and the provenance
  behind it.

They live here rather than beside their producers so the classifier can be a
pure function of an observation set: ``soc_ai.dossier.infer`` imports neither
Elasticsearch nor the database nor a clock, which is what makes every role rule
testable from a hand-built :class:`HostObservations` instead of a live grid.
The store, the resolver and the prompt renderer read the same names, so this
module is the one place a field name is spelled.

Both dataclasses are frozen. Not for thread-safety — the builder is sequential —
but because an observation set is a snapshot of a window that has already
passed, and a :class:`Fact` records what a specific build concluded. Something
that quietly edits either after the fact is a bug, and the freeze turns it into
an exception at the point of the edit rather than a wrong value in the prompt
three layers later. (``frozen`` stops attribute rebinding, not mutation of the
lists inside; the invariant is "replace, don't patch".)
"""

from __future__ import annotations

import dataclasses
import ipaddress
from collections.abc import Sequence
from datetime import datetime
from typing import Any, Literal

# The 12 dossier fields, in render order. `host_dossier_field` stores one row
# per (host, field), so this tuple is also the set of legal values for its
# `field` column.
#
# `criticality` and `policy_notes` are NEVER inferred — the classifier emits no
# Fact for them and only the operator lane is ever populated. They are where a
# deployment's own policy lives ("no interactive SSH; API-token access only"),
# which no amount of telemetry can derive.
DossierField = Literal[
    "hostname",
    "mac",
    "os_family",
    "os_detail",
    "role",
    "services_offered",
    "management_plane",
    "domain_membership",
    "is_static_addressed",
    "activity_profile",
    "criticality",
    "policy_notes",
]

DOSSIER_FIELDS: tuple[DossierField, ...] = (
    "hostname",
    "mac",
    "os_family",
    "os_detail",
    "role",
    "services_offered",
    "management_plane",
    "domain_membership",
    "is_static_addressed",
    "activity_profile",
    "criticality",
    "policy_notes",
)

ProvenanceSource = Literal["behaviour", "telemetry", "banner", "hostlog", "osquery"]

# The provenance ladder, ASCENDING: later rungs win the value.
#
# - `behaviour`  — what the host did (responder ports, peer counts, byte volume)
# - `telemetry`  — what it leaked in passing (User-Agent, vendor DNS, PTR)
# - `banner`     — what it announced about itself (DHCP, NTLM, SMB, SSH banners)
# - `hostlog`    — what an agent on the host reported
# - `osquery`    — what the host answered when asked directly
#
# This generalises `host_summary._merge_os_evidence`, which hardcoded the
# two-signal UA-vs-DNS-hint case. The weaker signal is never discarded: it stays
# in the Fact's evidence under its own key, and a family-level disagreement
# becomes an explicit `conflict` string naming both sides. A dossier that
# silently dropped the loser would hide precisely the case worth reading — a
# host whose banner and whose traffic tell different stories.
#
# `operator` is NOT a rung. An operator value lives in a physically separate
# column family and is resolved at read time, so it never competes in a merge;
# that separation is what makes an override un-clobberable by a rebuild.
PROVENANCE_LADDER: tuple[ProvenanceSource, ...] = (
    "behaviour",
    "telemetry",
    "banner",
    "hostlog",
    "osquery",
)

_PROVENANCE_RANK: dict[str, int] = {source: rank for rank, source in enumerate(PROVENANCE_LADDER)}

Strength = Literal["strong", "weak", "none"]

# Strength -> the confidence written to `inferred_confidence`. Three discrete
# values rather than a continuous score: the numbers exist to be compared
# against `dossier_min_confidence`, and a rule-based classifier that invented
# 0.73 would be claiming a precision it does not have.
STRENGTH_CONFIDENCE: dict[Strength, float] = {"strong": 0.9, "weak": 0.5, "none": 0.0}


def provenance_rank(source: str | None) -> int:
    """Rank a provenance source on the ladder; anything unrecognised loses.

    Returns ``-1`` for ``None``, for ``"operator"`` (a separate lane, not a
    rung), and for any string that is not on the ladder — including a value read
    back from an older schema. A merge is "highest rank wins", so an unknown
    source must be unable to displace a real signal, and must not raise either:
    a stale row is not a reason to fail a build.
    """
    if source is None:
        return -1
    return _PROVENANCE_RANK.get(source, -1)


@dataclasses.dataclass(frozen=True)
class AgentSelfReport:
    """What a log-shipping agent on one machine says that machine is.

    One of these per ``host.name`` in the host-log datasets: the newest
    self-report the window holds, plus the addresses that machine claimed across
    it. Every field is the machine's own account of itself — the ``hostlog`` rung
    of the ladder — so a value here outranks anything inferred from the wire.

    :attr:`ips` is the RAW claim list, link-local and bridge addresses included.
    It is not an attribution: which of those addresses may carry this identity is
    :class:`AgentInventory`'s decision, and it is deliberately not this object's
    to make.
    """

    host_name: str
    # host.os.{name,family,version,kernel,platform,type}, only the keys present.
    # A dict rather than six fields because the render is "whatever it told us"
    # and a grid that adds a key should not need a schema change.
    os: dict[str, str] = dataclasses.field(default_factory=dict)
    # EVERY interface the machine can see on itself, including the bridge and
    # veth addresses a container host owns. Nothing pairs one with an IP, so
    # which of them (if any) is "the" hardware address is the classifier's call.
    macs: tuple[str, ...] = ()
    architecture: str | None = None
    agent_type: str | None = None
    agent_version: str | None = None
    ips: tuple[str, ...] = ()
    # Documents shipped in the window, and the span they cover: how alive the
    # agent is, as opposed to installed once and dead since. The dossier's
    # lifetime for an agent-only host comes from the two timestamps.
    doc_count: int = 0
    first_report: datetime | None = None
    last_report: datetime | None = None


@dataclasses.dataclass(frozen=True)
class AgentInventory:
    """The network's self-reporting machines, and who may claim which address.

    Built once per sweep by ``soc_ai.dossier.observe.collect_agent_inventory``
    and handed to every host build, because the answer is identical for all of
    them. Empty is the honest answer for a grid with no host-log datasets: the
    lane then contributes nothing at all.

    **THE UNIQUE-CLAIM RULE.** ``host.ip`` is an ARRAY of every address the
    machine can see on itself, and on a real network those arrays overlap:

    * Docker's default bridge gateway ``172.17.0.1`` is reported by every host
      running Docker — four of them on the network this was built against — and
      the ``172.18-31.x`` gateways recur the same way.
    * Yet ``172.16/12`` is NOT categorically noise: two machines hold real second
      interfaces in it. A subnet predicate is therefore wrong in both directions,
      accepting shared bridges and rejecting genuine addresses.
    * Link-local (``fe80::/10``, ``169.254/16``) is scoped PER LINK, so the same
      address legitimately exists on several of them and a single claim inside
      one window is not evidence of a unique holder.

    So identity is attributed by CLAIM COUNT, not by address shape:
    :meth:`for_ip` returns a self-report only for an address exactly one
    ``host.name`` claimed, and returns the claimant list instead when several
    did. That is what stops a dossier on a shared bridge address flapping between
    four identities from sweep to sweep — the fingerprint flap that re-stamps
    ``identity_rebound_at`` and prods the operator about a machine swap that
    never happened. Link-local and loopback addresses are excluded from
    :attr:`claims` entirely, so they can never be a unique claim.

    :attr:`errors` carries a failed pass's reason. An empty inventory from a
    failure looks exactly like a grid with no host logs, and both are "no
    signal" — no belief is retracted either way, because the classifier reads the
    absence of a self-report as an absence of signal.
    """

    hosts: tuple[AgentSelfReport, ...] = ()
    # ip -> every host.name that claimed it, sorted. Never a scalar: the whole
    # point is that a claim can be contested, and the contest is the answer.
    claims: dict[str, tuple[str, ...]] = dataclasses.field(default_factory=dict)
    errors: tuple[str, ...] = ()
    # Advisory notes from a healthy-but-degraded pass (a truncated cap), kept
    # apart from `errors` so a cap the operator can see does not read as a
    # failure. The sweep folds these into `DossierSummary.notes`, never
    # `errors`. Empty today — the agent pass has no truncation note yet — but
    # carried for symmetry with `DnsNameInventory` and the merge that reads both.
    notes: tuple[str, ...] = ()

    @classmethod
    def from_reports(
        cls, reports: Sequence[AgentSelfReport], *, errors: Sequence[str] = ()
    ) -> AgentInventory:
        """Build the claim map from the reports, so the two cannot disagree."""
        claims: dict[str, set[str]] = {}
        for report in reports:
            for raw in report.ips:
                ip = identity_bearing_ip(raw)
                if ip is not None:
                    claims.setdefault(ip, set()).add(report.host_name)
        return cls(
            hosts=tuple(reports),
            claims={ip: tuple(sorted(names)) for ip, names in claims.items()},
            errors=tuple(errors),
        )

    def unique_claims(self) -> dict[str, AgentSelfReport]:
        """Every address exactly ONE agent claims, mapped to that agent's report.

        This is also the set of addresses the census may adopt as network members:
        a machine that self-reports is an asset even when it is silent on the
        wire, and the quiet machine is the one whose identity nobody could name.
        """
        by_name = {report.host_name: report for report in self.hosts}
        out: dict[str, AgentSelfReport] = {}
        for ip, names in self.claims.items():
            if len(names) != 1:
                continue
            report = by_name.get(names[0])
            if report is not None:
                out[ip] = report
        return out

    def for_ip(self, ip: str) -> tuple[AgentSelfReport | None, tuple[str, ...]]:
        """``(self-report, contending claimants)`` for one address.

        Exactly one of the two is ever populated. A contended address yields no
        report at all — the identity is structurally unavailable rather than
        available-but-discouraged, so no classifier rule can resurrect it — and
        the claimant names come back so the absence can be EXPLAINED instead of
        looking like a host that never reported.
        """
        key = identity_bearing_ip(ip) or ip
        claimants = self.claims.get(key, ())
        if len(claimants) != 1:
            return None, claimants
        return next((h for h in self.hosts if h.host_name == claimants[0]), None), ()


def identity_bearing_ip(value: Any) -> str | None:
    """Normalise an address that can carry an identity, else ``None``.

    Rejects what cannot name a machine on the network however many agents report
    it: link-local (per-link scope, so uniqueness inside a window means nothing),
    loopback (every machine has the same one), the unspecified address, and
    multicast/reserved space. Everything else is returned in canonical form, so
    ``claims`` keys match the addresses the census and the store use.

    Deliberately NOT a private-vs-public or subnet test: ``172.17.0.1`` and
    ``172.16.20.5`` are both RFC-1918 and only one of them is noise. That
    distinction is the claim count's job, not this function's.
    """
    text = value if isinstance(value, str) else str(value or "")
    try:
        address = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    if (
        address.is_link_local
        or address.is_loopback
        or address.is_unspecified
        or address.is_multicast
        or address.is_reserved
    ):
        return None
    return address.compressed


@dataclasses.dataclass(frozen=True)
class DnsNameClaim:
    """One name the network's DNS answers pointed at one address, and how often.

    A claim is per (address, name) PAIR because that is what one aggregation
    bucket is: the sub-bucket of a QUERY name is the address it resolved to,
    and its ``doc_count`` is how many answers said so. Nothing here is a
    conclusion — a name that answered three times and one that answered two
    hundred are both claims, and :class:`DnsNameInventory` is what weighs them.

    :attr:`answers` is the whole weight of the evidence: DNS is not a first-party
    claim (a machine does not choose what a resolver hands out for its address),
    so volume and agreement are all the lane has.

    **THE CLAIM IS THE BOUNDARY.** Both key fields are normalised on construction,
    so everything downstream compares one spelling and one only:

    * the address, through :func:`identity_bearing_ip`, because
      ``2001:db8:0:0:0:0:0:5`` and ``2001:db8::5`` are one host. Left to the
      collector, a hand-built claim could not be found by its own key —
      :meth:`DnsNameInventory.consensus` is the census's entry point, so the host
      did not fail loudly, it silently stopped being adopted.
    * the name, case-folded and stripped of its trailing dot, because DNS is
      case-insensitive and resolvers randomise query case (0x20 encoding) to
      harden against spoofing. Two spellings of one name split that host's own
      vote and turn its majority into a tie, so the lane goes silent on exactly
      its best-attested hosts.

    Normalising here rather than in the collector is what makes the majority rule
    a property of the TYPE: a hand-built inventory and a collected one behave
    identically, which is the only version of that claim worth making.
    """

    ip: str
    name: str
    answers: int = 0
    # The span of answers behind the claim, from the documents. A DNS-only host
    # takes its census lifetime from these — it is demonstrably reachable enough
    # that something asked for it — and a row with no lifetime sorts first for
    # pruning, which would delete the very host the lane just named.
    first_answer: datetime | None = None
    last_answer: datetime | None = None

    def __post_init__(self) -> None:
        # `object.__setattr__` is the documented way to write a frozen
        # dataclass's fields during construction. This is normalisation, not a
        # patch: the value is settled before anyone can observe it, so the
        # "replace, don't patch" invariant still holds afterwards.
        object.__setattr__(self, "ip", identity_bearing_ip(self.ip) or self.ip)
        object.__setattr__(self, "name", fold_dns_name(self.name))


def fold_dns_name(value: str) -> str:
    """A DNS name in the one spelling the consensus counts votes over.

    Case-folded and stripped of the trailing root dot. See THE CLAIM IS THE
    BOUNDARY on :class:`DnsNameClaim` for why this cannot live in the collector.
    """
    return value.strip().rstrip(".").lower()


@dataclasses.dataclass(frozen=True)
class DnsName:
    """The lane's answer for one address: a name, or why there is not one.

    :meth:`DnsNameInventory.resolve` is the only thing that builds one, and it
    populates at most one of :attr:`name` and :attr:`withheld` — the same shape
    :class:`AgentInventory` uses for its report-or-claimants split. That is a
    guarantee the CONSTRUCTOR makes, not one this dataclass enforces: a
    hand-built ``DnsName`` carrying both is nonsense, and nothing stops it. The
    separation is the point: "nothing named it", "its names disagree" and "its
    name belongs to a service" are three different facts about a host, and a
    caller handed one merged string would collapse them right back together —
    which is what made a tied name render as "no hostname signal".
    """

    name: str | None = None
    # How the name was attested ("214 A/AAAA answers over the window"). Only
    # meaningful beside a name: a DNS name means little without its weight.
    evidence: str = ""
    # Why there is no name, when one was contested rather than absent. Empty for
    # an address nothing ever answered for — that is a silence with no story.
    withheld: str = ""
    observed_at: datetime | None = None


@dataclasses.dataclass(frozen=True)
class DnsNameInventory:
    """What the network's DNS answers call each internal address.

    Built once per sweep by ``soc_ai.dossier.observe.collect_dns_names`` and
    handed to every host build, the same shape as :class:`AgentInventory` and for
    the same reason: the answer is network-wide, so re-deriving it per address
    would be one extra aggregation per dossier for an identical result.

    **THE MAJORITY RULE.** One address routinely carries several names — a server
    hosting three services answers to three of them, and a CNAME chain lands more
    on top. So the name is decided by ANSWER COUNT per address: :meth:`for_ip`
    returns the name that strictly leads, and returns nothing at all when two
    names tie. A tie is contention, not a coin flip; withholding is what keeps a
    dossier from flapping between two equally-attested names sweep to sweep, and
    the reason comes back beside the ``None`` so the silence can be explained.

    **THE FAMILY RULE.** Per-address consensus is not enough on its own, because
    it only decides between names that COMPETE. A round-robin or HA name is the
    only name either of its addresses carries, so it wins both of them
    uncontested — and two hosts end up wearing one hostname at strong confidence,
    which is worse than the blank this lane exists to fill. So a name is counted
    per address FAMILY first: holding several addresses of one family makes it a
    service record rather than a host's name, and it claims none of them.

    One address per family is the case the rule is shaped around, not an
    exception to it: ``nas.example.internal`` with an A and an AAAA record is one
    machine on two addresses, and a blanket "names must hold one address" would
    blind the lane to every dual-stack host on the network. The exclusion is also
    per family — two A records and one AAAA leaves the v6 address named, because
    the ambiguity is entirely on the v4 side and there is no reason to spread it.
    Dropping a spread name never drops its addresses: an address DNS also knows
    by a real name keeps that name, the VIP simply stops competing for it.

    This is the ``telemetry`` rung — below ``banner`` and ``hostlog`` — because a
    DNS name is what a resolver hands out for an address, not what the machine
    says it is. An address can be re-pointed at a new host without the host ever
    knowing, so a machine's own report always outranks what DNS calls it.

    :attr:`errors` carries a failed or truncated pass's reason, and an empty
    inventory from a failure looks exactly like a grid with no DNS telemetry.
    Both are "no signal": the classifier reads the absence of a name as an
    absence of evidence, so nothing is retracted either way.
    """

    claims: tuple[DnsNameClaim, ...] = ()
    errors: tuple[str, ...] = ()
    # A truncated pass is a NOTE, not a failure: it means the cap was hit, not
    # that the query broke. Kept apart from `errors` so a run-row count is not
    # inflated by a cap that fires every sweep (see `_dns_truncation`). A genuine
    # pass failure still goes to `errors`.
    notes: tuple[str, ...] = ()
    # `(name, family) -> how many distinct addresses it holds`, for the pairs
    # holding more than one. Derived, so it is out of `repr` and out of equality
    # — two inventories with the same claims are the same inventory.
    #
    # Computed ONCE here rather than per lookup. It costs an `ip_address()` parse
    # per claim, and `consensus()` resolves every distinct address, so deriving
    # it inside `_resolve` made the sweep O(addresses x claims) PARSES: 56s of
    # pure CPU at the 10,000 claims the aggregation caps permit, with no `await`
    # in it to yield the event loop. That is the connection-pool freeze from the
    # 2026-08-05 dogfood batch, in a nightly job.
    _spread: dict[tuple[str, int], int] = dataclasses.field(
        init=False, repr=False, compare=False, default_factory=dict
    )
    # The claims grouped by address, from the SAME pass — because the scan was
    # the other half of that quadratic. `_spread` removed the repeated parse;
    # `_resolve` still walked every claim to find the few belonging to one
    # address, and `consensus()` calls it once per distinct address. At the caps
    # the aggregations permit (10,000 claims) that is 10,000 x distinct
    # addresses comparisons in a synchronous loop with no `await` in it, once
    # per sweep. Grouped here it is one pass to build and one short list to read.
    _by_ip: dict[str, tuple[DnsNameClaim, ...]] = dataclasses.field(
        init=False, repr=False, compare=False, default_factory=dict
    )

    def __post_init__(self) -> None:
        held: dict[tuple[str, int], set[str]] = {}
        by_ip: dict[str, list[DnsNameClaim]] = {}
        for claim in self.claims:
            # Grouped on `claim.ip`, which `DnsNameClaim` normalised on
            # construction — the same key `_resolve` looks up. THE CLAIM IS THE
            # BOUNDARY is what makes one dict serve both.
            by_ip.setdefault(claim.ip, []).append(claim)
            family = _address_family(claim.ip)
            if family is None:
                continue
            held.setdefault((claim.name, family), set()).add(claim.ip)
        object.__setattr__(
            self, "_spread", {key: len(ips) for key, ips in held.items() if len(ips) > 1}
        )
        object.__setattr__(self, "_by_ip", {ip: tuple(claims) for ip, claims in by_ip.items()})

    def resolve(self, ip: str) -> DnsName:
        """The lane's whole answer for one address, in one pass over its claims.

        One method rather than a name getter and a timestamp getter: the callers
        want both, and asking twice walked the claim list twice for an answer
        that is derived from the same scan.
        """
        winner, withheld = self._resolve(ip)
        if winner is None:
            return DnsName(withheld=withheld)
        return DnsName(
            name=winner.name,
            evidence=f"{winner.answers} A/AAAA answers over the window",
            observed_at=winner.last_answer,
        )

    def for_ip(self, ip: str) -> tuple[str | None, str]:
        """``(consensus name, the string that explains the state)``.

        A narrow convenience over :meth:`resolve` for callers that only want the
        name; the two strings are kept apart on :class:`DnsName` itself, where a
        caller can tell an attestation from a withholding.
        """
        answer = self.resolve(ip)
        return answer.name, answer.evidence or answer.withheld

    def consensus(self) -> dict[str, DnsNameClaim]:
        """Every address one name leads on, mapped to that merged claim.

        Also the set of addresses the census may adopt as network members: a host
        the network's DNS names is an asset even when it barely talks, and the
        quiet machine is the one nobody could otherwise identify. An address
        whose names tie, or whose only name is spread across its family, is
        absent — an address with no decidable name is not a host this lane can
        contribute, and adopting it would put a row in the table that a later
        sweep would have to argue with.
        """
        out: dict[str, DnsNameClaim] = {}
        for ip in self._by_ip:
            winner, _ = self._resolve(ip)
            if winner is not None:
                out[ip] = winner
        return out

    def _resolve(self, ip: str) -> tuple[DnsNameClaim | None, str]:
        """``(winning claim, why not)`` — the one place the name is decided.

        Reads only THIS address's claims, out of the ``_by_ip`` grouping built
        once in ``__post_init__``. A scan of every claim per address is what made
        :meth:`consensus` quadratic.

        The note is empty on a win and on an address nothing named; anything else
        is a withheld name explaining itself.
        """
        key = identity_bearing_ip(ip) or ip
        merged: dict[str, DnsNameClaim] = {}
        excluded: dict[str, int] = {}
        for claim in self._by_ip.get(key, ()):
            family = _address_family(claim.ip)
            held = self._spread.get((claim.name, family)) if family is not None else None
            if held is not None:
                # Counted, not silently dropped: an address whose ONLY name is a
                # service record must be able to say so. The count is of distinct
                # ADDRESSES, which is what the rule decided on — counting claims
                # would say "3 addresses" about a name split over two buckets.
                excluded[claim.name] = held
                continue
            prior = merged.get(claim.name)
            merged[claim.name] = claim if prior is None else _merge_claims(prior, claim)
        if not merged:
            if excluded:
                name, count = sorted(excluded.items())[0]
                return None, (
                    f"{name} answers for {count} addresses of one family — "
                    "a service record, not a host name"
                )
            return None, ""
        # Name-ordered within an answer-count tie so a tie is DETECTED
        # identically every sweep rather than depending on bucket order.
        ranked = sorted(merged.values(), key=lambda claim: (-claim.answers, claim.name))
        leaders = [claim for claim in ranked if claim.answers == ranked[0].answers]
        if len(leaders) > 1:
            return None, f"{len(leaders)} names tie for {key}"
        return ranked[0], ""


def _merge_claims(first: DnsNameClaim, second: DnsNameClaim) -> DnsNameClaim:
    """Fold two claims of the same name on the same address into one.

    Answer counts add and the spans widen. The collector emits one claim per
    bucket, and a grid that splits a name across buckets (a dual-mapped field, a
    second dataset) must not have its evidence read as two competing claims.
    """
    return dataclasses.replace(
        first,
        answers=first.answers + second.answers,
        first_answer=_earlier(first.first_answer, second.first_answer),
        last_answer=_later(first.last_answer, second.last_answer),
    )


def _address_family(ip: str) -> int | None:
    """``4`` / ``6`` for an address, ``None`` for anything that will not parse.

    Unparseable is not a family: the family rule can only exclude a name it can
    reason about, and a claim whose address makes no sense is left to the
    majority to deal with rather than silently binned by a check that failed.
    """
    try:
        return ipaddress.ip_address(ip).version
    except ValueError:
        return None


def _earlier(first: datetime | None, second: datetime | None) -> datetime | None:
    if first is None or second is None:
        return first or second
    return min(first, second)


def _later(first: datetime | None, second: datetime | None) -> datetime | None:
    if first is None or second is None:
        return first or second
    return max(first, second)


@dataclasses.dataclass(frozen=True)
class HostObservations:
    """Everything the collector gathered about one IP over one window.

    Populated by ``soc_ai.dossier.observe.collect_host_observations`` and
    consumed by ``soc_ai.dossier.infer.infer_host_facts``. Every field defaults
    to empty so a partial collection is still a usable observation set: the
    collector never raises, and a sub-query that failed appends its reason to
    :attr:`errors` and leaves its slice empty rather than aborting the host.

    :attr:`available_datasets` is what separates "no signal" from "no such
    telemetry on this grid". A grid with no ``zeek.dhcp`` yields no DHCP lease
    for every host on it; without knowing the dataset is absent, the classifier
    would read that silence as "statically addressed" and be confidently wrong
    about the entire network.

    Timestamps come from the documents, never from the clock, so a build over a
    historical window concludes what was true then.
    """

    ip: str
    total_events: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    # Terms-agg buckets as [{"value": int, "count": int}] — the shape
    # `host_summary._bucket_pairs` already produces.
    resp_ports: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    orig_ports: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    resp_peer_count: int = 0
    orig_peer_count: int = 0
    # Distinct hour buckets with responder traffic. A service answering across
    # 19 hours is a service; one answering in a single hour is an incident.
    resp_hours: int = 0
    services: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    datasets: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    # 0..23 -> event count, folded client-side from the hourly date_histogram.
    # Scripting is disabled on hardened grids, so no painless hour-of-day agg.
    hour_of_day: dict[int, int] = dataclasses.field(default_factory=dict)
    orig_bytes_p50: float | None = None
    orig_bytes_p95: float | None = None
    resp_bytes_p50: float | None = None
    resp_bytes_p95: float | None = None
    registered_domains: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    dns_queries: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    sni: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    ja3_distinct: int = 0
    # Identity records, NEWEST-FIRST — the opposite of `host_summary`'s
    # oldest-first sample. A dossier reports what a host is now; the name it
    # announced 14 days ago is history, not identity.
    user_agents: tuple[str, ...] = ()
    dhcp: tuple[dict[str, Any], ...] = ()
    ssh_banners: tuple[dict[str, Any], ...] = ()
    windows_identity: tuple[dict[str, Any], ...] = ()
    software: tuple[dict[str, Any], ...] = ()
    host_names: tuple[str, ...] = ()
    ptr_name: str | None = None
    # `event.dataset` values this grid actually carries, from the TTL-cached
    # inventory. Absence of a dataset is a REPORTABLE answer, not a negative.
    available_datasets: frozenset[str] = frozenset()
    # What an agent ON this machine says it is — the `hostlog` rung. Present
    # ONLY when exactly one agent claimed this address (see `AgentInventory`);
    # `None` covers all three of "no host logs on this grid", "no agent here"
    # and "several agents claim this address", which the classifier tells apart
    # by looking at the field below.
    agent_report: AgentSelfReport | None = None
    # The agents contending for this address, when there are several. Non-empty
    # means the identity was WITHHELD rather than missing, and it is what lets
    # the classifier say which machines are arguing over the address.
    agent_ip_claimants: tuple[str, ...] = ()
    # What the network's DNS answers call this address — the `telemetry` rung,
    # below the machine's own report. Present ONLY when one name strictly leads
    # the window's answers for it (see `DnsNameInventory`); `None` covers "no DNS
    # on this grid", "nothing resolved here" and "its names tie" alike, because
    # none of the three is evidence of what the host is called.
    dns_name: str | None = None
    # How the name was attested ("214 A/AAAA answers over the window"), for the
    # Fact's evidence line: a DNS name means little without its weight. Only ever
    # set beside a name.
    dns_name_evidence: str = ""
    # Why this address has NO DNS name, when one was contested rather than
    # absent. The counterpart of `agent_ip_claimants`, and split from the
    # evidence for the same reason: non-empty means the name was WITHHELD, which
    # the classifier must be able to say out loud instead of reporting the host
    # as having no DNS signal at all.
    dns_name_withheld: str = ""
    # The newest answer behind that name. A DNS-only host has no network
    # sighting, so without this its one populated Fact would carry no timestamp
    # at all — or worse, the build clock, which looks freshly confirmed forever.
    dns_name_observed_at: datetime | None = None
    # Per-sub-query failures, human-readable. Non-empty is not an error state:
    # the build proceeds on whatever did come back.
    errors: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class Fact:
    """One concluded dossier field, with its evidence and its provenance.

    The classifier returns these keyed by :data:`DOSSIER_FIELDS` name; the store
    writes them into the inference lane and nowhere else. A Fact is never the
    effective value of a field — the resolver decides that at read time by
    checking the operator lane first — so a build may freely conclude something
    an operator has overridden. That is the point: continued disagreement is the
    signal that eventually prods the operator, and it can only accumulate
    because the builder keeps recording what it currently believes.

    :attr:`evidence` follows the ``host_summary`` convention verbatim —
    ``"pve01 (from dhcp)"`` — so a reader can see what the call was made from
    instead of inferring it. :attr:`conflict` is set when two sources disagree
    at family level and names both; it is never resolved by silently preferring
    one.

    :attr:`observed_at` is the timestamp of the supporting evidence, taken from
    the observation set. Never ``datetime.now()``: a fact stamped with the build
    time would look freshly confirmed forever, which is exactly how the resolver
    stops being able to tell a stale belief from a current one.
    """

    field: str
    value: str | None = None
    # Structured payload for the fields a scalar cannot carry:
    # `services_offered`, `activity_profile`, `management_plane`.
    value_json: Any | None = None
    confidence: float = 0.0
    strength: Strength = "none"
    source: ProvenanceSource = "behaviour"
    evidence: list[str] = dataclasses.field(default_factory=list)
    observed_at: datetime | None = None
    conflict: str | None = None
