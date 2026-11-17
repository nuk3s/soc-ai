"""The campaign engine: the facts of the runs in, the campaigns out.

Pure: no store, no grid, no clock. The result does not depend on the order
of the input, so a rebuild from the stored runs gives the same campaigns.

A campaign starts from a seed (:attr:`RunFacts.is_seed`). A run joins when
one link holds between it and a member:

* **Session.** The two runs hold the same community id, and the two times of
  that id are within one wave gap. The run has any verdict.
* **Actor.** Both are true positives of an attack class with the same source
  machine, within one horizon.
* **Artifact.** The run is a true positive with a source machine, on the
  target machine of the member, and both hold the same rule, CVE id or HTTP
  method and path. The same source machine has no time limit. A new source
  machine needs one horizon.
* **Documents.** The run is a true positive finding. Each document it cites
  is stored, and both machines of each are parties. Within one horizon.
* **Target as source.** The source machine of the run is the target machine
  of the member, within one horizon after the member. The impact of the
  member reads succeeded: the attack on that target worked.

An end with no machine never equals a machine. A true positive from a source
outside the estate therefore joins no campaign of another actor.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta

from soc_ai.campaigns.types import (
    DIRECTION_BEYOND,
    DIRECTION_FORWARD,
    DIRECTION_REVERSE,
    JOIN_NAMED,
    KIND_FINDING,
    LINK_ACTOR,
    LINK_ARTIFACT,
    LINK_DOCUMENTS,
    LINK_INCLUDED,
    LINK_NAMED,
    LINK_SEED,
    LINK_SESSION,
    LINK_TARGET_SOURCE,
    ROLE_ACTOR,
    ROLE_TARGET,
    STAGES,
    ActorWaves,
    CampaignDraft,
    Detection,
    DocFacts,
    Edge,
    Link,
    Member,
    NamedHost,
    Party,
    RunFacts,
    SessionGroup,
    StageStep,
    Wave,
)
from soc_ai.event_time import WAVE_GAP_SECONDS, Point, group_waves
from soc_ai.hunting.weight import decay_horizon_hours

# The most document ids that one piece of evidence lists.
MAX_IDS = 5


def _at(run: RunFacts) -> datetime:
    """The event time of an eligible run. The engine drops a run with none."""
    assert run.event_time is not None
    return run.event_time


def _order(run: RunFacts) -> tuple[datetime, str]:
    return (_at(run), run.run_id)


def _apart(a: RunFacts, b: RunFacts) -> timedelta:
    return abs(_at(a) - _at(b))


def _shared_artifact(a: RunFacts, b: RunFacts) -> str | None:
    """The artifact that two runs share, in words, or None."""
    rules = a.rules & b.rules
    if rules:
        return f"rule: {min(rules)}"
    cves = a.cves & b.cves
    if cves:
        return f"cve: {min(cves)}"
    http = a.http_keys & b.http_keys
    if http:
        return f"http: {min(http)}"
    return None


def _is_hit(m: RunFacts) -> bool:
    """True for a member whose attack on its target worked.

    Only such a member lets its target carry the activity on. An attempt
    with no proof, or a scan, does not: each host that was probed and that
    later acts would join the campaign of the prober. The impact guard keeps
    ``succeeded`` only with a cited content record.
    """
    return m.is_attack and m.impact == "succeeded"


@dataclass(frozen=True)
class _Rules:
    """The link rules between a run ``r`` and a member ``m``."""

    horizon: timedelta
    gap: timedelta

    def session(self, r: RunFacts, m: RunFacts) -> str | None:
        """The community id that both hold within one gap, or None.

        ``m`` is a true positive: a run joins the session of a true positive
        member only. A run with another verdict passes no link on.
        """
        if not m.is_true_positive or not r.sessions or not m.sessions:
            return None
        theirs: dict[str, list[datetime]] = defaultdict(list)
        for cid, at in m.sessions:
            theirs[cid].append(at)
        found: list[str] = []
        for cid, at in r.sessions:
            if any(abs(at - other) <= self.gap for other in theirs.get(cid, ())):
                found.append(cid)
        return min(found) if found else None

    def actor(self, r: RunFacts, m: RunFacts) -> bool:
        return (
            r.is_attack
            and m.is_attack
            and r.source is not None
            and r.source == m.source
            and _apart(r, m) <= self.horizon
        )

    def artifact(self, r: RunFacts, m: RunFacts) -> str | None:
        """The shared artifact when the Artifact link holds, or None."""
        if not (r.is_true_positive and m.is_attack):
            return None
        if r.source is None or r.target is None or r.target != m.target:
            return None
        shared = _shared_artifact(r, m)
        if shared is None:
            return None
        if r.source == m.source or _apart(r, m) <= self.horizon:
            return shared
        return None

    def target_source(self, r: RunFacts, m: RunFacts) -> bool:
        return (
            r.is_attack
            and _is_hit(m)
            and r.source is not None
            and r.source == m.target
            and _at(m) - self.gap <= _at(r) <= _at(m) + self.horizon
        )

    def joins(self, r: RunFacts, m: RunFacts) -> bool:
        return (
            self.session(r, m) is not None
            or self.actor(r, m)
            or self.artifact(r, m) is not None
            or self.target_source(r, m)
        )


def _documents_candidate(run: RunFacts) -> bool:
    return (
        run.kind == KIND_FINDING
        and run.is_true_positive
        and bool(run.cited_ids)
        and run.cited_unresolved == 0
    )


def _cited(run: RunFacts) -> list[DocFacts]:
    return [d for d in run.documents if d.cited]


def _between(documents: Sequence[DocFacts], machines: set[str] | frozenset[str]) -> bool:
    """True when there is a document and both machines of each are in the set."""
    return bool(documents) and all(
        d.source is not None
        and d.target is not None
        and d.source in machines
        and d.target in machines
        for d in documents
    )


def _attack_machines(members: Iterable[RunFacts]) -> set[str]:
    out: set[str] = set()
    for m in members:
        if m.is_attack:
            out.update(k for k in (m.source, m.target) if k is not None)
    return out


class _Sets:
    """Union-find over run ids. The lower id is the root, so the result is stable."""

    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def add(self, key: str) -> None:
        self.parent.setdefault(key, key)

    def __contains__(self, key: str) -> bool:
        return key in self.parent

    def find(self, key: str) -> str:
        root = key
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[key] != root:
            self.parent[key], key = root, self.parent[key]
        return root

    def union(self, a: str, b: str) -> bool:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return False
        self.parent[max(ra, rb)] = min(ra, rb)
        return True

    def groups(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = defaultdict(list)
        for key in self.parent:
            out[self.find(key)].append(key)
        return out


def _join_by_documents(
    runs: Sequence[RunFacts],
    by_id: dict[str, RunFacts],
    sets: _Sets,
    add: Callable[[RunFacts], None],
    rules: _Rules,
) -> bool:
    """Join each finding that the Documents link holds for. True when a set changed.

    The link reads the parties of a whole campaign, so it runs after the
    links between two runs settle.
    """
    changed = False
    groups = {root: [by_id[k] for k in keys] for root, keys in sets.groups().items()}
    machines = {root: _attack_machines(members) for root, members in groups.items()}
    for r in runs:
        if not _documents_candidate(r):
            continue
        cited = _cited(r)
        for root, members in groups.items():
            if r.run_id in sets and sets.find(r.run_id) == sets.find(root):
                continue
            if not _between(cited, machines[root]):
                continue
            if not any(_apart(r, m) <= rules.horizon for m in members):
                continue
            if r.run_id not in sets:
                add(r)
            sets.union(r.run_id, root)
            changed = True
    return changed


def _actor_clusters(runs: Sequence[RunFacts], rules: _Rules) -> dict[str, list[RunFacts]]:
    """For each attack run with a source machine, the runs that the Actor link chains to it.

    The attack runs of one source machine in time order, cut where two
    neighbours are more than one horizon apart. Each run of a part reaches
    each other run of it by Actor links, so the part joins as a whole. This
    keeps the work linear for a source machine with thousands of runs.
    """
    by_source: dict[str, list[RunFacts]] = defaultdict(list)
    for r in runs:
        if r.is_attack and r.source is not None:
            by_source[r.source].append(r)
    out: dict[str, list[RunFacts]] = {}
    for held in by_source.values():
        part: list[RunFacts] = []
        for r in sorted(held, key=_order):
            if part and _at(r) - _at(part[-1]) > rules.horizon:
                part = []
            part.append(r)
            out[r.run_id] = part
    return out


def _membership(
    runs: Sequence[RunFacts], rules: _Rules, included: Mapping[str, str] | None = None
) -> list[list[RunFacts]]:
    """The members of each campaign.

    The true positive runs that a seed reaches by the links form a campaign.
    A run with another verdict then joins the one campaign that holds the
    nearest true positive member on its session. Such a run passes no link
    on and merges no two campaigns.
    """
    positives = [r for r in runs if r.is_true_positive]
    by_id = {r.run_id: r for r in positives}
    by_source: dict[str, list[RunFacts]] = defaultdict(list)
    by_target: dict[str, list[RunFacts]] = defaultdict(list)
    by_session: dict[str, list[RunFacts]] = defaultdict(list)
    for r in positives:
        if r.source is not None:
            by_source[r.source].append(r)
        if r.target is not None:
            by_target[r.target].append(r)
        for cid in {cid for cid, _ in r.sessions}:
            by_session[cid].append(r)
    clusters = _actor_clusters(positives, rules)
    chained: set[int] = set()

    sets = _Sets()
    queue: deque[RunFacts] = deque()

    def add(run: RunFacts) -> None:
        sets.add(run.run_id)
        queue.append(run)

    def reach(m: RunFacts) -> list[RunFacts]:
        """The runs that a rule between two runs can join to the member ``m``."""
        seen: dict[str, RunFacts] = {}
        for cid in {cid for cid, _ in m.sessions}:
            seen.update((r.run_id, r) for r in by_session[cid])
        if m.is_attack and m.target is not None:
            seen.update((r.run_id, r) for r in by_target[m.target])
            seen.update((r.run_id, r) for r in by_source[m.target])
        seen.pop(m.run_id, None)
        return list(seen.values())

    for r in positives:
        if r.is_seed:
            add(r)

    while True:
        while queue:
            m = queue.popleft()
            cluster = clusters.get(m.run_id)
            if cluster is not None and id(cluster) not in chained:
                # The Actor link, for the whole chain of this source machine.
                chained.add(id(cluster))
                for r in cluster:
                    if r.run_id not in sets:
                        add(r)
                    sets.union(r.run_id, m.run_id)
            for r in reach(m):
                if r.run_id in sets and sets.find(r.run_id) == sets.find(m.run_id):
                    continue
                if not rules.joins(r, m):
                    continue
                if r.run_id not in sets:
                    add(r)
                sets.union(r.run_id, m.run_id)
        if not _join_by_documents(positives, by_id, sets, add, rules):
            break

    groups = {root: [by_id[k] for k in keys] for root, keys in sets.groups().items()}
    _attach_named(positives, groups, sets, rules)
    _attach_other_verdicts(runs, groups, sets, rules)
    _attach_included(runs, groups, sets, included or {})
    return [sorted(members, key=_order) for members in groups.values()]


def _attach_included(
    runs: Sequence[RunFacts],
    groups: dict[str, list[RunFacts]],
    sets: _Sets,
    included: Mapping[str, str],
) -> None:
    """Add each run that an analyst joined to the campaign of another run.

    ``included`` maps the run to its anchor: a run that was in the campaign
    when the analyst decided. The run joins the campaign that holds the anchor
    now. It has any verdict, it passes no link on and it starts no campaign.
    A run that the links already put in a campaign stays there, and an anchor
    that is in no campaign joins nothing.
    """
    if not included:
        return
    held = {m.run_id for members in groups.values() for m in members}
    for r in runs:
        anchor = included.get(r.run_id)
        if anchor is None or r.run_id in held or anchor not in sets:
            continue
        groups[sets.find(anchor)].append(r)
        held.add(r.run_id)


def _attach_named(
    positives: Sequence[RunFacts], groups: dict[str, list[RunFacts]], sets: _Sets, rules: _Rules
) -> None:
    """Add each finding run that names the two machines of a campaign.

    A finding can cite summary queries and no single record. Its run then
    knows its target and no source, so no link between two runs can hold. The
    finding still names its machines. When it names one machine beside the
    target, and a campaign holds an attack from that machine on that target
    within one horizon, the run joins that campaign with that machine as its
    source.

    The names prove no direction. So the run joins only a pair that other
    members prove: it starts no campaign, it adds no machine and it passes no
    link on. A finding that names three machines, or a pair that no campaign
    holds, stays out.
    """
    attacks: dict[tuple[str, str], list[RunFacts]] = defaultdict(list)
    for members in groups.values():
        for m in members:
            if m.is_attack and m.source is not None and m.target is not None:
                attacks[(m.source, m.target)].append(m)
    for r in positives:
        if r.run_id in sets or r.kind != KIND_FINDING or not r.is_attack:
            continue
        if r.source is not None or r.target is None or r.event_time is None:
            continue
        others = set(r.named_machines) - {r.target}
        if len(others) != 1:
            continue
        near = [
            m for m in attacks.get((min(others), r.target), ()) if _apart(r, m) <= rules.horizon
        ]
        if not near:
            continue
        proven = _nearest(r, near)
        groups[sets.find(proven.run_id)].append(
            replace(
                r,
                source=proven.source,
                source_address=proven.source_address,
                source_name=proven.source_name,
                source_join=JOIN_NAMED,
            )
        )


def _attach_other_verdicts(
    runs: Sequence[RunFacts], groups: dict[str, list[RunFacts]], sets: _Sets, rules: _Rules
) -> None:
    """Add each run with another verdict to the campaign of its session.

    The campaign is the one that holds the nearest true positive member on a
    session of the run. The run joins one campaign only.
    """
    member_sessions: dict[str, list[RunFacts]] = defaultdict(list)
    for members in groups.values():
        for m in members:
            for cid in {cid for cid, _ in m.sessions}:
                member_sessions[cid].append(m)
    for r in runs:
        if r.is_true_positive or not r.sessions:
            continue
        near = {
            m.run_id: m
            for cid in {cid for cid, _ in r.sessions}
            for m in member_sessions.get(cid, ())
            if rules.session(r, m) is not None
        }
        if near:
            groups[sets.find(_nearest(r, list(near.values())).run_id)].append(r)


def _pair(m: RunFacts) -> frozenset[str]:
    assert m.source is not None
    assert m.target is not None
    return frozenset((m.source, m.target))


def _pair_actors(core: Sequence[RunFacts]) -> dict[frozenset[str], str]:
    """For each two machines, the one that is the source of most of their runs.

    ``core`` is the attack members with two machines, in time order. An alert
    on the answer of a server has the server as its source, and the requests
    outnumber it. The earliest run decides a tie.
    """
    counts: dict[frozenset[str], Counter[str]] = defaultdict(Counter)
    first: dict[frozenset[str], str] = {}
    for m in core:
        assert m.source is not None
        counts[_pair(m)][m.source] += 1
        first.setdefault(_pair(m), m.source)
    out: dict[frozenset[str], str] = {}
    for pair, count in counts.items():
        best = max(count.values())
        leaders = [key for key, n in count.items() if n == best]
        out[pair] = leaders[0] if len(leaders) == 1 else first[pair]
    return out


def _roles(core: Sequence[RunFacts], pair_actor: dict[frozenset[str], str]) -> dict[str, str]:
    """Actor or target for each machine: its side in the first pair that holds it.

    A target that later acts on other hosts stays a target, however many
    runs it makes. An actor that another machine attacks later stays an actor.
    """
    roles: dict[str, str] = {}
    for m in core:
        actor = pair_actor[_pair(m)]
        other = m.target if actor == m.source else m.source
        assert other is not None
        roles.setdefault(actor, ROLE_ACTOR)
        roles.setdefault(other, ROLE_TARGET)
    return roles


def _first_hits(
    core: Sequence[RunFacts], pair_actor: dict[frozenset[str], str]
) -> dict[str, datetime]:
    """For each machine, the first time that an attack on it worked."""
    out: dict[str, datetime] = {}
    for m in core:
        if _is_hit(m) and pair_actor[_pair(m)] == m.source and m.target is not None:
            out.setdefault(m.target, _at(m))
    return out


def _direction(
    m: RunFacts,
    pair_actor: dict[frozenset[str], str],
    first_hit: dict[str, datetime],
    gap: timedelta,
) -> str:
    """Forward, reverse or beyond, for one member.

    Reverse: the source is the target side of its pair, for example an alert
    on the answer of a server. Beyond: an attack on the source worked before
    this run, so the activity moved on from it.
    """
    if not m.is_attack or m.source is None:
        return DIRECTION_FORWARD
    if m.target is not None and m.target != m.source:
        actor = pair_actor.get(frozenset((m.source, m.target)))
        if actor is not None and actor != m.source:
            return DIRECTION_REVERSE
    hit = first_hit.get(m.source)
    if hit is not None and hit <= _at(m) + gap:
        return DIRECTION_BEYOND
    return DIRECTION_FORWARD


def _stage(m: RunFacts, direction: str) -> str | None:
    """The stage that one member proves, or None."""
    if not m.is_true_positive:
        return None
    if direction == DIRECTION_BEYOND:
        return "movement"
    if m.stage_claim in STAGES:
        # Movement is a fact of the structure: a target that acts. A claim
        # alone does not prove it.
        return "action" if m.stage_claim == "movement" else m.stage_claim
    if m.attack_class == "recon":
        return "reconnaissance"
    if m.impact == "succeeded":
        return "access"
    if m.attack_class in ("exploit_attempt", "post_compromise") or m.impact == "attempted":
        return "attempt"
    return None


@dataclass
class _PartyAcc:
    role: str
    names: list[str] = field(default_factory=list)
    addresses: list[str] = field(default_factory=list)
    joins: list[str] = field(default_factory=list)
    first: datetime | None = None
    last: datetime | None = None
    runs: set[str] = field(default_factory=set)
    not_beyond: bool = False


def _parties(
    group: Sequence[RunFacts], roles: dict[str, str], direction: dict[str, str]
) -> tuple[Party, ...]:
    acc: dict[str, _PartyAcc] = {}

    def touch(
        key: str,
        default_role: str,
        name: str | None,
        address: str | None,
        join: str | None,
        at: datetime,
        run_id: str,
        *,
        beyond: bool,
    ) -> None:
        a = acc.get(key)
        if a is None:
            a = acc[key] = _PartyAcc(role=roles.get(key, default_role))
        for value, held in ((name, a.names), (address, a.addresses), (join, a.joins)):
            if value and value not in held:
                held.append(value)
        a.first = at if a.first is None else min(a.first, at)
        a.last = at if a.last is None else max(a.last, at)
        a.runs.add(run_id)
        if not beyond:
            a.not_beyond = True

    for m in group:
        if not m.is_true_positive:
            continue
        at, way = _at(m), direction[m.run_id]
        if m.source is not None:
            touch(
                m.source,
                ROLE_ACTOR,
                m.source_name,
                m.source_address,
                m.source_join,
                at,
                m.run_id,
                beyond=False,
            )
        if m.target is not None and m.target != m.source:
            touch(
                m.target,
                ROLE_TARGET,
                m.target_name,
                m.target_address,
                m.target_join,
                at,
                m.run_id,
                beyond=way == DIRECTION_BEYOND,
            )
        if m.kind == KIND_FINDING and way == DIRECTION_FORWARD and m.source is not None:
            # The alert documents of a finding are its evidence of an attack.
            # Each host that such an alert shows its source on is a target. A
            # name lookup or a package fetch of the source names no target.
            for doc in m.documents:
                if not doc.is_alert:
                    continue
                if doc.source == m.source and doc.target is not None and doc.target != m.source:
                    touch(
                        doc.target,
                        ROLE_TARGET,
                        None,
                        doc.target_address,
                        None,
                        at,
                        m.run_id,
                        beyond=False,
                    )

    def rank(item: tuple[str, _PartyAcc]) -> tuple[int, int, datetime, str]:
        key, a = item
        is_beyond = a.role == ROLE_TARGET and not a.not_beyond
        assert a.first is not None
        return (0 if a.role == ROLE_ACTOR else 1, 1 if is_beyond else 0, a.first, key)

    return tuple(
        Party(
            machine_key=key,
            role=a.role,
            name=a.names[0] if a.names else None,
            addresses=tuple(a.addresses),
            join=a.joins[0] if a.joins else None,
            first_event=a.first,
            last_event=a.last,
            member_runs=len(a.runs),
            beyond=a.role == ROLE_TARGET and not a.not_beyond,
        )
        for key, a in sorted(acc.items(), key=rank)
    )


def _nearest(m: RunFacts, candidates: Sequence[RunFacts]) -> RunFacts:
    return min(candidates, key=lambda o: (_apart(m, o), o.run_id))


@dataclass
class _GroupIndex:
    """The members of one campaign by what a link reads."""

    by_session: dict[str, list[RunFacts]] = field(default_factory=lambda: defaultdict(list))
    by_source: dict[str, list[RunFacts]] = field(default_factory=lambda: defaultdict(list))
    by_target: dict[str, list[RunFacts]] = field(default_factory=lambda: defaultdict(list))

    @classmethod
    def of(cls, group: Sequence[RunFacts]) -> _GroupIndex:
        index = cls()
        for m in group:
            if not m.is_true_positive:
                continue
            for cid in {cid for cid, _ in m.sessions}:
                index.by_session[cid].append(m)
            if m.is_attack and m.source is not None:
                index.by_source[m.source].append(m)
            if m.is_attack and m.target is not None:
                index.by_target[m.target].append(m)
        return index


def _link_among(
    m: RunFacts,
    index: _GroupIndex,
    allowed: Callable[[RunFacts], bool],
    roles: dict[str, str],
    machines: frozenset[str],
    rules: _Rules,
) -> Link | None:
    """The first link of the order that holds between ``m`` and an allowed member."""
    in_session = {
        o.run_id: o
        for cid in {cid for cid, _ in m.sessions}
        for o in index.by_session.get(cid, ())
        if allowed(o) and rules.session(m, o) is not None
    }
    if in_session:
        other = _nearest(m, list(in_session.values()))
        return Link(LINK_SESSION, other.run_id, community_id=rules.session(m, other))

    same_source = [o for o in index.by_source.get(m.source or "", ()) if allowed(o)]
    on_target = [o for o in index.by_target.get(m.target or "", ()) if allowed(o)]
    source_role = roles.get(m.source) if m.source is not None else None
    if m.is_attack and source_role == ROLE_TARGET:
        # A run from a target reads this link before any artifact: that the
        # target acts is what the analyst must see.
        hits = [o for o in index.by_target.get(m.source or "", ()) if allowed(o)]
        near = hits or same_source
        if near:
            return Link(LINK_TARGET_SOURCE, _nearest(m, near).run_id, machine=m.source)
    else:
        same_actor = [o for o in same_source if rules.actor(m, o)]
        if same_actor:
            return Link(LINK_ACTOR, _nearest(m, same_actor).run_id, machine=m.source)

    with_artifact = [o for o in on_target if rules.artifact(m, o) is not None]
    if with_artifact:
        other = _nearest(m, with_artifact)
        return Link(LINK_ARTIFACT, other.run_id, artifact=rules.artifact(m, other))

    if _documents_candidate(m) and _between(_cited(m), machines):
        return Link(LINK_DOCUMENTS, document_ids=tuple(d.id for d in _cited(m)[:MAX_IDS]))
    return None


def _link(
    m: RunFacts,
    index: _GroupIndex,
    seed: RunFacts,
    roles: dict[str, str],
    machines: frozenset[str],
    rules: _Rules,
    included: Mapping[str, str] | None = None,
) -> Link:
    """Why ``m`` is a member: the first link of the order that holds.

    A link with an earlier member comes first: the run joined what was there
    before it. A run with no such link reads its link with a later member.
    """
    if m.run_id == seed.run_id:
        return Link(LINK_SEED)
    if included and m.run_id in included:
        # The analyst joined it. A link that the engine can also prove reads
        # first, so this line is the answer only when no other link holds.
        proven = _link_among(m, index, lambda o: o.run_id != m.run_id, roles, machines, rules)
        return proven or Link(LINK_INCLUDED, included[m.run_id])
    if m.source_join == JOIN_NAMED:
        # The run holds no record between the two machines. Its link is the
        # nearest attack of the same pair, which is why it joined.
        pair = [
            o
            for o in index.by_source.get(m.source or "", ())
            if o.run_id != m.run_id and o.target == m.target and o.source_join != JOIN_NAMED
        ]
        return Link(LINK_NAMED, _nearest(m, pair).run_id if pair else None, machine=m.source)
    found = _link_among(
        m, index, lambda o: _order(o) < _order(m), roles, machines, rules
    ) or _link_among(m, index, lambda o: o.run_id != m.run_id, roles, machines, rules)
    if found is not None:
        return found
    # A member always has a link. This line is the answer for a run that
    # joined through a chain of the Actor link longer than one horizon.
    near = [o for o in index.by_source.get(m.source or "", ()) if o.run_id != m.run_id]
    kind = LINK_TARGET_SOURCE if roles.get(m.source or "") == ROLE_TARGET else LINK_ACTOR
    return Link(kind, _nearest(m, near).run_id if near else None, machine=m.source)


def _ladder(group: Sequence[RunFacts], stages: dict[str, str | None]) -> tuple[StageStep, ...]:
    steps: list[StageStep] = []
    for stage in STAGES:
        at_stage = [m for m in group if stages[m.run_id] == stage]
        if not at_stage:
            steps.append(StageStep(stage))
            continue
        first = at_stage[0]
        proof = first.cited_ids[0] if first.cited_ids else None
        if proof is None and first.documents:
            proof = first.documents[0].id
        held = next((d for d in first.documents if d.id == proof), None)
        steps.append(
            StageStep(
                stage,
                True,
                _at(first),
                len(at_stage),
                first.run_id,
                proof,
                held.label if held is not None else "",
                held.at if held is not None else None,
            )
        )
    return tuple(steps)


def _waves(
    group: Sequence[RunFacts],
    parties: Sequence[Party],
    direction: dict[str, str],
    gap_seconds: float,
) -> tuple[ActorWaves, ...]:
    out: list[ActorWaves] = []
    for party in parties:
        if party.role != ROLE_ACTOR:
            continue
        points = [
            Point(m.run_id, _at(m))
            for m in group
            if m.is_true_positive
            and m.source == party.machine_key
            and direction[m.run_id] == DIRECTION_FORWARD
        ]
        if not points:
            continue
        waves = tuple(Wave(w.n, w.start, w.end, w.count) for w in group_waves(points, gap_seconds))
        out.append(ActorWaves(party.machine_key, waves))
    return tuple(out)


def _documents(group: Sequence[RunFacts]) -> list[DocFacts]:
    """Each stored document of the members, once, in time order."""
    seen: dict[str, DocFacts] = {}
    for m in group:
        for doc in m.documents:
            if doc.id and doc.id not in seen:
                seen[doc.id] = doc
    return sorted(seen.values(), key=lambda d: (d.at or datetime.max, d.id))


def _sessions(documents: Sequence[DocFacts], machines: frozenset[str]) -> tuple[SessionGroup, ...]:
    """The documents between two parties on a port that no member alert is on."""
    attacked = {(d.target, d.target_port) for d in documents if d.is_alert and d.target is not None}
    grouped: dict[tuple[str, str, int], list[DocFacts]] = defaultdict(list)
    for doc in documents:
        if doc.at is None or doc.target_port is None or doc.is_alert:
            continue
        if doc.source is None or doc.target is None or doc.source == doc.target:
            continue
        if doc.source not in machines or doc.target not in machines:
            continue
        if (doc.target, doc.target_port) in attacked:
            continue
        grouped[(doc.source, doc.target, doc.target_port)].append(doc)
    out: list[SessionGroup] = []
    for (source, target, port), docs in grouped.items():
        times = [d.at for d in docs if d.at is not None]
        out.append(
            SessionGroup(
                source=source,
                target=target,
                port=port,
                dataset=docs[0].dataset,
                documents=len(docs),
                first_at=min(times),
                last_at=max(times),
                document_ids=tuple(d.id for d in docs[:MAX_IDS]),
            )
        )
    return tuple(sorted(out, key=lambda s: (s.first_at, s.source, s.target, s.port)))


def _named(
    group: Sequence[RunFacts], documents: Sequence[DocFacts], parties: Sequence[Party]
) -> tuple[NamedHost, ...]:
    """The hosts that member documents name and that are no end of the campaign."""
    known: set[str] = set()
    for party in parties:
        known.update(a.lower() for a in party.addresses)
        if party.name:
            known.add(party.name.lower())
    for m in group:
        known.update(v.lower() for v in (m.source_address, m.target_address) if v)
    for doc in documents:
        known.update(v.lower() for v in (doc.source_address, doc.target_address) if v)
    machines = {party.machine_key for party in parties}
    naming: dict[str, list[str]] = defaultdict(list)
    for doc in documents:
        # Only a document between two parties speaks for the campaign. A
        # finding also stores documents of other hosts.
        if doc.source not in machines or doc.target not in machines:
            continue
        for value in doc.named:
            if value.lower() not in known:
                naming[value].append(doc.id)
    return tuple(
        NamedHost(value, len(ids), tuple(ids[:MAX_IDS]))
        for value, ids in sorted(naming.items(), key=lambda item: (-len(item[1]), item[0]))
    )


def _detection(group: Sequence[RunFacts], stages: dict[str, str | None]) -> tuple[Detection, ...]:
    out: list[Detection] = []
    for stage in STAGES:
        judged = [m for m in group if stages[m.run_id] == stage and m.finished_at is not None]
        if not judged:
            continue
        first = min(judged, key=lambda m: (m.finished_at or datetime.max, m.run_id))
        assert first.finished_at is not None
        seconds = max(0, int((first.finished_at - _at(first)).total_seconds()))
        out.append(
            Detection(stage, first.tier, first.run_id, _at(first), first.finished_at, seconds)
        )
    return tuple(out)


@dataclass
class _EdgeAcc:
    runs: set[str] = field(default_factory=set)
    stage: str | None = None
    first: datetime | None = None
    last: datetime | None = None
    beyond: bool = False

    def add(
        self, run_id: str, at: datetime, stage: str | None = None, *, beyond: bool = False
    ) -> None:
        self.runs.add(run_id)
        if stage in STAGES and (
            self.stage is None or STAGES.index(stage) > STAGES.index(self.stage)
        ):
            self.stage = stage
        self.first = at if self.first is None else min(self.first, at)
        self.last = at if self.last is None else max(self.last, at)
        self.beyond = self.beyond or beyond


def _edges(
    group: Sequence[RunFacts], direction: dict[str, str], stages: dict[str, str | None]
) -> tuple[Edge, ...]:
    """The arrows of the attack graph, oldest first.

    One arrow for each two machines that a true positive member has as its
    ends. A run on the answer of a server counts on the arrow of its actor.
    A target that only an alert document of a finding shows gets an arrow
    from the source of that finding, with no stage: no run judged it.
    """
    by_run: dict[tuple[str, str], _EdgeAcc] = defaultdict(_EdgeAcc)
    by_document: dict[tuple[str, str], _EdgeAcc] = defaultdict(_EdgeAcc)
    for m in group:
        if not m.is_true_positive or m.source is None:
            continue
        way = direction[m.run_id]
        if m.target is not None and m.target != m.source:
            key = (m.target, m.source) if way == DIRECTION_REVERSE else (m.source, m.target)
            by_run[key].add(m.run_id, _at(m), stages[m.run_id], beyond=way == DIRECTION_BEYOND)
        if m.kind == KIND_FINDING and way == DIRECTION_FORWARD:
            for doc in m.documents:
                if doc.is_alert and doc.source == m.source and doc.target not in (None, m.source):
                    assert doc.target is not None
                    by_document[(m.source, doc.target)].add(m.run_id, _at(m))
    out: list[Edge] = []
    for from_documents, held in ((False, by_run), (True, by_document)):
        for (source, target), acc in held.items():
            if from_documents and (source, target) in by_run:
                continue
            assert acc.first is not None
            assert acc.last is not None
            out.append(
                Edge(
                    source,
                    target,
                    len(acc.runs),
                    acc.stage,
                    acc.first,
                    acc.last,
                    acc.beyond,
                    from_documents,
                )
            )
    return tuple(sorted(out, key=lambda edge: (edge.first_at, edge.source, edge.target)))


def _draft(
    group: Sequence[RunFacts],
    rules: _Rules,
    gap_seconds: float,
    included: Mapping[str, str] | None = None,
) -> CampaignDraft:
    core = [
        m
        for m in group
        if m.is_attack and m.source is not None and m.target is not None and m.source != m.target
    ]
    pair_actor = _pair_actors(core)
    roles = _roles(core, pair_actor)
    first_hit = _first_hits(core, pair_actor)
    seed = next(m for m in group if m.is_seed)
    direction = {m.run_id: _direction(m, pair_actor, first_hit, rules.gap) for m in group}
    stages = {m.run_id: _stage(m, direction[m.run_id]) for m in group}
    parties = _parties(group, roles, direction)
    machines = frozenset(p.machine_key for p in parties)
    index = _GroupIndex.of(group)
    members = tuple(
        Member(
            run=m,
            link=_link(m, index, seed, roles, machines, rules, included or {}),
            direction=direction[m.run_id],
            stage=stages[m.run_id],
            verdict_differs=not m.is_true_positive,
        )
        for m in group
    )
    ladder = _ladder(group, stages)
    reached = [step.stage for step in ladder if step.reached]
    times = [_at(m) for m in group if m.is_true_positive]
    documents = _documents(group)
    return CampaignDraft(
        seed_run_id=seed.run_id,
        members=members,
        parties=parties,
        ladder=ladder,
        stage=reached[-1] if reached else None,
        first_event=min(times),
        last_event=max(times),
        waves=_waves(group, parties, direction, gap_seconds),
        sessions=_sessions(documents, machines),
        named=_named(group, documents, parties),
        detection=_detection(group, stages),
        pairs=frozenset(
            (m.source, m.target)
            for m in core
            if direction[m.run_id] == DIRECTION_FORWARD
            and m.source is not None
            and m.target is not None
        ),
        edges=_edges(group, direction, stages),
    )


def build_campaigns(
    facts: Iterable[RunFacts],
    *,
    horizon_hours: float | None = None,
    gap_seconds: float = WAVE_GAP_SECONDS,
    excluded: Collection[str] = (),
    included: Mapping[str, str] | None = None,
) -> list[CampaignDraft]:
    """The campaigns that the facts of the runs form, oldest first.

    ``horizon_hours`` is the decay horizon of a lead when None. A run with no
    event time is in no campaign: the links read the time.

    ``excluded`` holds the run ids that an analyst took out of a campaign:
    such a run joins no campaign and passes no link on. ``included`` maps a
    run id to an anchor run id: the analyst joined the run to the campaign of
    the anchor (:func:`_attach_included`). An exclusion wins over an inclusion.
    """
    hours = decay_horizon_hours() if horizon_hours is None else horizon_hours
    rules = _Rules(timedelta(hours=hours), timedelta(seconds=gap_seconds))
    unique: dict[str, RunFacts] = {}
    out = frozenset(excluded)
    for run in facts:
        if run.run_id and run.event_time is not None and run.run_id not in out:
            unique.setdefault(run.run_id, run)
    runs = sorted(unique.values(), key=_order)
    joined = {k: v for k, v in (included or {}).items() if k not in out and v not in out}
    drafts = [
        _draft(group, rules, gap_seconds, joined) for group in _membership(runs, rules, joined)
    ]
    return sorted(drafts, key=lambda d: (d.first_event, d.seed_run_id))
