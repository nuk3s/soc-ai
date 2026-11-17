"""The records of the campaign engine. Pure: no I/O, no clock.

Every time is a naive UTC ``datetime``, like the times of the store. A
machine is its machine key, ``agent:<id>``, ``mac:<address>`` or
``ip:<address>``. None stands for an end that the Hosts data joins to no one
machine: such an end is never a party.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

# The five stages, lowest first.
STAGES: tuple[str, ...] = ("reconnaissance", "attempt", "access", "action", "movement")

TRUE_POSITIVE = "true_positive"

# The class of a run that can start a campaign and that can make a party: the
# three hostile alert classes of the classifier, and a finding of a hunt.
CLASS_FINDING = "finding"
ATTACK_CLASSES = frozenset({"recon", "exploit_attempt", "post_compromise", CLASS_FINDING})
# The impact values that state a hostile action. A true positive with one of
# them is an attack, whatever its class.
ATTACK_IMPACTS = frozenset({"attempted", "succeeded"})

KIND_ALERT = "alert"
KIND_FINDING = "finding"
KIND_LEAD = "lead"

LINK_SEED = "seed"
LINK_SESSION = "session"
LINK_ACTOR = "actor"
LINK_ARTIFACT = "artifact"
LINK_DOCUMENTS = "documents"
LINK_TARGET_SOURCE = "target_source"
# A finding names the two machines of a campaign and cites no single record.
LINK_NAMED = "named_pair"
# An analyst joined the investigation to the campaign of another investigation.
LINK_INCLUDED = "included"
# The order in which the engine names the link of a member.
LINK_ORDER: tuple[str, ...] = (
    LINK_SESSION,
    LINK_ACTOR,
    LINK_ARTIFACT,
    LINK_DOCUMENTS,
    LINK_TARGET_SOURCE,
    LINK_NAMED,
    LINK_INCLUDED,
)

# How a run got a machine that no record states: the engine took it from the
# machines that the finding names (:func:`soc_ai.campaigns.engine._attach_named`).
JOIN_NAMED = "named"

ROLE_ACTOR = "actor"
ROLE_TARGET = "target"

# The direction of a member run against the roles of the campaign.
DIRECTION_FORWARD = "forward"  # an actor acts
DIRECTION_REVERSE = "reverse"  # a target acts on an actor
DIRECTION_BEYOND = "beyond"  # a target acts on a host that is no actor

TIER_ALERT = "alert"
TIER_ANALYTIC = "analytic"
TIER_SCHEDULED_HUNT = "scheduled_hunt"
TIER_LEAD_HUNT = "lead_hunt"
TIER_HUNT = "hunt"


def naive_utc(value: Any) -> datetime | None:
    """An ISO string or a datetime as naive UTC, or None."""
    if isinstance(value, datetime):
        at = value
    elif isinstance(value, str) and value.strip():
        try:
            at = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    return at.astimezone(UTC).replace(tzinfo=None) if at.tzinfo is not None else at


def jsonable(value: Any) -> Any:
    """A record of this module as JSON types.

    A time is an ISO string, a set is a sorted list, a tuple is a list and a
    record is a mapping of its fields.
    """
    if isinstance(value, datetime):
        return value.isoformat()
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: jsonable(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, frozenset | set):
        return sorted(jsonable(v) for v in value)
    if isinstance(value, tuple | list):
        return [jsonable(v) for v in value]
    if isinstance(value, Mapping):
        return {str(k): jsonable(v) for k, v in value.items()}
    return value


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _texts(value: Any) -> tuple[str, ...]:
    items = value if isinstance(value, list | tuple) else []
    return tuple(v for v in items if isinstance(v, str) and v)


@dataclass(frozen=True)
class DocFacts:
    """What the engine reads of one stored grid document of a run."""

    id: str
    at: datetime | None = None
    community_id: str | None = None
    source: str | None = None
    target: str | None = None
    source_address: str | None = None
    target_address: str | None = None
    target_port: int | None = None
    dataset: str | None = None
    is_alert: bool = False
    rule_key: str = ""
    named: tuple[str, ...] = ()
    cited: bool = False
    # What the document records, in the words of the timeline:
    # :func:`soc_ai.event_time.document_label`. Empty in the facts of version 1.
    label: str = ""

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> DocFacts:
        port = data.get("target_port")
        return cls(
            id=str(data.get("id") or ""),
            at=naive_utc(data.get("at")),
            community_id=_text(data.get("community_id")),
            source=_text(data.get("source")),
            target=_text(data.get("target")),
            source_address=_text(data.get("source_address")),
            target_address=_text(data.get("target_address")),
            target_port=port if isinstance(port, int) and not isinstance(port, bool) else None,
            dataset=_text(data.get("dataset")),
            is_alert=bool(data.get("is_alert")),
            rule_key=str(data.get("rule_key") or ""),
            named=_texts(data.get("named")),
            cited=bool(data.get("cited")),
            label=_text(data.get("label")) or "",
        )


@dataclass(frozen=True)
class RunFacts:
    """What the engine reads of one stored run.

    ``source`` and ``target`` are machine keys. ``attack_class`` is one of
    :data:`ATTACK_CLASSES`, or empty for an alert of another class.
    ``stage_claim`` is the stage that a finding run states, after the guard.
    ``sessions`` are the community ids of the run, each with the time of its
    document.
    """

    run_id: str
    kind: str = KIND_ALERT
    verdict: str = TRUE_POSITIVE
    label: str = ""
    event_time: datetime | None = None
    finished_at: datetime | None = None
    source: str | None = None
    target: str | None = None
    source_address: str | None = None
    target_address: str | None = None
    source_name: str | None = None
    target_name: str | None = None
    source_join: str | None = None
    target_join: str | None = None
    attack_class: str = ""
    impact: str | None = None
    stage_claim: str | None = None
    rules: frozenset[str] = frozenset()
    cves: frozenset[str] = frozenset()
    http_keys: frozenset[str] = frozenset()
    sessions: tuple[tuple[str, datetime], ...] = ()
    documents: tuple[DocFacts, ...] = ()
    cited_ids: tuple[str, ...] = ()
    cited_unresolved: int = 0
    tier: str = TIER_ALERT
    hunt_id: str | None = None
    # The machine keys of the hosts that the finding of the run names. A
    # finding run only. A finding that cites summary queries gives its run no
    # record between two machines, and these names are then what it states.
    named_machines: tuple[str, ...] = ()

    @property
    def is_true_positive(self) -> bool:
        return self.verdict == TRUE_POSITIVE

    @property
    def is_attack(self) -> bool:
        """A true positive of an attack class, or with a hostile impact.

        The class comes from the Suricata classification of the rule. A true
        positive of a Sigma rule or of a Zeek notice has no such class: its
        impact of attempted or succeeded states that a hostile action was sent.
        """
        return self.is_true_positive and (
            self.attack_class in ATTACK_CLASSES or self.impact in ATTACK_IMPACTS
        )

    @property
    def is_seed(self) -> bool:
        """A run that can start a campaign.

        A true positive of an attack class with an event time and two
        different machines. A true positive with the impact ``none`` starts
        no campaign: a probe with no answer is the usual case.
        """
        return (
            self.is_attack
            and self.event_time is not None
            and self.source is not None
            and self.target is not None
            and self.source != self.target
            and self.impact != "none"
            # A source that the engine took from the names of a finding proves
            # no direction, so it starts no campaign.
            and self.source_join != JOIN_NAMED
        )

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = jsonable(self)
        return out

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> RunFacts:
        sessions: list[tuple[str, datetime]] = []
        for item in data.get("sessions") or []:
            if isinstance(item, list | tuple) and len(item) == 2:
                at = naive_utc(item[1])
                if isinstance(item[0], str) and item[0] and at is not None:
                    sessions.append((item[0], at))
        documents = tuple(
            DocFacts.from_json(d) for d in data.get("documents") or [] if isinstance(d, Mapping)
        )
        unresolved = data.get("cited_unresolved")
        return cls(
            run_id=str(data.get("run_id") or ""),
            kind=str(data.get("kind") or KIND_ALERT),
            verdict=str(data.get("verdict") or ""),
            label=str(data.get("label") or ""),
            event_time=naive_utc(data.get("event_time")),
            finished_at=naive_utc(data.get("finished_at")),
            source=_text(data.get("source")),
            target=_text(data.get("target")),
            source_address=_text(data.get("source_address")),
            target_address=_text(data.get("target_address")),
            source_name=_text(data.get("source_name")),
            target_name=_text(data.get("target_name")),
            source_join=_text(data.get("source_join")),
            target_join=_text(data.get("target_join")),
            attack_class=str(data.get("attack_class") or ""),
            impact=_text(data.get("impact")),
            stage_claim=_text(data.get("stage_claim")),
            rules=frozenset(_texts(data.get("rules"))),
            cves=frozenset(_texts(data.get("cves"))),
            http_keys=frozenset(_texts(data.get("http_keys"))),
            sessions=tuple(sessions),
            documents=documents,
            cited_ids=_texts(data.get("cited_ids")),
            cited_unresolved=unresolved if isinstance(unresolved, int) else 0,
            tier=str(data.get("tier") or TIER_ALERT),
            hunt_id=_text(data.get("hunt_id")),
            named_machines=_texts(data.get("named_machines")),
        )


@dataclass(frozen=True)
class Link:
    """Why a member belongs, with the evidence.

    ``member_run_id`` is the other member that the link holds with.
    ``machine`` is the actor of an Actor link and the target of a Target as
    source link. ``artifact`` reads ``rule: <name>``, ``cve: <id>`` or
    ``http: <method> <path>``.
    """

    type: str
    member_run_id: str | None = None
    machine: str | None = None
    artifact: str | None = None
    community_id: str | None = None
    document_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class Member:
    run: RunFacts
    link: Link
    direction: str = DIRECTION_FORWARD
    stage: str | None = None
    verdict_differs: bool = False


@dataclass(frozen=True)
class Party:
    """One machine of a campaign.

    ``beyond`` is true for a target that only a target of the campaign acted
    on: the activity moved to it.
    """

    machine_key: str
    role: str
    name: str | None = None
    addresses: tuple[str, ...] = ()
    join: str | None = None
    first_event: datetime | None = None
    last_event: datetime | None = None
    member_runs: int = 0
    beyond: bool = False


@dataclass(frozen=True)
class StageStep:
    """One stage of the ladder: reached or not, with the proving member.

    ``proof_label`` and ``proof_at`` are the label and the time of the proof
    document in the facts of the proof run. They are empty and None when the
    run holds no such document.
    """

    stage: str
    reached: bool = False
    first_at: datetime | None = None
    members: int = 0
    proof_run_id: str | None = None
    proof_document_id: str | None = None
    proof_label: str = ""
    proof_at: datetime | None = None


@dataclass(frozen=True)
class Wave:
    n: int
    start: datetime
    end: datetime
    events: int


@dataclass(frozen=True)
class ActorWaves:
    machine_key: str
    waves: tuple[Wave, ...] = ()


@dataclass(frozen=True)
class SessionGroup:
    """Documents between two parties on a port that no member alert is on."""

    source: str
    target: str
    port: int
    dataset: str | None
    documents: int
    first_at: datetime
    last_at: datetime
    document_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class NamedHost:
    """A host or an address that member documents name and that is no party."""

    value: str
    documents: int
    document_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class Edge:
    """One arrow of the attack graph: the true positive runs from one machine to another.

    ``stage`` is the highest stage that a run of the arrow proves. ``beyond``
    marks an arrow from a machine that an attack worked on. ``from_documents``
    marks an arrow that no run has as its two ends: an alert document of a
    finding shows it, and ``runs`` then counts the findings that hold one.
    """

    source: str
    target: str
    runs: int
    stage: str | None
    first_at: datetime
    last_at: datetime
    beyond: bool = False
    from_documents: bool = False


@dataclass(frozen=True)
class Detection:
    """The member that got the first verdict at one stage."""

    stage: str
    tier: str
    run_id: str
    event_at: datetime
    verdict_at: datetime
    seconds: int


@dataclass(frozen=True)
class CampaignDraft:
    """One campaign as the engine built it. The service gives it an id."""

    seed_run_id: str
    members: tuple[Member, ...]
    parties: tuple[Party, ...]
    ladder: tuple[StageStep, ...]
    stage: str | None
    first_event: datetime
    last_event: datetime
    waves: tuple[ActorWaves, ...] = ()
    sessions: tuple[SessionGroup, ...] = ()
    named: tuple[NamedHost, ...] = ()
    detection: tuple[Detection, ...] = ()
    pairs: frozenset[tuple[str, str]] = frozenset()
    edges: tuple[Edge, ...] = ()

    @property
    def run_ids(self) -> tuple[str, ...]:
        return tuple(m.run.run_id for m in self.members)

    @property
    def beyond_runs(self) -> int:
        return sum(1 for m in self.members if m.direction == DIRECTION_BEYOND)
