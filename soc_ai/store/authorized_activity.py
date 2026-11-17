"""Authorized activity: the store of the analyst's authorization decisions.

The owner runs exploit tests on the production grid. From 2026-10-31 to
2026-11-13, 18 of 27 true positive verdicts and 41 of 51 recommended actions
came from one such test. Each run asked for a case, and no record could say
"this activity is authorized".

One :class:`~soc_ai.store.models.AuthorizedActivity` row is one decision. It
holds a label, a scope and a mandatory expiry. The scope has three parts: the
exact source addresses, one target address and an explicit list of rule
names. A run must match all three
(:func:`soc_ai.agent.authorized_activity.match`).

Each address is stored with the key of the machine that held it when the
analyst made the decision. A source address must be an address that the
agent of its machine reports (:func:`address_problem`). A container address,
a bridge address, an address that joined its machine by a DNS name or a DHCP
lease, and an address that no agent reports can never be a source.

A run that matched keeps its verdict. It carries
``investigations.authorization_id`` and a display copy in
``report["authorized_activity"]``. Three things read the link and nothing
else changes: the case request is closed, the run raises no notification of
its own, and the run forms no lead (:func:`holds_run`).

A row is never deleted. An expiry keeps the marks of the runs that matched.
A revoke returns those runs to normal handling: every reader asks
:func:`marks_for` or :func:`holds_run`, and both answer "no" for a revoked row.

A record can also name one campaign (:func:`create_for_campaign`). Such a
record lists the machines of the campaign, each an actor or a target, and no
rule. The rules of that form live in :mod:`soc_ai.campaigns.authorization`.
The scope of a campaign record has an empty source list and an empty target
address, so the match of the rule-list form never takes it.

This module imports nothing from :mod:`soc_ai.agent`. The agent package
imports the store, and the pure match function lives there.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.auth import utcnow
from soc_ai.store.models import AuthorizedActivity, HostDossier, HostMachine, Investigation

__all__ = [
    "DEFAULT_DAYS",
    "EARLIER_DAYS_MAX",
    "LABEL_MAX",
    "MAX_DAYS",
    "MAX_RULE_NAMES",
    "MAX_SOURCES",
    "RECENT_DAYS",
    "REPORT_KEY",
    "ROLE_ACTOR",
    "ROLE_TARGET",
    "STATE_ACTIVE",
    "STATE_EXPIRED",
    "STATE_REVOKED",
    "MachineRef",
    "Mark",
    "PartyEntry",
    "RunCount",
    "Scope",
    "ScopeEntry",
    "ScopeError",
    "address_problem",
    "authorization_id_of",
    "bridge_addresses",
    "campaign_record",
    "create",
    "create_for_campaign",
    "earlier_candidates",
    "get",
    "holds_run",
    "holds_sql",
    "in_force",
    "list_recent",
    "machine_key_now",
    "machine_names",
    "machine_refs",
    "mark_expiry_recorded",
    "marks_for",
    "recently_expired",
    "revoke",
    "rule_name_key",
    "run_counts",
    "run_ids",
    "runs_after",
    "runs_on_pair",
    "scope_of",
    "state_of",
    "unrecorded_expiries",
]

# The expiry the dialog offers first, and the longest one the store accepts.
DEFAULT_DAYS = 7
MAX_DAYS = 30
# How far back "apply to the earlier runs" may reach.
EARLIER_DAYS_MAX = 30
MAX_SOURCES = 8
LABEL_MAX = 120
# The most rule names one scope lists.
MAX_RULE_NAMES = 20
# How long an ended authorization stays in the match read, in the hunt block
# and on the card list. The hunt block of earlier conclusions reads 7 days too
# (soc_ai.hunting.earlier.EARLIER_WINDOW_DAYS).
RECENT_DAYS = 7

STATE_ACTIVE = "active"
STATE_EXPIRED = "expired"
STATE_REVOKED = "revoked"

# The two roles of a machine of a campaign record.
ROLE_ACTOR = "actor"
ROLE_TARGET = "target"

# The key of the display copy in ``investigations.report``.
REPORT_KEY = "authorized_activity"
# The two values of ``report["authorized_activity"]["state"]``.
RUN_MATCHED = "matched"
RUN_OUTSIDE = "outside"


class ScopeError(ValueError):
    """A scope the store refuses. ``reason`` is the code, the text is the hint."""

    def __init__(self, reason: str, hint: str) -> None:
        super().__init__(hint)
        self.reason = reason
        self.hint = hint


@dataclass(frozen=True)
class ScopeEntry:
    """One machine of a scope: the address the analyst saw, and its identity.

    ``machine_key`` is the key of the machine in the Hosts data when the
    decision was made, or None when the Hosts data held no machine for the
    address. ``name`` is display text only.
    """

    address: str
    machine_key: str | None = None
    name: str | None = None

    def as_json(self) -> dict[str, Any]:
        return {"address": self.address, "machine_key": self.machine_key, "name": self.name}


@dataclass(frozen=True)
class PartyEntry:
    """One listed machine of a campaign record: its key, its role, its name and its addresses.

    ``machine_key`` decides a match. ``name`` and ``addresses`` are what the
    Hosts data held at the decision: display text, and the addresses that
    tell an address that moved to another machine.
    """

    machine_key: str
    role: str
    name: str | None = None
    addresses: tuple[str, ...] = ()

    def as_json(self) -> dict[str, Any]:
        return {
            "machine_key": self.machine_key,
            "role": self.role,
            "name": self.name,
            "addresses": list(self.addresses),
        }


@dataclass(frozen=True)
class Scope:
    """An authorization as the match function reads it. Times are naive UTC.

    ``campaign_id`` is set for a campaign record. Its ``parties`` list the
    machines, and its sources, target and rule names are empty.
    """

    id: int
    label: str
    sources: tuple[ScopeEntry, ...]
    target: ScopeEntry
    rule_names: tuple[str, ...]
    rule_class: str
    starts_at: datetime
    expires_at: datetime
    created_by: str = "anonymous"
    revoked_at: datetime | None = None
    campaign_id: int | None = None
    parties: tuple[PartyEntry, ...] = ()

    @property
    def actors(self) -> frozenset[str]:
        """The machine keys of the listed actors of a campaign record."""
        return frozenset(p.machine_key for p in self.parties if p.role == ROLE_ACTOR)

    @property
    def targets(self) -> frozenset[str]:
        """The machine keys of the listed targets of a campaign record."""
        return frozenset(p.machine_key for p in self.parties if p.role == ROLE_TARGET)


@dataclass(frozen=True)
class MachineRef:
    """The machine an address belongs to now: its key, its name and the join.

    ``kind`` is how the address joined the machine in the Hosts data: ``agent``
    when the agent of the machine reports the address, ``dhcp`` or ``name``
    for a weaker join, ``network`` for an address no agent reports, and
    ``container`` for an address inside a bridge of the machine.
    """

    key: str
    name: str | None = None
    kind: str | None = None


@dataclass(frozen=True)
class Mark:
    """What a run shows about its authorization.

    ``holds`` is False after a revoke: the run then gets normal handling.
    """

    id: int
    label: str
    state: str
    expires_at: datetime
    by: str
    holds: bool


@dataclass(frozen=True)
class RunCount:
    """The runs that matched one authorization.

    ``since_decision`` counts the runs made at or after the decision.
    ``earlier`` counts the earlier runs the analyst applied the decision to.
    """

    total: int = 0
    since_decision: int = 0
    earlier: int = 0
    last_at: datetime | None = None


# ── Pure helpers ───────────────────────────────────────────────────────────


# The text of a run inside a scope. The triage model never reads an
# authorization, by design, so a run inside a scope can say "No record of
# authorized testing covers this traffic." under a banner that names the
# authorization (polish review 2026-11-13). The owner rule: an ungrounded
# statement is grounded or stripped, never bannered. The page drops such a
# sentence when it reads the run, and the store keeps the report as the model
# wrote it, so a revoke returns the text.
_DENIAL_NEGATION = re.compile(
    r"\b(?:no|not|none|without|lacks?|lacking|absent|cannot find|can not find|could not find)\b"
    r"|n['\u2019]t\b",
    re.IGNORECASE,
)
# "Unauthorized" describes an action. It denies no authorization record, so
# the look-behind leaves it out: a sentence with it is evidence and stays.
_DENIAL_TERM = re.compile(
    r"(?<!un)authori[sz]|sanctioned|pen-?test|penetration test|red[ -]team"
    r"|approved (?:test|scan|activity)",
    re.IGNORECASE,
)
# A sentence ends at . ! or ? and any closing marks, before whitespace or the
# end of the line. The splitter of narrative grounding reads text the same way.
_SENTENCE_END = re.compile(r"[.!?]+(?:\*\*|__|[*_`\"')\]])*(?=\s|$)")
# A list bullet, a list number, a heading mark or a quote mark before the text.
_LINE_LEAD = re.compile(r"^\s*(?:[-*+\u2022]\s+|\d+[.)]\s+|#{1,6}\s+|>\s+)?")


def denies_authorization(sentence: str) -> bool:
    """True when a sentence denies an authorization: a negation and an authorization term."""
    return bool(_DENIAL_TERM.search(sentence) and _DENIAL_NEGATION.search(sentence))


def _sentences(line: str) -> list[str]:
    out: list[str] = []
    start = 0
    for m in _SENTENCE_END.finditer(line):
        out.append(line[start : m.end()].strip())
        start = m.end()
    out.append(line[start:].strip())
    return [s for s in out if s]


# The joins that close one clause and open the next inside a sentence.
_CLAUSE_JOIN = re.compile(r",\s+(?:and|but|so)\s+|;\s+")


def _without_denying_clauses(sentence: str) -> str:
    """One sentence without its clauses that deny an authorization.

    A sentence that denies nothing comes back as it was. A sentence that is a
    denial in each clause comes back empty, and the caller drops it. A
    sentence with evidence in one clause and the denial in another keeps the
    evidence: the headline of a run is often one such sentence.
    """
    if not denies_authorization(sentence):
        return sentence
    clauses = _CLAUSE_JOIN.split(sentence)
    kept = [c for c in clauses if not denies_authorization(c)]
    if not kept or len(kept) == len(clauses):
        return ""
    body = ", and ".join(c.strip().rstrip(".!?") for c in kept)
    # The clause that now opens the sentence takes the capital letter.
    return f"{body[:1].upper()}{body[1:]}."


def drop_authorization_denials(text: str) -> str:
    """``text`` without each sentence that denies an authorization.

    For a run whose authorization holds, at read time only. A sentence goes
    when it holds a negation and an authorization term
    (:func:`denies_authorization`). A sentence with no such term stays, so
    "No case exists." stays. A sentence that states an authorization stays,
    so "The scan was authorized by the owner." stays. The text works line by
    line, so a list keeps its shape. When every sentence would go, the text
    comes back whole. Text with nothing to drop comes back as it was.
    """
    if not text or not _DENIAL_TERM.search(text):
        return text
    lines: list[str] = []
    changed = False
    kept_any = False
    for line in text.split("\n"):
        if not line.strip():
            lines.append("")
            continue
        lead = _LINE_LEAD.match(line)
        prefix = lead.group(0) if lead else ""
        sentences = _sentences(line[len(prefix) :])
        kept = [c for s in sentences if (c := _without_denying_clauses(s))]
        if kept:
            kept_any = True
        if kept == sentences:
            lines.append(line)
            continue
        changed = True
        if kept:
            lines.append(prefix + " ".join(kept))
    if not changed or not kept_any:
        return text
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def run_text_for_mark(text: str, mark: Mark | None) -> str:
    """The text of a run as the console reads it under its mark.

    A mark that holds drops each sentence that denies an authorization. An
    unmarked run and a run whose authorization an analyst revoked keep every
    sentence.
    """
    if mark is None or not mark.holds:
        return text
    return drop_authorization_denials(text)


def _naive(value: datetime) -> datetime:
    return value.astimezone(UTC).replace(tzinfo=None) if value.tzinfo is not None else value


def rule_name_key(name: str | None) -> str:
    """A rule name with its whitespace folded. Two names match only when the keys are equal.

    The comparison is exact and keeps the case. No prefix and no pattern
    matches: a scope covers the rule names its list holds, and no other.
    """
    return " ".join((name or "").split())


def state_of(row: Any, now: datetime | None = None) -> str:
    """``active``, ``expired`` or ``revoked``. A revoke outranks an expiry."""
    if row.revoked_at is not None:
        return STATE_REVOKED
    return STATE_EXPIRED if _naive(row.expires_at) <= (now or utcnow()) else STATE_ACTIVE


def _entry(raw: Any) -> ScopeEntry | None:
    if not isinstance(raw, Mapping):
        return None
    address = str(raw.get("address") or "").strip()
    if not address:
        return None
    key = raw.get("machine_key")
    name = raw.get("name")
    return ScopeEntry(
        address=address,
        machine_key=str(key) if isinstance(key, str) and key else None,
        name=str(name) if isinstance(name, str) and name else None,
    )


def _party(raw: Any) -> PartyEntry | None:
    if not isinstance(raw, Mapping):
        return None
    key = raw.get("machine_key")
    role = raw.get("role")
    if not isinstance(key, str) or not key or role not in (ROLE_ACTOR, ROLE_TARGET):
        return None
    name = raw.get("name")
    addresses = raw.get("addresses")
    return PartyEntry(
        machine_key=key,
        role=str(role),
        name=name if isinstance(name, str) and name else None,
        addresses=tuple(str(a) for a in (addresses if isinstance(addresses, list) else []) if a),
    )


def scope_of(row: AuthorizedActivity) -> Scope:
    """The row as the match function reads it."""
    sources = tuple(e for e in (_entry(raw) for raw in (row.sources or [])) if e is not None)
    campaign_id = getattr(row, "campaign_id", None)
    parties = tuple(
        p for p in (_party(raw) for raw in (getattr(row, "parties", None) or [])) if p is not None
    )
    names = tuple(
        key for key in (rule_name_key(str(n)) for n in (row.rule_names or []) if n) if key
    )
    return Scope(
        id=int(row.id),
        label=row.label,
        sources=sources,
        target=ScopeEntry(
            address=row.target_address,
            machine_key=row.target_machine_key,
            name=row.target_name,
        ),
        rule_names=names,
        rule_class=row.rule_class,
        starts_at=_naive(row.starts_at),
        expires_at=_naive(row.expires_at),
        created_by=row.created_by,
        revoked_at=_naive(row.revoked_at) if row.revoked_at is not None else None,
        campaign_id=int(campaign_id) if campaign_id is not None else None,
        parties=parties if campaign_id is not None else (),
    )


def authorization_id_of(report: Any) -> int | None:
    """The authorization a report says its run matched, or None.

    The finalize step stamps the column from this. An "outside" report names
    an authorization too, and its run is not a match, so it gives None.
    """
    if not isinstance(report, Mapping):
        return None
    mark = report.get(REPORT_KEY)
    if not isinstance(mark, Mapping) or mark.get("state") != RUN_MATCHED:
        return None
    value = mark.get("id")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _address(value: str | None) -> str | None:
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        return None


# ── Writes ─────────────────────────────────────────────────────────────────


def _clean_sources(sources: Sequence[ScopeEntry]) -> list[ScopeEntry]:
    """The source entries of a scope, checked. Raises :class:`ScopeError`."""
    kept: list[ScopeEntry] = []
    seen: set[str] = set()
    for entry in sources:
        address = _address(entry.address)
        if address is None:
            raise ScopeError("bad_source", f"{entry.address!r} is not an address.")
        if not (entry.machine_key or "").startswith("agent:"):
            raise ScopeError(
                "source_not_agent_address",
                f"{address} is not an address that an agent reports.",
            )
        if address not in seen:
            seen.add(address)
            kept.append(ScopeEntry(address, entry.machine_key, entry.name))
    if not kept:
        raise ScopeError("source_required", "Name one source or more.")
    if len(kept) > MAX_SOURCES:
        raise ScopeError("too_many_sources", f"A scope has at most {MAX_SOURCES} sources.")
    return kept


def _clean_rule_names(rule_names: Sequence[str]) -> list[str]:
    """The rule names of a scope, folded and without repeats. Raises :class:`ScopeError`."""
    names: list[str] = []
    for raw in rule_names:
        key = rule_name_key(raw)
        if key and key not in names:
            names.append(key[:512])
    if not names:
        raise ScopeError("rule_required", "Name one rule or more.")
    if len(names) > MAX_RULE_NAMES:
        raise ScopeError("too_many_rules", f"A scope has at most {MAX_RULE_NAMES} rule names.")
    return names


def _clean_window(
    at: datetime, starts_at: datetime | None, expires_at: datetime
) -> tuple[datetime, datetime]:
    """The start and the end of a scope, checked. Raises :class:`ScopeError`."""
    end = _naive(expires_at)
    if end <= at:
        raise ScopeError("expiry_in_past", "The expiry must be later than now.")
    if end - at > timedelta(days=MAX_DAYS):
        raise ScopeError("expiry_too_far", f"The expiry is at most {MAX_DAYS} days from now.")
    start = _naive(starts_at) if starts_at is not None else at
    if start > at:
        raise ScopeError("start_in_future", "The start cannot be later than now.")
    if at - start > timedelta(days=EARLIER_DAYS_MAX):
        raise ScopeError(
            "start_too_early", f"The start is at most {EARLIER_DAYS_MAX} days before now."
        )
    return start, end


async def create(
    db: AsyncSession,
    *,
    label: str,
    sources: Sequence[ScopeEntry],
    target: ScopeEntry,
    rule_names: Sequence[str],
    rule_class: str,
    expires_at: datetime,
    created_by: str,
    note: str | None = None,
    starts_at: datetime | None = None,
    source_investigation_id: str | None = None,
    now: datetime | None = None,
    commit: bool = True,
) -> AuthorizedActivity:
    """Store one decision. Raises :class:`ScopeError` for a scope the store refuses.

    The guards here hold for every caller. The expiry is mandatory, lies in
    the future and is at most :data:`MAX_DAYS` away. The start lies at most
    :data:`EARLIER_DAYS_MAX` back. The scope names 1 to :data:`MAX_SOURCES`
    source addresses, each with the agent machine that reports it, one target
    address and 1 to :data:`MAX_RULE_NAMES` exact rule names. The route checks
    the addresses and the names against the run, because only the route
    knows that run.

    ``commit`` False flushes the row and leaves the commit to the caller. The
    create route writes the audit record between the two, so a record is
    never in force without its audit record.
    """
    at = _naive(now) if now is not None else utcnow()
    text = _clean_label(label)
    kept = _clean_sources(sources)
    target_address = _address(target.address)
    if target_address is None:
        raise ScopeError("bad_target", f"{target.address!r} is not an address.")
    if target_address in {entry.address for entry in kept}:
        raise ScopeError("target_is_source", "The target cannot also be a source.")
    names = _clean_rule_names(rule_names)
    if not (rule_class or "").strip():
        raise ScopeError("class_required", "The scope needs the alert class of its rules.")
    start, end = _clean_window(at, starts_at, expires_at)
    row = AuthorizedActivity(
        label=text,
        note=(note or "").strip() or None,
        sources=[entry.as_json() for entry in kept],
        target_address=target_address,
        target_machine_key=target.machine_key,
        target_name=target.name,
        rule_names=names,
        rule_class=rule_class.strip()[:32],
        source_investigation_id=source_investigation_id,
        starts_at=start,
        expires_at=end,
        created_by=(created_by or "anonymous")[:128],
        created_at=at,
    )
    db.add(row)
    if not commit:
        await db.flush()
        return row
    await db.commit()
    await db.refresh(row)
    return row


def _clean_label(label: str) -> str:
    text = " ".join((label or "").split())
    if not text:
        raise ScopeError("label_required", "Give the authorized activity a label.")
    if len(text) > LABEL_MAX:
        raise ScopeError("label_too_long", f"The label has at most {LABEL_MAX} characters.")
    return text


def _clean_parties(parties: Sequence[PartyEntry]) -> list[PartyEntry]:
    """The listed machines of a campaign record, checked. Raises :class:`ScopeError`."""
    kept: dict[str, PartyEntry] = {}
    for party in parties:
        key = (party.machine_key or "").strip()
        if not key or party.role not in (ROLE_ACTOR, ROLE_TARGET):
            raise ScopeError(
                "bad_machine", f"{party.machine_key!r} is not a machine of a campaign."
            )
        kept.setdefault(key, PartyEntry(key, party.role, party.name, tuple(party.addresses)))
    listed = list(kept.values())
    if not any(p.role == ROLE_ACTOR for p in listed):
        raise ScopeError("actor_required", "List one actor or more.")
    if not any(p.role == ROLE_TARGET for p in listed):
        raise ScopeError("target_required", "List one target or more.")
    return listed


async def create_for_campaign(
    db: AsyncSession,
    *,
    campaign_id: int,
    label: str,
    parties: Sequence[PartyEntry],
    starts_at: datetime,
    expires_at: datetime,
    created_by: str,
    note: str | None = None,
    now: datetime | None = None,
    commit: bool = True,
) -> AuthorizedActivity:
    """Store one authorization of a campaign. Raises :class:`ScopeError`.

    The record lists machines and no rule. It needs a label, one actor or
    more and one target or more, and an expiry later than now and at most
    :data:`MAX_DAYS` away. ``starts_at`` is the first event of the campaign,
    so it has no lower bound. It cannot be later than now. ``commit`` False
    flushes the row and leaves the commit to the caller, as :func:`create`.
    """
    at = _naive(now) if now is not None else utcnow()
    text = _clean_label(label)
    listed = _clean_parties(parties)
    end = _naive(expires_at)
    if end <= at:
        raise ScopeError("expiry_in_past", "The expiry must be later than now.")
    if end - at > timedelta(days=MAX_DAYS):
        raise ScopeError("expiry_too_far", f"The expiry is at most {MAX_DAYS} days from now.")
    start = min(_naive(starts_at), at)
    row = AuthorizedActivity(
        label=text,
        note=(note or "").strip() or None,
        sources=[],
        target_address="",
        target_machine_key=None,
        target_name=None,
        rule_names=[],
        rule_class="",
        starts_at=start,
        expires_at=end,
        created_by=(created_by or "anonymous")[:128],
        created_at=at,
        campaign_id=int(campaign_id),
        parties=[p.as_json() for p in listed],
    )
    db.add(row)
    if not commit:
        await db.flush()
        return row
    await db.commit()
    await db.refresh(row)
    return row


async def campaign_record(db: AsyncSession, authorization_id: int | None) -> Scope | None:
    """The scope of one campaign record, or None for no id and a record of the rule-list form."""
    if authorization_id is None:
        return None
    row = await db.get(AuthorizedActivity, authorization_id)
    if row is None or row.campaign_id is None:
        return None
    return scope_of(row)


async def revoke(
    db: AsyncSession,
    authorization_id: int,
    *,
    by: str,
    reason: str,
    now: datetime | None = None,
    commit: bool = True,
) -> tuple[AuthorizedActivity | None, bool]:
    """Revoke one authorization. Returns the row and whether this call revoked it.

    ``(None, False)`` when no such row exists. ``(row, False)`` when the row
    was revoked before: the first revoke keeps its actor and its reason.
    ``commit`` False flushes the revoke and leaves the commit to the caller.
    """
    row = await db.get(AuthorizedActivity, authorization_id)
    if row is None:
        return None, False
    if row.revoked_at is not None:
        return row, False
    row.revoked_at = _naive(now) if now is not None else utcnow()
    row.revoked_by = (by or "anonymous")[:128]
    row.revoke_reason = " ".join((reason or "").split())[:512] or None
    if not commit:
        await db.flush()
        return row, True
    await db.commit()
    await db.refresh(row)
    return row, True


async def mark_expiry_recorded(
    db: AsyncSession, authorization_id: int, *, now: datetime | None = None
) -> None:
    row = await db.get(AuthorizedActivity, authorization_id)
    if row is None or row.expiry_recorded_at is not None:
        return
    row.expiry_recorded_at = _naive(now) if now is not None else utcnow()
    await db.commit()


# ── Reads ──────────────────────────────────────────────────────────────────


async def get(db: AsyncSession, authorization_id: int) -> AuthorizedActivity | None:
    return await db.get(AuthorizedActivity, authorization_id)


async def in_force(db: AsyncSession, *, now: datetime | None = None) -> list[Scope]:
    """The scopes a run or a hunt reads: not revoked, and not long ended.

    An authorization that expired up to :data:`RECENT_DAYS` ago stays in the
    read. The alert time decides a match, so an alert from inside the window
    that soc-ai triages after the expiry still matches. A revoked row is out.
    """
    at = _naive(now) if now is not None else utcnow()
    rows = await db.scalars(
        select(AuthorizedActivity)
        .where(
            AuthorizedActivity.revoked_at.is_(None),
            AuthorizedActivity.expires_at >= at - timedelta(days=RECENT_DAYS),
        )
        .order_by(AuthorizedActivity.id)
    )
    return [scope_of(row) for row in rows.all()]


async def list_recent(
    db: AsyncSession, *, now: datetime | None = None, ended: bool = True
) -> list[AuthorizedActivity]:
    """The authorizations of the card list: the active ones, then the recent ended ones.

    An ended row stays for :data:`RECENT_DAYS` after its expiry or its revoke.
    ``ended`` False leaves the ended rows out.
    """
    at = _naive(now) if now is not None else utcnow()
    floor = at - timedelta(days=RECENT_DAYS)
    rows = (
        await db.scalars(
            select(AuthorizedActivity)
            .where(AuthorizedActivity.expires_at >= floor)
            .order_by(AuthorizedActivity.expires_at.desc(), AuthorizedActivity.id.desc())
        )
    ).all()
    active = [r for r in rows if state_of(r, at) == STATE_ACTIVE]
    if not ended:
        return active
    done = [
        r
        for r in rows
        if state_of(r, at) != STATE_ACTIVE
        and (r.revoked_at is None or _naive(r.revoked_at) >= floor)
    ]
    return active + done


async def unrecorded_expiries(
    db: AsyncSession, *, now: datetime | None = None
) -> list[AuthorizedActivity]:
    """The authorizations that expired and have no audit record of it yet."""
    at = _naive(now) if now is not None else utcnow()
    rows = await db.scalars(
        select(AuthorizedActivity)
        .where(
            AuthorizedActivity.expires_at <= at,
            AuthorizedActivity.revoked_at.is_(None),
            AuthorizedActivity.expiry_recorded_at.is_(None),
        )
        .order_by(AuthorizedActivity.id)
    )
    return list(rows.all())


async def recently_expired(
    db: AsyncSession, *, since: datetime, now: datetime | None = None
) -> list[AuthorizedActivity]:
    """The authorizations that expired between ``since`` and now. The bell reads this."""
    at = _naive(now) if now is not None else utcnow()
    rows = await db.scalars(
        select(AuthorizedActivity)
        .where(
            AuthorizedActivity.expires_at <= at,
            AuthorizedActivity.expires_at >= _naive(since),
            AuthorizedActivity.revoked_at.is_(None),
        )
        .order_by(AuthorizedActivity.expires_at.desc())
    )
    return list(rows.all())


async def machine_refs(
    db: AsyncSession, addresses: Iterable[str | None]
) -> dict[str, MachineRef | None]:
    """The machine each address belongs to now, keyed by the address as given.

    None when the Hosts data holds no machine for the address. The answer
    carries the join of the address (:class:`MachineRef`), so a caller can
    tell an address that an agent reports from a weaker join.
    """
    wanted: dict[str, str] = {}
    for raw in addresses:
        if not raw:
            continue
        normal = _address(raw)
        if normal is not None:
            wanted[raw] = normal
    out: dict[str, MachineRef | None] = dict.fromkeys(wanted)
    if not wanted:
        return out
    rows = (
        await db.execute(
            select(
                HostDossier.host_key,
                HostDossier.address_kind,
                HostMachine.machine_key,
                HostMachine.name,
                HostMachine.agent_name,
            )
            .join(HostMachine, HostMachine.id == HostDossier.machine_id)
            .where(
                HostDossier.host_key.in_(sorted(set(wanted.values()))),
                HostMachine.address_count > 0,
            )
        )
    ).all()
    by_key = {
        str(host_key): MachineRef(str(machine_key), name or agent_name or None, kind)
        for host_key, kind, machine_key, name, agent_name in rows
        if machine_key
    }
    for raw, normal in wanted.items():
        out[raw] = by_key.get(normal)
    return out


async def machine_names(db: AsyncSession) -> dict[str, frozenset[str]]:
    """Each machine name of the Hosts data, lower case, with the keys of its machines.

    One read for all machines. The match reads the names in the text of a
    report: a report that names a machine outside the scope is about more
    than the authorized activity. A machine has a name and an agent name,
    and both count.
    """
    rows = (
        await db.execute(
            select(HostMachine.machine_key, HostMachine.name, HostMachine.agent_name).where(
                HostMachine.address_count > 0
            )
        )
    ).all()
    out: dict[str, set[str]] = {}
    for machine_key, name, agent_name in rows:
        if not machine_key:
            continue
        for value in (name, agent_name):
            text = (value or "").strip().lower()
            if text:
                out.setdefault(text, set()).add(str(machine_key))
    return {name: frozenset(keys) for name, keys in out.items()}


def machine_key_now(ref: MachineRef | None) -> str | None:
    """The machine key the match compares, or None.

    A container address is inside a bridge of its machine. The traffic of a
    container is its own workload, so the address names no machine here.
    """
    if ref is None or ref.kind == "container":
        return None
    return ref.key


async def bridge_addresses(db: AsyncSession, addresses: Iterable[str | None]) -> set[str]:
    """The addresses that sit on a container bridge.

    A bridge network repeats on every container host: each host has its own
    10.89.0.1 and its own 10.89.0.5. An address in the /24 of a known
    container address is such an address, and more than one machine can hold
    it. IPv4 only, like the bridge rule of the machine clustering.
    """
    out: set[str] = set()
    for raw in addresses:
        normal = _address(raw)
        if normal is None or ":" in normal:
            continue
        prefix = normal.rsplit(".", 1)[0] + "."
        found = await db.scalar(
            select(HostDossier.id)
            .where(HostDossier.address_kind == "container", HostDossier.ip.startswith(prefix))
            .limit(1)
        )
        if found is not None and raw:
            out.add(raw)
    return out


def address_problem(
    address: str, ref: MachineRef | None, *, on_bridge: bool, source: bool
) -> tuple[str, str] | None:
    """Why an address cannot be in a scope: ``(reason, hint)``, or None.

    A source must be an address that the agent of its machine reports. That
    is the one join that names a machine and not only an address. A target
    may also be an address that no agent reports: the record then follows the
    address. No scope holds a container address, a bridge address or an
    address that joined its machine by a DNS name or a DHCP lease.
    """
    role = "source" if source else "target"
    kind = ref.kind if ref is not None else None
    if kind == "container" or on_bridge:
        return (
            f"{role}_on_bridge",
            f"The {role} address {address} is a container or bridge address. "
            "More than one machine can hold it.",
        )
    if kind == "name":
        return (
            f"{role}_joined_by_name",
            f"The {role} address {address} joined its machine by a DNS name only. "
            "A name does not prove the machine.",
        )
    if kind == "dhcp":
        return (
            f"{role}_joined_by_lease",
            f"The {role} address {address} joined its machine by a DHCP lease only. "
            "A lease does not prove the machine.",
        )
    if source and not (kind == "agent" and ref is not None and ref.key.startswith("agent:")):
        return (
            "source_not_agent_address",
            f"No agent reports the source address {address}. "
            "A source must be an address that the agent of its machine reports.",
        )
    return None


async def run_counts(db: AsyncSession, ids: Iterable[int]) -> dict[int, RunCount]:
    """The runs that matched each authorization, keyed by its id."""
    wanted = sorted({int(i) for i in ids})
    if not wanted:
        return {}
    since = func.sum(case((Investigation.created_at >= AuthorizedActivity.created_at, 1), else_=0))
    rows = (
        await db.execute(
            select(
                Investigation.authorization_id,
                func.count(Investigation.id),
                since,
                func.max(Investigation.created_at),
            )
            .join(AuthorizedActivity, AuthorizedActivity.id == Investigation.authorization_id)
            .where(Investigation.authorization_id.in_(wanted))
            .group_by(Investigation.authorization_id)
        )
    ).all()
    out = {i: RunCount() for i in wanted}
    for authorization_id, total, since_decision, last_at in rows:
        new = int(since_decision or 0)
        out[int(authorization_id)] = RunCount(
            total=int(total), since_decision=new, earlier=int(total) - new, last_at=last_at
        )
    return out


async def marks_for(
    db: AsyncSession, ids: Iterable[int | None], *, now: datetime | None = None
) -> dict[int, Mark]:
    """The mark of each authorization, keyed by its id. One read for a page of runs."""
    wanted = sorted({int(i) for i in ids if i is not None})
    if not wanted:
        return {}
    at = _naive(now) if now is not None else utcnow()
    rows = await db.scalars(select(AuthorizedActivity).where(AuthorizedActivity.id.in_(wanted)))
    out: dict[int, Mark] = {}
    for row in rows.all():
        state = state_of(row, at)
        out[int(row.id)] = Mark(
            id=int(row.id),
            label=row.label,
            state=state,
            expires_at=_naive(row.expires_at),
            by=row.created_by,
            holds=state != STATE_REVOKED,
        )
    return out


async def holds_run(db: AsyncSession, run: Any) -> bool:
    """Whether the authorized activity mark of a run holds now.

    The one predicate of "this run is authorized activity". True when the run
    matched an authorization that no analyst revoked. An expired authorization
    still holds its runs. The lead formation path asks this, so a run that
    matched forms no lead and starts no lead hunt.
    """
    authorization_id = getattr(run, "authorization_id", None)
    if authorization_id is None:
        return False
    row = (
        await db.execute(
            select(AuthorizedActivity.id, AuthorizedActivity.revoked_at).where(
                AuthorizedActivity.id == authorization_id
            )
        )
    ).first()
    return row is not None and row[1] is None


async def run_ids(db: AsyncSession, authorization_id: int, *, limit: int = 2000) -> list[str]:
    """The ids of the runs that matched one authorization, newest first."""
    rows = await db.scalars(
        select(Investigation.id)
        .where(Investigation.authorization_id == authorization_id)
        .order_by(Investigation.created_at.desc())
        .limit(limit)
    )
    return [str(i) for i in rows.all()]


async def earlier_candidates(
    db: AsyncSession, *, since: datetime, limit: int = 500
) -> list[Investigation]:
    """The stored alert runs an authorization could apply to, newest first.

    Complete true positives made at or after ``since``. A replay, a synthetic
    run, a pipeline fallback and a promoted run are left out: the match never
    takes one. A run that already holds a mark is left out too.
    """
    from soc_ai.store.investigations import (  # noqa: PLC0415 - light import
        PROMOTED_KINDS,
        not_backtest,
        not_hunt_subject,
    )

    rows = await db.scalars(
        select(Investigation)
        .where(
            Investigation.status == "complete",
            Investigation.verdict == "true_positive",
            Investigation.is_fallback.isnot(True),
            Investigation.is_synth_eval.isnot(True),
            Investigation.kind.notin_(PROMOTED_KINDS),
            Investigation.created_at >= _naive(since),
            not_backtest(),
            not_hunt_subject(),
            ~holds_sql(),
        )
        .order_by(Investigation.created_at.desc(), Investigation.id.desc())
        .limit(limit)
    )
    return list(rows.all())


async def runs_after(
    db: AsyncSession, authorization_id: int, *, after: str = "", limit: int = 200
) -> list[Investigation]:
    """One batch of the runs that matched an authorization, in id order.

    ``after`` is the id of the last run of the batch before. The revoke reads
    every run this way, batch after batch, so no run is left out.
    """
    rows = await db.scalars(
        select(Investigation)
        .where(Investigation.authorization_id == authorization_id, Investigation.id > after)
        .order_by(Investigation.id)
        .limit(limit)
    )
    return list(rows.all())


async def runs_on_pair(
    db: AsyncSession, target_address: str, *, since: datetime, limit: int = 2000
) -> list[Investigation]:
    """The true positive alert runs on one target address, newest first.

    The dialog reads the sources and the rule names it may offer from these
    runs. A replay, a synthetic run, a pipeline fallback and a promoted run
    are left out: a scope is built from live alert runs only.
    """
    from soc_ai.store.investigations import (  # noqa: PLC0415 - light import
        PROMOTED_KINDS,
        not_backtest,
        not_hunt_subject,
    )

    rows = await db.scalars(
        select(Investigation)
        .where(
            Investigation.status == "complete",
            Investigation.verdict == "true_positive",
            Investigation.dest_ip == target_address,
            Investigation.src_ip.is_not(None),
            Investigation.rule_name.is_not(None),
            Investigation.is_fallback.isnot(True),
            Investigation.is_synth_eval.isnot(True),
            Investigation.kind.notin_(PROMOTED_KINDS),
            Investigation.created_at >= _naive(since),
            not_backtest(),
            not_hunt_subject(),
        )
        .order_by(Investigation.created_at.desc())
        .limit(limit)
    )
    return list(rows.all())


def holds_sql(model: Any = Investigation) -> Any:
    """:func:`holds_run` as a SQL expression, for a query over many runs.

    True for a run that matched an authorization no analyst revoked. ``model``
    takes an alias of :class:`Investigation`.
    """
    live = select(AuthorizedActivity.id).where(AuthorizedActivity.revoked_at.is_(None))
    return and_(model.authorization_id.is_not(None), model.authorization_id.in_(live))
