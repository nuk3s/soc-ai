"""Authorized activity: the routes an analyst records, lists and revokes it with.

The analyst opens a true positive run and records the activity as
authorized. The record holds a label, a scope and an expiry
(:mod:`soc_ai.store.authorized_activity`). A later run inside the scope keeps
its verdict, carries the mark and requests no case
(:mod:`soc_ai.agent.authorized_activity`).

* ``GET /investigations/{id}/authorized-activity/draft`` reads what the run
  allows: its source address, its target address, and the source addresses
  and the rule names the dialog may offer. It says why it left an address
  out. For a choice of rules and sources it counts the earlier runs the
  scope matches.
* ``POST /authorized-activity`` creates the record. Admin only, like the mute
  of a rule: the record takes work out of the queue.
* ``POST /authorized-activity/{id}/revoke`` revokes it. Any signed-in caller
  may revoke, and the reason is required: a revoke returns runs to normal
  handling, which is the safe direction.
* ``GET /authorized-activity`` lists the records with the count of their runs.

The scope cannot be widened through a request body. The server takes the
target address and the alert class from the run. The body may name only
source addresses and rule names the draft offers, and the dialog lists
exactly those. What the dialog lists is what matches.

The create is atomic with its audit record: when the audit write fails, the
store keeps no record. Each revoke and each run the create marks writes an
audit record too.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import Depends, Query, Request
from pydantic import BaseModel, Field

from soc_ai.agent import authorized_activity as decision
from soc_ai.agent.decision_templates import _alert_signals_decoy
from soc_ai.api.security import identify_caller
from soc_ai.api.webui._decision_commit import commit_after_record
from soc_ai.api.webui._errors import api_error
from soc_ai.api.webui._shared import _iso_utc, require_admin_api, router
from soc_ai.store import authorized_activity as store
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.authorized_activity import Scope, ScopeEntry
from soc_ai.store.models import AuthorizedActivity, Investigation

_LOGGER = logging.getLogger(__name__)

# The expiries the dialog offers, in days. The store allows any whole number
# of days up to the maximum.
EXPIRY_CHOICES: tuple[int, ...] = (1, 7, 14, 30)
# How many marked runs one step of a revoke sends to the lead path.
_REVOKE_BATCH = 200


class AuthorizedMachineOut(BaseModel):
    """One address of a scope, with the machine that held it at the decision.

    ``identity`` says how the scope knows the machine: ``agent`` for a machine
    whose agent reports the address, ``address`` for a target that no agent
    reports. The record then follows the address.
    """

    address: str
    name: str | None = None
    machine_key: str | None = None
    identity: str = "address"


class DraftSourceOut(AuthorizedMachineOut):
    """One source address the dialog may offer.

    ``runs`` counts its true positive runs on the target in the last 30 days.
    ``of_this_run`` marks the source of the run. The scope always holds it.
    """

    runs: int = 0
    of_this_run: bool = False


class ExcludedSourceOut(BaseModel):
    """One source address the draft left out, and why."""

    address: str
    reason: str
    hint: str


class DraftRuleOut(BaseModel):
    """One rule name the dialog may offer, with its run count on the pair.

    ``of_this_run`` marks the rule of the run. The scope always holds it.
    """

    name: str
    runs: int = 0
    of_this_run: bool = False


class AuthorizedDraftOut(BaseModel):
    """What one run allows as authorized activity, for the dialog.

    ``allowed`` False means the run cannot start a record. ``reason`` is the
    code and ``hint`` the sentence. Every other field is then empty.
    """

    investigation_id: str
    allowed: bool
    reason: str | None = None
    hint: str | None = None
    rule_class: str | None = None
    target: AuthorizedMachineOut | None = None
    # False when no agent reports the target address. The record then follows
    # the address: another device on that address is inside until the expiry.
    target_has_agent: bool = False
    sources: list[DraftSourceOut] = Field(default_factory=list)
    excluded_sources: list[ExcludedSourceOut] = Field(default_factory=list)
    # The rule names of the true positive alert runs from an offered source
    # to the target. A match needs the exact name: no other rule is covered.
    rules: list[DraftRuleOut] = Field(default_factory=list)
    # The earlier runs the chosen scope matches, in the last
    # ``earlier_days_max`` days. The run of the dialog is not counted.
    earlier_runs: int = 0
    # Why the run of the dialog stays outside the chosen scope, or null when
    # it is inside. The usual cause: its report cites activity beyond the scope.
    this_run_outside: str | None = None
    earlier_days_max: int = store.EARLIER_DAYS_MAX
    default_days: int = store.DEFAULT_DAYS
    max_days: int = store.MAX_DAYS
    expiry_choices: list[int] = Field(default_factory=lambda: list(EXPIRY_CHOICES))
    max_sources: int = store.MAX_SOURCES
    max_rules: int = store.MAX_RULE_NAMES


class AuthorizedActivityIn(BaseModel):
    """The record an analyst saves from one true positive run.

    ``sources`` are addresses and ``rule_names`` are rule names the draft
    offers. The source and the rule of the run are always in the scope.
    ``expires_in_days`` defaults to 7 and is at most 30. ``apply_to_earlier``
    puts the mark on the earlier runs the scope matches. It is off by default.
    """

    investigation_id: str = Field(min_length=1, max_length=64)
    label: str = Field(min_length=1, max_length=store.LABEL_MAX)
    note: str | None = Field(default=None, max_length=2000)
    sources: list[str] = Field(min_length=1, max_length=store.MAX_SOURCES)
    rule_names: list[str] = Field(min_length=1, max_length=store.MAX_RULE_NAMES)
    expires_in_days: int = Field(default=store.DEFAULT_DAYS, ge=1, le=store.MAX_DAYS)
    apply_to_earlier: bool = False


class AuthorizedRevokeIn(BaseModel):
    reason: str = Field(min_length=1, max_length=512)


class AuthorizedActivityOut(BaseModel):
    """One authorized activity record, as the card shows it.

    ``state`` is ``active``, ``expired`` or ``revoked``. ``runs_since_decision``
    counts the runs that matched at or after the decision. ``earlier_runs``
    counts the earlier runs the analyst applied it to. Times are ISO UTC.
    ``runs_returned`` is set on the answer of a revoke: the count of the runs
    that went back to normal handling.
    """

    id: int
    label: str
    note: str | None = None
    state: str
    sources: list[AuthorizedMachineOut]
    target: AuthorizedMachineOut
    rule_names: list[str]
    rule_class: str
    starts_at: str
    expires_at: str
    created_at: str
    created_by: str
    revoked_at: str | None = None
    revoked_by: str | None = None
    revoke_reason: str | None = None
    source_investigation_id: str | None = None
    runs_since_decision: int = 0
    earlier_runs: int = 0
    runs_total: int = 0
    last_match_at: str | None = None
    # The Investigations list filtered to the runs of this record, over every
    # window. The list opens on 24 hours without a window in the link.
    runs_href: str = ""
    runs_returned: int | None = None


class AuthorizedActivityListOut(BaseModel):
    rows: list[AuthorizedActivityOut]
    active: int = 0


# ── Shapes ─────────────────────────────────────────────────────────────────


def _identity(machine_key: str | None) -> str:
    return "agent" if machine_key and machine_key.startswith("agent:") else "address"


def _machine_out(entry: ScopeEntry) -> AuthorizedMachineOut:
    return AuthorizedMachineOut(
        address=entry.address,
        name=entry.name,
        machine_key=entry.machine_key,
        identity=_identity(entry.machine_key),
    )


def _out(row: AuthorizedActivity, count: store.RunCount | None = None) -> AuthorizedActivityOut:
    scope = store.scope_of(row)
    runs = count or store.RunCount()
    return AuthorizedActivityOut(
        id=scope.id,
        label=scope.label,
        note=row.note,
        state=store.state_of(row),
        sources=[_machine_out(entry) for entry in scope.sources],
        target=_machine_out(scope.target),
        rule_names=list(scope.rule_names),
        rule_class=scope.rule_class,
        starts_at=_iso_utc(scope.starts_at),
        expires_at=_iso_utc(scope.expires_at),
        created_at=_iso_utc(row.created_at),
        created_by=row.created_by,
        revoked_at=_iso_utc(row.revoked_at) if row.revoked_at is not None else None,
        revoked_by=row.revoked_by,
        revoke_reason=row.revoke_reason,
        source_investigation_id=row.source_investigation_id,
        runs_since_decision=runs.since_decision,
        earlier_runs=runs.earlier,
        runs_total=runs.total,
        last_match_at=_iso_utc(runs.last_at) if runs.last_at is not None else None,
        runs_href=f"/investigations?authorization={scope.id}&range=all",
    )


async def _audit(request: Request, kind: str, payload: dict[str, Any]) -> None:
    """One audit record. Best-effort: the write is already committed."""
    try:
        audit = getattr(request.app.state, "audit", None)
        if audit is not None:
            await audit.log_kind(
                decision.AUDIT_SESSION, kind, payload, user=await identify_caller(request)
            )
    except Exception:
        _LOGGER.warning("%s audit write failed (continuing)", kind, exc_info=True)


# ── The draft ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _Refused:
    """A run that cannot start a record: the code and the sentence."""

    inv: Investigation
    reason: str
    hint: str


@dataclass(frozen=True)
class _Draft:
    """What one run allows: its pair, and the sources and rules to offer."""

    inv: Investigation
    rule_name: str
    rule_class: str
    alert_time: datetime
    source: ScopeEntry
    target: ScopeEntry
    # Every source address the dialog may offer, the source of the run first.
    offered: tuple[tuple[ScopeEntry, int], ...]
    # The addresses the draft left out, each with its code and its sentence.
    excluded: tuple[tuple[str, str, str], ...]
    # Every rule name the dialog may offer, the rule of the run first.
    rules: tuple[tuple[str, int], ...]


def _refusal_of_run(inv: Investigation) -> tuple[str, str] | None:
    """The reason a run cannot start a record, read from the row alone."""
    if inv.status != "complete" or inv.verdict != decision.TRUE_POSITIVE:
        return (
            "not_true_positive",
            "Only a complete true positive run can record authorized activity.",
        )
    if inv_svc.is_backtest(inv) or inv.is_synth_eval:
        return (
            "measurement_run",
            "A backtest replay and an evaluation run are measurements. Open a live run.",
        )
    if inv_svc.is_promoted(inv):
        return (
            "promoted_run",
            "soc-ai always judges a finding on its own. "
            "Open a true positive alert run of the same activity.",
        )
    return None


def _entry(address: str, refs: dict[str, store.MachineRef | None]) -> ScopeEntry:
    ref = refs.get(address)
    return ScopeEntry(address, store.machine_key_now(ref), ref.name if ref else None)


async def _offers(
    db: Any,
    source: ScopeEntry,
    target: ScopeEntry,
    rule_name: str,
    rule_class: str,
    since: datetime,
) -> tuple[list[tuple[ScopeEntry, int]], list[tuple[str, str, str]], list[tuple[str, int]]]:
    """The source addresses and the rule names the dialog may offer.

    Both come from the true positive alert runs on the target address. A
    source address is offered only when the agent of its machine reports it,
    and the draft states why it left another one out. A rule name is offered
    only when a run from an offered source carries it with the alert class of
    this run. The source and the rule of the run come first.
    """
    runs = await store.runs_on_pair(db, target.address, since=since)
    seen: dict[str, int] = {}
    for run in runs:
        address = str(run.src_ip)
        seen[address] = seen.get(address, 0) + 1
    refs = await store.machine_refs(db, list(seen))
    bridges = await store.bridge_addresses(db, list(seen))
    offered: list[tuple[ScopeEntry, int]] = [(source, seen.get(source.address, 0))]
    excluded: list[tuple[str, str, str]] = []
    for address, count in sorted(seen.items(), key=lambda pair: (-pair[1], pair[0])):
        if address == source.address:
            continue
        problem = store.address_problem(
            address, refs.get(address), on_bridge=address in bridges, source=True
        )
        if problem is not None:
            excluded.append((address, *problem))
        elif len(offered) < store.MAX_SOURCES:
            offered.append((_entry(address, refs), count))
    addresses = {entry.address for entry, _count in offered}
    on_pair = [run for run in runs if str(run.src_ip) in addresses]
    alerts = await decision.stored_alerts(db, [run.id for run in on_pair])
    names: dict[str, int] = {}
    for run in on_pair:
        alert = alerts.get(run.id)
        name = store.rule_name_key(run.rule_name)
        if alert is None or not name or _alert_signals_decoy(alert):
            continue
        if store.rule_name_key(alert.rule_name) != name:
            continue
        if decision.rule_class_of(alert) == rule_class:
            names[name] = names.get(name, 0) + 1
    own = (rule_name, names.pop(rule_name, 0))
    rest = sorted(names.items(), key=lambda pair: (-pair[1], pair[0]))
    return offered, excluded, [own, *rest][: store.MAX_RULE_NAMES]


async def _draft(db: Any, inv_id: str, *, now: datetime) -> _Draft | _Refused | None:
    """Read what the run allows. None when no such run exists."""
    inv = await db.get(Investigation, inv_id)
    if inv is None:
        return None
    refusal = _refusal_of_run(inv)
    if refusal is not None:
        return _Refused(inv, *refusal)
    held = (await store.marks_for(db, [inv.authorization_id])).get(inv.authorization_id or 0)
    if held is not None and held.holds:
        return _Refused(
            inv,
            "already_authorized",
            f'This investigation already matches the authorized activity "{held.label}".',
        )
    alert = await decision.alert_of_run(db, inv.id)
    if alert is None:
        return _Refused(inv, "no_alert_context", "This investigation recorded no alert context.")
    if _alert_signals_decoy(alert):
        return _Refused(
            inv, "decoy_alert", "A hit of a deception sensor cannot be authorized activity."
        )
    rule_name = store.rule_name_key(alert.rule_name)
    if not rule_name:
        return _Refused(inv, "no_rule_name", "The alert of this investigation has no rule name.")
    if not alert.source_ip or not alert.destination_ip:
        return _Refused(
            inv, "no_flow", "The alert of this investigation names no source and destination pair."
        )
    at = decision.event_time(alert)
    floor = now - timedelta(days=store.EARLIER_DAYS_MAX)
    if at is None or at < floor or at > now:
        return _Refused(
            inv,
            "run_too_old",
            f"The alert of this investigation is older than {store.EARLIER_DAYS_MAX} days, "
            "or it has no time. Open a newer investigation.",
        )
    ends = [str(alert.source_ip), str(alert.destination_ip)]
    refs = await store.machine_refs(db, ends)
    bridges = await store.bridge_addresses(db, ends)
    for address, is_source in ((ends[0], True), (ends[1], False)):
        problem = store.address_problem(
            address, refs.get(address), on_bridge=address in bridges, source=is_source
        )
        if problem is not None:
            return _Refused(inv, *problem)
    source = _entry(ends[0], refs)
    target = _entry(ends[1], refs)
    if source.address == target.address or (
        source.machine_key is not None and source.machine_key == target.machine_key
    ):
        return _Refused(inv, "same_machine", "The source and the target are one machine.")
    rule_class = decision.rule_class_of(alert)
    offered, excluded, rules = await _offers(db, source, target, rule_name, rule_class, floor)
    return _Draft(
        inv=inv,
        rule_name=rule_name,
        rule_class=rule_class,
        alert_time=at,
        source=source,
        target=target,
        offered=tuple(offered),
        excluded=tuple(excluded),
        rules=tuple(rules),
    )


def _selected_sources(draft: _Draft, addresses: list[str]) -> list[ScopeEntry]:
    """The offered source addresses the caller named. The source of the run is always in."""
    by_address = {entry.address: entry for entry, _runs in draft.offered}
    picked: list[ScopeEntry] = [draft.source]
    for raw in addresses:
        address = raw.strip()
        entry = by_address.get(address)
        if entry is None:
            raise api_error(
                422,
                "source_not_offered",
                f"{address} is not a source address the draft of this investigation offers. "
                "A scope holds only an address that an agent reports and that has a "
                "true positive investigation on the target.",
            )
        if all(entry.address != have.address for have in picked):
            picked.append(entry)
    return picked


def _selected_rules(draft: _Draft, names: list[str]) -> list[str]:
    """The offered rule names the caller named. The rule of the run is always in."""
    offered = {name for name, _runs in draft.rules}
    picked: list[str] = [draft.rule_name]
    for raw in names:
        name = store.rule_name_key(raw)
        if name not in offered:
            raise api_error(
                422,
                "rule_not_offered",
                f'"{name}" is not a rule the draft of this investigation offers. A scope holds '
                "only a rule of a true positive investigation from a source of the scope to the "
                "target.",
            )
        if name not in picked:
            picked.append(name)
    return picked


def _provisional(
    draft: _Draft, rules: list[str], sources: list[ScopeEntry], now: datetime
) -> Scope:
    """The scope as it would be saved with the earlier runs, for the count."""
    return Scope(
        id=0,
        label="",
        sources=tuple(sources),
        target=draft.target,
        rule_names=tuple(rules),
        rule_class=draft.rule_class,
        starts_at=now - timedelta(days=store.EARLIER_DAYS_MAX),
        expires_at=now,
    )


@router.get(
    "/investigations/{inv_id}/authorized-activity/draft",
    response_model=AuthorizedDraftOut,
)
async def authorized_activity_draft(
    request: Request,
    inv_id: str,
    rule: Annotated[
        list[str] | None,
        Query(description="The offered rule names to count with. Default: the rule of the run."),
    ] = None,
    source: Annotated[
        list[str] | None,
        Query(description="The offered sources to count with. Default: the source of the run."),
    ] = None,
) -> AuthorizedDraftOut:
    """What this run allows as authorized activity, and how wide the scope is.

    The answer names the target address, the source addresses and the rule
    names the dialog may offer, and each address it left out with the reason.
    For ``rule`` and ``source`` it counts the earlier runs the scope matches.
    A run that cannot start a record answers ``allowed`` false with the reason.
    """
    now = utcnow()
    async with request.app.state.db_sessionmaker() as db:
        draft = await _draft(db, inv_id, now=now)
        if draft is None:
            raise api_error(404, "not_found", f"No investigation has the id {inv_id}.")
        if isinstance(draft, _Refused):
            return AuthorizedDraftOut(
                investigation_id=draft.inv.id,
                allowed=False,
                reason=draft.reason,
                hint=draft.hint,
            )
        scope = _provisional(
            draft,
            _selected_rules(draft, rule or []),
            _selected_sources(draft, source or []),
            now,
        )
        matches = await decision.earlier_matches(db, scope, exclude={draft.inv.id})
        this_run = await decision.stored_run_line(db, scope, draft.inv)
    return AuthorizedDraftOut(
        investigation_id=draft.inv.id,
        allowed=True,
        rule_class=draft.rule_class,
        target=_machine_out(draft.target),
        target_has_agent=_identity(draft.target.machine_key) == "agent",
        sources=[
            DraftSourceOut(
                **_machine_out(entry).model_dump(),
                runs=runs,
                of_this_run=entry.address == draft.source.address,
            )
            for entry, runs in draft.offered
        ],
        excluded_sources=[
            ExcludedSourceOut(address=address, reason=reason, hint=hint)
            for address, reason, hint in draft.excluded
        ],
        rules=[
            DraftRuleOut(name=name, runs=runs, of_this_run=name == draft.rule_name)
            for name, runs in draft.rules
        ],
        earlier_runs=len(matches),
        this_run_outside=this_run,
    )


# ── The writes ─────────────────────────────────────────────────────────────


@router.post(
    "/authorized-activity",
    status_code=201,
    response_model=AuthorizedActivityOut,
    dependencies=[Depends(require_admin_api)],
)
async def create_authorized_activity(
    request: Request, body: AuthorizedActivityIn
) -> AuthorizedActivityOut:
    """Record the activity of one true positive run as authorized. Admin only.

    The server takes the target address and the alert class from the run.
    ``sources`` and ``rule_names`` may name only what the draft offers, and
    the source and the rule of the run are always in the scope. The run of
    the record gets the mark at once. The earlier runs get it only with
    ``apply_to_earlier``, and then the scope starts 30 days back.

    The audit record is written before the commit. When that write fails,
    the store keeps no record and the route answers 503.

    Refusals: 404 ``not_found``; 409 with the reason of a run that cannot
    start a record; 422 for a source, a rule or a scope the store refuses;
    503 ``audit_unavailable``.
    """
    now = utcnow()
    by = await identify_caller(request)
    audit = getattr(request.app.state, "audit", None)
    async with request.app.state.db_sessionmaker() as db:
        draft = await _draft(db, body.investigation_id, now=now)
        if draft is None:
            raise api_error(
                404, "not_found", f"No investigation has the id {body.investigation_id}."
            )
        if isinstance(draft, _Refused):
            raise api_error(409, draft.reason, draft.hint)
        sources = _selected_sources(draft, body.sources)
        rules = _selected_rules(draft, body.rule_names)
        try:
            row = await store.create(
                db,
                label=body.label,
                note=body.note,
                sources=sources,
                target=draft.target,
                rule_names=rules,
                rule_class=draft.rule_class,
                source_investigation_id=draft.inv.id,
                starts_at=(
                    now - timedelta(days=store.EARLIER_DAYS_MAX)
                    if body.apply_to_earlier
                    else draft.alert_time
                ),
                expires_at=now + timedelta(days=body.expires_in_days),
                created_by=by,
                now=now,
                commit=False,
            )
        except store.ScopeError as exc:
            raise api_error(422, exc.reason, exc.hint) from exc
        scope = store.scope_of(row)
        # The audit record first, then the commit. A record that is in force
        # always has its create record on the trail.
        try:
            if audit is not None:
                await audit.log_kind(
                    decision.AUDIT_SESSION,
                    "authorized_activity_created",
                    {
                        "authorization_id": scope.id,
                        "label": scope.label,
                        "sources": [entry.as_json() for entry in scope.sources],
                        "target": scope.target.as_json(),
                        "rule_names": list(scope.rule_names),
                        "rule_class": scope.rule_class,
                        "starts_at": _iso_utc(scope.starts_at),
                        "expires_at": _iso_utc(scope.expires_at),
                        "investigation_id": draft.inv.id,
                        "apply_to_earlier": body.apply_to_earlier,
                    },
                    user=by,
                    mutating=True,
                )
        except Exception as exc:
            await db.rollback()
            _LOGGER.warning("authorized activity: the create record failed, nothing saved: %s", exc)
            raise api_error(
                503,
                "audit_unavailable",
                "soc-ai could not write the audit record, so it saved no authorized "
                "activity. Try again when the grid answers.",
            ) from exc
        await db.commit()
        # The run of the record always gets the mark. The earlier runs get it
        # only when the analyst asked for that.
        runs = await decision.earlier_matches(db, scope)
        if not body.apply_to_earlier:
            runs = [run for run in runs if run.id == draft.inv.id]
        await decision.apply_to_stored_runs(db, audit, scope, runs, now=now)
        counts = await store.run_counts(db, [scope.id])
        return _out(row, counts.get(scope.id))


@router.post(
    "/authorized-activity/{authorization_id}/revoke",
    response_model=AuthorizedActivityOut,
)
async def revoke_authorized_activity(
    request: Request, authorization_id: int, body: AuthorizedRevokeIn
) -> AuthorizedActivityOut:
    """Revoke one authorized activity record. The reason is required.

    The record then matches no run. Every run that carries its mark gets
    normal handling again: its case request waits, the bell lists it, and it
    goes to the lead path. The route reads the runs in batches and leaves
    none out, and ``runs_returned`` states the count. Any signed-in caller
    may revoke.

    Refusals: 404 ``not_found``; 409 ``already_revoked``; 422
    ``reason_required``.
    """
    reason = " ".join(body.reason.split())
    if not reason:
        raise api_error(422, "reason_required", "State the reason for the revoke.")
    by = await identify_caller(request)
    now = utcnow()
    async with request.app.state.db_sessionmaker() as db:
        held = await store.get(db, authorization_id)
        if held is not None and held.campaign_id is not None:
            # A campaign record: the campaign holds its investigations again
            # and waits as one item. No investigation goes to the lead path.
            record, count = await revoke_campaign_record(
                request, db, authorization_id, reason=reason, by=by, now=now
            )
            held_out = _out(record, count)
            held_out.runs_returned = count.total
            return held_out
        row, changed = await store.revoke(db, authorization_id, by=by, reason=reason, now=now)
        if row is None:
            raise api_error(
                404,
                "not_found",
                f"No authorized activity has the id {authorization_id}. "
                "GET /api/v1/authorized-activity lists the records.",
            )
        if not changed:
            raise api_error(
                409,
                "already_revoked",
                f"{row.revoked_by or 'An analyst'} revoked this authorized activity before.",
            )
        counts = await store.run_counts(db, [authorization_id])
        # Normal handling again. The lead path skipped these runs while the
        # mark held, so every one of them goes to it now.
        returned = 0
        after = ""
        while True:
            batch = await store.runs_after(db, authorization_id, after=after, limit=_REVOKE_BATCH)
            if not batch:
                break
            after = str(batch[-1].id)
            for run in batch:
                await inv_svc._observe_verdict(db, run)
                returned += 1
        await _audit(
            request,
            "authorized_activity_revoked",
            {
                "authorization_id": authorization_id,
                "label": row.label,
                "reason": reason,
                "runs": returned,
            },
        )
        out = _out(row, counts.get(authorization_id))
        out.runs_returned = returned
        return out


async def revoke_campaign_record(
    request: Request,
    db: Any,
    authorization_id: int,
    *,
    reason: str,
    by: str,
    now: datetime,
) -> tuple[AuthorizedActivity, store.RunCount]:
    """Revoke one campaign record, with its audit record first. The row and its run count.

    The revoke ends every mark of the record, clears the decision of its
    campaign and writes one ``reopened`` change with the cause ``revoked``
    (:func:`soc_ai.campaigns.authorization.revoke_record`). It sends no
    investigation to the lead path: the campaign holds them again. The audit
    record ``authorized_activity_revoked`` is written before the commit.
    When that write fails, nothing changes and the answer is 503. When the
    commit fails after it, ``authorized_activity_revoke_failed`` follows and
    the answer is 503 ``store_unavailable``.

    Refusals: 404 ``not_found``; 409 ``already_revoked``; 503
    ``audit_unavailable`` and ``store_unavailable``.
    """
    from soc_ai.campaigns import authorization as campaign_auth  # noqa: PLC0415 - cycle

    row, changed = await campaign_auth.revoke_record(
        db, authorization_id, by=by, reason=reason, now=now
    )
    if row is None:
        await db.rollback()
        raise api_error(404, "not_found", f"No authorized activity has the id {authorization_id}.")
    if not changed:
        await db.rollback()
        raise api_error(
            409,
            "already_revoked",
            f"{row.revoked_by or 'An analyst'} revoked this authorized activity before.",
        )
    counts = (await store.run_counts(db, [authorization_id])).get(
        authorization_id, store.RunCount()
    )
    audit = getattr(request.app.state, "audit", None)
    revoked = {
        "authorization_id": authorization_id,
        "campaign_id": row.campaign_id,
        "label": row.label,
        "reason": reason,
        "runs": counts.total,
    }
    try:
        if audit is not None:
            await audit.log_kind(
                decision.AUDIT_SESSION,
                "authorized_activity_revoked",
                revoked,
                user=by,
                mutating=True,
            )
    except Exception as exc:
        await db.rollback()
        _LOGGER.warning("authorized activity: the revoke record failed, nothing changed: %s", exc)
        raise api_error(
            503,
            "audit_unavailable",
            "soc-ai could not write the audit record, so it did not revoke the authorization. "
            "Try again when the grid answers.",
        ) from exc
    await commit_after_record(
        request,
        db,
        decision.AUDIT_SESSION,
        "authorized_activity_revoked",
        revoked,
        by=by,
        action="revoke",
    )
    await db.refresh(row)
    return row, counts


@router.get("/authorized-activity", response_model=AuthorizedActivityListOut)
async def list_authorized_activity(
    request: Request,
    ended: Annotated[
        bool,
        Query(description="Include the records that expired or were revoked in the last 7 days."),
    ] = True,
) -> AuthorizedActivityListOut:
    """The authorized activity records, the active ones first.

    Each row carries the count of the runs that matched it since the
    decision, the count of the earlier runs, and the time of the last match.
    An ended record stays for 7 days after its end.
    """
    async with request.app.state.db_sessionmaker() as db:
        rows = await store.list_recent(db, ended=ended)
        counts = await store.run_counts(db, [int(row.id) for row in rows])
    out = [_out(row, counts.get(int(row.id))) for row in rows]
    return AuthorizedActivityListOut(
        rows=out, active=sum(1 for row in out if row.state == store.STATE_ACTIVE)
    )
