"""Repository for the host dossier — two physically separate lanes per field.

Async store functions over :class:`~soc_ai.store.models.HostDossier` and
:class:`~soc_ai.store.models.HostDossierField` (migration 0024). The dossier
answers "what IS this host?", and this module is the only writer of either lane.

**The load-bearing invariant.** There is no ``value`` column. :func:`upsert_inferred`
names the ``inferred_*`` columns explicitly and never writes an ``operator_*``
one; :func:`set_override` writes only the operator lane and never touches the
inference lane. The effective value is computed at read time by
``soc_ai.dossier.resolve``. An operator override therefore survives every
subsequent build *structurally* — there is nothing for a build to clobber — and
not because some code path remembered to skip it.

**And the builder never stops observing.** ``internal_identifiers.upsert_detected``
returns a dismissed row untouched, which is the trap this design exists to avoid:
a system that stops recording what it currently believes can never notice that it
has kept disagreeing with the operator, so it can never ask. Here an override
suppresses EFFECT, never OBSERVATION. Every build writes what it saw into the
inference lane, and the disagreement that accumulates in the ``conflict_*``
columns is what eventually earns a single, rate-limited prod
(:class:`InferredWrite.prompted`).

Transaction discipline is split by caller, deliberately:

* **Builder-facing** (:func:`upsert_host`, :func:`upsert_inferred`) flush but do
  NOT commit. The network sweep writes one host header plus ~12 field rows and
  commits once per host — 2,400 commits per sweep would be the same
  connection-pool pressure that has frozen this app before — and the conflict
  state machine has to land in the same transaction as the field write it is
  derived from.
* **Operator/route-facing** (:func:`set_override`, :func:`clear_override`,
  :func:`snooze_conflict`, :func:`prune`) commit: each is one complete act.

Lookups are keyed on the normalized IP string (``host_key``). An IP that will not
parse cannot name a stored host, so the read and operator paths return ``None``
for one (the route answers 404); :func:`upsert_host` raises instead, because a
builder handing this module a non-address is a bug worth surfacing.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from time import monotonic as _monotonic
from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import (
    and_,
    case,
    distinct,
    func,
    null,
    nulls_first,
    nulls_last,
    or_,
    select,
    update,
)
from sqlalchemy import delete as sa_delete
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.dossier import policy
from soc_ai.dossier.types import DOSSIER_FIELDS, Fact
from soc_ai.store.auth import utcnow
from soc_ai.store.models import HostDossier, HostDossierField

if TYPE_CHECKING:
    from sqlalchemy import CursorResult

# The `dossier_*` policy defaults, bound from the single source in
# `soc_ai.dossier.policy`. The knobs are passed in by the caller (the store does
# not read Settings), and these keep an ad-hoc call — a route, a test, a CLI
# probe — on the same policy as the scheduled sweep. Routes read
# `dossier_store.DEFAULT_*`, so these stay module attributes here (real
# assignments, not a re-import, so the attribute access is an explicit export);
# sourcing the numbers once is what stops the three mirrors drifting apart.
DEFAULT_MIN_CONFIDENCE = policy.DEFAULT_MIN_CONFIDENCE
DEFAULT_STALENESS_HOURS = policy.DEFAULT_STALENESS_HOURS
DEFAULT_CONFLICT_MIN_OBSERVATIONS = policy.DEFAULT_CONFLICT_MIN_OBSERVATIONS
DEFAULT_CONFLICT_PROMPT_INTERVAL_HOURS = policy.DEFAULT_CONFLICT_PROMPT_INTERVAL_HOURS

# The provenance rung an agent running ON the machine writes — `hostlog` in
# soc_ai.dossier.types.PROVENANCE_LADDER, spelled here because
# :func:`summarize_dossiers` compares it against a stored column in SQL.
HOSTLOG_SOURCE = "hostlog"

# The field whose resolved value is a host's NAME. The one field the summary
# singles out, because "how much of the network has a name" is the question the
# host list is currently worst at answering.
HOSTNAME_FIELD = "hostname"

# The field whose operator value grades a host's importance. Never inferred
# (soc_ai.dossier.types: the classifier emits no Fact for it), so the operator
# lane is the only lane the attention order has to read.
CRITICALITY_FIELD = "criticality"

# The two fields :func:`environment_profile` counts over, and the one os_family
# value it matches. "windows" is the classifier's coarse-family vocabulary
# (soc_ai.dossier.infer._HOSTLOG_OS_FAMILY / _SSH_OS_PATTERNS both emit it);
# domain_membership carries the domain NAME itself (never a boolean), so
# "joined" is "resolves to a non-empty value".
OS_FAMILY_FIELD = "os_family"
DOMAIN_MEMBERSHIP_FIELD = "domain_membership"
WINDOWS_OS_FAMILY = "windows"

# The field that says what KIND of machine a host is — the summary's role-mix
# buckets group on its resolved value.
ROLE_FIELD = "role"

# Rank of a declared criticality inside the attention order, best first.
# Compared lower(trim())-folded in SQL so "Critical" and "critical" are one
# claim. Free text outside this vocabulary ranks with "not stated"
# (_CRITICALITY_UNRANKED): a wording the order cannot grade must neither sink
# nor float the host, only leave it to the later keys.
_CRITICALITY_RANK: tuple[tuple[str, int], ...] = (
    ("critical", 0),
    ("high", 1),
    ("medium", 2),
    ("low", 3),
)
_CRITICALITY_UNRANKED = 4

# The grades a criticality may be declared as, worst first — the public name for
# the rank map above, and the same four words the Hosts screen offers. Derived
# from _CRITICALITY_RANK rather than re-typed beside it, for the reason the rank
# map exists: this vocabulary IS the order, and a second hand-maintained copy
# could name a grade the order cannot rank (or omit one it can). The bulk
# declare validates against it (soc_ai/api/webui/routes_dossier.py); the
# single-host declare is deliberately free text, as with `role`.
CRITICALITY_VOCABULARY: tuple[str, ...] = tuple(name for name, _rank in _CRITICALITY_RANK)

# The grades that lead the IMPORTANCE order — ahead of being named. Only the
# two that assert the host matters, because "the operator graded this" and "the
# operator said this matters" are different claims and the landing screen ranks
# on the second. Ranking every grade ahead of named would let one bulk-tagging
# pass rebuild the defect the order was written to undo: a /24 of printers
# declared `low` is 200 dash-under-HOST rows in front of the domain controller
# — the same "first screen of nothing" the sort exists to prevent, arriving by
# way of the sort itself. `medium` and `low` are still ranked, one key below.
# Derived from _CRITICALITY_RANK so re-grading the vocabulary cannot leave a
# stale cutoff behind.
_CRITICALITY_LEADS: tuple[str, ...] = ("critical", "high")
_CRITICALITY_LEAD_MAX = max(rank for name, rank in _CRITICALITY_RANK if name in _CRITICALITY_LEADS)

# Ceiling on the "keep mine" backoff. Per field, per host: this snoozes ONE
# disagreement about one host's role (or criticality, or hostname), not the
# sweep. Past three months it is worth re-raising even if the operator has waved
# it off three times, because the machine has probably changed since.
MAX_SNOOZE_DAYS = 90

DEFAULT_LIST_LIMIT = 50
MAX_LIST_LIMIT = 200

# Render order for a host's fields — the order DOSSIER_FIELDS declares, which is
# the order the prompt block and the detail card read in.
_FIELD_ORDER: dict[str, int] = {name: index for index, name in enumerate(DOSSIER_FIELDS)}

_SORTS = ("importance", "attention", "last_seen", "first_seen", "ip", "stale", "event_count")

_WS_RE = re.compile(r"\s+")

# The third answer :func:`_conflict_kind` can give. Not a named disagreement,
# and NOT agreement either: this build had nothing usable to say. The two are
# kept apart because agreement RESETS the prod machine and "nobody could tell"
# has to hold it — folding them together let a host that alternates strong and
# weak inferences reset its own counter forever and never earn a prod.
_NO_SIGNAL = "no_signal"

# Columns whose absence must be written as SQL NULL rather than as the JSON
# literal 'null'. See :func:`_update_values` / :func:`_insert_values`.
_JSON_COLUMNS = frozenset({"inferred_value_json", "operator_value_json", "inferred_evidence"})


@dataclass(frozen=True)
class InferredWrite:
    """The outcome of one field write, for the sweep's counters and its audit.

    ``conflict_kind`` is non-``None`` whenever this build disagreed with a
    standing override (``mismatch`` | ``retracted`` | ``rebound``);
    ``prompted`` is ``True`` only on the build that actually fires the prod, so
    the caller emits exactly one ``dossier_conflict_nudge`` per cycle.
    """

    row: HostDossierField
    conflict_kind: str | None
    prompted: bool


def normalize_host_key(ip: str) -> str:
    """Return the canonical key for *ip*; raises ``ValueError`` if it is not one.

    Canonicalized through :mod:`ipaddress` so ``192.168.10.202`` and an IPv6
    address written in a different case or expansion resolve to the same row
    rather than to two dossiers for one host.
    """
    stripped = ip.strip()
    if not stripped:
        raise ValueError("empty host key")
    return str(ipaddress.ip_address(stripped))


def _lookup_key(ip: str) -> str | None:
    """Normalize *ip* for a lookup, or ``None`` when it is not an address.

    Read and operator paths take user-supplied path segments. A string that is
    not an address cannot name a stored host, so ``None`` here becomes the
    route's 404 rather than a 500.
    """
    try:
        return normalize_host_key(ip)
    except ValueError:
        return None


def _validate_field(field: str) -> str:
    if field not in DOSSIER_FIELDS:
        raise ValueError(f"unknown dossier field {field!r}; expected one of {DOSSIER_FIELDS}")
    return field


def _naive_utc(value: datetime | None) -> datetime | None:
    """Coerce to the naive-UTC the schema stores (``store.auth.utcnow``'s shape).

    Elasticsearch timestamps arrive tz-aware; the columns are naive. Mixing the
    two raises at the first comparison — and the conflict machine compares
    timestamps on every build — so the store is the boundary that normalizes.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


def _min_dt(current: datetime | None, candidate: datetime | None) -> datetime | None:
    if candidate is None:
        return current
    if current is None:
        return candidate
    return min(current, candidate)


def _max_dt(current: datetime | None, candidate: datetime | None) -> datetime | None:
    if candidate is None:
        return current
    if current is None:
        return candidate
    return max(current, candidate)


def _comparable(value: str | None) -> str | None:
    """Fold a value for the disagreement check: case and whitespace are not news."""
    if value is None:
        return None
    return _WS_RE.sub(" ", value.strip()).casefold()


def _update_values(values: dict[str, Any]) -> dict[str, Any]:
    """The UPDATE form of a value map: an absent JSON column as SQL NULL.

    SQLAlchemy's JSON type defaults to ``none_as_null=False``, so a plain Python
    ``None`` is stored as the JSON literal ``'null'`` — a value, not an absence.
    It reads back as ``None`` in Python, which is why this hides so well, but
    every SQL predicate that asks whether a lane holds anything spells it
    ``IS NULL``: :func:`prune`'s override protection, the ``source=`` filter in
    :func:`list_dossiers`. A cleared override stored as ``'null'`` would keep
    reading as held forever — the field would never go back to the builder.
    """
    return {
        key: (null() if key in _JSON_COLUMNS and value is None else value)
        for key, value in values.items()
    }


def _insert_values(values: dict[str, Any]) -> dict[str, Any]:
    """The INSERT form: an absent JSON column left OUT of the statement entirely.

    Same SQL NULL :func:`_update_values` writes, by omission — a column the
    INSERT does not name is NULL. ``null()`` would be correct SQL here too, but
    a column written as a SQL expression is EXPIRED on the object after the
    flush, and reading it back on an async session raises ``MissingGreenlet``
    instead of returning ``None``.
    """
    return {
        key: value for key, value in values.items() if not (key in _JSON_COLUMNS and value is None)
    }


async def _get_host(db: AsyncSession, host_key: str) -> HostDossier | None:
    row: HostDossier | None = await db.scalar(
        select(HostDossier).where(HostDossier.host_key == host_key)
    )
    return row


async def _get_field_row(db: AsyncSession, dossier_id: int, field: str) -> HostDossierField | None:
    """Read one field row, ALWAYS from the database.

    ``populate_existing`` because the sweep holds one session across a whole
    host: a row already in the identity map would otherwise be handed back with
    the operator lane as it stood before a route committed an override, and the
    build would then argue with a claim that no longer stands — and prod the
    operator about a value they had just settled. Nothing here mutates these
    rows in Python (both lanes are written through UPDATE), so there are no
    pending changes for the refresh to discard.
    """
    row: HostDossierField | None = await db.scalar(
        select(HostDossierField)
        .where(
            HostDossierField.dossier_id == dossier_id,
            HostDossierField.field == field,
        )
        .execution_options(populate_existing=True)
    )
    return row


# ---------------------------------------------------------------------------
# Host header
# ---------------------------------------------------------------------------


async def upsert_host(
    db: AsyncSession,
    ip: str,
    *,
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
    last_observed_at: datetime | None = None,
    event_count: int | None = None,
    identity_fingerprint: str | None = None,
    last_built_at: datetime | None = None,
    build_error: str | None = None,
    now: datetime | None = None,
) -> HostDossier:
    """Insert or refresh the per-host header. Flushes; the caller commits.

    ``first_seen`` is monotone (``min``) and ``last_seen`` monotone (``max``): a
    sweep over a narrower window widens the lifetime, never resets it, or a host
    that has been on the network for a year would keep reporting itself as newly
    arrived every time the lookback shrank. ``event_count`` is the *window*
    count and replaces.

    ``identity_fingerprint`` stamps ``identity_rebound_at`` only when it moves
    from one non-null value to a *different* non-null value. A build that saw no
    DHCP/NTLM this window passes ``None``, and silence is not evidence that the
    machine changed.

    A build's outcome is one atomic fact: pass ``last_built_at`` and
    ``build_error`` together and ``build_error`` is written verbatim (``None``
    clears it). Without ``last_built_at`` the previous outcome is left alone, so
    the census pass — which touches every host before any of them is built —
    cannot erase the reason a host failed to build last night. A FAILED build
    still stamps ``last_built_at``: the sweep picks hosts by staleness, and a
    host that never advanced its stamp would be retried first on every sweep
    forever, spending the per-run host budget on it while the rest of the table
    goes unrebuilt.

    ``build_error`` WITHOUT ``last_built_at`` raises. The census branch above
    used to swallow it — an error string accepted, discarded, and read back as
    null, which to the caller looks like a column that does not persist. No
    production caller passes that combination (both build paths pass the pair),
    so the loud refusal costs nothing and ends the silent-drop trap.
    """
    if build_error is not None and last_built_at is None:
        raise ValueError(
            "build_error requires last_built_at: a build outcome is one atomic "
            "fact, and an error without its stamp would be silently discarded"
        )
    key = normalize_host_key(ip)
    stamp = _naive_utc(now) or utcnow()
    row = await _get_host(db, key)
    if row is None:
        row = HostDossier(host_key=key, ip=key)
        db.add(row)

    row.first_seen = _min_dt(row.first_seen, _naive_utc(first_seen))
    row.last_seen = _max_dt(row.last_seen, _naive_utc(last_seen))
    if last_observed_at is not None:
        row.last_observed_at = _naive_utc(last_observed_at)
    if event_count is not None:
        row.event_count = event_count
    if identity_fingerprint is not None:
        known = row.identity_fingerprint
        if known is not None and known != identity_fingerprint:
            row.identity_rebound_at = stamp
        row.identity_fingerprint = identity_fingerprint
    if last_built_at is not None:
        row.last_built_at = _naive_utc(last_built_at)
        row.build_error = build_error

    await db.flush()
    return row


# ---------------------------------------------------------------------------
# Inference lane + the persistent-disagreement state machine
# ---------------------------------------------------------------------------


def _conflict_kind(
    existing: HostDossierField | None,
    *,
    inferred_value: str | None,
    inferred_value_json: Any | None,
    confidence: float,
    retracted_at: datetime | None,
    identity_rebound_at: datetime | None,
    min_confidence: float,
) -> str | None:
    """Name this build's disagreement with the standing override.

    Three shapes of answer, and the third is the subtle one:

    * a kind (``rebound`` | ``retracted`` | ``mismatch``) — this build argues;
    * ``None`` — this build AGREES, which resets the prod machine;
    * :data:`_NO_SIGNAL` — this build had nothing usable to say, which must HOLD
      the prod machine. Folding that into agreement let a host whose inference
      alternates strong and weak wipe its own observation counter on every other
      build, so it could never reach the three-consecutive threshold and the
      prod could never fire.

    The kinds are ordered by how deeply each undermines the override.
    ``rebound`` first: if a different machine now answers on this address, the
    override may be about a different host entirely, and any value disagreement
    is downstream of that. Then ``retracted`` — the evidence the field rested on
    is gone — and finally ``mismatch``, where the evidence simply points
    somewhere else.

    ``retracted`` is a STANDING condition (the value is still absent), not a
    one-build edge. Firing it only on the build that stamps
    ``inferred_retracted_at`` would make the min-observations gate unreachable,
    and a retraction would never earn a prod at all.

    A weak inference never conflicts: ``min_confidence`` is the same floor the
    resolver uses, so the dossier only argues with an operator over a belief it
    would have been willing to assert. It does not concede either — that is what
    :data:`_NO_SIGNAL` is for.
    """
    if existing is None:
        return None
    held, held_json = existing.operator_value, existing.operator_value_json
    if held is None and held_json is None:
        return None  # nothing declared, nothing to disagree with
    operator_set_at = existing.operator_set_at
    if (
        identity_rebound_at is not None
        and operator_set_at is not None
        and identity_rebound_at > operator_set_at
    ):
        return "rebound"
    if inferred_value is None and inferred_value_json is None:
        return "retracted" if retracted_at is not None else _NO_SIGNAL
    if confidence < min_confidence:
        return _NO_SIGNAL
    # Argue with the lane the operator actually used. services_offered /
    # activity_profile / management_plane are overridden through value_json with
    # the scalar left NULL — the documented path, and what DossierOverrideIn's
    # value_json exists to supply — so a check that only read the scalar could
    # never see one of those disagree and those three fields silently lost the
    # cyclic prod. A build that answered in the other lane cannot be compared to
    # the claim at all, which is no signal rather than agreement.
    if held_json is not None:
        if inferred_value_json is None:
            return _NO_SIGNAL
        return None if _json_agrees(held_json, inferred_value_json) else "mismatch"
    if inferred_value is None:
        return _NO_SIGNAL
    if _comparable(inferred_value) == _comparable(held):
        return None
    return "mismatch"


def _json_agrees(held: Any, inferred: Any) -> bool:
    """Does the inference contradict the structured claim the operator made?

    Deliberately NOT deep equality. The builder's structured payloads carry
    volatile bookkeeping the operator never writes — per-port connection counts,
    hour-of-day histograms, byte percentiles — so equality would report a
    mismatch on every single build and prod the operator forever about a
    services list they got exactly right.

    The rule instead: an operator's mapping is contradicted only on the keys
    they actually stated (extra inferred keys are detail, not disagreement),
    while a list IS a complete enumeration, so it must match one-for-one with
    order treated as noise — a services list bucketed differently by the next
    sweep is the same fact.
    """
    if isinstance(held, dict) and isinstance(inferred, dict):
        return all(
            key in inferred and _json_agrees(value, inferred[key]) for key, value in held.items()
        )
    if isinstance(held, list) and isinstance(inferred, list):
        if len(held) != len(inferred):
            return False
        unmatched = list(inferred)
        for item in held:
            for index, other in enumerate(unmatched):
                if _json_agrees(item, other):
                    del unmatched[index]
                    break
            else:
                return False
        return True
    if isinstance(held, str) and isinstance(inferred, str):
        return _comparable(held) == _comparable(inferred)
    return bool(held == inferred)


def _conflict_state(
    existing: HostDossierField | None,
    kind: str | None,
    *,
    now: datetime,
    min_observations: int,
    prompt_interval_hours: int,
) -> tuple[dict[str, Any], bool]:
    """Advance the prod state machine; return (column values, prompt fired).

    Agreement clears ``conflict_first_seen_at`` / ``observations`` / ``snoozed_until``
    / ``kind`` but KEEPS ``conflict_prompt_count`` and ``conflict_last_prompted_at``:
    those are history, and the backoff of a second disagreement should start
    where the first one left off rather than nagging from scratch.

    :data:`_NO_SIGNAL` writes NOTHING — an empty mapping leaves every conflict
    column exactly as it stands. A build that could not tell has not settled the
    argument, and treating its silence as agreement is what let an alternating
    host reset its own counter forever.
    """
    if kind == _NO_SIGNAL:
        return {}, False
    if kind is None:
        return (
            {
                "conflict_kind": None,
                "conflict_first_seen_at": None,
                "conflict_observations": 0,
                "conflict_snoozed_until": None,
            },
            False,
        )

    values: dict[str, Any] = {"conflict_kind": kind}
    if existing is None or existing.conflict_first_seen_at is None:
        values["conflict_first_seen_at"] = now
        observations = 1
    else:
        observations = (existing.conflict_observations or 0) + 1
    values["conflict_observations"] = observations

    snoozed_until = existing.conflict_snoozed_until if existing is not None else None
    last_prompted = existing.conflict_last_prompted_at if existing is not None else None
    prompt_count = (existing.conflict_prompt_count or 0) if existing is not None else 0

    prompted = (
        prompt_interval_hours > 0
        and observations >= min_observations
        and (snoozed_until is None or now >= snoozed_until)
        and (last_prompted is None or now - last_prompted >= timedelta(hours=prompt_interval_hours))
    )
    if prompted:
        values["conflict_last_prompted_at"] = now
        values["conflict_prompt_count"] = prompt_count + 1
    return values, prompted


def _inferred_values(
    existing: HostDossierField | None,
    fact: Fact,
    *,
    now: datetime,
    identity_rebound_at: datetime | None,
    min_confidence: float,
    min_observations: int,
    prompt_interval_hours: int,
) -> tuple[dict[str, Any], str | None, bool]:
    """Build the column values for one inference write. Pure.

    The returned mapping names ``inferred_*`` and ``conflict_*`` columns and
    NOTHING else — that disjointness is the two-lane invariant, and a test
    asserts it against the model's own operator columns so a future edit cannot
    smuggle an ``operator_set_at=now`` into the build path.
    """
    observed = _naive_utc(fact.observed_at)
    has_value = fact.value is not None or fact.value_json is not None
    previously_held = existing is not None and (
        existing.inferred_value is not None or existing.inferred_value_json is not None
    )

    if has_value:
        retracted_at = None
    elif previously_held:
        # A build that looked and found nothing retracts the belief in the same
        # write that nulls it, rather than leaving a fact standing on evidence
        # that has gone.
        retracted_at = now
    else:
        retracted_at = existing.inferred_retracted_at if existing is not None else None

    values: dict[str, Any] = {
        "inferred_value": fact.value,
        "inferred_value_json": fact.value_json,
        "inferred_confidence": fact.confidence,
        # No value, no provenance: a null cannot have a source.
        "inferred_source": fact.source if has_value else None,
        # The last build that EVALUATED this field, even when it concluded
        # nothing — how the resolver tells "still true" from "nobody looked".
        "inferred_last_run_at": now,
        "inferred_retracted_at": retracted_at,
    }

    if has_value:
        values["inferred_first_seen"] = _min_dt(
            existing.inferred_first_seen if existing is not None else None, observed
        )
        values["inferred_last_seen"] = _max_dt(
            existing.inferred_last_seen if existing is not None else None, observed
        )

    if has_value or fact.evidence:
        # Keyed BY SOURCE, and REASSIGNED rather than mutated: SQLAlchemy JSON
        # columns do not track in-place mutation, so a dict edited in place is
        # silently not persisted (the same trap discovery.py works around).
        merged = dict(existing.inferred_evidence or {}) if existing is not None else {}
        entry: dict[str, Any] = {
            "strings": list(fact.evidence),
            "value": fact.value,
            "strength": fact.strength,
            "confidence": fact.confidence,
            "last_seen": observed.isoformat() if observed is not None else None,
        }
        if fact.conflict:
            entry["conflict"] = fact.conflict
        merged[fact.source] = entry
        values["inferred_evidence"] = merged

    kind = _conflict_kind(
        existing,
        inferred_value=fact.value,
        inferred_value_json=fact.value_json,
        confidence=fact.confidence,
        retracted_at=retracted_at,
        identity_rebound_at=identity_rebound_at,
        min_confidence=min_confidence,
    )
    conflict_values, prompted = _conflict_state(
        existing,
        kind,
        now=now,
        min_observations=min_observations,
        prompt_interval_hours=prompt_interval_hours,
    )
    values.update(conflict_values)
    # _NO_SIGNAL is internal to the state machine: to the sweep and its audit
    # this build simply had no disagreement to report.
    return values, (None if kind == _NO_SIGNAL else kind), prompted


async def upsert_inferred(
    db: AsyncSession,
    dossier: HostDossier,
    fact: Fact,
    *,
    now: datetime | None = None,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    min_observations: int = DEFAULT_CONFLICT_MIN_OBSERVATIONS,
    prompt_interval_hours: int = DEFAULT_CONFLICT_PROMPT_INTERVAL_HOURS,
) -> InferredWrite:
    """Write one build's belief about one field, and advance the prod machine.

    Called for every field on every build, INCLUDING fields an operator has
    overridden — that is the whole mechanic. The operator lane is read here (to
    detect disagreement) and never written.

    The conflict evaluation lands in the same transaction as the field write it
    is derived from: a prod that fired against a build whose values were then
    rolled back would nag about evidence the dossier does not hold. Flushes; the
    caller commits once per host.

    The knobs mirror ``settings.dossier_min_confidence`` /
    ``dossier_conflict_min_observations`` / ``dossier_conflict_prompt_interval_hours``;
    the caller passes them so this module stays independent of Settings.
    """
    _validate_field(fact.field)
    stamp = _naive_utc(now) or utcnow()

    def _values(against: HostDossierField | None) -> tuple[dict[str, Any], str | None, bool]:
        """This write's columns, argued against the row as *against* has it."""
        return _inferred_values(
            against,
            fact,
            now=stamp,
            identity_rebound_at=dossier.identity_rebound_at,
            min_confidence=min_confidence,
            min_observations=min_observations,
            prompt_interval_hours=prompt_interval_hours,
        )

    existing = await _get_field_row(db, dossier.id, fact.field)
    values, kind, prompted = _values(existing)

    if existing is None:
        row = HostDossierField(dossier_id=dossier.id, field=fact.field, **_insert_values(values))
        db.add(row)
        await db.flush()
        return InferredWrite(row=row, conflict_kind=kind, prompted=prompted)

    # Conditional on the operator lane still being the one this write was argued
    # from. A sweep can take minutes per host; an override committed inside that
    # window would otherwise be answered with a verdict computed against the
    # claim it replaced — re-opening a disagreement the operator just settled and
    # prodding them about their own brand-new value.
    result = await db.execute(
        update(HostDossierField)
        .where(
            HostDossierField.id == existing.id,
            HostDossierField.operator_value == existing.operator_value,
            HostDossierField.operator_set_at == existing.operator_set_at,
        )
        .values(**_update_values(values))
        .execution_options(synchronize_session=False)
    )
    # cast: AsyncSession.execute is typed Result, but an UPDATE always returns a
    # CursorResult, and its rowcount is how the guard above reports itself.
    if cast("CursorResult[Any]", result).rowcount:
        await db.refresh(existing)
        return InferredWrite(row=existing, conflict_kind=kind, prompted=prompted)

    fresh = await _get_field_row(db, dossier.id, fact.field)
    if fresh is None:
        # The row went out from under us (a prune racing the sweep). Re-inserting
        # it would resurrect a host the per-sweep host cap just dropped.
        return InferredWrite(row=existing, conflict_kind=None, prompted=False)
    # The observation itself still has to land — a build that silently declined to
    # record what it saw is the dismissed-row trap this design exists to avoid —
    # so only the VERDICT is recomputed, against the claim that now stands.
    values, kind, prompted = _values(fresh)
    await db.execute(
        update(HostDossierField)
        .where(HostDossierField.id == fresh.id)
        .values(**_update_values(values))
        .execution_options(synchronize_session=False)
    )
    await db.refresh(fresh)
    return InferredWrite(row=fresh, conflict_kind=kind, prompted=prompted)


# ---------------------------------------------------------------------------
# Operator lane
# ---------------------------------------------------------------------------


async def set_override(
    db: AsyncSession,
    ip: str,
    field: str,
    value: str | None,
    *,
    value_json: Any | None = None,
    actor: str | None = None,
    note: str | None = None,
    now: datetime | None = None,
) -> HostDossierField | None:
    """Set the operator value for one field. ``None`` if the host is unknown.

    Writes only ``operator_*``. Creates the field row when the builder has never
    produced one — ``criticality`` and ``policy_notes`` are never inferred, so
    for those the operator lane is the only lane there will ever be.

    Setting an override also restarts the disagreement clock
    (``conflict_first_seen_at`` / ``observations`` / ``snoozed_until`` /
    ``kind``): the counter measures builds that disagreed with *this* claim, and
    a new claim has not been contradicted yet. ``conflict_prompt_count`` is kept,
    so the backoff still grows. Re-affirming an override after an identity
    rebind settles the ``rebound`` conflict for the same reason — the operator
    has looked at the new machine and said "still this".
    """
    _validate_field(field)
    key = _lookup_key(ip)
    if key is None:
        return None
    host = await _get_host(db, key)
    if host is None:
        return None
    stamp = _naive_utc(now) or utcnow()
    values: dict[str, Any] = {
        "operator_value": value,
        "operator_value_json": value_json,
        "operator_set_at": stamp,
        "operator_actor": actor,
        "operator_note": note,
        "conflict_kind": None,
        "conflict_first_seen_at": None,
        "conflict_observations": 0,
        "conflict_snoozed_until": None,
    }

    row = await _get_field_row(db, host.id, field)
    if row is None:
        # inferred_last_run_at is NOT NULL; omitting it lets the column's own
        # server default apply. Nothing in the inference lane is written here,
        # and the resolver ignores the stamp when there is no inferred value.
        row = HostDossierField(dossier_id=host.id, field=field, **_insert_values(values))
        db.add(row)
        await db.flush()
    else:
        await db.execute(
            update(HostDossierField)
            .where(HostDossierField.id == row.id)
            .values(**_update_values(values))
            .execution_options(synchronize_session=False)
        )
        await db.refresh(row)
    await db.commit()
    return row


async def clear_override(db: AsyncSession, ip: str, field: str) -> HostDossierField | None:
    """Accept the inference: drop the operator value and the disagreement.

    Clears ``operator_*`` and the open conflict, keeping ``conflict_prompt_count``
    and ``conflict_last_prompted_at`` as history. The inference lane is not
    touched — the value the operator just accepted is already there.

    Returns ``None`` for BOTH an unknown host/field and a field carrying no
    override; the route disambiguates 404 from 409 with :func:`get_field`, the
    same shape ``routes_identifiers`` uses for dismiss/delete.
    """
    _validate_field(field)
    row = await get_field(db, ip, field)
    if row is None or (row.operator_value is None and row.operator_value_json is None):
        return None
    await db.execute(
        update(HostDossierField)
        .where(HostDossierField.id == row.id)
        .values(
            **_update_values(
                {
                    "operator_value": None,
                    # SQL NULL, not the JSON literal 'null' — see _update_values.
                    # Stored as 'null' the cleared override would still satisfy
                    # `operator_value_json IS NOT NULL`, so prune would go on
                    # sparing the host and the source filter would go on calling
                    # it operator-touched.
                    "operator_value_json": None,
                    "operator_set_at": None,
                    "operator_actor": None,
                    "operator_note": None,
                    "conflict_kind": None,
                    "conflict_first_seen_at": None,
                    "conflict_observations": 0,
                    "conflict_snoozed_until": None,
                }
            )
        )
        .execution_options(synchronize_session=False)
    )
    await db.refresh(row)
    await db.commit()
    return row


async def snooze_conflict(
    db: AsyncSession,
    ip: str,
    field: str,
    *,
    now: datetime | None = None,
    interval_hours: int = DEFAULT_CONFLICT_PROMPT_INTERVAL_HOURS,
    max_snooze_days: int = MAX_SNOOZE_DAYS,
) -> HostDossierField | None:
    """ "Keep mine": silence this disagreement for a doubling interval.

    ``interval_hours * 2 ** min(conflict_prompt_count, 4)``, capped at
    ``max_snooze_days``. The nag decays instead of repeating — an operator who
    has answered the same question three times should not be asked a fourth time
    on the same schedule — and the cap stops it decaying into never.

    ``conflict_observations`` resets so the next cycle needs fresh continued
    evidence rather than resuming a count the operator has already answered.
    The operator lane and the inference lane are both left alone: nothing is
    resolved here, only postponed. If the evidence later agrees, the build's own
    state machine clears the snooze along with the rest of the conflict.

    With prodding disabled (``interval_hours <= 0``) the default interval is
    used as the base: "keep mine" must still take the row off the conflicts
    list, and a zero-length snooze would not.
    """
    _validate_field(field)
    row = await get_field(db, ip, field)
    if row is None:
        return None
    stamp = _naive_utc(now) or utcnow()
    base = interval_hours if interval_hours > 0 else DEFAULT_CONFLICT_PROMPT_INTERVAL_HOURS
    hours = base * 2 ** min(row.conflict_prompt_count or 0, 4)
    until = stamp + min(timedelta(hours=hours), timedelta(days=max_snooze_days))
    await db.execute(
        update(HostDossierField)
        .where(HostDossierField.id == row.id)
        .values(conflict_snoozed_until=until, conflict_observations=0)
        .execution_options(synchronize_session=False)
    )
    await db.refresh(row)
    await db.commit()
    return row


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


async def get_field(db: AsyncSession, ip: str, field: str) -> HostDossierField | None:
    """One field row by host + name, or ``None``. The 404-vs-409 disambiguator."""
    _validate_field(field)
    key = _lookup_key(ip)
    if key is None:
        return None
    host = await _get_host(db, key)
    if host is None:
        return None
    return await _get_field_row(db, host.id, field)


def _ordered(rows: list[HostDossierField]) -> list[HostDossierField]:
    """Sort field rows into DOSSIER_FIELDS order; unknown names sort last."""
    return sorted(rows, key=lambda row: (_FIELD_ORDER.get(row.field, len(_FIELD_ORDER)), row.field))


async def _fields_for(
    db: AsyncSession, dossier_ids: list[int]
) -> dict[int, list[HostDossierField]]:
    """All field rows for a page of hosts in ONE query (never N+1 per host)."""
    grouped: dict[int, list[HostDossierField]] = {did: [] for did in dossier_ids}
    if not dossier_ids:
        return grouped
    rows = (
        await db.scalars(
            select(HostDossierField).where(HostDossierField.dossier_id.in_(dossier_ids))
        )
    ).all()
    for row in rows:
        grouped[row.dossier_id].append(row)
    return {did: _ordered(rows) for did, rows in grouped.items()}


async def get_dossier(
    db: AsyncSession, ip: str
) -> tuple[HostDossier, list[HostDossierField]] | None:
    """The host header plus its fields in render order, or ``None`` if unknown."""
    key = _lookup_key(ip)
    if key is None:
        return None
    host = await _get_host(db, key)
    if host is None:
        return None
    rows = (
        await db.scalars(select(HostDossierField).where(HostDossierField.dossier_id == host.id))
    ).all()
    return host, _ordered(list(rows))


async def get_dossiers(
    db: AsyncSession, ips: list[str]
) -> list[tuple[HostDossier, list[HostDossierField]]]:
    """Several hosts' dossiers in TWO queries, however many addresses are asked.

    The per-host :func:`get_dossier` is the wrong shape behind the host page's
    peer table, which resolves a dozen addresses on every load; looping it there
    would be the N+1 :func:`_fields_for` exists to prevent, one layer up.
    Addresses with no row — and path segments that are not addresses at all —
    are simply absent from the result rather than raising, because the caller is
    naming peers off a live aggregation and most of them will be unknown.

    ``ips`` is NOT truncated, and the caller is responsible for bounding it —
    the host page passes at most its twelve displayed peers. Truncating here
    instead would name some peers and leave others blank with no signal which,
    which is a worse failure than a large query.

    Note that nothing about the table constrains ``len(ips)``: the caller
    derives its addresses from a live Elasticsearch aggregation, not from these
    rows, so :func:`prune` capping how many hosts EXIST says nothing about how
    many parameters a caller BINDS. A caller that needs an unbounded list should
    chunk it rather than assume this function does.
    """
    keys = [key for ip in ips if (key := _lookup_key(ip)) is not None]
    if not keys:
        return []
    hosts = list(await db.scalars(select(HostDossier).where(HostDossier.host_key.in_(keys))))
    grouped = await _fields_for(db, [host.id for host in hosts])
    return [(host, grouped.get(host.id, [])) for host in hosts]


def _no_clean_build() -> Any:
    """No clean build on record: never built at all, or the last build errored.

    The one spelling behind both the summary's ``never_built`` count and the
    list's ``health="broken"`` filter. Two spellings is how a KPI ends up
    counting a set its own click-through cannot show.
    """
    return or_(
        HostDossier.last_built_at.is_(None),
        HostDossier.build_error.is_not(None),
    )


def _lane_declared() -> Any:
    """The operator lane holds a claim — scalar or structured.

    One spelling for every consumer (the ``source=`` filter, the attention
    order's declared tier, :func:`summarize_dossiers`, :func:`prune`'s
    protection): a second spelling is how a JSON-only override — the documented
    path for the three structured fields — ends up counted by one reader and
    invisible to another.
    """
    return or_(
        HostDossierField.operator_value.is_not(None),
        HostDossierField.operator_value_json.is_not(None),
    )


def _lane_assertable(fresh_since: datetime, min_confidence: float) -> Any:
    """The resolver's two gates on the inference lane, in SQL.

    What ``soc_ai.dossier.resolve.resolve_field`` demands before it asserts an
    inferred value: the lane holds something, the last build that evaluated it
    is inside the staleness window, and the confidence clears the floor.
    ``is_not(None)`` on the stamp is defensive — the column is NOT NULL, but the
    resolver treats a missing stamp as stale and this predicate has to keep
    meaning the same thing if that ever changes.

    Shared by :func:`summarize_dossiers` and the attention order so the KPI, the
    list order and the resolved rows underneath them cannot disagree about
    which stored values count.
    """
    return and_(
        or_(
            HostDossierField.inferred_value.is_not(None),
            HostDossierField.inferred_value_json.is_not(None),
        ),
        HostDossierField.inferred_last_run_at.is_not(None),
        HostDossierField.inferred_last_run_at >= fresh_since,
        func.coalesce(HostDossierField.inferred_confidence, 0.0) >= min_confidence,
    )


def _attention_order(
    stamp: datetime,
    *,
    min_confidence: float,
    staleness_hours: int,
    min_observations: int,
) -> list[Any]:
    """ORDER BY keys that rank what needs the operator, entirely in SQL.

    The failure this replaces: the list defaulted to ``last_seen``, so the
    anonymous tail — whichever addresses happened to talk most recently —
    floated to the top, and the one named, critical, conflicted host in the
    dogfood seed was the last row of 41.

    Five tiers, then two refinements, then the stability key:

    1. NO CLEAN BUILD (:func:`_no_clean_build`: never built, or the last build
       errored) — the same predicate the KPI counts and ``health="broken"``
       filters, so the top of this order IS the click-through set. Drawn
       narrower (``build_error`` only, as first shipped) a never-built host was
       "broken" to two surfaces and invisible to the third;
    2. an open conflict that is DUE (:func:`_conflict_due_conditions`, the same
       predicate as the queue and the KPI — a snoozed or below-gate disagreement
       is not yet asking anything);
    3. declared — the operator lane holds a value on any field;
    4. named — the ``hostname`` field as the RESOLVER would assert it (declared,
       or fresh AND confident via :func:`_lane_assertable`); a stored name the
       resolver withholds must not rank here, or the order would promote a row
       whose name column renders a dash;
    5. everything else.

    Within and across tiers: declared criticality first (``critical`` > ``high``
    > ``medium`` > ``low`` > unstated/unparseable — only hosts in tiers 1-3 can
    carry one, since declaring is what puts a host there), then ``last_seen``
    newest-first, then ``host_key`` ascending so two loads of identical data can
    never swap rows under the operator's cursor.

    Every key is computed IN the page query (correlated EXISTS / scalar
    subqueries over ``ix_host_dossier_field_dossier_id``), never in Python: the
    list is paged in SQL, and ordering rows after the page is cut orders the
    page, not the list.
    """
    conflict_open = (
        select(HostDossierField.id)
        .where(
            HostDossierField.dossier_id == HostDossier.id,
            *_conflict_due_conditions(stamp, min_observations),
        )
        .exists()
    )
    tier = case(
        (_no_clean_build(), 0),
        (conflict_open, 1),
        (_declared_exists(), 2),
        (_named_exists(stamp, min_confidence, staleness_hours), 3),
        else_=4,
    )
    return [
        tier.asc(),
        _criticality_rank().asc(),
        nulls_last(HostDossier.last_seen.desc()),
        HostDossier.host_key.asc(),
    ]


def _declared_exists() -> Any:
    """Correlated EXISTS: the operator has declared SOMETHING about this host."""
    return (
        select(HostDossierField.id)
        .where(HostDossierField.dossier_id == HostDossier.id, _lane_declared())
        .exists()
    )


def _named_exists(stamp: datetime, min_confidence: float, staleness_hours: int) -> Any:
    """Correlated EXISTS: the ``hostname`` field as the RESOLVER would assert it.

    Declared, or fresh AND confident. A stored name the resolver withholds must
    not rank the host as named, or an order would promote a row whose name
    column renders a dash.
    """
    fresh_since = stamp - timedelta(hours=staleness_hours)
    return (
        select(HostDossierField.id)
        .where(
            HostDossierField.dossier_id == HostDossier.id,
            HostDossierField.field == HOSTNAME_FIELD,
            or_(_lane_declared(), _lane_assertable(fresh_since, min_confidence)),
        )
        .exists()
    )


def _criticality_rank() -> Any:
    """This host's declared criticality as a sortable rank, best first.

    At most one row per (dossier, field) — the unique constraint — so the
    scalar subquery cannot multiply rows; no declaration coalesces to
    :data:`_CRITICALITY_UNRANKED`, which is also where free text outside the
    graded vocabulary lands.
    """
    folded = func.lower(func.trim(HostDossierField.operator_value))
    rank = (
        select(
            case(
                *[(folded == name, value) for name, value in _CRITICALITY_RANK],
                else_=_CRITICALITY_UNRANKED,
            )
        )
        .where(
            HostDossierField.dossier_id == HostDossier.id,
            HostDossierField.field == CRITICALITY_FIELD,
            HostDossierField.operator_value.is_not(None),
        )
        .scalar_subquery()
    )
    return func.coalesce(rank, _CRITICALITY_UNRANKED)


def _importance_order(
    stamp: datetime,
    *,
    min_confidence: float,
    staleness_hours: int,
) -> list[Any]:
    """ORDER BY keys that lead with the machines the operator already cares about.

    The failure this answers (dogfood B2a, 2026-08-11): on a real estate almost
    nothing has been built yet, so :func:`_attention_order`'s tier 0 — no clean
    build — IS the first screen, every row of it a dash under HOST and ROLE,
    and the handful of named, operator-graded hosts sat below the fold. That
    order answers "which hosts is the sweep failing to reach"; a landing screen
    has to answer "which hosts matter" first, and keep the other question one
    click away in the sort control.

    Four keys, then the stability key:

    1. graded ``critical`` or ``high`` (:data:`_CRITICALITY_LEADS`) — never
       inferred, so this is purely the operator saying the host matters, and it
       leads even when the host has never been built: the sweep failing to
       reach a crown jewel does not make it matter less;
    2. named — the ``hostname`` field as the RESOLVER would assert it, so a row
       ranked here never renders a dash in the column it was ranked for;
    3. the rest of the criticality grading, best first, so ``medium`` still
       beats ``low`` still beats ungraded — BELOW named on purpose. Leading
       with every grade would mean any declaration at all outranks every named
       host, and a single bulk tagging pass over a subnet of printers as ``low``
       would bury the named servers under them: the first-screen-of-nothing this
       order exists to prevent, rebuilt by the order itself;
    4. declared anything at all — a host a human has touched outranks one
       nobody has.

    Then ``last_seen`` newest-first and ``host_key`` ascending, so two loads of
    identical data cannot swap rows under the operator's cursor.

    Computed IN the page query like the attention order, because the list is
    paged in SQL and ordering rows after the page is cut orders the page, not
    the list.
    """
    leads = case((_criticality_rank() <= _CRITICALITY_LEAD_MAX, 0), else_=1)
    named = case((_named_exists(stamp, min_confidence, staleness_hours), 0), else_=1)
    declared = case((_declared_exists(), 0), else_=1)
    return [
        leads.asc(),
        named.asc(),
        _criticality_rank().asc(),
        declared.asc(),
        nulls_last(HostDossier.last_seen.desc()),
        HostDossier.host_key.asc(),
    ]


async def list_dossiers(
    db: AsyncSession,
    *,
    q: str | None = None,
    role: str | None = None,
    source: str | None = None,
    health: str | None = None,
    limit: int = DEFAULT_LIST_LIMIT,
    offset: int = 0,
    sort: str = "attention",
    now: datetime | None = None,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    staleness_hours: int = DEFAULT_STALENESS_HOURS,
    min_observations: int = DEFAULT_CONFLICT_MIN_OBSERVATIONS,
) -> tuple[list[tuple[HostDossier, list[HostDossierField]]], int]:
    """A page of dossiers with their fields, plus the total matching count.

    Paged in SQL rather than shipping the table: the identifiers list can hand
    the client ~100 rows, but this table is capped at 5,000 hosts x ~12 fields.

    ``role`` matches ``coalesce(operator_value, inferred_value)`` — the operator
    lane wins, exactly as the resolver decides it. This is a coarse prefilter:
    the resolver still applies the confidence floor and the staleness window, so
    a listed host may resolve to "unknown" on the detail card. ``source`` splits
    the network by whether a human has touched it at all (``operator`` = at least
    one override, ``inferred`` = none). ``q`` matches the IP or a hostname in
    either lane.

    ``health="broken"`` selects hosts with NO CLEAN BUILD on record — never
    built at all, or the last build errored — which is exactly the set
    :func:`summarize_dossiers` counts as ``never_built``. The KPI must click
    through to the rows it counted; a filter drawn narrower (say,
    ``build_error`` only) would make the strip say "2" over a list showing 1,
    the untriaged-tile defect rebuilt here. Unknown values are ignored like the
    ``source`` filter's; the route's ``Literal`` is what rejects typos.

    ``sort`` defaults to ``attention`` (:func:`_attention_order`): what needs
    the operator, not what talked last. ``importance``
    (:func:`_importance_order`) asks the other half of that question — which
    hosts the operator has already said matter — and is what the Hosts screen
    lands on, because on a real estate "never built" describes almost every
    row. The other keys remain for callers that ask. An unknown sort falls back
    to the default rather than raising — a client typo is not a 500.

    ``now`` and the three knobs exist for the ranked orders (their "named" tier
    applies the resolver's gates, the attention order's conflict tier the
    queue's); they mirror
    ``dossier_min_confidence`` / ``dossier_staleness_hours`` /
    ``dossier_conflict_min_observations`` and are passed by the caller, the same
    way the rest of this module takes them. Ignored by the other sorts.
    """
    conditions: list[Any] = []
    if q:
        needle = q.strip()
        if needle:
            hostname_hit = (
                select(HostDossierField.id)
                .where(
                    HostDossierField.dossier_id == HostDossier.id,
                    HostDossierField.field == "hostname",
                    or_(
                        HostDossierField.operator_value.contains(needle, autoescape=True),
                        HostDossierField.inferred_value.contains(needle, autoescape=True),
                    ),
                )
                .exists()
            )
            conditions.append(or_(HostDossier.ip.contains(needle, autoescape=True), hostname_hit))
    if role:
        conditions.append(
            select(HostDossierField.id)
            .where(
                HostDossierField.dossier_id == HostDossier.id,
                HostDossierField.field == "role",
                func.coalesce(HostDossierField.operator_value, HostDossierField.inferred_value)
                == role,
            )
            .exists()
        )
    if source in ("operator", "inferred"):
        overridden = (
            select(HostDossierField.id)
            .where(HostDossierField.dossier_id == HostDossier.id, _lane_declared())
            .exists()
        )
        conditions.append(overridden if source == "operator" else ~overridden)
    if health == "broken":
        conditions.append(_no_clean_build())

    total = await db.scalar(select(func.count(HostDossier.id)).where(*conditions)) or 0

    if sort not in _SORTS:
        sort = "attention"
    order: list[Any]
    if sort == "stale":
        # The sweep's own priority: never built sorts first.
        order = [nulls_first(HostDossier.last_built_at.asc())]
    elif sort == "first_seen":
        order = [nulls_last(HostDossier.first_seen.desc())]
    elif sort == "ip":
        order = [HostDossier.host_key.asc()]
    elif sort == "event_count":
        order = [HostDossier.event_count.desc()]
    elif sort == "last_seen":
        order = [nulls_last(HostDossier.last_seen.desc())]
    elif sort == "importance":
        order = _importance_order(
            _naive_utc(now) or utcnow(),
            min_confidence=min_confidence,
            staleness_hours=staleness_hours,
        )
    else:
        order = _attention_order(
            _naive_utc(now) or utcnow(),
            min_confidence=min_confidence,
            staleness_hours=staleness_hours,
            min_observations=min_observations,
        )

    page = (
        await db.scalars(
            select(HostDossier)
            .where(*conditions)
            .order_by(*order, HostDossier.id.desc())
            .limit(max(1, min(limit, MAX_LIST_LIMIT)))
            .offset(max(0, offset))
        )
    ).all()
    fields = await _fields_for(db, [row.id for row in page])
    return [(row, fields.get(row.id, [])) for row in page], total


def _conflict_due_conditions(stamp: datetime, min_observations: int) -> list[Any]:
    """What "needs review" MEANS, in one place.

    Both :func:`conflicts_due` (the queue) and :func:`summarize_dossiers` (the
    count above it) build their WHERE from this. Two spellings of the same
    predicate is how a KPI ends up disagreeing with the list it sits on top of.
    """
    return [
        HostDossierField.conflict_first_seen_at.is_not(None),
        HostDossierField.conflict_observations >= min_observations,
        or_(
            HostDossierField.conflict_snoozed_until.is_(None),
            HostDossierField.conflict_snoozed_until <= stamp,
        ),
    ]


async def conflicts_due(
    db: AsyncSession,
    *,
    now: datetime | None = None,
    min_observations: int = DEFAULT_CONFLICT_MIN_OBSERVATIONS,
    limit: int = MAX_LIST_LIMIT,
) -> tuple[list[tuple[HostDossier, HostDossierField]], int]:
    """Open disagreements that have earned the operator's attention, plus the count.

    The gate minus its prompt-interval throttle: the interval governs how often
    the *notification* re-fires, not whether the conflict is still open. A row
    that vanished from this list the moment it was prodded would be unresolvable
    from the UI. Snoozed rows are excluded — that is what "keep mine" bought.

    Oldest disagreement first: a build that has disagreed with the operator for
    weeks is more likely to be describing a machine that really changed than one
    that started arguing yesterday.
    """
    stamp = _naive_utc(now) or utcnow()
    conditions = _conflict_due_conditions(stamp, min_observations)
    total = await db.scalar(select(func.count(HostDossierField.id)).where(*conditions)) or 0
    rows = (
        await db.execute(
            select(HostDossier, HostDossierField)
            .join(HostDossierField, HostDossierField.dossier_id == HostDossier.id)
            .where(*conditions)
            .order_by(HostDossierField.conflict_first_seen_at.asc(), HostDossierField.id.asc())
            .limit(max(1, min(limit, MAX_LIST_LIMIT)))
        )
    ).all()
    return [(host, field) for host, field in rows], total


@dataclass(frozen=True)
class DossierSummary:
    """Network-wide dossier counts — the whole table, never a page.

    Every number here describes every row in ``host_dossier``. That is the
    entire point of this type: the host list is paged in SQL
    (:data:`DEFAULT_LIST_LIMIT` of a table capped at 5,000 hosts), so a count
    derived from the rows on screen would describe one page and read as the
    network's.

    ``last_built_at`` is the NEWEST build stamp in the table, so a reader can
    date the other five numbers. It is ``None`` for a table nothing has ever
    swept — which is the default state, since ``dossier_schedule_enabled`` is
    off until someone turns it on.
    """

    hosts: int
    # No clean build on record: never swept at all, or the last sweep errored.
    never_built: int
    named: int
    reporting: int
    conflicts: int
    # Hosts per EFFECTIVE role — operator lane first, then an inferred value the
    # resolver would assert (confidence floor + staleness window). Hosts whose
    # role resolves to nothing appear in no bucket, so the values need not sum
    # to ``hosts``: the difference IS the unresolved remainder.
    roles: dict[str, int]
    last_built_at: datetime | None


async def summarize_dossiers(
    db: AsyncSession,
    *,
    now: datetime | None = None,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    staleness_hours: int = DEFAULT_STALENESS_HOURS,
    min_observations: int = DEFAULT_CONFLICT_MIN_OBSERVATIONS,
) -> DossierSummary:
    """The network-wide counts behind the host list's KPI strip, in FOUR queries.

    One aggregate over ``host_dossier`` (total, unbuilt, newest sweep), one over
    ``host_dossier_field`` (named, reporting), one conflict count, and one
    GROUP BY over the role rows (the distribution bar). Nothing here is
    per-host: this runs on every load of the landing screen, and an N+1 over a
    5,000-host cap is the connection-pool pressure that has frozen this app
    before.

    How each number is defined, because two of them could honestly be defined
    more than one way:

    * **named** — hosts whose ``hostname`` field the RESOLVER would assert. Both
      of its gates are applied here in SQL (the ``dossier_min_confidence`` floor
      and the ``dossier_staleness_hours`` window), and the operator lane wins
      unconditionally, exactly as :func:`soc_ai.dossier.resolve.resolve_field`
      decides it. A stored ``inferred_value`` the resolver withholds must not be
      counted, or the KPI would claim a name for a host whose row shows a dash.
    * **reporting** — hosts whose INFERENCE lane currently holds at least one
      value at the ``hostlog`` rung (an agent on the machine reporting about
      itself), under the same freshness and confidence gates. Deliberately NOT
      resolver-faithful in one respect: an operator override on the field does
      not hide it, because an override suppresses EFFECT and never OBSERVATION,
      and the question this count answers is whether the box is shipping logs —
      not what the dossier ends up saying about it. Approximate in one
      direction: ``inferred_source`` names only the rung that WON the field, so
      a hostlog observation beaten by a higher one is invisible to this count.
      ``inferred_evidence`` does keep the losers — it is keyed by source — but
      it is merged across builds and never pruned, so counting it would report
      an agent that has since gone quiet as if it were still reporting. The
      column is the narrower answer and the honest one. In practice the two
      coincide: ``osquery`` is the only rung above ``hostlog``, and nothing in
      :mod:`soc_ai.dossier.infer` builds a :class:`Fact` with that source.

    Cost note: neither ``field`` nor ``inferred_source`` is indexed, so the
    field-lane query is a full scan — about 60,000 rows at the 5,000-host cap
    times twelve fields. That is cheap at this size, and an index would be paid
    for on every field write the sweep makes (twelve per host, every sweep) to
    speed up one read per screen load. Revisit if the cap moves.

    The knobs mirror ``dossier_min_confidence`` / ``dossier_staleness_hours`` /
    ``dossier_conflict_min_observations`` and are passed in by the caller, the
    same way the rest of this module takes them.
    """
    stamp = _naive_utc(now) or utcnow()
    fresh_since = stamp - timedelta(hours=staleness_hours)

    # ---- one pass over the host headers ----
    totals = (
        await db.execute(
            select(
                func.count(HostDossier.id),
                func.sum(case((_no_clean_build(), 1), else_=0)),
                func.max(HostDossier.last_built_at),
            )
        )
    ).one()
    hosts, unbuilt, last_built_at = int(totals[0] or 0), int(totals[1] or 0), totals[2]

    # ---- one pass over the field rows ----
    # The resolver's gates and the operator-lane predicate, in the one SQL
    # spelling every reader here shares (see _lane_assertable / _lane_declared).
    assertable = _lane_assertable(fresh_since, min_confidence)
    declared = _lane_declared()
    # COUNT(DISTINCT CASE WHEN ...) rather than two EXISTS subqueries per host:
    # a CASE with no ELSE yields NULL, and COUNT ignores NULLs, so each host is
    # counted once however many of its twelve fields match.
    counts = (
        await db.execute(
            select(
                func.count(
                    distinct(
                        case(
                            (
                                and_(
                                    HostDossierField.field == HOSTNAME_FIELD,
                                    or_(declared, assertable),
                                ),
                                HostDossierField.dossier_id,
                            )
                        )
                    )
                ),
                func.count(
                    distinct(
                        case(
                            (
                                and_(
                                    HostDossierField.inferred_source == HOSTLOG_SOURCE,
                                    assertable,
                                ),
                                HostDossierField.dossier_id,
                            )
                        )
                    )
                ),
            )
        )
    ).one()

    # ---- and the disagreements, on the queue's own definition ----
    conflicts = (
        await db.scalar(
            select(func.count(HostDossierField.id)).where(
                *_conflict_due_conditions(stamp, min_observations)
            )
        )
        or 0
    )

    # ---- the role mix, grouped in SQL ----
    # NOT a third resolution: the coalesce is the ``list_dossiers`` role
    # filter's spelling (operator lane wins), and the gate on the inferred side
    # is ``_lane_assertable`` — the same predicate ``named`` counts through. A
    # role the resolver would withhold groups under NULL and is dropped, so a
    # bucket never claims a host whose own row renders a dash. At most one
    # role row per host (the (dossier, field) unique constraint), so COUNT(id)
    # counts hosts.
    effective_role = func.coalesce(
        HostDossierField.operator_value,
        case((assertable, HostDossierField.inferred_value)),
    )
    role_rows = (
        await db.execute(
            select(effective_role, func.count(HostDossierField.id))
            .where(HostDossierField.field == ROLE_FIELD)
            .group_by(effective_role)
        )
    ).all()
    roles = {
        str(value): int(count or 0)
        for value, count in role_rows
        if value is not None and str(value).strip()
    }

    return DossierSummary(
        hosts=hosts,
        never_built=unbuilt,
        named=int(counts[0] or 0),
        reporting=int(counts[1] or 0),
        conflicts=int(conflicts),
        roles=roles,
        last_built_at=last_built_at,
    )


@dataclass(frozen=True)
class EnvironmentProfile:
    """What kind of network the dossier table currently describes.

    Built for the hunt catalogue's environment-fit annotation ("don't offer
    Kerberoasting to a network with no domain"), so the counts are deliberately
    coarse: how many hosts EFFECTIVELY resolve to a Windows ``os_family``, how
    many to a domain membership, out of how many rows total and how many a
    sweep has ever built. ``built_hosts`` is the consumer's fail-open gate — a
    table nothing ever built describes an UNKNOWN network, not an empty one,
    and no hunt should be demoted on the strength of nobody having looked.
    """

    windows_hosts: int
    domain_joined_hosts: int
    total_hosts: int
    built_hosts: int


# --- environment_profile cache ----------------------------------------------
#
# `_compute_environment_profile` is two whole-table scans, and `/hunt-templates`
# calls the profile fresh on a 60s poll from every open tab — harmless now, two
# ~60k-row scans per tab per minute at the 5,000-host cap. The profile changes
# only when the dossier data does (a sweep, an adopted census row), so the LIVE
# read (``now`` unset) is cached at the store level keyed on a CHEAP data
# SIGNATURE: `(host count, built count, newest build stamp)` from one small pass
# over the header table. When the signature is unchanged the expensive field
# scan is skipped; the moment a host is added or (re)built the signature moves
# and the hunt reopens WITHOUT waiting out a clock — the property
# `test_environment_fit_one_qualifying_host_reopens_the_hunts` pins.
#
# The signature also gives per-DB isolation for free (two databases have
# different counts / stamps), so the module-level cache cannot bleed one
# request's profile into another's. A short TTL rides alongside as the backstop
# for the one change the header signature cannot see — an operator override on a
# field, which touches no host row — so that too is picked up within one poll.
# `_monotonic` is aliased so a test can advance the clock; the cache dict can be
# cleared directly.
_ENV_PROFILE_TTL_S = 45.0
_ENV_PROFILE_CACHE_MAX = 32
# key: (min_confidence, staleness_hours, total_hosts, built_hosts, newest_build)
_EnvProfileKey = tuple[float, int, int, int, str | None]
_env_profile_cache: dict[_EnvProfileKey, tuple[float, EnvironmentProfile]] = {}


async def _profile_signature(db: AsyncSession) -> tuple[int, int, str | None]:
    """A cheap `(total_hosts, built_hosts, newest build stamp)` over the headers.

    One pass over ``host_dossier`` (the ~5k-row header table, not the ~60k-row
    field table), so it is a fraction of the field scan it lets us skip. It moves
    whenever a host is added, built or rebuilt — every data change the profile's
    Windows / domain counts can turn on except a bare operator override, which
    the TTL backstop covers.
    """
    row = (
        await db.execute(
            select(
                func.count(HostDossier.id),
                func.sum(case((HostDossier.last_built_at.is_not(None), 1), else_=0)),
                func.max(HostDossier.last_built_at),
            )
        )
    ).one()
    last = row[2]
    return int(row[0] or 0), int(row[1] or 0), last.isoformat() if last is not None else None


def _prune_env_cache(clock: float) -> None:
    """Drop expired signatures; hard-clear if it somehow grows unbounded.

    Stale signatures accumulate as the table changes (each build stamps a new
    one). Expired entries are dead weight, so they go; the size cap is a belt to
    the TTL's braces in case a caller sweeps knob combinations.
    """
    for key in [k for k, (ts, _) in _env_profile_cache.items() if clock - ts >= _ENV_PROFILE_TTL_S]:
        del _env_profile_cache[key]
    if len(_env_profile_cache) > _ENV_PROFILE_CACHE_MAX:
        _env_profile_cache.clear()


async def environment_profile(
    db: AsyncSession,
    *,
    now: datetime | None = None,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    staleness_hours: int = DEFAULT_STALENESS_HOURS,
) -> EnvironmentProfile:
    """The network's Windows / domain-joined counts, cached for the live poll.

    Delegates to :func:`_compute_environment_profile`; see there for the query
    shape and the resolver-faithful counting. Only the live read (``now`` unset)
    is cached — a caller pinning an explicit ``now`` wants an exact computation
    for that instant (and the per-instant tests stay deterministic), so it runs
    fresh. The cache is keyed on the resolver knobs plus a cheap data signature
    (see the module comment above), so the expensive field scan is skipped when
    nothing changed, a first domain join reopens a demoted hunt at once, and a
    short TTL backstops the one change the signature cannot see.
    """
    if now is not None:
        return await _compute_environment_profile(
            db, now=now, min_confidence=min_confidence, staleness_hours=staleness_hours
        )
    total_hosts, built_hosts, newest_build = await _profile_signature(db)
    key: _EnvProfileKey = (
        float(min_confidence),
        int(staleness_hours),
        total_hosts,
        built_hosts,
        newest_build,
    )
    clock = _monotonic()
    cached = _env_profile_cache.get(key)
    if cached is not None and clock - cached[0] < _ENV_PROFILE_TTL_S:
        return cached[1]
    profile = await _compute_environment_profile(
        db, now=None, min_confidence=min_confidence, staleness_hours=staleness_hours
    )
    _env_profile_cache[key] = (clock, profile)
    _prune_env_cache(clock)
    return profile


async def _compute_environment_profile(
    db: AsyncSession,
    *,
    now: datetime | None = None,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    staleness_hours: int = DEFAULT_STALENESS_HOURS,
) -> EnvironmentProfile:
    """Count the network's Windows / domain-joined hosts from RESOLVED facts.

    Two queries, whole-table (same discipline as :func:`summarize_dossiers`).
    A host counts only as the resolver would answer it: the operator lane wins
    unconditionally when it holds a claim (and never expires), otherwise the
    inference lane counts only under :func:`_lane_assertable`'s freshness and
    confidence gates. A looser coalesce would call this network Windows-free
    while the host page shows a Windows box — the two surfaces must not
    disagree. Values are lower(trim())-folded, the criticality-rank convention,
    so an operator's "Windows" and the classifier's "windows" are one claim.

    The knobs mirror ``dossier_min_confidence`` / ``dossier_staleness_hours``
    and are passed by the caller, the same way the rest of this module takes
    them.
    """
    stamp = _naive_utc(now) or utcnow()
    fresh_since = stamp - timedelta(hours=staleness_hours)

    # ---- one pass over the host headers ----
    totals = (
        await db.execute(
            select(
                func.count(HostDossier.id),
                func.sum(case((HostDossier.last_built_at.is_not(None), 1), else_=0)),
            )
        )
    ).one()
    total_hosts, built_hosts = int(totals[0] or 0), int(totals[1] or 0)

    # ---- one pass over the field rows ----
    declared = _lane_declared()
    assertable = _lane_assertable(fresh_since, min_confidence)
    folded_operator = func.lower(func.trim(HostDossierField.operator_value))
    folded_inferred = func.lower(func.trim(HostDossierField.inferred_value))

    def _effective_matches(operator_hit: Any, inferred_hit: Any) -> Any:
        """The resolver's rule as one predicate: a declared operator lane
        decides alone (a JSON-only or non-matching claim BLOCKS the inference
        underneath, it does not fall through to it); an undeclared lane defers
        to the inference, gated."""
        return or_(
            and_(declared, operator_hit),
            and_(~declared, assertable, inferred_hit),
        )

    windows = and_(
        HostDossierField.field == OS_FAMILY_FIELD,
        _effective_matches(
            folded_operator == WINDOWS_OS_FAMILY,
            folded_inferred == WINDOWS_OS_FAMILY,
        ),
    )
    domain_joined = and_(
        HostDossierField.field == DOMAIN_MEMBERSHIP_FIELD,
        _effective_matches(
            and_(folded_operator.is_not(None), folded_operator != ""),
            and_(folded_inferred.is_not(None), folded_inferred != ""),
        ),
    )
    # COUNT(DISTINCT CASE WHEN ...) — a CASE with no ELSE yields NULL and COUNT
    # ignores NULLs, so each host is counted once per axis (summarize_dossiers'
    # shape; at most one row per (dossier, field) by the unique constraint).
    counts = (
        await db.execute(
            select(
                func.count(distinct(case((windows, HostDossierField.dossier_id)))),
                func.count(distinct(case((domain_joined, HostDossierField.dossier_id)))),
            )
        )
    ).one()

    return EnvironmentProfile(
        windows_hosts=int(counts[0] or 0),
        domain_joined_hosts=int(counts[1] or 0),
        total_hosts=total_hosts,
        built_hosts=built_hosts,
    )


# ---------------------------------------------------------------------------
# Prune
# ---------------------------------------------------------------------------


async def prune(db: AsyncSession, *, max_hosts: int) -> int:
    """Trim the table to *max_hosts*, sparing every host a human has touched.

    Oldest ``last_seen`` first (never seen = oldest). A host carrying ANY
    operator override is never pruned: a scanned /16 must not be able to push a
    hand-written criticality or a site policy out of the table. Returns the
    number of host rows deleted; their field rows go with them via the FK's
    ``ON DELETE CASCADE``.
    """
    total = await db.scalar(select(func.count(HostDossier.id))) or 0
    excess = total - max(0, max_hosts)
    if excess <= 0:
        return 0

    protected = select(HostDossierField.dossier_id).where(_lane_declared())
    doomed = list(
        (
            await db.scalars(
                select(HostDossier.id)
                .where(HostDossier.id.not_in(protected))
                .order_by(nulls_first(HostDossier.last_seen.asc()), HostDossier.id.asc())
                .limit(excess)
            )
        ).all()
    )
    if not doomed:
        return 0
    await db.execute(
        sa_delete(HostDossier)
        .where(HostDossier.id.in_(doomed))
        .execution_options(synchronize_session=False)
    )
    await db.commit()
    return len(doomed)
