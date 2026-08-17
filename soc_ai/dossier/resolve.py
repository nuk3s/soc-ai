"""The dossier resolver: the ONE place an effective field value comes from.

``host_dossier_field`` has no ``value`` column. The builder writes an inference
lane (``inferred_*``), an operator writes a physically separate override lane
(``operator_*``), and what the field *actually says* is computed here, at read
time, by a pure function. That is why an override cannot be clobbered by a
rebuild: there is nothing for a rebuild to clobber. Every consumer — the
investigation prompt block, ``t_host_dossier``, the API, the UI — goes through
this module, the same way every consumer of the managed identifier list goes
through :func:`soc_ai.oracle.identifiers.effective_internal_identifiers`. A
second path to an effective value would be a second answer.

The rule::

    operator value set              -> that value, source "operator", confidence 1.0
    inferred value, fresh, confident-> that value, its own source and confidence
    otherwise                       -> unknown, WITH a reason

The reason is the part that earns its keep. "We looked and found nothing"
(``no_signal``), "we are not sure" (``low_confidence``) and "nobody has looked
lately" (``stale``) are three different answers, and an agent handed a bare
``None`` for all three will read every one of them as "nothing notable" — the
exact failure the dossier exists to fix. A stale belief is reported as stale
rather than asserted, because a fact nobody has re-confirmed in three days is
how a decommissioned box stays a "domain controller" in a verdict.

Deliberately pure: no database, no Elasticsearch, and no clock beyond the ``now``
the caller passes in. Staleness is the one behaviour here that a hidden
``datetime.now()`` would make untestable without freezing time, and it is also
the behaviour most worth testing.

An override suppresses **effect**, never **observation**: a resolved field still
reports what the builder currently believes underneath (``inferred_value`` and
friends) plus any open disagreement, because that is what the conflict UI shows
and what the rate-limited prod is argued from. Copying
``InternalIdentifier.dismissed`` semantics — where an overridden row simply stops
being refreshed — is what left the identifier feature unable to say "three builds
running now disagree with you".
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Literal

from soc_ai.dossier import policy
from soc_ai.dossier.types import DOSSIER_FIELDS, STRENGTH_CONFIDENCE, Strength

if TYPE_CHECKING:
    from collections.abc import Iterable

    from soc_ai.config import Settings
    from soc_ai.store.models import HostDossier, HostDossierField

# The `dossier_min_confidence` / `dossier_staleness_hours` defaults, bound from
# the single source in `soc_ai.dossier.policy` so the resolver stays callable —
# and testable — without a Settings, and so a caller whose Settings predates the
# knobs degrades to the documented behaviour instead of raising mid-investigation.
# Real assignments, not a re-import, so `from soc_ai.dossier.resolve import
# DEFAULT_MIN_CONFIDENCE` (what `infer` does) is an explicit export; both are used
# below as the resolver's default arguments.
DEFAULT_MIN_CONFIDENCE = policy.DEFAULT_MIN_CONFIDENCE
DEFAULT_STALENESS_HOURS = policy.DEFAULT_STALENESS_HOURS

# Not a rung on PROVENANCE_LADDER: the operator lane never competes in a merge,
# it wins outright. Spelled once here so consumers can compare against it.
OPERATOR_SOURCE = "operator"


def below_confidence_floor(confidence: float, floor: float) -> bool:
    """THE render gate: an inferred value below the floor resolves to unknown.

    Spelled once because two decisions hang on the same comparison: the
    resolver's ``low_confidence`` branch at read time, and build-time candidate
    ranking in ``infer._rank_candidates`` (a candidate this gate would hide must
    not shadow one it would show). If the boundary ever changes — strict to
    inclusive, an epsilon — both must move together or selection and rendering
    silently disagree.
    """
    return confidence < floor


# The rung an agent running ON the machine writes — `hostlog` on
# soc_ai.dossier.types.PROVENANCE_LADDER. Spelled here for the same reason the
# store spells its own copy: types owns the ladder, not a named constant, and
# :attr:`ResolvedDossier.reporting` compares against it.
HOSTLOG_SOURCE = "hostlog"

ResolveReason = Literal["stale", "low_confidence", "no_signal"]


@dataclasses.dataclass(frozen=True)
class ResolvedConflict:
    """An OPEN disagreement between the two lanes, with its throttle state.

    Present only while ``conflict_first_seen_at`` is set — the state machine
    NULLs it the moment the lanes agree again. ``prompt_count`` survives that
    reset (it is history, and the notification cycle id), so a resolved
    disagreement leaves a count behind but no conflict object.
    """

    kind: str | None = None
    first_seen_at: datetime | None = None
    observations: int = 0
    last_prompted_at: datetime | None = None
    prompt_count: int = 0
    snoozed_until: datetime | None = None


@dataclasses.dataclass(frozen=True)
class ResolvedField:
    """What one dossier field effectively says, and where that came from.

    Defaults describe an unknown field: no value, no source, and the
    ``no_signal`` reason. A caller that only reads :attr:`value` gets the right
    answer; a caller that renders provenance gets everything it needs to say
    *why*, without a second query.

    The ``inferred_*`` attributes are the lane underneath the answer. When an
    operator override wins they hold the belief it is suppressing; when nothing
    resolves they hold the stale or low-confidence belief that failed the gate,
    which is what lets a UI offer "last built 5 days ago — rebuild?" instead of
    claiming the host was never seen.
    """

    field: str
    value: str | None = None
    # Structured payload for services_offered / activity_profile /
    # management_plane, whose answers a scalar cannot carry.
    value_json: Any | None = None
    # "operator", a PROVENANCE_LADDER rung, or None when nothing resolved.
    source: str | None = None
    confidence: float = 0.0
    strength: Strength = "none"
    # None when the field resolved; otherwise why it did not.
    reason: ResolveReason | None = "no_signal"
    # The inference lane's evidence, keyed BY SOURCE, so the weaker signal that
    # lost the merge is still readable beside the one that won.
    evidence: dict[str, Any] = dataclasses.field(default_factory=dict)
    observed_at: datetime | None = None
    first_seen: datetime | None = None
    # Last build that EVALUATED this field, even if it concluded nothing. None
    # means never evaluated — the difference between "no signal" and "not
    # looked at yet", which the reason alone cannot express.
    last_run_at: datetime | None = None
    retracted_at: datetime | None = None
    operator_actor: str | None = None
    operator_note: str | None = None
    operator_set_at: datetime | None = None
    inferred_value: str | None = None
    inferred_value_json: Any | None = None
    inferred_confidence: float | None = None
    inferred_source: str | None = None
    # Whether the INFERENCE lane alone clears both of the resolver's gates —
    # the belief the builder could assert, regardless of any override. On a
    # field that resolved from the inference lane this equals `is_known`; its
    # reason to exist is the overridden field, where resolution says nothing
    # about the lane underneath. A consumer inferring it from `inferred_source`
    # instead cannot apply the staleness window (a knob it does not hold), so
    # it would report an agent that went quiet weeks ago as still reporting.
    inference_assertable: bool = False
    conflict: ResolvedConflict | None = None

    @property
    def overridden(self) -> bool:
        """True when an operator value is what this field resolves to."""
        return self.source == OPERATOR_SOURCE

    @property
    def is_known(self) -> bool:
        """True when the field resolved to something assertable."""
        return self.reason is None


@dataclasses.dataclass(frozen=True)
class ResolvedDossier:
    """Every dossier field for one host, resolved, plus the host header.

    :attr:`fields` always carries all twelve of :data:`DOSSIER_FIELDS`, in render
    order, whether or not a row exists for each. Absence is an answer the
    consumer has to be able to state ("no DHCP signal on this grid"), and a dict
    that silently omits it turns that into a shrug.

    :attr:`found` is False for a host the network sweep has no row for at all.
    The prompt block renders that case out loud too — silently omitting a host
    reads as "nothing notable", which is the failure the dossier exists to fix.
    """

    ip: str
    found: bool = True
    fields: dict[str, ResolvedField] = dataclasses.field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    last_built_at: datetime | None = None
    last_observed_at: datetime | None = None
    event_count: int = 0
    # Set when a DIFFERENT machine appears to hold this address now. A reader
    # weighing an operator override needs it: the override may describe a host
    # that has moved on.
    identity_rebound_at: datetime | None = None
    build_error: str | None = None

    @property
    def resolved_fields(self) -> tuple[ResolvedField, ...]:
        """Only the fields that actually resolved, in render order."""
        return tuple(f for f in self.fields.values() if f.is_known)

    @property
    def reporting(self) -> bool:
        """True when an agent ON this machine is currently reporting about itself.

        Any field whose inference lane holds a live (fresh, confident) value at
        the ``hostlog`` rung. The OBSERVATION, deliberately: an operator
        override on such a field hides the value, never the fact that the box
        is shipping logs — and "no agent, network-only visibility" derived from
        the winning ``source`` alone would go falsely negative on exactly the
        operator-curated hosts the headline matters most for, sending someone
        to install an agent that is already running. Same approximation as the
        summary's ``reporting`` count (and for the same reason): only the rung
        that WON the field is stored, so a hostlog fact outranked by a higher
        rung is invisible — a case nothing currently produces, since no builder
        emits the one rung above.
        """
        return any(
            f.inference_assertable and f.inferred_source == HOSTLOG_SOURCE
            for f in self.fields.values()
        )


def resolve_field(
    row: HostDossierField,
    *,
    now: datetime,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    staleness_hours: int = DEFAULT_STALENESS_HOURS,
) -> ResolvedField:
    """Resolve one stored field row into its effective value.

    Operator first, unconditionally — an override is not a tie-break, and it
    does not expire (nobody re-confirms "this box is critical" every 72 hours).
    Then the inference lane, but only if it can prove both freshness and
    confidence; anything else resolves unknown with the reason that fits.

    Staleness is reported ahead of low confidence when a row fails both gates: a
    stale row's confidence describes a belief nobody has re-checked, so calling
    it ``low_confidence`` would imply the builder looked recently and was unsure.
    """
    value: str | None
    value_json: Any | None
    source: str | None
    confidence: float
    reason: ResolveReason | None

    inferred_confidence = row.inferred_confidence

    # The inference lane's own verdict first, so it is known even when an
    # override goes on to win — `inference_assertable` is about the builder's
    # belief, and evaluating the gates only on the losing branch would leave it
    # undefined for exactly the overridden fields it exists to describe.
    inference_reason: ResolveReason | None
    if not _lane_holds_a_value(row.inferred_value, row.inferred_value_json):
        # Either the build looked and found nothing, or it retracted a value it
        # used to hold. Both are "no signal"; `retracted_at` tells them apart.
        inference_reason = "no_signal"
    elif _is_stale(row.inferred_last_run_at, now=now, staleness_hours=staleness_hours):
        inference_reason = "stale"
    elif below_confidence_floor(inferred_confidence or 0.0, min_confidence):
        inference_reason = "low_confidence"
    else:
        inference_reason = None

    if _lane_holds_a_value(row.operator_value, row.operator_value_json):
        value, value_json = row.operator_value, row.operator_value_json
        source, confidence, reason = OPERATOR_SOURCE, 1.0, None
    elif inference_reason is not None:
        value, value_json, source, confidence = None, None, None, 0.0
        reason = inference_reason
    else:
        value, value_json = row.inferred_value, row.inferred_value_json
        source, confidence, reason = row.inferred_source, float(inferred_confidence or 0.0), None

    return ResolvedField(
        field=row.field,
        value=value,
        value_json=value_json,
        source=source,
        confidence=confidence,
        strength=_strength_for(confidence),
        reason=reason,
        # Shallow copy: the read model must not be a handle on a live ORM row's
        # JSON column, which does not track in-place mutation anyway.
        evidence=dict(row.inferred_evidence or {}),
        observed_at=row.inferred_last_seen,
        first_seen=row.inferred_first_seen,
        last_run_at=row.inferred_last_run_at,
        retracted_at=row.inferred_retracted_at,
        operator_actor=row.operator_actor,
        operator_note=row.operator_note,
        operator_set_at=row.operator_set_at,
        inferred_value=row.inferred_value,
        inferred_value_json=row.inferred_value_json,
        inferred_confidence=inferred_confidence,
        inferred_source=row.inferred_source,
        inference_assertable=inference_reason is None,
        conflict=_resolve_conflict(row),
    )


def resolve_dossier(
    host: HostDossier,
    field_rows: Iterable[HostDossierField],
    *,
    now: datetime,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    staleness_hours: int = DEFAULT_STALENESS_HOURS,
) -> ResolvedDossier:
    """Resolve every dossier field for one host.

    Rows for names outside :data:`DOSSIER_FIELDS` are dropped: the vocabulary is
    fixed, and a row left behind by an older build or a renamed field must not
    smuggle itself into a prompt. Fields with no row at all still appear, as
    ``no_signal``.
    """
    stored = {row.field: row for row in field_rows}
    fields: dict[str, ResolvedField] = {
        name: (
            resolve_field(
                stored[name],
                now=now,
                min_confidence=min_confidence,
                staleness_hours=staleness_hours,
            )
            if name in stored
            else ResolvedField(field=name)
        )
        for name in DOSSIER_FIELDS
    }
    return ResolvedDossier(
        ip=host.ip,
        found=True,
        fields=fields,
        first_seen=host.first_seen,
        last_seen=host.last_seen,
        last_built_at=host.last_built_at,
        last_observed_at=host.last_observed_at,
        event_count=host.event_count or 0,
        identity_rebound_at=host.identity_rebound_at,
        build_error=host.build_error,
    )


def resolve_dossier_from_settings(
    host: HostDossier,
    field_rows: Iterable[HostDossierField],
    *,
    now: datetime,
    settings: Settings,
) -> ResolvedDossier:
    """:func:`resolve_dossier` with the thresholds read off *settings*.

    Both knobs are hot-appliable, so they are read per call rather than captured.
    They are read through ``getattr`` with the module defaults for the same
    reason the orchestrator reads ``dossier_context_enabled`` that way: a test
    double standing in for Settings must not be able to break resolution, and a
    missing knob should degrade to the documented default rather than raise
    inside an investigation.
    """
    return resolve_dossier(
        host,
        field_rows,
        now=now,
        min_confidence=float(getattr(settings, "dossier_min_confidence", DEFAULT_MIN_CONFIDENCE)),
        staleness_hours=int(getattr(settings, "dossier_staleness_hours", DEFAULT_STALENESS_HOURS)),
    )


def unknown_dossier(ip: str) -> ResolvedDossier:
    """The result for a host the network sweep has no row for.

    A first-class value rather than ``None`` so consumers render "no dossier for
    this host" instead of dropping the host from the output — the dossier's whole
    claim is that absence is a reportable answer.
    """
    fields: dict[str, ResolvedField] = {name: ResolvedField(field=name) for name in DOSSIER_FIELDS}
    return ResolvedDossier(ip=ip, found=False, fields=fields)


def _lane_holds_a_value(value: str | None, value_json: Any | None) -> bool:
    """True when a lane holds a belief, scalar or structured.

    ``services_offered`` and ``activity_profile`` live entirely in the JSON
    column; a predicate that only checked the scalar would resolve them to
    ``no_signal`` forever, on both lanes.
    """
    return value is not None or value_json is not None


def _is_stale(last_run_at: datetime | None, *, now: datetime, staleness_hours: int) -> bool:
    """True when the last build that evaluated this field is too old to assert.

    A missing stamp counts as stale: freshness has to be proven, and a value with
    no record of the build behind it cannot prove it.
    """
    if last_run_at is None:
        return True
    return _naive_utc(now) - _naive_utc(last_run_at) > timedelta(hours=staleness_hours)


def _naive_utc(value: datetime) -> datetime:
    """Naive UTC, matching what the store writes.

    Callers reach for ``datetime.now(UTC)``; stored timestamps are naive. Mixing
    the two raises ``TypeError`` on subtraction, which would turn an API handler's
    tz-aware clock into a 500 on every dossier read.
    """
    if value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


def _strength_for(confidence: float) -> Strength:
    """Bucket a confidence back onto the classifier's three-valued strength."""
    if confidence >= STRENGTH_CONFIDENCE["strong"]:
        return "strong"
    if confidence > STRENGTH_CONFIDENCE["none"]:
        return "weak"
    return "none"


def _resolve_conflict(row: HostDossierField) -> ResolvedConflict | None:
    """The open disagreement on this row, if there is one.

    ``conflict_first_seen_at`` is the state machine's "currently disagreeing"
    flag — it is NULLed when the lanes agree again, while the prompt counters are
    kept as history. Reading the counters instead would resurrect a conflict that
    has already been resolved.
    """
    if row.conflict_first_seen_at is None:
        return None
    return ResolvedConflict(
        kind=row.conflict_kind,
        first_seen_at=row.conflict_first_seen_at,
        observations=_counter(row.conflict_observations),
        last_prompted_at=row.conflict_last_prompted_at,
        prompt_count=_counter(row.conflict_prompt_count),
        snoozed_until=row.conflict_snoozed_until,
    )


def _counter(value: int | None) -> int:
    """Column defaults land at INSERT, so an uncommitted row reads NULL here."""
    return value or 0
