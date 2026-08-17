"""Tests for the dossier resolver — the single path to an effective value.

``soc_ai.dossier.resolve`` is where "what does this host's ``role`` field
actually say?" is answered, and it is the reason an operator override survives
every inference run: there is no stored effective value to clobber, so the
answer is computed from the two lanes at read time.

Four rules are pinned here, because every consumer (prompt block, agent tool,
API, UI) inherits them:

* an operator value wins, always, even against a fresher and more confident
  inference — an override suppresses *effect*, never *observation*, so the
  inference lane is still reported alongside it;
* an inferred value has to be fresh enough AND confident enough to be asserted;
* an unresolved field comes back with a REASON, because "we looked and found
  nothing" (``no_signal``), "we are not sure" (``low_confidence``) and "nobody
  has looked lately" (``stale``) are three different answers and an agent that
  cannot tell them apart will treat all three as "benign";
* provenance and evidence travel with the value, so a reader can see what the
  call was made from.

Rows are real (transient, never flushed) ORM instances rather than doubles: an
unflushed row reads ``None`` for every column-default counter, which is exactly
the shape the inline cold-start refresh hands the resolver before its commit.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

from soc_ai.dossier.resolve import (
    DEFAULT_MIN_CONFIDENCE,
    DEFAULT_STALENESS_HOURS,
    ResolvedDossier,
    ResolvedField,
    resolve_dossier,
    resolve_dossier_from_settings,
    resolve_field,
    unknown_dossier,
)
from soc_ai.dossier.types import DOSSIER_FIELDS
from soc_ai.store.models import HostDossier, HostDossierField

# Naive UTC, matching what the store writes. Every staleness comparison in this
# file is relative to this constant — never to the wall clock.
NOW = datetime(2026, 8, 6, 12, 0, 0)


def _row(field: str, **columns: Any) -> HostDossierField:
    """A transient ``host_dossier_field`` row; unset columns read as NULL."""
    return HostDossierField(field=field, **columns)


def _inferred(
    field: str = "role",
    *,
    value: str | None = "server",
    confidence: float = 0.9,
    source: str = "behaviour",
    age_hours: float = 1.0,
    **columns: Any,
) -> HostDossierField:
    """An inference-lane row that is fresh and confident by default."""
    return _row(
        field,
        inferred_value=value,
        inferred_confidence=confidence,
        inferred_source=source,
        inferred_last_run_at=NOW - timedelta(hours=age_hours),
        **columns,
    )


# ---------------------------------------------------------------------------
# The operator lane always wins
# ---------------------------------------------------------------------------


def test_operator_value_wins_over_a_higher_confidence_inference() -> None:
    """The whole point: an override is not a tie-break, it is the answer."""
    row = _inferred("role", value="server", confidence=0.99, age_hours=0)
    row.operator_value = "workstation"
    row.operator_actor = "analyst"
    row.operator_set_at = NOW - timedelta(days=5)

    resolved = resolve_field(row, now=NOW)

    assert resolved.value == "workstation"
    assert resolved.source == "operator"
    assert resolved.confidence == 1.0
    assert resolved.reason is None
    assert resolved.overridden is True


def test_an_override_reports_the_inference_it_is_suppressing() -> None:
    """Suppressing the EFFECT of an inference must not hide the observation.

    The conflict UI, the prod ("your override disagrees with three builds") and
    the analyst deciding whether to keep the override all need to see what the
    builder currently believes underneath.
    """
    row = _inferred("role", value="hypervisor", confidence=0.9, source="behaviour")
    row.operator_value = "workstation"

    resolved = resolve_field(row, now=NOW)

    assert resolved.value == "workstation"
    assert resolved.inferred_value == "hypervisor"
    assert resolved.inferred_confidence == 0.9
    assert resolved.inferred_source == "behaviour"


def test_an_operator_value_never_goes_stale() -> None:
    # Staleness is a statement about the builder, not about the operator: nobody
    # re-confirms "this box is a domain controller" every 72 hours.
    row = _row("criticality", operator_value="high", operator_set_at=datetime(2024, 1, 1))
    resolved = resolve_field(row, now=NOW, staleness_hours=1)
    assert resolved.value == "high"
    assert resolved.source == "operator"
    assert resolved.reason is None


def test_an_operator_json_override_wins_without_a_scalar_value() -> None:
    # services_offered / activity_profile / management_plane carry their payload
    # in the JSON column; a resolver that only looked at the scalar would drop an
    # operator's structured override on the floor.
    row = _inferred("services_offered", value=None, confidence=0.9)
    row.inferred_value_json = [{"port": 22, "proto": "tcp", "count": 9}]
    row.operator_value_json = [{"port": 8006, "proto": "tcp", "count": 0}]

    resolved = resolve_field(row, now=NOW)

    assert resolved.source == "operator"
    assert resolved.value_json == [{"port": 8006, "proto": "tcp", "count": 0}]
    assert resolved.reason is None


def test_operator_provenance_travels_with_the_value() -> None:
    set_at = NOW - timedelta(days=5)
    row = _row(
        "policy_notes",
        operator_value="no interactive SSH; API-token access only",
        operator_actor="analyst",
        operator_note="lab standard",
        operator_set_at=set_at,
    )
    resolved = resolve_field(row, now=NOW)
    assert resolved.operator_actor == "analyst"
    assert resolved.operator_note == "lab standard"
    assert resolved.operator_set_at == set_at


# ---------------------------------------------------------------------------
# Freshness
# ---------------------------------------------------------------------------


def test_a_stale_inference_resolves_unknown_with_reason_stale() -> None:
    row = _inferred("role", value="server", confidence=0.9, age_hours=DEFAULT_STALENESS_HOURS + 1)
    resolved = resolve_field(row, now=NOW)
    assert resolved.value is None
    assert resolved.value_json is None
    assert resolved.source is None
    assert resolved.confidence == 0.0
    assert resolved.reason == "stale"


def test_a_stale_belief_is_still_reported_as_the_last_thing_believed() -> None:
    # "unknown" is the effective value; the row still says what it last held and
    # when, so the UI can offer "last built 5 days ago — rebuild?" instead of
    # pretending the host was never seen.
    row = _inferred("role", value="server", age_hours=200)
    resolved = resolve_field(row, now=NOW)
    assert resolved.reason == "stale"
    assert resolved.inferred_value == "server"
    assert resolved.last_run_at == NOW - timedelta(hours=200)


def test_an_inference_exactly_at_the_staleness_boundary_still_resolves() -> None:
    row = _inferred("role", age_hours=DEFAULT_STALENESS_HOURS)
    assert resolve_field(row, now=NOW).value == "server"


def test_an_inference_with_no_run_stamp_is_treated_as_stale() -> None:
    # Freshness has to be PROVEN. A row with a value but no record of the build
    # that produced it cannot prove it, and asserting it anyway is how a
    # pre-migration row becomes a confidently wrong fact in a prompt.
    row = _row("role", inferred_value="server", inferred_confidence=0.9)
    assert resolve_field(row, now=NOW).reason == "stale"


def test_staleness_is_measured_against_now_not_the_wall_clock() -> None:
    """Purity check: the resolver takes a clock, it does not read one.

    Both of these would fail if the module called ``datetime.now()`` — the first
    is six years "old" by the wall clock, the second six years in the future.
    """
    long_ago = datetime(2020, 1, 1, 12, 0, 0)
    fresh = _row("role", inferred_value="server", inferred_confidence=0.9)
    fresh.inferred_last_run_at = long_ago - timedelta(hours=1)
    assert resolve_field(fresh, now=long_ago).value == "server"

    ahead = datetime(2031, 1, 1, 12, 0, 0)
    later = _row("role", inferred_value="server", inferred_confidence=0.9)
    later.inferred_last_run_at = ahead - timedelta(hours=1)
    assert resolve_field(later, now=ahead).value == "server"


def test_tz_aware_now_is_compared_against_naive_stored_timestamps() -> None:
    # Stored timestamps are naive UTC; a caller handing in an aware `now` (an API
    # handler using datetime.now(UTC)) must not make every field explode.
    row = _inferred("role", age_hours=1)
    resolved = resolve_field(row, now=NOW.replace(tzinfo=UTC))
    assert resolved.value == "server"


# ---------------------------------------------------------------------------
# Confidence
# ---------------------------------------------------------------------------


def test_below_threshold_confidence_resolves_unknown_with_reason_low_confidence() -> None:
    row = _inferred("role", value="workstation", confidence=0.5)
    resolved = resolve_field(row, now=NOW, min_confidence=0.6)
    assert resolved.value is None
    assert resolved.reason == "low_confidence"
    assert resolved.inferred_value == "workstation"
    assert resolved.inferred_confidence == 0.5


def test_confidence_exactly_at_the_floor_resolves() -> None:
    row = _inferred("role", confidence=0.6)
    resolved = resolve_field(row, now=NOW, min_confidence=0.6)
    assert resolved.value == "server"
    assert resolved.confidence == 0.6
    # 0.9 is `strong`; anything resolving below it is a weak belief.
    assert resolved.strength == "weak"


def test_a_missing_confidence_is_not_a_confident_value() -> None:
    row = _row("role", inferred_value="server", inferred_last_run_at=NOW)
    assert resolve_field(row, now=NOW).reason == "low_confidence"


def test_lowering_the_floor_lets_a_weak_belief_through() -> None:
    row = _inferred("role", value="workstation", confidence=0.5)
    assert resolve_field(row, now=NOW, min_confidence=0.4).value == "workstation"


def test_staleness_is_reported_ahead_of_low_confidence() -> None:
    """A stale row's confidence describes a belief nobody has re-checked.

    Reporting ``low_confidence`` for it would imply the builder looked recently
    and was unsure; ``stale`` is the truthful — and actionable — half.
    """
    row = _inferred("role", confidence=0.1, age_hours=DEFAULT_STALENESS_HOURS + 1)
    assert resolve_field(row, now=NOW).reason == "stale"


# ---------------------------------------------------------------------------
# Absence
# ---------------------------------------------------------------------------


def test_a_field_that_was_evaluated_and_found_nothing_resolves_no_signal() -> None:
    row = _row("mac", inferred_last_run_at=NOW - timedelta(hours=1))
    resolved = resolve_field(row, now=NOW)
    assert resolved.value is None
    assert resolved.reason == "no_signal"
    # The build DID look — the stamp is what separates this from "never built".
    assert resolved.last_run_at == NOW - timedelta(hours=1)


def test_a_field_never_inferred_resolves_no_signal() -> None:
    dossier = resolve_dossier(HostDossier(ip="192.168.10.202"), [], now=NOW)
    criticality = dossier.fields["criticality"]
    assert criticality.value is None
    assert criticality.reason == "no_signal"
    assert criticality.source is None
    # Never evaluated, so there is no run stamp to report either.
    assert criticality.last_run_at is None


def test_a_retracted_value_resolves_no_signal_and_keeps_the_retraction() -> None:
    # The builder found no evidence for a value it used to hold and nulled it in
    # the same write. "No signal" is right; the stamp says a belief was withdrawn
    # rather than never formed.
    retracted_at = NOW - timedelta(hours=2)
    row = _row(
        "hostname",
        inferred_last_run_at=NOW,
        inferred_retracted_at=retracted_at,
    )
    resolved = resolve_field(row, now=NOW)
    assert resolved.reason == "no_signal"
    assert resolved.retracted_at == retracted_at


def test_an_unknown_dossier_reports_every_field_as_no_signal() -> None:
    # "No dossier" is a stated answer, not an omission: the prompt block renders
    # it out loud because silence reads as "nothing notable".
    dossier = unknown_dossier("8.8.8.8")
    assert dossier.found is False
    assert dossier.ip == "8.8.8.8"
    assert set(dossier.fields) == set(DOSSIER_FIELDS)
    assert all(f.reason == "no_signal" for f in dossier.fields.values())
    assert dossier.resolved_fields == ()


# ---------------------------------------------------------------------------
# Provenance + evidence reach the caller
# ---------------------------------------------------------------------------


def test_a_resolved_value_carries_its_provenance_and_evidence() -> None:
    evidence = {
        "banner": {"strings": ["OpenSSH_9.6p1 Debian-3"], "event_count": 12},
        "telemetry": {"strings": ["Mozilla/5.0 (X11; Linux x86_64)"]},
    }
    observed_at = NOW - timedelta(minutes=30)
    row = _inferred(
        "os_family",
        value="linux",
        confidence=0.9,
        source="banner",
        inferred_evidence=evidence,
        inferred_first_seen=NOW - timedelta(days=14),
        inferred_last_seen=observed_at,
    )

    resolved = resolve_field(row, now=NOW)

    assert resolved.value == "linux"
    assert resolved.source == "banner"
    assert resolved.confidence == 0.9
    assert resolved.strength == "strong"
    # Evidence is keyed BY SOURCE, and the weaker signal survives beside the
    # stronger one that beat it.
    assert resolved.evidence == evidence
    assert resolved.observed_at == observed_at
    assert resolved.first_seen == NOW - timedelta(days=14)


def test_evidence_defaults_to_an_empty_mapping() -> None:
    # Consumers index into it; None would make every renderer guard.
    assert resolve_field(_inferred("role"), now=NOW).evidence == {}


def test_a_json_only_inference_resolves_on_its_json_payload() -> None:
    services = [{"port": 8006, "proto": "tcp", "count": 3412, "service": None}]
    row = _inferred("services_offered", value=None, confidence=0.9)
    row.inferred_value_json = services
    resolved = resolve_field(row, now=NOW)
    assert resolved.reason is None
    assert resolved.value_json == services
    assert resolved.source == "behaviour"


def test_open_conflict_state_is_carried_through() -> None:
    first_seen_at = NOW - timedelta(days=9)
    row = _inferred("role", value="hypervisor")
    row.operator_value = "server"
    row.conflict_kind = "mismatch"
    row.conflict_first_seen_at = first_seen_at
    row.conflict_observations = 3
    row.conflict_prompt_count = 1
    row.conflict_last_prompted_at = NOW - timedelta(days=2)

    conflict = resolve_field(row, now=NOW).conflict

    assert conflict is not None
    assert conflict.kind == "mismatch"
    assert conflict.first_seen_at == first_seen_at
    assert conflict.observations == 3
    assert conflict.prompt_count == 1


def test_no_conflict_object_when_the_lanes_agree() -> None:
    row = _inferred("role", value="server")
    row.operator_value = "server"
    row.conflict_prompt_count = 2  # history from a resolved disagreement
    assert resolve_field(row, now=NOW).conflict is None


def test_null_counters_on_an_unflushed_row_do_not_crash() -> None:
    # Column defaults are applied at INSERT, so a row the inline refresh built
    # but has not committed reads NULL for both counters.
    row = _inferred("role")
    row.operator_value = "workstation"
    row.conflict_kind = "mismatch"
    row.conflict_first_seen_at = NOW
    row.conflict_observations = None  # type: ignore[assignment]
    row.conflict_prompt_count = None  # type: ignore[assignment]
    conflict = resolve_field(row, now=NOW).conflict
    assert conflict is not None
    assert (conflict.observations, conflict.prompt_count) == (0, 0)


# ---------------------------------------------------------------------------
# Whole-host resolution
# ---------------------------------------------------------------------------


def test_resolve_dossier_covers_every_field_in_render_order() -> None:
    host = HostDossier(ip="192.168.10.202")
    dossier = resolve_dossier(host, [_inferred("role")], now=NOW)
    assert tuple(dossier.fields) == DOSSIER_FIELDS
    assert dossier.found is True
    assert dossier.fields["role"].value == "server"


def test_resolve_dossier_carries_the_host_header() -> None:
    host = HostDossier(
        ip="192.168.10.202",
        first_seen=datetime(2026, 6, 2),
        last_seen=NOW - timedelta(minutes=3),
        last_built_at=NOW - timedelta(hours=4),
        event_count=3412,
        identity_rebound_at=NOW - timedelta(days=1),
        build_error="elastic timeout",
    )
    dossier = resolve_dossier(host, [], now=NOW)
    assert dossier.ip == "192.168.10.202"
    assert dossier.first_seen == datetime(2026, 6, 2)
    assert dossier.last_seen == NOW - timedelta(minutes=3)
    assert dossier.last_built_at == NOW - timedelta(hours=4)
    assert dossier.event_count == 3412
    # The "different machine now holds this address" tripwire has to reach the
    # reader deciding whether an override still applies.
    assert dossier.identity_rebound_at == NOW - timedelta(days=1)
    assert dossier.build_error == "elastic timeout"


def test_resolved_fields_lists_only_what_is_actually_known() -> None:
    rows = [
        _inferred("role", value="server"),
        _inferred("hostname", value="pve01", confidence=0.5),  # below the floor
        _row("mac", inferred_last_run_at=NOW),  # looked, found nothing
        _row("criticality", operator_value="high"),
    ]
    dossier = resolve_dossier(HostDossier(ip="192.168.10.202"), rows, now=NOW)
    assert [f.field for f in dossier.resolved_fields] == ["role", "criticality"]


def test_rows_for_retired_field_names_are_ignored() -> None:
    # DOSSIER_FIELDS is the vocabulary. A row left behind by an older build (or a
    # renamed field) must not smuggle itself into a prompt.
    rows = [_inferred("oui_vendor", value="Intel Corporate"), _inferred("role")]
    dossier = resolve_dossier(HostDossier(ip="192.168.10.202"), rows, now=NOW)
    assert "oui_vendor" not in dossier.fields
    assert tuple(dossier.fields) == DOSSIER_FIELDS


def test_resolve_dossier_returns_a_frozen_read_model() -> None:
    dossier = resolve_dossier(HostDossier(ip="192.168.10.202"), [], now=NOW)
    assert isinstance(dossier, ResolvedDossier)
    assert isinstance(dossier.fields["role"], ResolvedField)


# ---------------------------------------------------------------------------
# The inference lane's own verdict, and the per-host reporting flag
# ---------------------------------------------------------------------------


def test_the_inference_lane_reports_its_own_assertability_under_an_override() -> None:
    """Whether the BUILDER'S belief clears the gates, regardless of who wins.

    Resolution alone cannot answer this: an overridden field resolves from the
    operator lane whatever state the inference underneath is in, so a consumer
    reading only ``source``/``reason`` sees the same answer over a live agent
    report and over a belief that went stale weeks ago.
    """
    live = _inferred("hostname", value="pve01", source="hostlog")
    live.operator_value = "blue"
    assert resolve_field(live, now=NOW).inference_assertable is True

    stale = _inferred(
        "hostname", value="pve01", source="hostlog", age_hours=DEFAULT_STALENESS_HOURS + 1
    )
    stale.operator_value = "blue"
    assert resolve_field(stale, now=NOW).inference_assertable is False

    weak = _inferred("hostname", value="pve01", source="hostlog", confidence=0.5)
    weak.operator_value = "blue"
    assert resolve_field(weak, now=NOW).inference_assertable is False

    silent = _row("criticality", operator_value="high")
    assert resolve_field(silent, now=NOW).inference_assertable is False

    # And without an override it simply agrees with resolution.
    assert resolve_field(_inferred("hostname"), now=NOW).inference_assertable is True


def test_reporting_is_true_only_for_a_live_hostlog_fact() -> None:
    """``reporting`` = an agent ON the machine is currently telling us about it.

    The 'why should I care' headline says "No agent — network-only visibility"
    off this flag, and a false negative sends someone to install an agent that
    is already running. Deriving it from resolved ``source`` fails exactly
    there: an operator who renamed the host masks the hostlog provenance on the
    one field most likely to carry it.
    """
    host = HostDossier(ip="192.168.10.202")

    reporting = resolve_dossier(host, [_inferred("hostname", source="hostlog")], now=NOW)
    assert reporting.reporting is True

    # An override suppresses EFFECT, never OBSERVATION: the agent is still
    # shipping logs, which is the only question this flag answers.
    overridden = _inferred("hostname", source="hostlog")
    overridden.operator_value = "blue"
    assert resolve_dossier(host, [overridden], now=NOW).reporting is True

    # A name the network merely overheard is not an agent on the box.
    overheard = resolve_dossier(host, [_inferred("hostname", source="banner")], now=NOW)
    assert overheard.reporting is False

    # An agent that has stopped is not coverage NOW.
    quiet = _inferred("hostname", source="hostlog", age_hours=DEFAULT_STALENESS_HOURS + 1)
    assert resolve_dossier(host, [quiet], now=NOW).reporting is False

    assert unknown_dossier("192.168.10.77").reporting is False


# ---------------------------------------------------------------------------
# Settings adapter
# ---------------------------------------------------------------------------


def test_settings_adapter_reads_the_dossier_knobs() -> None:
    settings = SimpleNamespace(dossier_min_confidence=0.95, dossier_staleness_hours=1)
    rows = [_inferred("role", confidence=0.9, age_hours=0.5)]
    dossier = resolve_dossier_from_settings(
        HostDossier(ip="192.168.10.202"), rows, now=NOW, settings=settings
    )
    assert dossier.fields["role"].reason == "low_confidence"

    relaxed = SimpleNamespace(dossier_min_confidence=0.6, dossier_staleness_hours=72)
    dossier = resolve_dossier_from_settings(
        HostDossier(ip="192.168.10.202"), rows, now=NOW, settings=relaxed
    )
    assert dossier.fields["role"].value == "server"


def test_settings_adapter_falls_back_to_the_documented_defaults() -> None:
    # A Settings object (or test double) without the dossier knobs resolves at
    # the contract defaults rather than raising mid-investigation.
    rows = [_inferred("role", confidence=DEFAULT_MIN_CONFIDENCE)]
    dossier = resolve_dossier_from_settings(
        HostDossier(ip="192.168.10.202"), rows, now=NOW, settings=SimpleNamespace()
    )
    assert dossier.fields["role"].value == "server"
