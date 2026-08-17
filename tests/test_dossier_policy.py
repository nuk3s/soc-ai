"""The dossier policy defaults live in ONE module, and every consumer reads it.

Finding ``dossier-policy-triplet``: ``DEFAULT_MIN_CONFIDENCE`` /
``DEFAULT_STALENESS_HOURS`` (plus the two conflict defaults) used to be spelled
independently in :mod:`soc_ai.dossier.resolve`, again in
:mod:`soc_ai.store.host_dossier`, and a third time as ``Settings`` field
defaults, with no import link. A release that bumped one left the mirrors
behind, so the host page, the agent's dossier tool and the summary counts could
silently apply different floors. These tests pin that the constants now flow
from :mod:`soc_ai.dossier.policy` to all three.
"""

from __future__ import annotations

from soc_ai.config import Settings
from soc_ai.dossier import policy, resolve
from soc_ai.store import host_dossier as store


def test_resolve_reads_the_policy_constants() -> None:
    assert resolve.DEFAULT_MIN_CONFIDENCE == policy.DEFAULT_MIN_CONFIDENCE
    assert resolve.DEFAULT_STALENESS_HOURS == policy.DEFAULT_STALENESS_HOURS


def test_store_reads_the_policy_constants() -> None:
    assert store.DEFAULT_MIN_CONFIDENCE == policy.DEFAULT_MIN_CONFIDENCE
    assert store.DEFAULT_STALENESS_HOURS == policy.DEFAULT_STALENESS_HOURS
    assert store.DEFAULT_CONFLICT_MIN_OBSERVATIONS == policy.DEFAULT_CONFLICT_MIN_OBSERVATIONS
    assert (
        store.DEFAULT_CONFLICT_PROMPT_INTERVAL_HOURS
        == policy.DEFAULT_CONFLICT_PROMPT_INTERVAL_HOURS
    )


def test_settings_defaults_track_the_policy_constants(settings_kratos: Settings) -> None:
    s = settings_kratos
    assert s.dossier_min_confidence == policy.DEFAULT_MIN_CONFIDENCE
    assert s.dossier_staleness_hours == policy.DEFAULT_STALENESS_HOURS
    assert s.dossier_conflict_min_observations == policy.DEFAULT_CONFLICT_MIN_OBSERVATIONS
    assert s.dossier_conflict_prompt_interval_hours == policy.DEFAULT_CONFLICT_PROMPT_INTERVAL_HOURS


def test_the_three_paths_are_one_value(settings_kratos: Settings) -> None:
    # The whole point: resolve, the store and the Settings default read the same
    # source, so a bump to policy.py moves all three together instead of leaving
    # two mirrored literals behind.
    assert (
        policy.DEFAULT_MIN_CONFIDENCE
        == resolve.DEFAULT_MIN_CONFIDENCE
        == store.DEFAULT_MIN_CONFIDENCE
        == settings_kratos.dossier_min_confidence
    )
    assert (
        policy.DEFAULT_STALENESS_HOURS
        == resolve.DEFAULT_STALENESS_HOURS
        == store.DEFAULT_STALENESS_HOURS
        == settings_kratos.dossier_staleness_hours
    )
