"""The investigator strategy setting of the swarm triage experiment.

docs/dev/specs/2026-10-08-swarm-triage-experiment-design.md, "The seam". One
setting picks the strategy of the investigation loop. The default is
``single``. The override store accepts it live, so the backtest replay can
switch an arm on and restore ``single`` after it. It is an experiment knob, so
the console groups do not show it.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from soc_ai.config import Settings
from soc_ai.store import config_overrides as cfg

from tests.conftest import _base_settings_kwargs

_STRATEGIES = ("single", "spend", "ensemble", "advocates", "planes")


def test_the_default_strategy_is_single() -> None:
    assert Settings.model_fields["investigator_strategy"].default == "single"


@pytest.mark.parametrize(
    ("field", "default"),
    [
        ("advocate_tool_calls", 10),
        ("advocate_request_limit", 8),
        ("plane_worker_tool_calls", 6),
        ("plane_worker_request_limit", 5),
        ("judge_request_limit", 3),
    ],
)
def test_the_swarm_budgets_have_their_defaults(field: str, default: int) -> None:
    assert Settings.model_fields[field].default == default


def test_the_env_variable_sets_the_strategy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INVESTIGATOR_STRATEGY", "advocates")
    assert Settings(**_base_settings_kwargs()).investigator_strategy == "advocates"


def test_an_unknown_strategy_is_refused() -> None:
    with pytest.raises(ValidationError):
        Settings(**_base_settings_kwargs(), investigator_strategy="debate")


def test_the_store_accepts_each_strategy_live() -> None:
    spec = cfg.WHITELIST_BY_KEY["investigator_strategy"]
    assert spec.type == "select"
    assert spec.options == _STRATEGIES
    assert spec.hot is True
    for value in _STRATEGIES:
        assert cfg.coerce("investigator_strategy", value) == value


def test_the_store_refuses_an_unknown_strategy() -> None:
    with pytest.raises(cfg.SettingValueError):
        cfg.coerce("investigator_strategy", "debate")


def test_the_console_groups_do_not_show_the_strategy() -> None:
    """GET /config iterates SECTION_ORDER. The experiment section is not in it."""
    spec = cfg.WHITELIST_BY_KEY["investigator_strategy"]
    assert spec.section not in cfg.SECTION_ORDER
    assert spec.section not in cfg.SECTION_PARENTS


def test_an_override_switches_the_strategy_without_a_restart() -> None:
    settings = Settings(**_base_settings_kwargs())
    applied = cfg.apply_to_settings(settings, {"investigator_strategy": "planes"})
    assert applied == ["investigator_strategy"]
    assert settings.investigator_strategy == "planes"
    cfg.apply_to_settings(settings, {"investigator_strategy": "single"})
    assert settings.investigator_strategy == "single"


def test_the_help_keeps_the_prose_rules() -> None:
    text = cfg.WHITELIST_BY_KEY["investigator_strategy"].help
    assert "—" not in text and "–" not in text
    for sentence in text.split(". "):
        assert len(sentence.split()) <= 25, sentence
