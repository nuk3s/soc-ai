"""The words the Config help texts use for the hunting layer.

Dogfood 2026-10-06 found internal words on the Config page: "fire budget",
"precision floor", "the loop" for auto-hunt, "candidate" for a draft analytic,
"role priors" and "the ml extra". An operator reads none of them. The help
texts now use the words the console uses: daily hit limit, minimum precision,
auto-hunt, draft, and an extra package.
"""

from __future__ import annotations

import pytest
from soc_ai.store import config_overrides as cfg

_RETIRED = ("fire budget", "precision floor", "ml extra", "role priors", "the hunts the loop")


def _help(key: str) -> str:
    return next(s for s in cfg.WHITELIST if s.key == key).help


@pytest.mark.parametrize("word", _RETIRED)
def test_no_help_text_uses_a_retired_word(word: str) -> None:
    hits = [s.key for s in cfg.WHITELIST if word in s.help.lower()]
    assert hits == [], f"{word!r} is still in the help of {hits}"


def test_self_heal_names_the_daily_hit_limit_and_the_minimum_precision() -> None:
    text = _help("analytic_self_heal_enabled")
    assert "daily hit limit" in text
    assert "minimum precision" in text


def test_auto_hunt_concurrency_names_auto_hunt() -> None:
    assert "the hunts that auto-hunt started" in _help("lead_auto_hunt_concurrency")


def test_a_drafted_analytic_is_a_draft() -> None:
    text = _help("analytic_drafting_enabled")
    assert "as a draft. A draft does not run" in text
    assert "candidate" not in text


def test_profiles_help_reads_in_plain_words() -> None:
    """The profile of a host is no model. "The model" is the language model
    (dogfood 2026-10-19, R5 STE item 22)."""
    text = _help("entity_profiles_enabled")
    assert "compares new activity with the profile" in text
    assert "model" not in text
    assert "A departure from it becomes an observation." in text


def test_the_investigation_loop_keeps_its_word() -> None:
    """Negative control: "the loop" on the investigation tool budget names the
    tool loop of one investigation. It is no auto-hunt and keeps its word."""
    assert "The loop stops at the cap." in _help("agent_tool_calls_limit")


@pytest.mark.parametrize(
    "key",
    [
        "analytic_self_heal_enabled",
        "lead_auto_hunt_concurrency",
        "analytic_drafting_enabled",
        "entity_profiles_enabled",
        "estate_model_enabled",
    ],
)
def test_the_rewritten_help_keeps_the_prose_rules(key: str) -> None:
    text = _help(key)
    assert "—" not in text and "–" not in text
    for sentence in text.split(". "):
        assert len(sentence.split()) <= 25, sentence
