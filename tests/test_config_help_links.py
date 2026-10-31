"""The Settings help texts: section references, display words and true facts.

Dogfood 2026-10-19 (R5-D17 to R5-D21, H1 STE item 18) read every help text on
the Settings page. The page shows one section at a time, so "the API keys panel
below" named a panel the operator could not see. A help text now names the
section in the form "Settings > <Section title>", and the console component
HelpText (frontend/src/components/HelpText.tsx) makes that a link. These tests
hold each reference to a section that exists, and hold the HelpText list of
server sections to the backend list.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from soc_ai.config import Settings
from soc_ai.store import config_overrides as cfg

_ROOT = Path(__file__).resolve().parents[1]
_LAYOUT = _ROOT / "frontend" / "src" / "lib" / "configLayout.ts"
_HELP_TEXT = _ROOT / "frontend" / "src" / "components" / "HelpText.tsx"

_REF = re.compile(r"Settings > ")


def _panel_labels() -> set[str]:
    """The labels of the standalone panels in PANELS of configLayout.ts."""
    return set(re.findall(r"label: '([^']+)'", _LAYOUT.read_text(encoding="utf-8")))


def _helptext_titles() -> list[str]:
    source = _HELP_TEXT.read_text(encoding="utf-8")
    block = source.split("SETTINGS_SECTION_TITLES", 1)[1].split("];", 1)[0]
    return re.findall(r"'([^']+)'", block)


def _known_titles() -> set[str]:
    return set(cfg.SECTION_ORDER) | _panel_labels()


def _references(text: str) -> list[str]:
    """The section title after each "Settings > " in *text*, longest match first."""
    titles = sorted(_known_titles(), key=len, reverse=True)
    found: list[str] = []
    for match in _REF.finditer(text):
        rest = text[match.end() :]
        hit = next(
            (t for t in titles if rest.startswith(t) and not rest[len(t) : len(t) + 1].isalnum()),
            None,
        )
        found.append(hit or rest.split(".")[0])
    return found


def _help(key: str) -> str:
    return cfg.WHITELIST_BY_KEY[key].help


def test_helptext_lists_every_server_section_in_order() -> None:
    assert _helptext_titles() == list(cfg.SECTION_ORDER)


def test_every_section_reference_in_a_help_text_names_a_real_section() -> None:
    known = _known_titles()
    bad = {
        spec.key: ref
        for spec in cfg.WHITELIST
        for ref in _references(spec.help)
        if ref not in known
    }
    assert bad == {}, bad


def test_the_reference_parser_flags_an_unknown_section() -> None:
    """Negative control: a reference to a section that does not exist is caught."""
    assert _references("Set it in Settings > Nowhere.") == ["Nowhere"]
    assert "Nowhere" not in _known_titles()


@pytest.mark.parametrize(
    ("key", "section"),
    [
        ("allow_online_enrichment", "API keys"),
        ("misp_url", "API keys"),
        ("misp_api_key", "Online enrichment"),
        ("crawl4ai_token", "Web research"),
        ("dossier_lookback_days", "Behavioural profiles"),
        ("pcap_enabled", "Connections"),
        ("oracle_rule_mode", "Detection tuning"),
        ("update_check_enabled", "About"),
        ("discovery_schedule_enabled", "Internal identifiers"),
        ("estate_model_enabled", "Diagnostics"),
    ],
)
def test_a_cross_section_pointer_names_the_section(key: str, section: str) -> None:
    assert section in _references(_help(key)), _help(key)


@pytest.mark.parametrize(
    "key", ["allow_online_enrichment", "misp_url", "misp_api_key", "crawl4ai_token"]
)
def test_a_pointer_to_another_section_says_no_above_or_below(key: str) -> None:
    """These four said "the API keys panel below" or "above under Web research".
    Each pointed to a panel in another section."""
    text = _help(key)
    assert " above" not in text and " below" not in text, text


def test_the_investigation_model_label_keeps_the_key() -> None:
    spec = cfg.WHITELIST_BY_KEY["analyst_model"]
    assert spec.label == "Investigation model"
    assert spec.help.startswith(
        "The model runs every investigation. Set the gateway model name here."
    )


def test_the_oracle_model_has_help() -> None:
    assert "Oracle" in _help("oracle_model")


def test_the_maxmind_key_help_states_that_no_command_downloads() -> None:
    text = _help("maxmind_license_key")
    assert "blocklists refresh" not in text
    assert "No soc-ai command" in text


def test_the_profile_sweep_help_names_no_fixed_hour() -> None:
    assert "every hour" not in _help("hunting_prior_sweep_enabled")


def test_the_severity_floor_is_a_select_of_the_four_values() -> None:
    spec = cfg.WHITELIST_BY_KEY["auto_triage_min_severity"]
    assert spec.type == "select"
    assert spec.options == ("critical", "high", "medium", "low")
    assert cfg.coerce("auto_triage_min_severity", "medium") == "medium"
    with pytest.raises(ValueError, match="critical, high, medium, low"):
        cfg.coerce("auto_triage_min_severity", "med")


@pytest.mark.parametrize(
    "key", ["auto_triage_max_targets", "auto_triage_min_severity", "auto_triage_retry_limit"]
)
def test_an_auto_investigate_setting_does_not_call_a_run_a_sweep(key: str) -> None:
    spec = cfg.WHITELIST_BY_KEY[key]
    assert "sweep" not in spec.label.lower()
    assert "sweep" not in spec.help.lower()


def test_the_retry_limit_help_states_the_runs_past_the_limit() -> None:
    """The help said "at most this many times", and its next sentence said the
    alert runs again each 6 hours with no end (autotriage_health.retry_wait)."""
    spec = cfg.WHITELIST_BY_KEY["auto_triage_retry_limit"]
    assert "at most" not in spec.help
    assert spec.help.startswith(
        "Auto-Investigate retries a failed alert this many times after a short wait. "
        "After the last short retry, the alert runs again once each 6 hours."
    )
    assert "pipeline fallback" in spec.help
    assert "pipeline error" not in spec.help


@pytest.mark.parametrize(
    "word", ["needs_more_info", "true_positive", "false_positive", "`inconclusive`"]
)
def test_no_help_text_shows_a_raw_verdict_value(word: str) -> None:
    hits = [s.key for s in cfg.WHITELIST if word in s.help or word in s.label]
    assert hits == [], f"{word!r} is in {hits}"


def test_every_help_text_keeps_the_prose_rules() -> None:
    for spec in cfg.WHITELIST:
        assert "—" not in spec.help and "–" not in spec.help, spec.key
        for sentence in re.split(r"(?<=[.!?])\s+", spec.help):
            assert len(sentence.split()) <= 25, (spec.key, sentence)


def test_the_pcap_help_claim_holds(settings_kratos: Settings) -> None:
    """The pcap_enabled help says soc-ai refuses the setting while the sensor SSH
    host is empty. The console saves a hot setting only after the same
    assignment passes on a copy of the live settings."""
    assert "refuses this setting while the sensor SSH host is empty" in _help("pcap_enabled")
    copy = settings_kratos.model_copy(update={"so_ssh_host": "", "pcap_enabled": False})
    with pytest.raises(ValueError, match="SO_SSH_HOST"):
        copy.pcap_enabled = True
