"""Tests for soc_ai.eval.synth_loader — YAML scenario loader for #45.

The loader reads YAML files from ``soc_ai/eval/synth_scenarios/`` into
typed ``Scenario`` objects so the renderer / ingester / scorer
downstream can rely on a validated schema.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from pydantic import ValidationError

SCENARIOS_DIR = Path(__file__).parent.parent / "soc_ai" / "eval" / "synth_scenarios"


def test_load_all_scenarios_returns_twelve_validated_objects() -> None:
    from soc_ai.eval.synth_loader import load_all_scenarios

    scenarios = load_all_scenarios(SCENARIOS_DIR)

    # 9 malicious (e/m/h) + 3 benign (b) for the precision stratum.
    assert len(scenarios) == 12
    ids = {s.id for s in scenarios}
    expected_ids = {
        "e1-emotet-feodo-c2",
        "e2-urlhaus-pe-delivery",
        "e3-tor-exit-ssh",
        "m1-cobalt-strike-beacon",
        "m2-dns-tunnel-exfil",
        "m3-quasar-rat-self-signed",
        "h1-kerberoasting",
        "h2-psexec-smb-lateral",
        "h3-low-slow-exfil-r2",
        "b1-cdn-update-beacon",
        "b2-authorized-vuln-scanner",
        "b3-rmm-admin-lateral",
    }
    assert ids == expected_ids
    # The benign class is expected to be false_positive ground truth.
    benign = {s.id for s in scenarios if s.ground_truth.verdict == "false_positive"}
    assert benign == {"b1-cdn-update-beacon", "b2-authorized-vuln-scanner", "b3-rmm-admin-lateral"}


def test_easy_tier_filter_returns_four_scenarios() -> None:
    from soc_ai.eval.synth_loader import load_all_scenarios

    scenarios = load_all_scenarios(SCENARIOS_DIR)
    easy = [s for s in scenarios if s.tier == "easy"]
    assert len(easy) == 4
    assert {s.id for s in easy} == {
        "e1-emotet-feodo-c2",
        "e2-urlhaus-pe-delivery",
        "e3-tor-exit-ssh",
        "b1-cdn-update-beacon",
    }


def test_e1_emotet_fields_parsed_correctly() -> None:
    from soc_ai.eval.synth_loader import load_all_scenarios

    scenarios = load_all_scenarios(SCENARIOS_DIR)
    e1 = next(s for s in scenarios if s.id == "e1-emotet-feodo-c2")

    assert e1.name == "Emotet/Feodo C2 callback"
    # version bumped to 2 when the dest IP was switched
    # from the illustrative 185.220.101.7 (Tor exit) to a real Feodo
    # blocklist entry (162.243.103.246) so enrichment fires correctly.
    assert e1.version >= 2
    assert e1.tier == "easy"
    assert "T1071.001" in e1.attack
    assert e1.ground_truth.verdict == "true_positive"
    assert e1.ground_truth.confidence_min == 0.75
    assert "blocklist_hit" in e1.ground_truth.required_citation_kinds
    # Exactly one triage-target event
    targets = [e for e in e1.events if e.is_triage_target]
    assert len(targets) == 1
    # First event is the Suricata alert
    assert targets[0].fields["event.dataset"] == "suricata.alert"


def test_every_scenario_has_exactly_one_triage_target() -> None:
    from soc_ai.eval.synth_loader import load_all_scenarios

    scenarios = load_all_scenarios(SCENARIOS_DIR)
    for s in scenarios:
        targets = [e for e in s.events if e.is_triage_target]
        assert len(targets) == 1, f"{s.id} has {len(targets)} triage targets, want 1"


def test_load_rejects_scenario_with_two_triage_targets(tmp_path: Path) -> None:
    from soc_ai.eval.synth_loader import load_scenario_file

    bad = tmp_path / "bad.yaml"
    bad.write_text(
        textwrap.dedent(
            """
            id: bad-two-targets
            name: invalid
            version: 1
            tier: easy
            story: bad
            attack: [T1071.001]
            ground_truth:
              verdict: true_positive
              confidence_min: 0.7
              required_citation_kinds: [blocklist_hit]
              expected_actions: []
              expected_field_reconciliation: false
            events:
              - index: logs-synth-suricata-alert
                time_offset_seconds: 0
                is_triage_target: true
                fields: {}
              - index: logs-synth-suricata-alert
                time_offset_seconds: 1
                is_triage_target: true
                fields: {}
            """
        ).strip()
    )

    with pytest.raises(ValidationError, match="exactly one triage target"):
        load_scenario_file(bad)


def test_load_rejects_bad_tier(tmp_path: Path) -> None:
    from soc_ai.eval.synth_loader import load_scenario_file

    bad = tmp_path / "bad-tier.yaml"
    bad.write_text(
        textwrap.dedent(
            """
            id: bad-tier
            name: invalid
            version: 1
            tier: extreme
            story: bad
            attack: [T1071.001]
            ground_truth:
              verdict: true_positive
              confidence_min: 0.7
              required_citation_kinds: []
              expected_actions: []
              expected_field_reconciliation: false
            events:
              - index: logs-synth-suricata-alert
                time_offset_seconds: 0
                is_triage_target: true
                fields: {}
            """
        ).strip()
    )

    with pytest.raises(ValidationError):
        load_scenario_file(bad)


def test_load_rejects_bad_verdict(tmp_path: Path) -> None:
    from soc_ai.eval.synth_loader import load_scenario_file

    bad = tmp_path / "bad-verdict.yaml"
    bad.write_text(
        textwrap.dedent(
            """
            id: bad-verdict
            name: invalid
            version: 1
            tier: easy
            story: bad
            attack: [T1071.001]
            ground_truth:
              verdict: maybe_malicious
              confidence_min: 0.7
              required_citation_kinds: []
              expected_actions: []
              expected_field_reconciliation: false
            events:
              - index: logs-synth-suricata-alert
                time_offset_seconds: 0
                is_triage_target: true
                fields: {}
            """
        ).strip()
    )

    with pytest.raises(ValidationError):
        load_scenario_file(bad)


def test_load_rejects_id_filename_mismatch(tmp_path: Path) -> None:
    from soc_ai.eval.synth_loader import load_scenario_file

    bad = tmp_path / "actual-filename.yaml"
    bad.write_text(
        textwrap.dedent(
            """
            id: declared-different-id
            name: invalid
            version: 1
            tier: easy
            story: bad
            attack: [T1071.001]
            ground_truth:
              verdict: true_positive
              confidence_min: 0.7
              required_citation_kinds: []
              expected_actions: []
              expected_field_reconciliation: false
            events:
              - index: logs-synth-suricata-alert
                time_offset_seconds: 0
                is_triage_target: true
                fields: {}
            """
        ).strip()
    )

    with pytest.raises(ValueError, match=r"id .* does not match filename"):
        load_scenario_file(bad)


def test_select_scenarios_by_tier() -> None:
    from soc_ai.eval.synth_loader import load_all_scenarios, select_scenarios

    scenarios = load_all_scenarios(SCENARIOS_DIR)
    easy = select_scenarios(scenarios, selector="easy")
    assert {s.id for s in easy} == {
        "e1-emotet-feodo-c2",
        "e2-urlhaus-pe-delivery",
        "e3-tor-exit-ssh",
        "b1-cdn-update-beacon",
    }
    medium = select_scenarios(scenarios, selector="medium")
    assert {s.tier for s in medium} == {"medium"}
    assert len(medium) == 4  # m1/m2/m3 + benign b2


def test_select_scenarios_all_returns_all() -> None:
    from soc_ai.eval.synth_loader import load_all_scenarios, select_scenarios

    scenarios = load_all_scenarios(SCENARIOS_DIR)
    assert len(select_scenarios(scenarios, selector="all")) == 12


def test_select_scenarios_by_explicit_ids() -> None:
    from soc_ai.eval.synth_loader import load_all_scenarios, select_scenarios

    scenarios = load_all_scenarios(SCENARIOS_DIR)
    picked = select_scenarios(scenarios, selector="e1-emotet-feodo-c2,h1-kerberoasting")
    assert {s.id for s in picked} == {"e1-emotet-feodo-c2", "h1-kerberoasting"}


def test_select_scenarios_unknown_id_raises() -> None:
    from soc_ai.eval.synth_loader import load_all_scenarios, select_scenarios

    scenarios = load_all_scenarios(SCENARIOS_DIR)
    with pytest.raises(KeyError, match="not-a-real-id"):
        select_scenarios(scenarios, selector="not-a-real-id")


def test_attack_techniques_must_match_mitre_pattern(tmp_path: Path) -> None:
    """T-prefixed ATT&CK IDs, optionally followed by .NNN sub-technique."""
    from soc_ai.eval.synth_loader import load_scenario_file

    bad = tmp_path / "bad-attack.yaml"
    bad.write_text(
        textwrap.dedent(
            """
            id: bad-attack
            name: invalid
            version: 1
            tier: easy
            story: bad
            attack:
              - lateral-movement
              - T1071.001
            ground_truth:
              verdict: true_positive
              confidence_min: 0.7
              required_citation_kinds: []
              expected_actions: []
              expected_field_reconciliation: false
            events:
              - index: logs-synth-suricata-alert
                time_offset_seconds: 0
                is_triage_target: true
                fields: {}
            """
        ).strip()
    )

    with pytest.raises(ValidationError, match=r"ATT.CK"):
        load_scenario_file(bad)
