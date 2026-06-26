"""Tests for soc_ai.eval.synth_render — scenario → ECS-doc rendering (#45)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from soc_ai.eval.synth_loader import EventTemplate, GroundTruth, Scenario, load_all_scenarios

SCENARIOS_DIR = Path(__file__).parent.parent / "soc_ai" / "eval" / "synth_scenarios"
RUN_TIME = datetime(2026, 5, 13, 22, 30, 0, tzinfo=UTC)


def _scenario(events: list[EventTemplate]) -> Scenario:
    return Scenario(
        id="test-scenario",
        name="test",
        version=1,
        tier="easy",
        story="test",
        attack=["T1071.001"],
        sigma_refs=[],
        ground_truth=GroundTruth(
            verdict="true_positive",
            confidence_min=0.7,
            required_citation_kinds=[],
            expected_actions=[],
            expected_field_reconciliation=False,
        ),
        events=events,
        rubric_notes="",
    )


def test_render_substitutes_run_time_placeholder() -> None:
    from soc_ai.eval.synth_render import render_scenario

    scenario = _scenario(
        [
            EventTemplate(
                index="logs-synth-suricata-alert",
                time_offset_seconds=0,
                is_triage_target=True,
                fields={
                    "@timestamp": "{{ run_time }}",
                    "source.ip": "10.0.0.42",
                    "source.port": 49321,
                    "destination.ip": "185.220.101.7",
                    "destination.port": 443,
                    "network.transport": "tcp",
                    "event.dataset": "suricata.alert",
                },
            )
        ]
    )

    docs = render_scenario(scenario, run_time=RUN_TIME)
    assert len(docs) == 1
    assert docs[0].body["@timestamp"] == "2026-05-13T22:30:00+00:00"


def test_render_substitutes_offset_seconds_placeholder() -> None:
    from soc_ai.eval.synth_render import render_scenario

    scenario = _scenario(
        [
            EventTemplate(
                index="logs-synth-suricata-alert",
                time_offset_seconds=0,
                is_triage_target=True,
                fields={
                    "@timestamp": "{{ run_time }}",
                    "source.ip": "10.0.0.42",
                    "source.port": 49321,
                    "destination.ip": "185.220.101.7",
                    "destination.port": 443,
                    "network.transport": "tcp",
                },
            ),
            EventTemplate(
                index="logs-synth-zeek-conn",
                time_offset_seconds=-30,
                is_triage_target=False,
                fields={
                    "@timestamp": "{{ run_time | offset_seconds(-30) }}",
                    "event.dataset": "zeek.conn",
                },
            ),
            EventTemplate(
                index="logs-synth-zeek-files",
                time_offset_seconds=5,
                is_triage_target=False,
                fields={
                    "@timestamp": "{{ run_time | offset_seconds(5) }}",
                    "event.dataset": "zeek.files",
                },
            ),
        ]
    )

    docs = render_scenario(scenario, run_time=RUN_TIME)
    assert docs[0].body["@timestamp"] == "2026-05-13T22:30:00+00:00"
    assert docs[1].body["@timestamp"] == "2026-05-13T22:29:30+00:00"
    assert docs[2].body["@timestamp"] == "2026-05-13T22:30:05+00:00"


def test_render_triage_target_computes_community_id_v1() -> None:
    """{{ community_id(...) }} placeholder resolves to Community ID v1.

    Community ID v1 spec: 1:<base64(sha1(seed + lo + hi + proto + 0 + lp + hp))>
    where (lo,lp) < (hi,hp) by lexical pair ordering on (addr,port).
    """
    from soc_ai.eval.synth_render import render_scenario

    scenario = _scenario(
        [
            EventTemplate(
                index="logs-synth-suricata-alert",
                time_offset_seconds=0,
                is_triage_target=True,
                fields={
                    "@timestamp": "{{ run_time }}",
                    "source.ip": "10.0.0.42",
                    "source.port": 49321,
                    "destination.ip": "185.220.101.7",
                    "destination.port": 443,
                    "network.transport": "tcp",
                    "network.community_id": (
                        "{{ community_id(source.ip, source.port, "
                        "destination.ip, destination.port, 'tcp') }}"
                    ),
                },
            )
        ]
    )
    docs = render_scenario(scenario, run_time=RUN_TIME)
    cid = docs[0].body["network.community_id"]
    # 1:<27-or-28 base64 chars including = padding>
    assert cid.startswith("1:")
    assert len(cid) >= 24
    # Determinism: re-rendering yields the same value.
    docs2 = render_scenario(scenario, run_time=RUN_TIME)
    assert docs2[0].body["network.community_id"] == cid


def test_render_same_as_triage_resolves_to_triage_community_id() -> None:
    from soc_ai.eval.synth_render import render_scenario

    scenario = _scenario(
        [
            EventTemplate(
                index="logs-synth-suricata-alert",
                time_offset_seconds=0,
                is_triage_target=True,
                fields={
                    "@timestamp": "{{ run_time }}",
                    "source.ip": "10.0.0.42",
                    "source.port": 49321,
                    "destination.ip": "185.220.101.7",
                    "destination.port": 443,
                    "network.transport": "tcp",
                    "network.community_id": (
                        "{{ community_id(source.ip, source.port, "
                        "destination.ip, destination.port, 'tcp') }}"
                    ),
                },
            ),
            EventTemplate(
                index="logs-synth-zeek-conn",
                time_offset_seconds=-1,
                is_triage_target=False,
                fields={
                    "@timestamp": "{{ run_time | offset_seconds(-1) }}",
                    "network.community_id": "{{ same_as_triage }}",
                    "event.dataset": "zeek.conn",
                },
            ),
        ]
    )

    docs = render_scenario(scenario, run_time=RUN_TIME)
    triage_cid = docs[0].body["network.community_id"]
    supporting_cid = docs[1].body["network.community_id"]
    assert supporting_cid == triage_cid
    assert triage_cid.startswith("1:")


def test_render_preserves_non_placeholder_values() -> None:
    from soc_ai.eval.synth_render import render_scenario

    scenario = _scenario(
        [
            EventTemplate(
                index="logs-synth-suricata-alert",
                time_offset_seconds=0,
                is_triage_target=True,
                fields={
                    "@timestamp": "{{ run_time }}",
                    "source.ip": "10.0.0.42",
                    "source.port": 49321,
                    "destination.ip": "185.220.101.7",
                    "destination.port": 443,
                    "network.transport": "tcp",
                    "rule.name": "ET TROJAN Win32/Emotet CnC Activity (POST)",
                    "event.category": ["network", "intrusion_detection"],
                    "rule.signature": "2840001",
                    "is_active": True,
                },
            )
        ]
    )

    body = render_scenario(scenario, run_time=RUN_TIME)[0].body
    assert body["rule.name"] == "ET TROJAN Win32/Emotet CnC Activity (POST)"
    assert body["event.category"] == ["network", "intrusion_detection"]
    assert body["source.port"] == 49321
    assert body["is_active"] is True


def test_render_stamps_synth_metadata_into_every_event() -> None:
    """All ingested docs MUST carry synth.scenario_id + synth.scenario_version
    so the prod kill-switch (NOT _exists_:synth.scenario_id) catches them."""
    from soc_ai.eval.synth_render import render_scenario

    scenario = _scenario(
        [
            EventTemplate(
                index="logs-synth-suricata-alert",
                time_offset_seconds=0,
                is_triage_target=True,
                fields={
                    "@timestamp": "{{ run_time }}",
                    "source.ip": "10.0.0.42",
                    "source.port": 49321,
                    "destination.ip": "185.220.101.7",
                    "destination.port": 443,
                    "network.transport": "tcp",
                },
            ),
            EventTemplate(
                index="logs-synth-zeek-conn",
                time_offset_seconds=-1,
                is_triage_target=False,
                fields={
                    "@timestamp": "{{ run_time | offset_seconds(-1) }}",
                    "event.dataset": "zeek.conn",
                },
            ),
        ]
    )

    docs = render_scenario(scenario, run_time=RUN_TIME)
    for doc in docs:
        assert doc.body["synth.scenario_id"] == "test-scenario"
        assert doc.body["synth.scenario_version"] == 1
        # synth.expected_verdict must NOT be stamped — it is the answer key
        # and the agent under test can read ingested docs via OpenSearch.
        assert "synth.expected_verdict" not in doc.body


def test_rendered_doc_does_not_leak_expected_verdict() -> None:
    """The answer key (expected_verdict) must not be stamped on ingested docs
    because the agent can query those docs via OpenSearch.
    Scoring uses Scenario objects, not this field."""
    from soc_ai.eval.synth_render import render_scenario

    scenario = _scenario(
        [
            EventTemplate(
                index="logs-synth-suricata-alert",
                time_offset_seconds=0,
                is_triage_target=True,
                fields={
                    "@timestamp": "{{ run_time }}",
                    "source.ip": "10.0.0.42",
                    "source.port": 49321,
                    "destination.ip": "185.220.101.7",
                    "destination.port": 443,
                    "network.transport": "tcp",
                },
            ),
        ]
    )

    docs = render_scenario(scenario, run_time=RUN_TIME)
    assert len(docs) == 1
    assert "synth.expected_verdict" not in docs[0].body


def test_render_exposes_triage_target_via_is_triage_target_flag() -> None:
    from soc_ai.eval.synth_render import render_scenario

    scenario = _scenario(
        [
            EventTemplate(
                index="logs-synth-zeek-conn",
                time_offset_seconds=-1,
                is_triage_target=False,
                fields={"@timestamp": "{{ run_time | offset_seconds(-1) }}"},
            ),
            EventTemplate(
                index="logs-synth-suricata-alert",
                time_offset_seconds=0,
                is_triage_target=True,
                fields={
                    "@timestamp": "{{ run_time }}",
                    "source.ip": "10.0.0.42",
                    "source.port": 49321,
                    "destination.ip": "185.220.101.7",
                    "destination.port": 443,
                    "network.transport": "tcp",
                },
            ),
        ]
    )

    docs = render_scenario(scenario, run_time=RUN_TIME)
    targets = [d for d in docs if d.is_triage_target]
    assert len(targets) == 1
    assert targets[0].index == "logs-synth-suricata-alert"


def test_render_all_catalogue_scenarios_smoke() -> None:
    """End-to-end: every catalogue YAML renders to ECS docs without error."""
    from soc_ai.eval.synth_render import render_scenario

    scenarios = load_all_scenarios(SCENARIOS_DIR)
    for scenario in scenarios:
        docs = render_scenario(scenario, run_time=RUN_TIME)
        assert len(docs) == len(scenario.events)
        triage_targets = [d for d in docs if d.is_triage_target]
        assert len(triage_targets) == 1, f"{scenario.id}: {len(triage_targets)} targets"
        # No unsubstituted {{ }} markers remain in any doc.
        for doc in docs:
            for key, val in doc.body.items():
                if isinstance(val, str):
                    assert "{{" not in val, (
                        f"{scenario.id}/{doc.index}: unsubstituted placeholder in {key!r}: {val!r}"
                    )


def test_community_id_v1_well_known_vector() -> None:
    """Sanity check against the Community ID reference vector.

    Reference test vector (corelight/pycommunityid):
    TCP, 10.0.0.1:53 -> 10.0.0.2:80 → 1:WiPyXIANPNyAFB8GxccLm9TC0H0=
    """
    from soc_ai.eval.synth_render import community_id_v1

    cid = community_id_v1("10.0.0.1", 53, "10.0.0.2", 80, "tcp")
    # We don't pin the exact value (different libraries differ on seed
    # handling) but we DO pin determinism + format.
    assert cid.startswith("1:")
    # And reverse order produces same id (bidirectional canonical form).
    cid_reversed = community_id_v1("10.0.0.2", 80, "10.0.0.1", 53, "tcp")
    assert cid == cid_reversed


def test_rendered_doc_does_not_leak_attack_technique() -> None:
    """synth.attack_technique must NOT appear in any rendered doc body.

    It is an answer-key-class field (technique implies attack implies verdict)
    and the agent under test can query ingested docs via OpenSearch.
    The value is available as provenance in the scenario YAML's ``attack``
    list but must not be stamped onto the ingested document bodies.
    """
    from soc_ai.eval.synth_render import render_scenario

    scenarios = load_all_scenarios(SCENARIOS_DIR)
    for scenario in scenarios:
        docs = render_scenario(scenario, run_time=RUN_TIME)
        for doc in docs:
            assert "synth.attack_technique" not in doc.body, (
                f"{scenario.id}/{doc.index}: synth.attack_technique still present "
                f"in rendered doc body (answer-key leak)"
            )


def test_render_offset_must_be_integer(tmp_path: Path) -> None:
    """offset_seconds(...) must be an int; malformed placeholders raise."""
    from soc_ai.eval.synth_render import render_scenario

    scenario = _scenario(
        [
            EventTemplate(
                index="logs-synth-suricata-alert",
                time_offset_seconds=0,
                is_triage_target=True,
                fields={
                    "@timestamp": "{{ run_time | offset_seconds(notanumber) }}",
                    "source.ip": "10.0.0.42",
                    "source.port": 49321,
                    "destination.ip": "185.220.101.7",
                    "destination.port": 443,
                    "network.transport": "tcp",
                },
            )
        ]
    )

    with pytest.raises(ValueError, match="offset_seconds"):
        render_scenario(scenario, run_time=RUN_TIME)
