"""Dogfood 2026-10-19, round 2 verify (R2-A): the investigation timeline.

The timeline showed internal labels: a tool id and a result key in the
citation step, the raw JSON of the auto-acknowledge, a verdict code, a
dossier line with a dash and a contrast, "east-west", and a false cause for
the deeper run (V1-A1, V1-A4, V1-A5, R2-D6 residual).

The blocks plant the stored shapes the merge gate of 2026-10-19 found:
arguments as a string, older result fields, odd payload types. A mapping
that does not know a shape keeps the stored text and never raises. Every
positive test has a negative control beside it.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from soc_ai.api.webui._timeline import _build_timeline, _failure_out

_DASHES = ("\u2014", "\u2013")

# ── V1-A1: the deeper run names the trigger that fired ──────────────────────


def _step(events: list[Any], seq: int) -> Any:
    return {s.id: s for s in _build_timeline(events)[0]}[f"e{seq}"]


def _loop(payload: Any) -> list[Any]:
    return [SimpleNamespace(kind="investigation_loop_entered", sequence=1, payload=payload)]


@pytest.mark.parametrize(
    ("trigger", "sentence"),
    [
        ("malware_rule", "The alert has an exploit or malware signal."),
        ("host_concurrent_threat", "Another alert on the same host signals a threat."),
        (
            "provisional_template",
            "A pattern proposed a false positive. The pattern cannot close the alert "
            "without evidence.",
        ),
    ],
)
def test_the_deeper_run_names_the_trigger_that_fired(trigger: str, sentence: str) -> None:
    payload = {"reason": "definitely_investigate", "trigger": trigger, "round1_verdict": None}
    assert _step(_loop(payload), 1).detail == f"{sentence} soc-ai skipped the first pass."


@pytest.mark.parametrize("trigger", [None, "", "a_trigger_from_the_future", 7, ["x"]])
def test_a_run_with_no_known_trigger_reads_a_neutral_sentence(trigger: Any) -> None:
    """The NTLMv1 run stored no trigger. It read "exploit or malware signal",
    which was false. A stored run without the field states no cause."""
    payload: dict[str, Any] = {"reason": "definitely_investigate", "round1_verdict": None}
    if trigger is not None:
        payload["trigger"] = trigger
    detail = _step(_loop(payload), 1).detail
    assert "malware" not in detail
    assert detail == (
        "A soc-ai rule sends this alert to the full investigation. soc-ai skipped the first pass."
    )


def test_another_loop_reason_ignores_a_trigger() -> None:
    """NEGATIVE CONTROL. Only definitely_investigate reads the trigger."""
    payload = {"reason": "deep_rerun", "trigger": "malware_rule", "round1_verdict": None}
    assert _step(_loop(payload), 1).detail == (
        "An analyst asked for a deep run. soc-ai skipped the first pass."
    )


def test_the_trigger_function_names_each_trigger() -> None:
    from soc_ai.agent.decision_templates import CandidateVerdict
    from soc_ai.agent.orchestrator import (
        DI_TRIGGER_HOST_THREAT,
        DI_TRIGGER_MALWARE_RULE,
        DI_TRIGGER_PROVISIONAL_TEMPLATE,
        _definitely_investigate,
        _definitely_investigate_trigger,
    )
    from soc_ai.so_client.models import SoAlert

    from tests.test_agent import _malware_signal_enriched, _non_malware_benign_enriched

    provisional = CandidateVerdict(
        verdict="false_positive",
        confidence=0.85,
        cited_evidence=[],
        template_id="clean_internal_traffic",
        rationale="Both endpoints are internal.",
    )
    dispositive = CandidateVerdict(
        verdict="false_positive",
        confidence=0.85,
        cited_evidence=["alert.rule_name=ET INFO STUN Binding Request"],
        template_id="stun_quic_keepalive",
        rationale="x",
        authority="dispositive",
    )
    host_threat = _non_malware_benign_enriched()
    host_threat.host_events = [
        SoAlert(
            id="c2",
            rule_name="ET REMOTE_ACCESS NetSupport Remote Admin Checkin",
            source_ip="192.0.2.1",
            destination_ip="203.0.113.9",
            severity_label="low",
        )
    ]

    trig = _definitely_investigate_trigger
    assert trig(_malware_signal_enriched(), provisional) == DI_TRIGGER_MALWARE_RULE
    assert trig(host_threat, provisional) == DI_TRIGGER_HOST_THREAT
    assert trig(_non_malware_benign_enriched(), provisional) == DI_TRIGGER_PROVISIONAL_TEMPLATE
    # NEGATIVE CONTROL: a dispositive template and no candidate fire nothing,
    # and the boolean predicate agrees with the trigger.
    assert trig(_non_malware_benign_enriched(), dispositive) is None
    assert trig(_non_malware_benign_enriched(), None) is None
    assert _definitely_investigate(_non_malware_benign_enriched(), dispositive) is False
    assert _definitely_investigate(_non_malware_benign_enriched(), provisional) is True


# ── V1-A4 / R2-D6 residual: internal labels in the timeline details ─────────


def _citations(per: Any) -> list[Any]:
    return [
        SimpleNamespace(
            kind="citation_validation",
            sequence=1,
            payload={
                "counts": {"valid": 2},
                "total": 3,
                "coverage_ratio": 0.66,
                "per_citation": per,
            },
        )
    ]


def test_the_citation_step_names_a_tool_in_words() -> None:
    detail = _step(
        _citations(
            [
                {
                    "citation": "tool t_query_zeek_logs:result.prefetch_already_has_this",
                    "resolved": True,
                },
                {"citation": "tool t_prevalence:result.rarity", "resolved": True},
                {"citation": "(tool t_enrich_ip)", "resolved": False},
            ]
        ),
        1,
    ).detail
    assert "valid: Zeek logs: the events soc-ai already loaded" in detail
    assert "valid: Indicator prevalence: rarity" in detail
    assert "not resolved: IP reputation" in detail
    assert "t_query_zeek_logs" not in detail
    assert "prefetch" not in detail


def test_a_field_or_id_citation_keeps_its_text() -> None:
    """NEGATIVE CONTROL. A field path and a document id are what the analyst opens."""
    detail = _step(
        _citations(
            [
                {"citation": "alert.rule_metadata.signature_severity", "resolved": True},
                {"citation": "UY9kWqABvPAn45WM7_Xj", "resolved": False},
                {"citation": 42, "resolved": True},
            ]
        ),
        1,
    ).detail
    assert "valid: alert.rule_metadata.signature_severity" in detail
    assert "not resolved: UY9kWqABvPAn45WM7_Xj" in detail
    assert "valid: 42" in detail


def _ack(payload: Any) -> Any:
    return _step([SimpleNamespace(kind="auto_ack", sequence=1, payload=payload)], 1)


def test_the_auto_ack_step_reads_in_words() -> None:
    step = _ack(
        {"es_id": "kZ-ZX6ABvPAn45WMlEiS", "confidence": 0.8, "threshold": 0.7, "success": True}
    )
    assert step.title == "Auto-acknowledged in Security Onion"
    assert step.detail == (
        "soc-ai acknowledged alert kZ-ZX6ABvPAn45WMlEiS in Security Onion. "
        "The confidence 0.80 is at or above the threshold 0.70."
    )


def test_a_failed_auto_ack_says_the_write_failed() -> None:
    step = _ack(
        {"es_id": "xd6cTp8BwxVkvmc70vpI", "confidence": 0.85, "threshold": 0.7, "success": False}
    )
    assert step.detail == (
        "soc-ai tried to acknowledge alert xd6cTp8BwxVkvmc70vpI in Security Onion. "
        "The write failed."
    )


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"success": True},
        {"es_id": 7, "confidence": "high", "threshold": None, "success": "yes"},
        {"es_id": ["a"], "confidence": True, "threshold": 0.7, "success": True},
    ],
)
def test_an_odd_auto_ack_payload_never_shows_json(payload: dict[str, Any]) -> None:
    detail = _ack(payload).detail
    assert not detail.startswith("{")
    assert "soc-ai" in detail


def test_the_verdict_step_detail_starts_with_the_summary() -> None:
    step = _step(
        [
            SimpleNamespace(
                kind="triage_report",
                sequence=1,
                payload={"verdict": "false_positive", "confidence": 0.8, "summary": "Routine SMB."},
            )
        ],
        1,
    )
    assert step.detail == "Routine SMB."
    assert "false_positive" not in step.detail


@pytest.mark.parametrize(
    "payload",
    [
        {"verdict": "false_positive", "confidence": 0.8, "summary": ""},
        {"verdict": "false_positive", "confidence": "n/a"},
        {"summary": {"text": "odd"}},
    ],
)
def test_a_verdict_step_with_no_summary_states_the_verdict(payload: dict[str, Any]) -> None:
    detail = _step([SimpleNamespace(kind="triage_report", sequence=1, payload=payload)], 1).detail
    assert "_positive" not in detail
    assert detail


def _dossier(block: str) -> str:
    events = [
        SimpleNamespace(
            kind="host_dossier",
            sequence=1,
            payload={
                "hosts": {"192.0.2.20": "source", "192.0.2.40": "destination"},
                "block": block,
            },
        )
    ]
    return str(_step(events, 1).detail)


def test_the_dossier_lines_read_in_ste() -> None:
    block = (
        "## Host dossier\n\nIntro.\n\n"
        "- 192.0.2.20 (source) — no dossier: the network sweep has no record of this "
        "address. It is external, or never observed. That is not evidence it is benign.\n"
        "- 192.0.2.40 (destination) — role: unknown [stale. No build has re-confirmed it.]\n"
        "  first seen 2026-08-31 · last seen 46d ago\n"
    )
    detail = _dossier(block)
    for dash in _DASHES:
        assert dash not in detail
    assert "not evidence" not in detail
    assert (
        "- 192.0.2.20 (source): soc-ai has no dossier for this address. "
        "The network sweep has no record of it."
    ) in detail
    assert "- 192.0.2.40 (destination): role unknown [stale." in detail
    assert "first seen 2026-08-31" in detail


def test_a_dossier_line_of_another_shape_keeps_its_text() -> None:
    """NEGATIVE CONTROL. A line the mapping does not know stays as stored."""
    detail = _dossier("- 192.0.2.40 (destination): role: server\n")
    assert "- 192.0.2.40 (destination): role: server" in detail


@pytest.mark.parametrize(
    ("stored", "expected"),
    [
        (
            "Both endpoints are internal. This is likely benign east-west traffic. The "
            "blocklist was not loaded. No indicator reached threat intel.",
            "Both hosts are internal. The blocklist was not loaded. "
            "No indicator reached threat intel.",
        ),
        (
            "Both endpoints are internal and the blocklist answered with no hit. This "
            "is very likely benign east-west traffic.",
            "Both hosts are internal. The blocklist answered with no hit.",
        ),
        (
            "Both endpoints internal → likely benign east-west traffic, but the blocklist "
            "was not loaded, so nothing was checked against threat intel.",
            "Both hosts are internal. The blocklist was not loaded. "
            "No indicator reached threat intel.",
        ),
        (
            "Both endpoints internal and no blocklist hits → very likely benign east-west traffic.",
            "Both hosts are internal. The blocklist answered with no hit.",
        ),
    ],
)
def test_the_internal_traffic_rationale_drops_east_west(stored: str, expected: str) -> None:
    detail = _step(
        [
            SimpleNamespace(
                kind="decision_template_match",
                sequence=1,
                payload={
                    "matched": True,
                    "template_id": "clean_internal_traffic",
                    "verdict": "false_positive",
                    "confidence": 0.85,
                    "rationale": stored,
                },
            )
        ],
        1,
    ).detail
    assert detail == (
        "The run matched the internal traffic pattern. The pattern gives a false "
        f"positive at 0.85. {expected}"
    )
    assert "east-west" not in detail


def test_another_template_rationale_keeps_its_text() -> None:
    """NEGATIVE CONTROL. Only the internal-traffic rationale is rewritten."""
    detail = _step(
        [
            SimpleNamespace(
                kind="decision_template_match",
                sequence=1,
                payload={
                    "matched": True,
                    "template_id": "ntp_sync",
                    "verdict": "false_positive",
                    "confidence": 0.9,
                    "rationale": "NTP traffic carries a clean Zeek SF conn.",
                },
            )
        ],
        1,
    ).detail
    assert detail.endswith("NTP traffic carries a clean Zeek SF conn.")


@pytest.mark.parametrize(
    ("enrichments", "profile", "expected"),
    [
        (
            {"a": {}, "b": {}},
            {"r1": 1, "r2": 2, "r3": 3},
            "soc-ai loaded the alert. soc-ai enriched 2 indicators. "
            "The host shows 3 alert types in the window.",
        ),
        (
            {"a": {}},
            {"r1": 1},
            "soc-ai loaded the alert. soc-ai enriched 1 indicator. "
            "The host shows 1 alert type in the window.",
        ),
        ("odd", ["odd"], "soc-ai loaded the alert. soc-ai enriched 0 indicators."),
    ],
)
def test_the_enrichment_step_counts_in_words(enrichments: Any, profile: Any, expected: str) -> None:
    detail = _step(
        [
            SimpleNamespace(
                kind="enriched_alert_context",
                sequence=1,
                payload={"enrichments": enrichments, "host_alert_profile": profile},
            )
        ],
        1,
    ).detail
    assert detail.startswith(expected)
    assert "(s)" not in detail


def _tool(tool: str, result: Any, args: Any = None) -> Any:
    return _step(
        [
            SimpleNamespace(
                kind="tool_call",
                sequence=1,
                payload={
                    "tool_name": tool,
                    "args": args or {"rule_id": "2054989"},
                    "tool_call_id": "c1",
                },
            ),
            SimpleNamespace(
                kind="tool_result", sequence=2, payload={"tool_call_id": "c1", "result": result}
            ),
        ],
        1,
    )


def test_the_rule_content_note_reads_in_ste() -> None:
    step = _tool(
        "t_get_rule_content",
        {
            "found": True,
            "matches": 2,
            "title": "ET INFO NTLMv1",
            "note": "2 detections matched; returning the best-ranked one",
        },
    )
    assert step.title == "Rule content: 2 detections match. soc-ai read the best-ranked one."
    assert "returning" not in step.detail
    assert ";" not in step.title


def test_a_rule_content_miss_reads_in_ste() -> None:
    step = _tool(
        "t_get_rule_content",
        {
            "found": False,
            "rule_id": "2054989",
            "hint": "no detection matched this publicId/SID or exact title — check the "
            "alert's rule.uuid, or free-text search with t_query_detections",
        },
    )
    assert step.title == "Rule content: no detection matches this rule id or title."
    for dash in _DASHES:
        assert dash not in step.detail


@pytest.mark.parametrize(
    "result",
    [
        {"found": True},
        {"found": True, "matches": "two", "note": 5},
        {"found": "maybe"},
        "a plain string",
        ["a", "list"],
    ],
)
def test_an_odd_rule_content_result_never_raises(result: Any) -> None:
    step = _tool("t_get_rule_content", result, args="rule_id=2054989")
    assert step.title.startswith("Rule content:")


# ── V1-A5: stored failure hint, read-time mapping ───────────────────────────


@pytest.mark.parametrize(
    "stored",
    [
        "alert id may be wrong; verify it exists in ES.",
        "The alert id can be wrong. Check that the alert exists in Elasticsearch.",
    ],
)
def test_a_stored_alert_id_hint_reads_in_ste(stored: str) -> None:
    events = [
        SimpleNamespace(
            kind="error",
            sequence=1,
            payload={
                "message": "alert not found: NOPE_ID_x",
                "type": "SoNotFoundError",
                "hint": stored,
            },
        )
    ]
    out = _failure_out("error", events)
    assert out is not None
    assert out.hint == "The alert id can be wrong. Check that the alert is in the grid."


def test_another_stored_hint_keeps_its_text() -> None:
    """NEGATIVE CONTROL."""
    events = [
        SimpleNamespace(
            kind="error",
            sequence=1,
            payload={"message": "boom", "hint": "Check the model gateway."},
        )
    ]
    out = _failure_out("error", events)
    assert out is not None
    assert out.hint == "Check the model gateway."


def test_the_orchestrator_writes_the_grid_hint() -> None:
    from soc_ai.agent.orchestrator import _hint_for
    from soc_ai.errors import SoApiError

    assert _hint_for(SoApiError("404")) == (
        "The alert id can be wrong. Check that the alert is in the grid."
    )


# ── stored shapes: the whole demo corpus builds without a raise ─────────────


def test_every_demo_investigation_builds_its_timeline() -> None:
    """The demo fixtures carry the odd stored shapes. None fails the page,
    and no step the mappings above own shows a JSON dump."""
    fixtures = json.loads(
        (Path(__file__).resolve().parents[1] / "soc_ai/demo/fixtures.json").read_text()
    )
    runs = [v for v in _walk(fixtures) if isinstance(v, dict) and isinstance(v.get("events"), list)]
    assert runs, "the demo fixtures hold no event lists"
    for run in runs:
        events = [
            SimpleNamespace(kind=e.get("kind", ""), sequence=i, payload=e.get("payload"))
            for i, e in enumerate(run["events"])
            if isinstance(e, dict)
        ]
        steps = _build_timeline(events)[0]
        by_seq = {s.id: s for s in steps}
        for i, e in enumerate(events):
            step = by_seq.get(f"e{i}")
            if step is None or e.kind not in {"auto_ack", "triage_report", "citation_validation"}:
                continue
            assert not step.detail.startswith("{"), (e.kind, step.detail)


def _walk(node: Any) -> Iterator[Any]:
    yield node
    if isinstance(node, dict):
        for v in node.values():
            yield from _walk(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk(v)


# ── V1-A5: the empty Alerts window ──────────────────────────────────────────


def test_the_quiet_hint_reads_in_ste() -> None:
    from soc_ai.api.webui.routes_alerts import _QUIET_HINT

    assert _QUIET_HINT.startswith("No alert in this window matches an alert label.")
    assert "anything" not in _QUIET_HINT


# ── R2-D6 residual: a verdict gate shows words, never its JSON ──────────────


def test_a_downgrade_step_reads_in_words() -> None:
    payload = {
        "original_verdict": "true_positive",
        "downgraded_verdict": "needs_more_info",
        "reason": "The claim rests on host context only.",
        "original_summary": "The host scanned the server.",
    }
    detail = _step(
        [
            SimpleNamespace(
                kind="ungrounded_host_anchored_tp_downgrade", sequence=1, payload=payload
            )
        ],
        1,
    ).detail
    assert detail == (
        "soc-ai changed the verdict from a true positive to needs more info.\n"
        "Reason: The claim rests on host context only.\n"
        "The summary before the change: The host scanned the server."
    )


def test_a_downgrade_of_another_shape_keeps_its_text() -> None:
    """NEGATIVE CONTROL. A payload without both verdicts keeps the stored text."""
    detail = _step(
        [SimpleNamespace(kind="evidence_gate_downgrade", sequence=1, payload={"from": 1})], 1
    ).detail
    assert detail == '{"from": 1}'
