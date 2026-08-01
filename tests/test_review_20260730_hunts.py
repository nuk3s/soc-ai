"""Regression tests for the 2026-07-30 hunts code-review batch (bucket B02).

F01 — ``build_hunt_synthesizer`` must deliver ``HUNT_SYNTH_PROMPT`` to the model on
      the partial-report path, where ``message_history`` is ALWAYS non-empty
      (pydantic-ai only emits an agent ``system_prompt`` when the history is empty;
      ``instructions`` are re-applied on every request).
F02 — the corroboration gate must count an aggregation-only OQL result
      (``groupby``/``count``, ``size=0``) as corroborating telemetry, not discard it.
F17 — a non-canonical ``category`` string must be treated as a threat by the
      corroboration cap (agreeing with the read path), not bypass it.
"""

from __future__ import annotations

import asyncio
from typing import Any

from soc_ai.agent import hunt_gates
from soc_ai.agent.hunt import HuntFinding, build_hunt_synthesizer

# ── F01: synth prompt reaches the model on the (always non-empty) replay path ──

_SYNTH_MARKER = "reached its exploration budget"


def _capturing_model(seen: list[Any]) -> Any:
    """A FunctionModel that records the messages it was shown and returns a valid
    HuntReport via the output tool."""
    from pydantic_ai.messages import ModelResponse, ToolCallPart
    from pydantic_ai.models.function import AgentInfo, FunctionModel

    def _fn(messages: list[Any], info: AgentInfo) -> Any:
        seen.append(list(messages))
        return ModelResponse(
            parts=[
                ToolCallPart(
                    tool_name=info.output_tools[0].name,
                    args={"narrative": "cut short", "findings": [], "confidence": 0.2},
                )
            ]
        )

    return FunctionModel(_fn)


def test_synth_prompt_reaches_model_with_nonempty_history() -> None:
    """F01: the synthesizer is only ever run with a NON-empty replayed history, so
    the HUNT_SYNTH_PROMPT anti-over-claim framing must arrive as re-applied
    ``instructions``. Pre-fix it was passed via ``system_prompt=``, which
    pydantic-ai drops when the history is non-empty — the partial write-up then
    ran under the replayed EXPLORATION prompt and lost every 'a detector claim is
    not a threat' rule."""
    from pydantic_ai.messages import (
        ModelRequest,
        ModelResponse,
        SystemPromptPart,
        TextPart,
        UserPromptPart,
    )

    seen: list[Any] = []
    synth = build_hunt_synthesizer(_capturing_model(seen), objective="hunt for beaconing")

    # A replayed exploration transcript already carries the exploration system
    # prompt as its first part (as pydantic-ai leaves it), so the synth agent's
    # own system prompt would never be re-emitted.
    history = [
        ModelRequest(
            parts=[
                SystemPromptPart(
                    content="OLD EXPLORATION PROMPT — t_query_events_oql is your lens"
                ),
                UserPromptPart(content="hunt for beaconing"),
            ]
        ),
        ModelResponse(parts=[TextPart(content="ran some queries")]),
    ]

    asyncio.run(synth.run("Write the HuntReport now.", message_history=history))

    assert len(seen) == 1
    instructions_seen = [getattr(m, "instructions", None) for m in seen[0]]
    assert any(instr and _SYNTH_MARKER in instr for instr in instructions_seen), (
        f"HUNT_SYNTH_PROMPT never reached the model; instructions={instructions_seen!r}"
    )
    # The objective was interpolated into the synth prompt the model received.
    assert any(instr and "hunt for beaconing" in instr for instr in instructions_seen)


# ── F02: aggregation-only OQL result corroborates a telemetry finding ──────────


def test_aggregation_only_oql_corroborates_threat_finding() -> None:
    """F02: a ``groupby``/``count`` OQL query runs ``size=0`` — every measured value
    lives in ``aggregations`` and ``hits`` is empty. Such a result must still
    corroborate a telemetry finding; pre-fix the corroboration gate walked only
    ``hits`` and so demoted a real measured beacon to medium with a factually-false
    alert-only note."""
    tool_results = [
        {
            "tool_name": "t_query_events_oql",
            "result": {
                "total": 4213,
                "hits": [],
                "aggregations": {
                    "by_destination_ip": {
                        "buckets": [
                            {"key": "203.0.113.77", "doc_count": 1440},
                            {"key": "198.51.100.9", "doc_count": 12},
                        ]
                    }
                },
            },
        }
    ]
    finding = HuntFinding(
        title="Periodic outbound beacon to 203.0.113.77",
        detail="Measured periodic outbound flow rollup.",
        severity="high",
        category="threat",
        hosts=["10.0.0.5"],
        citations=["203.0.113.77"],
    )
    validated, _counts = hunt_gates._validate_hunt_findings([finding], tool_results)
    assert validated[0].severity == "high"
    assert validated[0].validator_note is None


def test_alert_only_hit_still_capped_after_aggregation_fix() -> None:
    """F02 guard: the aggregation latitude must not open a hole — a threat whose
    only support is a ``suricata.alert`` HIT (no aggregation rollup) is still
    capped to medium."""
    tool_results = [
        {
            "tool_name": "t_query_events_oql",
            "result": {
                "total": 1,
                "hits": [
                    {
                        "_id": "XYZ987654321",
                        "_source": {
                            "event": {"dataset": "suricata.alert", "kind": "alert"},
                            "rule": {"name": "ET MALWARE BPFDoor heartbeat"},
                        },
                    }
                ],
            },
        }
    ]
    finding = HuntFinding(
        title="BPFDoor C2 confirmed",
        detail="x",
        severity="high",
        category="threat",
        citations=["XYZ987654321"],
    )
    validated, _ = hunt_gates._validate_hunt_findings([finding], tool_results)
    assert validated[0].severity == "medium"
    assert validated[0].validator_note == hunt_gates._ALERT_ONLY_NOTE


# ── F17: a non-canonical category must not bypass the corroboration cap ─────────


def test_non_canonical_category_still_hits_corroboration_cap() -> None:
    """F17: ``category`` is a free ``str``; a non-canonical value ('suspicious
    activity') must still be treated as a threat by the corroboration cap, because
    the read path (``routes_hunts._finding_category``) renders anything outside the
    canonical triple as a threat. Pre-fix the exact ``== \"threat\"`` test let it
    escape the cap while still showing the red threat badge at critical."""
    tool_results = [
        {
            "tool_name": "t_query_events_oql",
            "result": {
                "total": 1,
                "hits": [
                    {
                        "_id": "AbC123456789",
                        "_source": {
                            "event": {"dataset": "suricata.alert", "kind": "alert"},
                            "rule": {"name": "ET MALWARE BPFDoor heartbeat"},
                        },
                    }
                ],
            },
        }
    ]
    finding = HuntFinding(
        title="BPFDoor heartbeat",
        detail="x",
        severity="critical",
        category="suspicious activity",
        citations=["AbC123456789"],
    )
    validated, _ = hunt_gates._validate_hunt_findings([finding], tool_results)
    assert validated[0].severity == "medium"
    assert validated[0].validator_note == hunt_gates._ALERT_ONLY_NOTE


def test_canonical_non_threat_category_not_capped() -> None:
    """F17 guard: a genuine ``visibility_gap`` / ``observation`` finding with a
    resolving telemetry citation is NOT a threat and passes the corroboration cap
    untouched."""
    tool_results = [
        {
            "tool_name": "t_query_events_oql",
            "result": {
                "total": 1,
                "hits": [
                    {
                        "_id": "ZK99887766",
                        "_source": {
                            "event": {"dataset": "zeek.dns", "kind": "event"},
                            "dns": {"question": {"name": "evil.example"}},
                        },
                    }
                ],
            },
        }
    ]
    for category in ("visibility_gap", "observation"):
        finding = HuntFinding(
            title="context finding",
            detail="x",
            severity="high",
            category=category,
            citations=["ZK99887766"],
        )
        validated, _ = hunt_gates._validate_hunt_findings([finding], tool_results)
        assert validated[0].severity == "high", category
        assert validated[0].validator_note is None, category
