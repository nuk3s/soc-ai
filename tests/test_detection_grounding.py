"""Integration test for the detection-bridge arc (1.3 slice 3, Task 7).

Unlike the per-unit tests (``test_detection_drafter.py``,
``test_detection_validators.py``, ``test_detection_routes.py``), this drives the
WHOLE arc end-to-end — a scripted drafter model → :func:`draft_detection` →
:func:`validate_sigma_yaml` → :func:`dry_run_detection` over a mocked grid — to
prove the three QUALITY properties the bridge exists for, not the plumbing each
unit test already covers:

1. **Grounding + dry run fires.** The finding's discriminating field values
   (``dce_rpc.operation`` = NetrServerAuthenticate3) reach the model, the
   drafted rule keys on them, the Sigma schema validates, and the
   would-have-fired dry run returns a real hit count.
2. **FP-surfacing.** A shape-only rule (keys on "any dce_rpc call" — the b3-rmm
   benign-twin trap the drafter prompt warns against) dry-runs to an INFLATED
   count that folds in the benign events, and surfaces a benign sample id. The
   high would-have-fired total the analyst sees is the review pane's whole point.
3. **Injection boundary holds.** A drafted OQL touching a forbidden field
   (``_source``) is rejected by the SAME whitelist a live query hits; the dry
   run fails soft (``ran=False``) and ES is never queried.

The drafter model is a pydantic-ai ``FunctionModel`` (``test_detection_drafter.py``'s
pattern): it captures the outbound prompt and returns a scripted ``SigmaDraft``,
with ``build_synthesizer_model`` patched where the drafter imports it. The dry
run runs the REAL :func:`query_events_oql` (and therefore the REAL
:func:`validate_oql` whitelist) against a mocked ``AsyncElasticsearch``
(``test_detection_validators.py``'s ``_make_elastic``), so the OQL boundary is
proven end-to-end, not asserted in isolation.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

from pydantic_ai.messages import (
    ModelMessage,
    ModelRequest,
    ModelResponse,
    ToolCallPart,
    UserPromptPart,
)
from pydantic_ai.models.function import AgentInfo, FunctionModel
from soc_ai.config import Settings
from soc_ai.detection.drafter import draft_detection
from soc_ai.detection.validators import dry_run_detection, validate_sigma_yaml
from soc_ai.so_client.elastic import ElasticClient

_BUILD = "soc_ai.detection.drafter.build_synthesizer_model"


def _user_prompt(messages: list[ModelMessage]) -> str:
    """Extract the composed user prompt from a FunctionModel's request."""
    for msg in messages:
        if isinstance(msg, ModelRequest):
            for part in msg.parts:
                if isinstance(part, UserPromptPart):
                    assert isinstance(part.content, str)
                    return part.content
    raise AssertionError("no UserPromptPart in model request")


def _drafter_model(captured: dict[str, Any], args: dict[str, Any]) -> FunctionModel:
    """A FunctionModel that records the outbound prompt and returns a scripted draft."""

    def _fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        captured["prompt"] = _user_prompt(messages)
        return ModelResponse(parts=[ToolCallPart(tool_name=info.output_tools[0].name, args=args)])

    return FunctionModel(_fn)


def _make_elastic(
    settings: Settings, response: dict[str, Any] | None = None
) -> tuple[ElasticClient, AsyncMock]:
    """A real :class:`ElasticClient` over a mocked ``AsyncElasticsearch``.

    Mirrors ``test_tools_read.py`` / ``test_detection_validators.py``: builds a
    real client so the REAL ``query_events_oql`` — and its ``validate_oql``
    whitelist check — actually runs against the scripted ``response``. When
    ``response`` is ``None`` no return value is set, so a test can assert
    ``search`` was never reached.
    """
    fake_es = AsyncMock()
    if response is not None:
        fake_es.search.return_value = response
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        client = ElasticClient(settings)
    return client, fake_es


def _es_response(total: int, hit_ids: list[str]) -> dict[str, Any]:
    """A raw ES search response carrying a total and a set of hit ``_id``s."""
    return {
        "took": 3,
        "hits": {
            "total": {"value": total},
            "hits": [{"_id": hid, "_source": {}} for hid in hit_ids],
        },
    }


# The Zerologon-shaped finding whose DISCRIMINATING evidence is the specific
# dce_rpc.operation names — not "some dce_rpc traffic happened".
ZEROLOGON_FINDING: dict[str, Any] = {
    "title": "Zerologon-pattern DCE-RPC authentication anomaly",
    "detail": "Repeated NetrServerAuthenticate3 calls to the domain controller from one host.",
    "hosts": ["10.0.0.5"],
    "citations": ["es-abc123"],
}
ZEROLOGON_EVIDENCE = (
    "dce_rpc.operation: NetrServerAuthenticate3 observed 40x from 10.0.0.5 to the DC "
    "(also NetrServerReqChallenge)"
)


# ── Property 1: grounding + dry run fires ────────────────────────────────────

# The GROUNDED draft: keys on the specific operations the evidence named.
_GROUNDED_DRAFT: dict[str, Any] = {
    "title": "Zerologon NetrServerAuthenticate3 anomaly",
    "sigma_yaml": (
        "title: Zerologon NetrServerAuthenticate3 anomaly\n"
        "logsource:\n"
        "  category: dce_rpc\n"
        "detection:\n"
        "  selection:\n"
        "    zeek.dce_rpc.operation:\n"
        "      - NetrServerAuthenticate3\n"
        "      - NetrServerReqChallenge\n"
        "  condition: selection\n"
    ),
    "oql": (
        "event.dataset:zeek.dce_rpc AND zeek.dce_rpc.operation:"
        "(NetrServerAuthenticate3 OR NetrServerReqChallenge)"
    ),
    "rationale": (
        "Keys on the specific NetrServerAuthenticate3/NetrServerReqChallenge operations the "
        "evidence named, not any dce_rpc call, so routine RMM/admin traffic won't fire it."
    ),
}


async def test_grounded_draft_carries_evidence_validates_and_dry_run_fires(
    settings_kratos: Settings,
) -> None:
    """Property 1: the evidence's discriminating operations reach the model, the
    drafted rule keys on them, the Sigma schema validates, and the dry run fires
    with a real hit count."""
    captured: dict[str, Any] = {}
    with patch(_BUILD, return_value=_drafter_model(captured, _GROUNDED_DRAFT)):
        draft = await draft_detection(
            settings_kratos, finding=ZEROLOGON_FINDING, evidence=ZEROLOGON_EVIDENCE
        )

    # (a) The prompt the model actually saw carried the discriminating operations.
    prompt = captured["prompt"]
    assert "dce_rpc.operation" in prompt
    assert "NetrServerAuthenticate3" in prompt

    # (b) The returned rule keys on that operation, not a bare-dataset shape.
    assert "dce_rpc.operation" in draft.oql
    assert "NetrServerAuthenticate3" in draft.oql

    # (c) The Sigma schema validates.
    validated = validate_sigma_yaml(draft)
    assert validated.schema_ok is True
    assert validated.validator_note is None

    # (d) The would-have-fired dry run runs the REAL OQL path (parse + whitelist
    #     + DSL) over a grid returning 4 matches and reports that count.
    elastic, fake_es = _make_elastic(
        settings_kratos, _es_response(4, [f"zerologon-{i}" for i in range(4)])
    )
    result = await dry_run_detection(validated, elastic=elastic, settings=settings_kratos)

    assert result.dry_run is not None
    assert result.dry_run.ran is True
    assert result.dry_run.hit_count == 4
    fake_es.search.assert_awaited()  # the real query path really dispatched to ES


# ── Property 2: FP-surfacing (b3-rmm benign twin) ────────────────────────────

# A shape-only draft: keys on "any dce_rpc call", NOT the operation — the
# b3-rmm benign-twin trap the drafter prompt warns against.
_SHAPE_ONLY_DRAFT: dict[str, Any] = {
    "title": "DCE-RPC traffic to domain controller",
    "sigma_yaml": (
        "title: DCE-RPC traffic to domain controller\n"
        "logsource:\n"
        "  category: dce_rpc\n"
        "detection:\n"
        "  selection:\n"
        "    event.dataset: zeek.dce_rpc\n"
        "  condition: selection\n"
    ),
    # No operation filter — matches routine RMM/admin DCE-RPC too.
    "oql": "event.dataset:zeek.dce_rpc",
    "rationale": "Fires on DCE-RPC traffic to the domain controller.",
}

_N_MALICIOUS = 40
_N_BENIGN = 260  # the b3-rmm benign twin: routine RMM/admin DCE-RPC


async def test_shape_only_draft_dry_run_surfaces_inflated_benign_count(
    settings_kratos: Settings,
) -> None:
    """Property 2: a too-broad rule dry-runs to a count that folds in the benign
    twin's events — the inflated would-have-fired total (and a benign sample id)
    is exactly what the review pane shows the analyst."""
    captured: dict[str, Any] = {}
    with patch(_BUILD, return_value=_drafter_model(captured, _SHAPE_ONLY_DRAFT)):
        draft = await draft_detection(
            settings_kratos, finding=ZEROLOGON_FINDING, evidence=ZEROLOGON_EVIDENCE
        )
    validated = validate_sigma_yaml(draft)
    assert validated.schema_ok is True

    # The grid returns the malicious matches AND the benign RMM twin under the
    # SAME over-broad OQL; the sample hits carry both so the analyst can see the
    # benign events that padded the count.
    inflated_total = _N_MALICIOUS + _N_BENIGN
    elastic, _ = _make_elastic(
        settings_kratos,
        _es_response(inflated_total, ["zerologon-1", "b3-rmm-benign-1", "b3-rmm-benign-2"]),
    )
    result = await dry_run_detection(validated, elastic=elastic, settings=settings_kratos)

    assert result.dry_run is not None
    assert result.dry_run.ran is True
    # The dry run reports the INFLATED total — it did not silently drop the
    # benign twin's events; the too-broad rule shows a high would-have-fired count.
    assert result.dry_run.hit_count == inflated_total
    assert result.dry_run.hit_count > _N_MALICIOUS
    # The benign twin is visible in the surfaced sample evidence.
    assert any("b3-rmm-benign" in sid for sid in result.dry_run.sample_ids)


# ── Property 3: injection boundary holds ─────────────────────────────────────

# A drafted OQL that reaches for a FORBIDDEN field — the injection surface the
# whitelist exists to close.
_FORBIDDEN_FIELD_DRAFT: dict[str, Any] = {
    "title": "Raw-source probe",
    "sigma_yaml": (
        "title: Raw-source probe\n"
        "logsource:\n"
        "  category: dce_rpc\n"
        "detection:\n"
        "  selection:\n"
        "    dce_rpc.operation: NetrServerAuthenticate3\n"
        "  condition: selection\n"
    ),
    "oql": "_source:NetrServerAuthenticate3",
    "rationale": "Reads the raw document source.",
}


async def test_forbidden_field_draft_dry_run_fails_soft_without_touching_es(
    settings_kratos: Settings,
) -> None:
    """Property 3: a drafted OQL touching a forbidden field (``_source``) is
    rejected by the REAL validate_oql whitelist inside the dry run — ``ran=False``
    with the whitelist error, and ES is never queried."""
    captured: dict[str, Any] = {}
    with patch(_BUILD, return_value=_drafter_model(captured, _FORBIDDEN_FIELD_DRAFT)):
        draft = await draft_detection(
            settings_kratos, finding=ZEROLOGON_FINDING, evidence=ZEROLOGON_EVIDENCE
        )

    # No response set — search MUST NOT be reached; validate_oql raises first.
    elastic, fake_es = _make_elastic(settings_kratos)
    result = await dry_run_detection(draft, elastic=elastic, settings=settings_kratos)

    assert result.dry_run is not None
    assert result.dry_run.ran is False
    assert result.dry_run.error is not None
    assert "forbidden" in result.dry_run.error.lower()
    # The whitelist raised before dispatch — ES was never touched.
    fake_es.search.assert_not_called()
