"""Tests for the structured-output detection drafter (:mod:`soc_ai.detection.drafter`).

Mirrors ``tests/test_runbook_promotion.py``'s harness: the analyst model is a
pydantic-ai ``FunctionModel`` that captures the outbound prompt and returns a
structured output via the agent's synthesized output tool — no real gateway
or model is ever hit. ``build_synthesizer_model`` is patched where the
drafter module imports it (``soc_ai.detection.drafter.build_synthesizer_model``).

The guard-round-trip tests below close a confirmed egress leak: a hunt
finding's evidence carries REAL internal IPs/hostnames (``Hunt.report`` is
desanitized before persistence), and ``draft_detection`` used to only
DESANITIZE the model's output — it never sanitized the outbound prompt. With
``analyst_cloud_redaction=True`` + a cloud analyst model, that meant internal
identifiers egressed unredacted. The fix mirrors
``runbook_promotion.draft_runbook_for_rule``'s full round trip: sanitize the
prompt, fail-closed residue sweep, THEN call the model, THEN desanitize the
output.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from pydantic_ai.messages import (
    ModelMessage,
    ModelRequest,
    ModelResponse,
    ToolCallPart,
    UserPromptPart,
)
from pydantic_ai.models.function import AgentInfo, FunctionModel
from soc_ai.agent.egress_guard import EgressResidueError
from soc_ai.config import Settings
from soc_ai.detection.drafter import _build_draft_prompt, draft_detection
from soc_ai.detection.models import SigmaDraft
from soc_ai.detection.prompts import DRAFTER_PROMPT

# A canned Zerologon-shaped draft: keys on the specific NetrServerAuthenticate3
# operation the evidence names, not a shape that fires on every dce_rpc call
# (the b3-rmm benign-twin risk the drafter prompt warns against).
ZEROLOGON_DRAFT_ARGS: dict[str, Any] = {
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
        "The finding's evidence shows 40 NetrServerAuthenticate3 calls from a single "
        "source host, the Zerologon authentication-bypass pattern. Keying on the "
        "specific operation names (not 'any dce_rpc call') keeps the rule from firing "
        "on routine RMM/admin DCE-RPC traffic."
    ),
}

FINDING: dict[str, Any] = {
    "title": "Zerologon-pattern DCE-RPC authentication anomaly",
    "detail": "Repeated NetrServerAuthenticate3 calls to the domain controller from one host.",
    "hosts": ["10.0.0.5"],
    "citations": ["es-abc123"],
}
EVIDENCE = "dce_rpc.operation: NetrServerAuthenticate3 x40 from 10.0.0.5"

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


def _drafter_model(captured: dict[str, Any], args: dict[str, Any] | None = None) -> FunctionModel:
    """A FunctionModel that records the outbound prompt and returns a canned draft."""
    out = args if args is not None else ZEROLOGON_DRAFT_ARGS

    def _fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        captured["prompt"] = _user_prompt(messages)
        return ModelResponse(parts=[ToolCallPart(tool_name=info.output_tools[0].name, args=out)])

    return FunctionModel(_fn)


# ── draft_detection: happy path ─────────────────────────────────────────────


async def test_draft_detection_returns_scripted_sigma_draft(settings_kratos: Settings) -> None:
    captured: dict[str, Any] = {}
    with patch(_BUILD, return_value=_drafter_model(captured)):
        draft = await draft_detection(settings_kratos, finding=FINDING, evidence=EVIDENCE)

    assert isinstance(draft, SigmaDraft)
    assert draft.title == "Zerologon NetrServerAuthenticate3 anomaly"
    assert "NetrServerAuthenticate3" in draft.sigma_yaml
    assert "NetrServerAuthenticate3" in draft.oql
    assert "NetrServerReqChallenge" in draft.oql
    # Never set by the model / this call — only Task 3's validators set these.
    assert draft.validator_note is None
    assert draft.schema_ok is None
    assert draft.dry_run is None


async def test_draft_detection_prompt_carries_finding_and_evidence(
    settings_kratos: Settings,
) -> None:
    captured: dict[str, Any] = {}
    with patch(_BUILD, return_value=_drafter_model(captured)):
        await draft_detection(settings_kratos, finding=FINDING, evidence=EVIDENCE)

    prompt = captured["prompt"]
    assert FINDING["title"] in prompt
    assert "NetrServerAuthenticate3" in prompt  # the evidence string itself
    assert "10.0.0.5" in prompt  # from the evidence AND the finding's hosts


# ── DRAFTER_PROMPT: grounding contract ──────────────────────────────────────


def test_drafter_prompt_keys_rule_on_observed_values() -> None:
    """The drafter has no tools — the system prompt must pin the rule to the
    OBSERVED field values the route resolved from the cited events, and
    forbid inventing values the evidence does not show."""
    assert "Observed field values" in DRAFTER_PROMPT
    assert "Never invent a field value" in DRAFTER_PROMPT


# ── _build_draft_prompt: pure rendering ─────────────────────────────────────


def test_build_draft_prompt_carries_evidence_and_title() -> None:
    prompt = _build_draft_prompt(FINDING, EVIDENCE)
    assert FINDING["title"] in prompt
    assert FINDING["detail"] in prompt
    assert "10.0.0.5" in prompt
    assert "dce_rpc.operation: NetrServerAuthenticate3 x40 from 10.0.0.5" in prompt


def test_build_draft_prompt_handles_missing_optional_fields() -> None:
    prompt = _build_draft_prompt({"title": "bare finding"}, "some evidence")
    assert "bare finding" in prompt
    assert "some evidence" in prompt


# ── guard round trip ─────────────────────────────────────────────────────────


class _IdentityGuard:
    """A fake guard whose sanitize/desanitize are the identity function and
    whose residue check never blocks.

    Proves the guard branch actually runs the FULL round trip
    (``sanitize_text`` → ``check_or_raise`` → model call →
    ``model_dump(mode='json')`` → ``desanitize_obj`` →
    ``SigmaDraft.model_validate``) without needing the real
    :class:`~soc_ai.agent.egress_guard.EgressGuard` label machinery.
    """

    def sanitize_text(self, text: str) -> str:
        return text

    def check_or_raise(self, text: str, *, fail_closed: bool) -> None:
        return None

    def desanitize_obj(self, obj: Any) -> Any:
        return obj


async def test_draft_detection_guard_path_validates_and_returns_draft(
    settings_kratos: Settings,
) -> None:
    captured: dict[str, Any] = {}
    with patch(_BUILD, return_value=_drafter_model(captured)):
        draft = await draft_detection(
            settings_kratos, finding=FINDING, evidence=EVIDENCE, guard=_IdentityGuard()
        )

    assert isinstance(draft, SigmaDraft)
    assert draft.title == ZEROLOGON_DRAFT_ARGS["title"]
    assert draft.oql == ZEROLOGON_DRAFT_ARGS["oql"]
    assert draft.sigma_yaml == ZEROLOGON_DRAFT_ARGS["sigma_yaml"]
    assert draft.rationale == ZEROLOGON_DRAFT_ARGS["rationale"]


# ── Egress: sanitize INPUT before the model call (the leak this closes) ────


def _replace_deep(obj: Any, old: str, new: str) -> Any:
    """Recursively swap *old* for *new* through str/list/dict — enough to
    stand in for ``EgressGuard.desanitize_obj`` over a ``model_dump(mode='json')``
    payload without needing the real label-mapping machinery."""
    if isinstance(obj, str):
        return obj.replace(old, new)
    if isinstance(obj, list):
        return [_replace_deep(v, old, new) for v in obj]
    if isinstance(obj, dict):
        return {k: _replace_deep(v, old, new) for k, v in obj.items()}
    return obj


class _FakeRedactionGuard:
    """A fake guard that swaps the real IP for a stable opaque label.

    Cheap enough to prove the full sanitize → check_or_raise → model call →
    desanitize round trip without constructing a real
    :class:`~soc_ai.agent.egress_guard.EgressGuard`'s identifier-discovery
    machinery. ``check_or_raise`` records every call (with the *sanitized*
    text and the ``fail_closed`` flag it was given) so tests can assert it
    ran, and on what, before the model was ever invoked.
    """

    LABEL = "IP_01"
    REAL = "10.0.0.5"

    def __init__(self, *, raise_residue: bool = False) -> None:
        self.check_or_raise_calls: list[tuple[str, bool]] = []
        self._raise_residue = raise_residue

    def sanitize_text(self, text: str) -> str:
        return text.replace(self.REAL, self.LABEL)

    def check_or_raise(self, text: str, *, fail_closed: bool) -> None:
        self.check_or_raise_calls.append((text, fail_closed))
        if self._raise_residue:
            raise EgressResidueError([f"{self.REAL} leaked"])

    def desanitize_obj(self, obj: Any) -> Any:
        return _replace_deep(obj, self.LABEL, self.REAL)


async def test_draft_detection_guard_sanitizes_input_before_model_call(
    settings_kratos: Settings,
) -> None:
    """The leak this closes: the model must see the LABEL, never the real
    internal IP — and the fail-closed residue sweep must run on the
    SANITIZED prompt before the model is ever called."""
    captured: dict[str, Any] = {}
    guard = _FakeRedactionGuard()
    with patch(_BUILD, return_value=_drafter_model(captured)):
        await draft_detection(settings_kratos, finding=FINDING, evidence=EVIDENCE, guard=guard)

    # Input: the model never saw the real IP — only the opaque label.
    prompt = captured["prompt"]
    assert guard.REAL not in prompt
    assert guard.LABEL in prompt
    # The residue sweep ran exactly once, on that same sanitized prompt, with
    # the settings' fail-closed flag threaded through.
    assert len(guard.check_or_raise_calls) == 1
    swept_text, fail_closed = guard.check_or_raise_calls[0]
    assert swept_text == prompt
    assert fail_closed is settings_kratos.analyst_redaction_fail_closed


async def test_draft_detection_guard_desanitizes_output(settings_kratos: Settings) -> None:
    """The model answers in label-space; the returned draft must carry the
    real IP back so it is useful to the analyst reviewing it."""
    captured: dict[str, Any] = {}
    guard = _FakeRedactionGuard()
    args = {**ZEROLOGON_DRAFT_ARGS, "rationale": f"Fires on traffic from {guard.LABEL}."}
    with patch(_BUILD, return_value=_drafter_model(captured, args)):
        draft = await draft_detection(
            settings_kratos, finding=FINDING, evidence=EVIDENCE, guard=guard
        )

    assert guard.LABEL not in draft.rationale
    assert guard.REAL in draft.rationale


async def test_draft_detection_fail_closed_residue_blocks_model_call(
    settings_kratos: Settings,
) -> None:
    """A residue leak on the sanitized prompt raises BEFORE the model call —
    the caller (the route) maps this; ``draft_detection`` itself must never
    let the model see a payload the residue sweep flagged."""
    captured: dict[str, Any] = {}
    guard = _FakeRedactionGuard(raise_residue=True)
    with (
        patch(_BUILD, return_value=_drafter_model(captured)),
        pytest.raises(EgressResidueError),
    ):
        await draft_detection(settings_kratos, finding=FINDING, evidence=EVIDENCE, guard=guard)

    # The model was never invoked — the FunctionModel never ran, so nothing
    # was captured.
    assert captured == {}


async def test_draft_detection_guard_none_sends_prompt_unsanitized(
    settings_kratos: Settings,
) -> None:
    """Today's path, preserved: with no guard, nothing is sanitized — the
    real IP goes out exactly as composed. Redaction only applies when the
    caller opts in by passing a guard."""
    captured: dict[str, Any] = {}
    with patch(_BUILD, return_value=_drafter_model(captured)):
        draft = await draft_detection(settings_kratos, finding=FINDING, evidence=EVIDENCE)

    assert "10.0.0.5" in captured["prompt"]
    assert isinstance(draft, SigmaDraft)
