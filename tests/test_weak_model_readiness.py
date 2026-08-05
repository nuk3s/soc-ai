"""Weak-model readiness pass (2026-08-04).

There is currently no lesser GPU model in the lab to test against, so every
change covered here is either behavior-preserving by default (config knobs that
default to today's behavior) or mechanically provable with unit tests. The
failure shapes targeted are the ones this project has actually recorded from
serving models: stringified JSON containers, null-sentinel strings, verdict
formatting wobble, prose-instead-of-tool-call, reasoning-budget burn.

The one live lower-tier backend reachable today is ``qwen3.6-35b-cpu``
(the llama.cpp CPU host) — the emergency CPU fallback tier in the router config.
Live validation against it happens via ``soc-ai model-probe``, not in this
suite.
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError
from soc_ai.config import Settings
from soc_ai.triage_models import TriageReport


def _settings(**over) -> Settings:
    """Settings without env loading (mirrors conftest's ``_base_settings_kwargs``)."""
    kwargs = {
        "so_host": "https://so.example.com",
        "so_username": "analyst",
        "so_password": SecretStr("password123"),
        "so_verify_ssl": False,
        "es_hosts": ["https://so.example.com:9200"],
        "litellm_base_url": "http://localhost:4000",
        "api_auth_required": False,
    }
    kwargs.update(over)
    return Settings(**kwargs)


def _report(**over):
    base = dict(verdict="false_positive", confidence=0.8, summary="x" * 40)
    base.update(over)
    return base


# --------------------------------------------------------------------------
# Verdict formatting wobble
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        ("False Positive", "false_positive"),
        ("FALSE_POSITIVE", "false_positive"),
        ("false-positive", "false_positive"),
        (" true_positive ", "true_positive"),
        ("True Positive", "true_positive"),
        ("Needs More Info", "needs_more_info"),
        ("needs-more-info", "needs_more_info"),
    ],
)
def test_verdict_formatting_variants_normalize(raw, canonical):
    """Case/space/hyphen variants of the canonical verdicts must not burn a
    schema retry — the model chose the right verdict and fumbled the format."""
    assert TriageReport.model_validate(_report(verdict=raw)).verdict == canonical


@pytest.mark.parametrize("raw", ["benign", "malicious", "suspicious", "fp", "tp"])
def test_verdict_synonyms_still_fail(raw):
    """Only FORMATTING is normalized, never meaning. A synonym is the model
    failing to follow the contract, and mapping it would put words in its
    mouth — that must stay a validation error the retry loop can correct."""
    with pytest.raises(ValidationError):
        TriageReport.model_validate(_report(verdict=raw))


# --------------------------------------------------------------------------
# citations: list[str] rescue
# --------------------------------------------------------------------------


def test_bare_string_citation_wraps_into_a_list():
    """Weak models emit `"citations": "evt-123"` for a single citation. The
    downstream citation resolver validates every entry anyway, so wrapping is
    strictly more accepting with no trust cost."""
    rep = TriageReport.model_validate(_report(citations="evt-abc123"))
    assert rep.citations == ["evt-abc123"]


@pytest.mark.parametrize("sentinel", ["None", "null", "", "N/A"])
def test_citation_null_sentinels_become_empty_list(sentinel):
    rep = TriageReport.model_validate(_report(citations=sentinel))
    assert rep.citations == []


def test_stringified_citation_list_still_decodes():
    """Regression guard: the existing stringified-JSON rescue must survive."""
    rep = TriageReport.model_validate(_report(citations='["a", "b"]'))
    assert rep.citations == ["a", "b"]


def test_real_citation_list_passes_through():
    rep = TriageReport.model_validate(_report(citations=["a", "b"]))
    assert rep.citations == ["a", "b"]


# --------------------------------------------------------------------------
# recommended_actions: list[RecommendedAction] rescue
# --------------------------------------------------------------------------


def test_single_action_dict_wraps_into_a_list():
    """A model recommending ONE action often emits the object bare instead of
    as a one-element array."""
    action = {"tool_name": "ack_alert", "tool_args": {}, "rationale": "benign browsing"}
    rep = TriageReport.model_validate(_report(recommended_actions=action))
    assert len(rep.recommended_actions) == 1
    assert rep.recommended_actions[0].tool_name == "ack_alert"


@pytest.mark.parametrize("sentinel", ["None", "null", ""])
def test_action_null_sentinels_become_empty_list(sentinel):
    rep = TriageReport.model_validate(_report(recommended_actions=sentinel))
    assert rep.recommended_actions == []


def test_stringified_action_dict_wraps_and_validates():
    """Stringified single object: decode then wrap."""
    rep = TriageReport.model_validate(
        _report(recommended_actions='{"tool_name": "ack_alert", "tool_args": {}, "rationale": "r"}')
    )
    assert rep.recommended_actions[0].tool_name == "ack_alert"


def test_action_prose_still_fails():
    """A sentence where the schema wants actions must stay an error."""
    with pytest.raises(ValidationError):
        TriageReport.model_validate(_report(recommended_actions="ack the alert please"))


def test_unknown_action_tool_still_fails():
    """The WriteToolName Literal is a security boundary — never widened."""
    with pytest.raises(ValidationError):
        TriageReport.model_validate(
            _report(
                recommended_actions=[{"tool_name": "delete_all", "tool_args": {}, "rationale": "x"}]
            )
        )


# --------------------------------------------------------------------------
# Config knobs: tool_choice + synthesizer output mode
# --------------------------------------------------------------------------


def test_tool_choice_required_defaults_off():
    """Default MUST preserve today's behavior: tool_choice='auto' everywhere
    (the Nemotron qwen3_coder workaround, harmless on V4, refuted-as-needed on
    the CPU tier). The knob exists so the NEXT lesser model gets a config flip
    instead of a code change."""
    from soc_ai.agent.models import build_synthesizer_model

    model = build_synthesizer_model(_settings())
    assert model.profile.openai_supports_tool_choice_required is False


def test_tool_choice_required_knob_flips_the_profile():
    from soc_ai.agent.models import build_investigator_model, build_synthesizer_model

    s = _settings(analyst_tool_choice_required=True)
    assert build_synthesizer_model(s).profile.openai_supports_tool_choice_required is True
    assert build_investigator_model(s).profile.openai_supports_tool_choice_required is True


def test_synth_output_mode_defaults_to_tool_calling():
    """Default 'tool' produces the exact agent shape shipped today."""
    from pydantic_ai.models.test import TestModel
    from soc_ai.agent.orchestrator import build_synth_first_agent

    # TestModel, not a model-id string: an id would make the OpenAI SDK demand
    # credentials at construction, coupling a pure schema-shape assertion to CI
    # env vars (the exact failure the 2026-08-05 pipeline caught).
    agent = build_synth_first_agent(TestModel())
    assert type(agent._output_schema).__name__ == "AutoOutputSchema"


@pytest.mark.parametrize(
    ("mode", "schema_cls"),
    [("native", "NativeOutputSchema"), ("prompted", "PromptedOutputSchema")],
)
def test_synth_output_mode_switches_the_output_schema(mode, schema_cls):
    """'native' = server-side guided decoding via response_format json_schema —
    the strongest fix for schema wobble, and it removes the tool-call parser
    from the path entirely (the DSML-markup-leak failure class). 'prompted' =
    JSON-in-text, for backends whose tool parser AND response_format are both
    broken. Applies to the no-tools synthesizers only."""
    from pydantic_ai.models.test import TestModel
    from soc_ai.agent.orchestrator import (
        build_partial_triage_synthesizer,
        build_synth_first_agent,
        build_synthesizer,
    )

    for builder in (build_synth_first_agent, build_synthesizer, build_partial_triage_synthesizer):
        agent = builder(TestModel(), output_mode=mode)
        assert type(agent._output_schema).__name__ == schema_cls, builder.__name__


def test_synth_output_mode_rejects_unknown_mode():
    from pydantic_ai.models.test import TestModel
    from soc_ai.agent.orchestrator import build_synth_first_agent

    with pytest.raises(ValueError, match="output_mode"):
        build_synth_first_agent(TestModel(), output_mode="grammar")


def test_synth_output_mode_setting_exists_with_safe_default():
    s = _settings()
    assert s.synthesizer_output_mode == "tool"
    assert s.analyst_tool_choice_required is False


# --------------------------------------------------------------------------
# served_backend on usage events (success attribution)
# --------------------------------------------------------------------------


class _FakeUsage:
    tool_calls = 2
    requests = 3
    input_tokens = 10
    output_tokens = 5
    total_tokens = 15


def test_usage_payload_carries_served_backend():
    """Error events got backend attribution in the diagnosability MR; usage
    events on SUCCESSFUL runs need it too, or verdict quality can never be
    sliced by backend after a fallback window (the question the operator asks
    the day after: 'are the fallback-window verdicts trustworthy?')."""
    from soc_ai.agent.orchestrator import _usage_event_payload

    p = _usage_event_payload(
        1, _FakeUsage(), served_backend={"api_base": "http://192.0.2.10:8000/v1"}
    )
    assert p["served_backend"]["api_base"] == "http://192.0.2.10:8000/v1"
    assert p["total_tokens"] == 15
    assert p["phase"] == "synthesizer"
    assert p["round"] == 1


def test_usage_payload_omits_backend_when_unknown():
    """Absent, not null — old-row shape preserved when attribution failed."""
    from soc_ai.agent.orchestrator import _usage_event_payload

    p = _usage_event_payload(2, _FakeUsage(), served_backend=None)
    assert "served_backend" not in p
    assert p["round"] == 2


# --------------------------------------------------------------------------
# model-probe: the first command to run when a new analyst backend lands
# --------------------------------------------------------------------------


def test_probe_classifies_the_known_failure_modes():
    """Each recorded weak-model failure class maps to a distinct probe label,
    so a probe report reads as a diagnosis rather than a stack trace."""
    from pydantic_ai.exceptions import UnexpectedModelBehavior
    from soc_ai.model_probe import classify_probe_exception

    assert (
        classify_probe_exception(UnexpectedModelBehavior("Exceeded maximum output retries (3)"))
        == "schema_retry_exhausted"
    )
    assert classify_probe_exception(TimeoutError()) == "timeout"
    assert classify_probe_exception(RuntimeError("weird")) == "RuntimeError"


def test_probe_classifies_http_errors_with_status():
    from pydantic_ai.exceptions import ModelHTTPError
    from soc_ai.model_probe import classify_probe_exception

    exc = ModelHTTPError(status_code=502, model_name="m", body=None)
    assert classify_probe_exception(exc) == "http_502"


def test_probe_summary_shape_and_math():
    from soc_ai.model_probe import summarize_probe

    outcomes = [
        ("OK", "false_positive conf=0.85"),
        ("OK", "false_positive conf=0.9"),
        ("schema_retry_exhausted", "Exceeded maximum output retries (3)"),
    ]
    rep = summarize_probe(
        model="qwen3.6-35b-cpu",
        output_mode="native",
        tool_choice_required=False,
        outcomes=outcomes,
        served_backend={"api_base": "http://llamacpp-text:8080/v1"},
        elapsed_s=42.5,
    )
    assert rep["model"] == "qwen3.6-35b-cpu"
    assert rep["n"] == 3
    assert rep["ok"] == 2
    assert rep["usable_rate"] == pytest.approx(2 / 3)
    assert rep["tally"] == {"OK": 2, "schema_retry_exhausted": 1}
    assert rep["failures"] == ["Exceeded maximum output retries (3)"]
    assert rep["served_backend"]["api_base"] == "http://llamacpp-text:8080/v1"
    assert rep["output_mode"] == "native"


def test_probe_model_runs_n_attempts_through_injected_runner():
    """probe_model builds the REAL synth agent (same builders prod uses) and
    tallies outcomes; the runner is injectable so this test needs no gateway."""
    import asyncio

    from soc_ai import model_probe

    calls = []

    async def fake_run_once(agent, prompt):
        calls.append(type(agent).__name__)
        return ("OK", "false_positive conf=0.8") if len(calls) < 3 else ("timeout", "600s")

    # analyst_model is env-aliased (HEAVY_MODEL), so overriding uses model_copy —
    # the same shape the CLI's --model flag uses.
    s = _settings().model_copy(update={"analyst_model": "fake-model"})
    rep = asyncio.run(model_probe.probe_model(s, n=4, output_mode="tool", run_once=fake_run_once))
    assert len(calls) == 4
    assert rep["ok"] == 2
    assert rep["tally"] == {"OK": 2, "timeout": 2}
    assert rep["model"] == "fake-model"


def test_analyst_profile_declares_json_schema_output_support():
    """pydantic-ai gates output_mode='native' on this profile flag CLIENT-SIDE
    (UserError before any request). The stock openai profile sets it; our
    custom analyst profile must too, or the synthesizer_output_mode='native'
    knob can never be exercised. Whether the BACKEND honors response_format is
    a separate, per-backend fact that model-probe measures over the wire."""
    from soc_ai.agent.models import build_synthesizer_model

    assert build_synthesizer_model(_settings()).profile.supports_json_schema_output is True


# --------------------------------------------------------------------------
# Dogfood 2026-08-05: the knobs must be USABLE from the Config console
# --------------------------------------------------------------------------


def test_new_knobs_are_registered_in_the_config_console():
    """Shipping a knob that requires editing .env + restart defeats its purpose
    (flip DURING an outage window). Both new knobs are hot: the agent builders
    read settings per investigation run, so a save applies to the next run.

    Found dogfooding the 2026-08-04 deploy: neither knob appeared in the
    console because neither was in the SettingSpec WHITELIST."""
    from soc_ai.store.config_overrides import WHITELIST_BY_KEY

    om = WHITELIST_BY_KEY["synthesizer_output_mode"]
    assert om.type == "select"
    assert om.options == ("tool", "native", "prompted")
    assert om.hot
    assert om.section == "Agent"

    tc = WHITELIST_BY_KEY["analyst_tool_choice_required"]
    assert tc.type == "bool"
    assert tc.hot
    assert tc.section == "Agent"


def test_select_setting_coerce_enforces_membership():
    """A select is only as safe as its membership check — the form string path
    (coerce) and the typed path (_validate_typed) must both reject a value
    outside the options, or a typo'd override would crash agent construction
    on the next investigation instead of failing the save."""
    from soc_ai.store.config_overrides import WHITELIST_BY_KEY, _validate_typed, coerce

    assert coerce("synthesizer_output_mode", "native") == "native"
    with pytest.raises(ValueError, match="one of"):
        coerce("synthesizer_output_mode", "grammar")

    spec = WHITELIST_BY_KEY["synthesizer_output_mode"]
    assert _validate_typed(spec, "prompted") == "prompted"
    with pytest.raises(ValueError, match="one of"):
        _validate_typed(spec, "grammar")


def test_config_api_emits_select_type_and_options(settings_kratos):
    """The frontend's select branch keys on type=='select' + options — plumbing
    that existed on both ends but was never connected server-side."""
    from unittest.mock import AsyncMock, patch

    from fastapi.testclient import TestClient
    from soc_ai.main import create_app

    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as client:
            groups = {g["title"]: g["items"] for g in client.get("/api/v1/config").json()["groups"]}
            by_key = {item["key"]: item for item in groups["Agent"]}

            om = by_key["synthesizer_output_mode"]
            assert om["type"] == "select"
            assert om["options"] == ["tool", "native", "prompted"]
            assert om["value"] == "tool"
            assert om["apply"] == "hot-apply"

            assert by_key["analyst_tool_choice_required"]["type"] == "toggle"
            assert by_key["analyst_tool_choice_required"]["value"] is False
