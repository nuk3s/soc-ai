"""PydanticAI model + provider construction for the investigation agents.

Extracted from ``orchestrator.py`` (which had grown past 3.3K lines). These are
pure construction helpers: they depend only on :class:`Settings` and the
pydantic_ai / openai model classes, and nothing in the orchestrator reaches
into their internals — so they live cleanly on their own. ``orchestrator``
re-imports the public builders, so existing import paths (and the tests that
patch ``soc_ai.agent.orchestrator.build_*_model``) keep working unchanged.
"""

from __future__ import annotations

import httpx
from openai import AsyncOpenAI
from pydantic_ai.models import Model
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.profiles.openai import OpenAIModelProfile
from pydantic_ai.providers.openai import OpenAIProvider

from soc_ai.agent._gateway_retry import RetryingAsyncTransport
from soc_ai.config import Settings
from soc_ai.demo.guard import assert_egress_allowed


def _build_provider(settings: Settings) -> OpenAIProvider:
    """Shared LiteLLM-backed provider for both investigator + synthesizer.

    HTTP read timeout is :attr:`Settings.litellm_request_timeout_s` (300s
    default). The synthesizer can legitimately need 60-150s on a busy
    GPU; under batch concurrency 2+ that exceeded the old 120s default
    and surfaced as ``ModelAPIError: Request timed out`` under sustained
    batch load. The harness's per-run wall-clock cap
    (``BatchConfig.per_run_timeout_s``) is what catches genuine hangs.
    """
    assert_egress_allowed(settings, "llm gateway")
    api_key = settings.litellm_api_key.get_secret_value() if settings.litellm_api_key else "dummy"
    # Resilient transport: retries transient gateway failures (429/502/503/504 +
    # connection/read/timeout errors) with jittered exponential backoff. This is
    # the single retry authority for the primary model path — matching the Oracle
    # client's backoff — so the OpenAI SDK's own retry is disabled (max_retries=0)
    # to avoid compounding. Bursty 502s from the LiteLLM gateway repeatedly
    # confounded investigations, hunts, and eval batches before this.
    http_client = httpx.AsyncClient(
        verify=settings.litellm_verify_ssl,
        timeout=settings.litellm_request_timeout_s,
        transport=RetryingAsyncTransport(
            max_retries=settings.litellm_max_retries,
            verify=settings.litellm_verify_ssl,
        ),
    )
    openai_client = AsyncOpenAI(
        base_url=str(settings.litellm_base_url).rstrip("/") + "/v1",
        api_key=api_key,
        http_client=http_client,
        max_retries=0,
    )
    return OpenAIProvider(openai_client=openai_client)


def _analyst_profile(settings: Settings) -> OpenAIModelProfile:
    """Model profile for the analyst routes (config-adaptive since 2026-08-04).

    Historically ``_nemotron_profile`` — a hardcoded profile for Nemotron 3
    served via vLLM with the qwen3_coder tool parser, silently applied to EVERY
    analyst backend that came after it. The knobs:

    1. ``supports_thinking=True`` + ``openai_chat_thinking_field="reasoning_content"``
       so PydanticAI binds a reasoning trace arriving in
       ``choices[0].message.reasoning_content`` (rather than inline ``<think>``
       tags) to ``ThinkingPart`` events for the SSE stream. Harmless when the
       field is absent.

    2. ``openai_supports_tool_choice_required`` — now
       :attr:`Settings.analyst_tool_choice_required`. The historical False
       (still the default) forces ``tool_choice='auto'``, the workaround for
       the vLLM 0.19.2rc1.dev qwen3_coder parser returning zero tool calls
       under ``required``. Whether ``required`` helps or hurts is per-backend;
       measure with ``soc-ai model-probe`` before flipping the setting.
    """
    return OpenAIModelProfile(
        supports_thinking=True,
        openai_chat_thinking_field="reasoning_content",
        # Don't echo the trace back on the next request — bloats context and
        # repeats per locked architecture decision.
        openai_chat_send_back_thinking_parts=False,
        openai_supports_tool_choice_required=settings.analyst_tool_choice_required,
        # Capability declaration, not a behavior change: pydantic-ai refuses
        # output_mode='native' client-side unless the profile declares json_schema
        # support (models/__init__.py: "Native structured output is not supported
        # by this model"). The stock openai profile declares it; this custom
        # profile must too or the synthesizer_output_mode='native' knob is dead
        # on arrival. Whether the backend HONORS response_format is per-backend —
        # measured over the wire by `soc-ai model-probe --output-mode native`.
        supports_json_schema_output=True,
    )


def build_investigator_model(settings: Settings) -> Model:
    """PydanticAI model for the investigator phase (heavy model, tool calling).

    Uses the HEAVY model — the same model the synth-first loop runs the
    investigator on (the loop must reason on the strong model). The separate
    builder is kept because the investigator caps its per-turn response budget,
    which the synthesizer must not.

    F2 (issue #23) caps the response token budget per turn via
    ``max_tokens=settings.investigator_max_response_tokens`` (default 2500).
    Phase 3 v5 critiques surfaced individual investigator turns producing
    13.6K reasoning-trace tokens for 2 tool calls — pure waste, dominant
    contributor to p95 ``investigation_ms``. The cap goes through
    OpenAI-compatible ``max_completion_tokens`` (not chat-template
    reasoning_mode), so it applies to reasoning + content combined.

    History note: this builder used a separate ``fast_model`` alias in the
    pre-synth-first pipeline; that alias was retired (the loop always uses the
    single analyst model now), so the investigator builds from ``analyst_model``.
    """
    from pydantic_ai.models.openai import OpenAIChatModelSettings  # noqa: PLC0415

    return OpenAIChatModel(
        settings.analyst_model,
        provider=_build_provider(settings),
        profile=_analyst_profile(settings),
        settings=OpenAIChatModelSettings(
            max_tokens=settings.investigator_max_response_tokens,
        ),
    )


def build_synthesizer_model(settings: Settings, *, temperature: float | None = None) -> Model:
    """PydanticAI model for the synthesizer phase (analyst model, structured output).

    ``temperature`` (when given) sets the sampling temperature — the synth-first
    pipeline passes a low value for the synthesizer (deterministic verdict) and a
    moderate one for the investigator (some exploration). ``None`` leaves the
    gateway default.

    ``max_tokens`` is ALWAYS set (``synthesizer_max_response_tokens``): with no
    explicit value the request falls to the provider/route default, and on a
    REASONING model the thinking phase can burn that whole default budget before
    the TriageReport JSON starts — the response truncates with zero content and
    pydantic-ai raises "Model token limit (provider default) exceeded before any
    response was generated", landing a fallback NMI verdict. Observed live on
    qwen3.6-reason (investigation 01KWX3E9A4…). An explicit generous cap gives
    the reasoning + report a real budget instead of an accidental one.
    """
    from pydantic_ai.models.openai import OpenAIChatModelSettings  # noqa: PLC0415

    model_settings = OpenAIChatModelSettings(
        max_tokens=settings.synthesizer_max_response_tokens,
    )
    if temperature is not None:
        model_settings["temperature"] = temperature
    return OpenAIChatModel(
        settings.analyst_model,
        provider=_build_provider(settings),
        profile=_analyst_profile(settings),
        settings=model_settings,
    )


# Backwards-compat shim — older callers passed a single `agent` with the
# heavy model doing both jobs. Internally we now split. The `build_model`
# alias keeps the import path stable for any in-tree callers; new code
# should use the explicit pair above.
def build_model(settings: Settings) -> Model:  # pragma: no cover - thin alias
    """Deprecated: use build_investigator_model / build_synthesizer_model."""
    return build_synthesizer_model(settings)


__all__ = [
    "build_investigator_model",
    "build_model",
    "build_synthesizer_model",
]
