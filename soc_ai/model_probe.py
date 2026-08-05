"""Structured-output contract probe for candidate analyst backends.

``soc-ai model-probe`` answers, in minutes, the question that previously took a
debugging session: *can this model actually drive soc-ai's triage contract, and
under which settings?* It runs the REAL synthesizer agent (same builders and
prompt the pipeline uses) against a canned scenario N times and tallies the
outcomes into the failure classes this project has recorded from live serving
models — schema-retry exhaustion, no tool call, HTTP failures, timeouts.

Run it before pointing prod at a new analyst backend, and again for each
candidate setting::

    soc-ai model-probe --model qwen3.6-35b-cpu
    soc-ai model-probe --model qwen3.6-35b-cpu --output-mode native
    soc-ai model-probe --model qwen3.6-35b-cpu --tool-choice required
    soc-ai model-probe --model new-thing -n 12 --min-ok 10   # CI-gateable

The probe reports ``served_backend`` from the gateway's own attribution
headers, so an aliased or fallback-routed model name cannot misattribute the
result (the exact trap that derailed the 2026-08-03 investigation).
"""

from __future__ import annotations

import time
from collections.abc import Callable, Coroutine
from typing import Any

from soc_ai.config import Settings

# A realistic, self-contained benign-DNS triage scenario. Deliberately easy:
# the probe measures CONTRACT compliance (schema, tool call, JSON), not verdict
# quality — an easy scenario keeps a failed probe unambiguous about what broke.
PROBE_SCENARIO = """Alert: ET POLICY Observed DNS Query to .top TLD
src=10.0.0.42 dest=8.8.8.8 host=WKSTN-114 time=2026-08-03T14:02:11Z

Evidence gathered:
- dns.question.name = cdn-assets-01.top
- 3 queries in 60s, all NOERROR, resolving to 104.21.x.x (Cloudflare)
- Destination reputation: no hits on any blocklist
- Process: chrome.exe, user browsing session active
- No subsequent connection to the resolved IP beyond TLS 443
- Host has no other alerts in the last 30 days

Write the TriageReport now."""


def classify_probe_exception(exc: BaseException) -> str:
    """Map an exception from a probe attempt to a failure-class label.

    The labels line up with the failure taxonomy in the lesser-model runbook so
    a probe report reads as a diagnosis: ``schema_retry_exhausted`` points at
    output-shape wobble (try ``--output-mode native``), ``http_5xx`` at the
    serving stack, ``timeout`` at generation speed vs the configured budgets.
    """
    from pydantic_ai.exceptions import ModelHTTPError, UnexpectedModelBehavior  # noqa: PLC0415

    if isinstance(exc, ModelHTTPError):
        return f"http_{exc.status_code}"
    if isinstance(exc, UnexpectedModelBehavior):
        msg = str(exc).lower()
        if "retries" in msg:
            return "schema_retry_exhausted"
        return "unexpected_model_behavior"
    if isinstance(exc, TimeoutError):
        return "timeout"
    return type(exc).__name__


def summarize_probe(
    *,
    model: str,
    output_mode: str,
    tool_choice_required: bool,
    outcomes: list[tuple[str, str]],
    served_backend: dict[str, Any] | None,
    elapsed_s: float,
) -> dict[str, Any]:
    """Fold raw (label, detail) outcomes into the probe report dict."""
    tally: dict[str, int] = {}
    failures: list[str] = []
    for label, detail in outcomes:
        tally[label] = tally.get(label, 0) + 1
        if label != "OK" and len(failures) < 3:
            failures.append(detail)
    ok = tally.get("OK", 0)
    return {
        "model": model,
        "output_mode": output_mode,
        "tool_choice_required": tool_choice_required,
        "n": len(outcomes),
        "ok": ok,
        "usable_rate": (ok / len(outcomes)) if outcomes else 0.0,
        "tally": tally,
        "failures": failures,
        "served_backend": served_backend,
        "elapsed_s": round(elapsed_s, 1),
    }


async def _run_once(agent: Any, prompt: str) -> tuple[str, str]:
    """One probe attempt: run the agent, return (label, detail)."""
    try:
        result = await agent.run(prompt)
        out = result.output
        return ("OK", f"{out.verdict} conf={out.confidence}")
    except Exception as exc:
        detail = " ".join(str(exc).split())[:300]
        return (classify_probe_exception(exc), detail)


async def probe_model(
    settings: Settings,
    *,
    n: int = 6,
    output_mode: str = "tool",
    run_once: Callable[[Any, str], Coroutine[Any, Any, tuple[str, str]]] | None = None,
) -> dict[str, Any]:
    """Probe ``settings.analyst_model`` with the real synth agent, N attempts.

    Attempts run SEQUENTIALLY on purpose: a lesser backend (single llama.cpp
    slot, small vLLM) queues concurrent requests, which would fold queue wait
    into the timing and can flip timeout outcomes — sequential keeps each
    attempt's result attributable to the model alone.

    ``run_once`` is injectable for tests; the default runs the agent for real.
    """
    from soc_ai.agent._gateway_retry import capture_backend_attribution  # noqa: PLC0415
    from soc_ai.agent.models import build_synthesizer_model  # noqa: PLC0415
    from soc_ai.agent.orchestrator import build_synth_first_agent  # noqa: PLC0415

    runner = run_once if run_once is not None else _run_once
    agent = build_synth_first_agent(
        build_synthesizer_model(settings, temperature=settings.synthesizer_temperature),
        output_mode=output_mode,
    )
    outcomes: list[tuple[str, str]] = []
    started = time.monotonic()
    with capture_backend_attribution() as attribution:
        for _ in range(n):
            outcomes.append(await runner(agent, PROBE_SCENARIO))
    return summarize_probe(
        model=settings.analyst_model,
        output_mode=output_mode,
        tool_choice_required=settings.analyst_tool_choice_required,
        outcomes=outcomes,
        served_backend=dict(attribution) if attribution else None,
        elapsed_s=time.monotonic() - started,
    )


def format_probe_report(rep: dict[str, Any]) -> str:
    """Human-readable probe report for the CLI."""
    lines = [
        f"model            : {rep['model']}",
        f"output mode      : {rep['output_mode']}"
        + ("  (tool_choice=required)" if rep["tool_choice_required"] else ""),
        f"usable           : {rep['ok']}/{rep['n']}  ({rep['usable_rate']:.0%})",
        f"tally            : {rep['tally']}",
        f"elapsed          : {rep['elapsed_s']}s",
    ]
    backend = rep.get("served_backend") or {}
    if backend.get("api_base"):
        served = backend["api_base"]
        fallbacks = backend.get("attempted_fallbacks")
        lines.append(
            f"served by        : {served}"
            + (f"  (fallbacks attempted: {fallbacks})" if fallbacks not in (None, "0") else "")
        )
    for f in rep.get("failures", []):
        lines.append(f"  failure: {f}")
    return "\n".join(lines)


# ── Battery: the four knob configurations + a deterministic recommendation ───

# Fixed probe order. Baseline first — it is the comparison anchor and, on a
# healthy backend, also the fastest way to confirm the battery itself works.
BATTERY_CONFIGS: tuple[tuple[str, bool], ...] = (
    ("tool", False),  # baseline: today's prod behavior
    ("native", False),
    ("prompted", False),
    ("tool", True),
)

# Equal-rate speed bar: recommend on speed alone only when the candidate is at
# least this much faster than baseline (elapsed <= baseline * 0.75).
_SPEEDUP_BAR = 0.75


def _config_label(mode: str, required: bool) -> str:
    return f"{mode}+required" if required else mode


def recommend(configs: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Pick the configuration to recommend over the baseline, or None.

    Deterministic and explainable by design: rank by usable rate desc then
    elapsed asc; recommend only a STRICT improvement over the baseline (higher
    rate, or equal rate and >= 25% faster). ``prompted`` — the
    weakest-guarantees mode — is recommended only when it is the sole
    configuration at the top usable rate, so it never displaces a tied
    ``native``/``tool`` result on speed. Returns the two knob values plus a
    human-readable reason, or None when the baseline stands (including when
    everything failed — "configure nothing" is the honest answer to that).
    """
    baseline = next(
        (c for c in configs if c["output_mode"] == "tool" and not c["tool_choice_required"]),
        None,
    )
    if baseline is None or not configs:
        return None

    candidates = [c for c in configs if c is not baseline and c["usable_rate"] > 0]
    if not candidates:
        return None
    top_rate = max(c["usable_rate"] for c in candidates)
    top = [c for c in candidates if c["usable_rate"] == top_rate]
    # Demote prompted unless it is the sole top-rate configuration.
    non_prompted = [c for c in top if c["output_mode"] != "prompted"]
    if non_prompted:
        top = non_prompted
    best = min(top, key=lambda c: c["elapsed_s"])

    label = _config_label(best["output_mode"], best["tool_choice_required"])
    rate_str = f"{best['ok']}/{best['n']}"
    if best["usable_rate"] > baseline["usable_rate"]:
        reason = f"{label}: {rate_str} usable vs baseline {baseline['ok']}/{baseline['n']}"
    elif (
        best["usable_rate"] == baseline["usable_rate"]
        and baseline["elapsed_s"] > 0
        and best["elapsed_s"] <= baseline["elapsed_s"] * _SPEEDUP_BAR
    ):
        speedup = baseline["elapsed_s"] / max(best["elapsed_s"], 0.1)
        reason = f"{label}: {rate_str} usable, {speedup:.1f}x faster than tool mode"
    else:
        return None

    return {
        "synthesizer_output_mode": best["output_mode"],
        "analyst_tool_choice_required": best["tool_choice_required"],
        "config": label,
        "reason": reason,
    }


async def run_battery(
    settings: Settings,
    *,
    model: str | None = None,
    n: int = 2,
    run_once: Callable[[Any, str], Coroutine[Any, Any, tuple[str, str]]] | None = None,
    per_attempt_timeout_s: float = 120.0,
    on_progress: Callable[[str, int, int], None] | None = None,
) -> dict[str, Any]:
    """Probe *model* under every battery configuration; attach a recommendation.

    Sequential across configurations for the same reason probe attempts are
    sequential within one. ``per_attempt_timeout_s`` bounds each attempt so one
    hung backend read cannot wedge the whole battery (a timed-out attempt lands
    as a ``timeout`` outcome, it does not abort the run). ``on_progress`` is
    called with (config label, 1-based index, total) before each configuration —
    the API's status object hooks in there.
    """
    import asyncio  # noqa: PLC0415

    base_runner = run_once if run_once is not None else _run_once

    async def bounded_runner(agent: Any, prompt: str) -> tuple[str, str]:
        try:
            return await asyncio.wait_for(base_runner(agent, prompt), per_attempt_timeout_s)
        except TimeoutError:
            return ("timeout", f"attempt exceeded {per_attempt_timeout_s:.0f}s")

    probe_settings = settings
    if model:
        probe_settings = settings.model_copy(update={"analyst_model": model})

    started = time.monotonic()
    configs: list[dict[str, Any]] = []
    total = len(BATTERY_CONFIGS)
    for i, (mode, required) in enumerate(BATTERY_CONFIGS, start=1):
        if on_progress is not None:
            on_progress(_config_label(mode, required), i, total)
        cfg_settings = probe_settings.model_copy(update={"analyst_tool_choice_required": required})
        configs.append(
            await probe_model(cfg_settings, n=n, output_mode=mode, run_once=bounded_runner)
        )

    return {
        "model": probe_settings.analyst_model,
        "n_per_config": n,
        "configs": configs,
        "recommendation": recommend(configs),
        "elapsed_s": round(time.monotonic() - started, 1),
    }
