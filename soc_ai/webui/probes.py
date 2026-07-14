"""Read-only connectivity probes for the admin config console.

Each probe targets one upstream (the LiteLLM gateway, the Security Onion
Elasticsearch cluster), is bounded by a timeout so a hung upstream cannot wedge
the request, and returns a small ``{"ok": bool, "detail": str}`` dict.

SECURITY: the ``detail`` string is rendered verbatim in an HTTP response and is
NEVER allowed to contain a secret — no API key, no ES/SO password, no
``user:pass@`` userinfo. Probes catch ALL exceptions and build ``detail`` from a
secret-free summary (exception type + a sanitized message), then pass it through
:func:`_scrub` defensively before returning.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import httpx

from soc_ai.demo.guard import assert_egress_allowed

# Default timeout (seconds) for every outbound probe. Kept short so the admin
# UI stays responsive when an upstream is down or hanging.
_PROBE_TIMEOUT_S = 10.0

# Defensive scrubbing patterns. Even though we build details from safe pieces,
# we strip anything that *looks* like a credential as a last line of defence.
_SCRUB_PATTERNS: tuple[re.Pattern[str], ...] = (
    # user:pass@host  →  host  (strip URL userinfo)
    re.compile(r"//[^/@\s]+@", flags=re.IGNORECASE),
    # Bearer <token>
    re.compile(r"bearer\s+\S+", flags=re.IGNORECASE),
    # key=..., api_key=..., apikey=..., password=..., token=...  query/kv params
    re.compile(r"(?i)(api[-_]?key|key|password|passwd|pwd|token|secret)=([^&\s]+)"),
)


def _scrub(text: str) -> str:
    """Strip credential-shaped substrings from *text* defensively."""
    out = text
    out = _SCRUB_PATTERNS[0].sub("//", out)
    out = _SCRUB_PATTERNS[1].sub("Bearer ***", out)
    out = _SCRUB_PATTERNS[2].sub(r"\1=***", out)
    return out


def _safe_reason(exc: BaseException) -> str:
    """Build a secret-free one-line reason from an exception.

    Connection errors expose only host/port (safe). For other errors we report
    the exception *type* and a scrubbed message, avoiding raw ``str(exc)`` that
    could embed a credentialed URL.
    """
    name = type(exc).__name__
    msg = _scrub(str(exc)).strip()
    # Bound the length so a chatty upstream can't bloat the response.
    msg = msg[:160]
    return f"{name}: {msg}" if msg else name


async def list_gateway_models(settings: Any) -> tuple[list[str], str | None]:
    """Model ids served by the LiteLLM gateway (``GET {base}/v1/models``).

    Returns ``(ids, error)`` — ``error`` is a scrubbed, secret-free human
    reason and ``ids`` is empty when the gateway can't be listed. Never
    raises. Feeds both the connectivity probe and the config console's
    analyst-model dropdown.
    """
    base = str(settings.litellm_base_url).rstrip("/")
    api_key = ""
    secret = getattr(settings, "litellm_api_key", None)
    if secret is not None:
        # SecretStr — may be empty.
        api_key = secret.get_secret_value()
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    # Mirror the real LLM connection's TLS policy (agent.models uses the same
    # knob) so the probe reflects actual reachability — homelab gateways use a
    # self-signed cert with litellm_verify_ssl=false.
    verify = bool(getattr(settings, "litellm_verify_ssl", True))
    try:
        # Demo guard inside the try: a blocked probe reports a normal ✗ result
        # (this function never raises), before any client is constructed.
        assert_egress_allowed(settings, "diagnostics probe")
        async with httpx.AsyncClient(timeout=_PROBE_TIMEOUT_S, verify=verify) as client:
            resp = await client.get(f"{base}/v1/models", headers=headers)
        if resp.status_code != 200:
            # status_code + reason phrase are credential-free.
            reason = resp.reason_phrase or ""
            return [], _scrub(f"HTTP {resp.status_code} {reason}".strip())
        try:
            data = resp.json()
        except ValueError:
            return [], "200 OK but response was not JSON"
        models = data.get("data") if isinstance(data, dict) else None
        ids = (
            [str(m["id"]) for m in models if isinstance(m, dict) and m.get("id")]
            if isinstance(models, list)
            else []
        )
        return ids, None
    except Exception as exc:  # a listing failure is a normal ✗ result, never a raise
        return [], _safe_reason(exc)


async def probe_llm(settings: Any) -> dict[str, Any]:
    """Probe the LiteLLM gateway by listing models.

    Never raises; returns ``ok``/``detail``. The API key is never placed into
    ``detail``.
    """
    ids, err = await list_gateway_models(settings)
    if err is not None:
        return {"ok": False, "detail": err}
    count = len(ids)
    # The gateway answering /v1/models doesn't mean ANALYST_MODEL is one of
    # them — a misconfigured value returns 200 here but 400s every actual
    # completion (every hunt silently falls back). Catch that up front.
    analyst = getattr(settings, "analyst_model", None)
    if analyst and analyst not in ids:
        return {
            "ok": False,
            "detail": _scrub(
                f"gateway reachable ({count} models) but ANALYST_MODEL "
                f"'{analyst}' is not configured on it — set ANALYST_MODEL to a "
                f"model the gateway serves"
            ),
        }
    return {"ok": True, "detail": f"200 OK — {count} models (analyst: {analyst})"}


async def probe_es(elastic: Any) -> dict[str, Any]:
    """Probe the Elasticsearch cluster via :meth:`ElasticClient.ping`.

    Never raises; returns ``ok``/``detail``. No password ever reaches ``detail``.
    """
    try:
        info = await elastic.ping()
        cluster = str(info.get("cluster", "")) or "(unknown cluster)"
        version = str(info.get("version", "")) or "?"
        return {"ok": True, "detail": _scrub(f"{cluster} — ES {version}")}
    except Exception as exc:  # a probe failure is a normal ✗ result, never a raise
        return {"ok": False, "detail": _safe_reason(exc)}


# The re-creation hint shown when the PCAP path is broken — the publish-blocker
# requirement: tell the operator the sensor user/key/sudo is gone and how to fix.
_PCAP_BROKEN_HINT = (
    "sensor PCAP path is down — the socpcap user, its SSH key, or its NOPASSWD "
    "tcpdump sudo rule is missing/broken. Re-run the sensor setup "
    "(docs/SENSOR_PCAP_SETUP.md)."
)


# ── Model-fitness preflight probe ─────────────────────────────────────────────
# WHY: pointing ``analyst_model`` at an unfit model (e.g. the A3B qwen variant
# that can't hold structured-output discipline, or a model whose reasoning phase
# eats the whole token budget before emitting JSON) silently produced ALL-fallback
# NMI verdicts — every investigation degraded, and the gateway couldn't tell us:
# a /v1/models listing (probe_llm) confirms the id is SERVED, not that it can DO
# THE JOB. This probe exercises the three model behaviours the pipeline actually
# depends on, against the real provider/retry/timeout path, and grades the model
# so the operator sees "this model can't do structured output" BEFORE it silently
# ruins a shift's triage.

# Hard ceiling on the whole probe so a wedged gateway can't hang the admin UI.
# Each leg also has its own bound (below); this is the belt to their suspenders.
_FITNESS_TOTAL_TIMEOUT_S = 30.0
# Per-leg wall-clock bound. A leg that blows this is graded (never raises) so one
# slow leg degrades to a clear result instead of eating the whole budget.
_FITNESS_LEG_TIMEOUT_S = 12.0

# The canned structured-output fixture. A one-line benign-DNS prompt with an
# unambiguous expected shape (false_positive / 0.9 / one citation) — trivial for a
# fit model, but it still forces the model through the ENTIRE structured-output
# machinery (tool-choice, schema-constrained JSON, pydantic validation, retries).
_FITNESS_SO_PROMPT = (
    "Return a false_positive verdict for this benign internal DNS lookup "
    "with confidence 0.9 and one citation 'demo-1'."
)
# The tool-loop fixture. Requires exactly one tool call then a final answer — the
# minimal shape of the investigate loop (call a read tool, then synthesise).
_FITNESS_TOOL_PROMPT = (
    "Call the echo tool once with x='ping', then reply with the single word it "
    "returns. You MUST use the echo tool — do not answer from memory."
)

# Substrings that identify the "token limit exceeded before any response" class
# raised by pydantic-ai (_agent_graph) when a reasoning model burns the whole
# max_tokens budget on thinking and emits ZERO output content. Matching the
# message (rather than a bespoke exception type) keeps this robust across the
# two phrasings pydantic-ai uses ("before any response" / "while generating").
_TRUNCATION_MARKERS: tuple[str, ...] = ("before any response", "token limit")


def _fitness_leg(name: str, grade: str, detail: str, *, ok: bool | None = None) -> dict[str, Any]:
    """Build one leg result. ``ok`` defaults to (grade == 'pass'); ``detail`` is
    always scrubbed so a model/gateway error string can never leak a credential.
    """
    return {
        "name": name,
        "ok": ok if ok is not None else (grade == "pass"),
        "grade": grade,
        "detail": _scrub(detail)[:200],
    }


async def _leg_structured_output(settings: Any) -> dict[str, Any]:
    """PASS if the model returns a valid ``TriageReport`` on the canned prompt.

    This is the load-bearing capability: the synth-first pipeline's whole output
    is a structured ``TriageReport``. A model that can't produce one (schema
    exhaustion → ``UnexpectedModelBehavior``, or any validation failure) is unfit
    regardless of how good its prose is — it will fall back on every alert.
    """
    # Local imports: the agent stack is heavy and only needed when a probe runs
    # (the config console imports probes.py at startup). Also avoids an import
    # cycle (agent.models → config → … ).
    from pydantic_ai import Agent  # noqa: PLC0415
    from pydantic_ai.exceptions import UnexpectedModelBehavior  # noqa: PLC0415

    from soc_ai.agent.models import build_synthesizer_model  # noqa: PLC0415
    from soc_ai.triage_models import TriageReport  # noqa: PLC0415

    try:
        model = build_synthesizer_model(settings)
        agent = Agent(model=model, output_type=TriageReport)
        result = await asyncio.wait_for(
            agent.run(_FITNESS_SO_PROMPT), timeout=_FITNESS_LEG_TIMEOUT_S
        )
        # pydantic-ai guarantees a schema-valid TriageReport here or it would have
        # raised UnexpectedModelBehavior (caught below) — reaching here is a PASS.
        report = result.output
        return _fitness_leg(
            "structured_output", "pass", f"valid TriageReport (verdict={report.verdict})"
        )
    except UnexpectedModelBehavior as exc:
        # Schema-validation exhaustion is THE unfit signal — the model kept
        # emitting JSON the schema rejected until pydantic-ai gave up.
        return _fitness_leg("structured_output", "fail", _safe_reason(exc))
    except TimeoutError:
        return _fitness_leg("structured_output", "fail", "timed out producing a TriageReport")
    except Exception as exc:  # any other failure is a graded FAIL, never a raise
        return _fitness_leg("structured_output", "fail", _safe_reason(exc))


async def _leg_tool_loop(settings: Any) -> dict[str, Any]:
    """PASS if the model calls the one trivial tool then answers.

    Mirrors the investigate loop's minimal shape (invoke a read tool, then
    synthesise). DEGRADED if the model answers WITHOUT calling the tool (it works
    but won't use tools — the loop can't gather evidence); FAIL on any error.
    """
    from pydantic_ai import Agent  # noqa: PLC0415

    from soc_ai.agent.models import build_synthesizer_model  # noqa: PLC0415

    # A closure-captured flag is the cleanest in-process signal that the model
    # actually invoked the tool — pydantic-ai runs the tool body, flipping it.
    called = {"echo": False}

    async def echo(x: str) -> str:  # the single trivial, in-process tool
        """Echo the input back verbatim (probe-only; no side effects)."""
        called["echo"] = True
        return x

    try:
        model = build_synthesizer_model(settings)
        agent = Agent(model=model, tools=[echo])
        result = await asyncio.wait_for(
            agent.run(_FITNESS_TOOL_PROMPT), timeout=_FITNESS_LEG_TIMEOUT_S
        )
        answered = bool((result.output or "").strip())
        if called["echo"] and answered:
            return _fitness_leg("tool_loop", "pass", "tool invoked + final answer")
        if answered:
            # It produced an answer but skipped the tool — usable for one-shot
            # synth, but it won't drive the evidence-gathering loop.
            return _fitness_leg(
                "tool_loop", "degraded", "answered WITHOUT calling the tool", ok=True
            )
        return _fitness_leg("tool_loop", "fail", "no final answer")
    except TimeoutError:
        return _fitness_leg("tool_loop", "fail", "timed out on the tool-loop prompt")
    except Exception as exc:  # any error → graded FAIL, never a raise
        return _fitness_leg("tool_loop", "fail", _safe_reason(exc))


async def _leg_reasoning_budget(settings: Any) -> dict[str, Any]:
    """Re-run the structured-output call under a TIGHT ``max_tokens`` and detect the
    "reasoning ate the whole budget" failure class.

    A reasoning model can burn its entire token budget on the thinking phase and
    emit ZERO output content — pydantic-ai then raises "token limit … exceeded
    before any response was generated". When that happens under a deliberately
    small budget we grade DEGRADED (not FAIL): the model IS structured-output
    capable (proved by the first leg) but its reasoning is un-budgetable at the
    pipeline's response cap — the operator needs the hint, not a hard block.
    """
    from pydantic_ai import Agent  # noqa: PLC0415
    from pydantic_ai.exceptions import UnexpectedModelBehavior  # noqa: PLC0415
    from pydantic_ai.models.openai import OpenAIChatModelSettings  # noqa: PLC0415

    from soc_ai.agent.models import build_synthesizer_model  # noqa: PLC0415
    from soc_ai.triage_models import TriageReport  # noqa: PLC0415

    # Deliberately tight cap: the pipeline's real cap, clamped to 2048 so a
    # reasoning model that can't fit thinking+JSON there surfaces the truncation
    # class here rather than silently on live alerts.
    budget = min(int(getattr(settings, "synthesizer_max_response_tokens", 2048)), 2048)
    try:
        model = build_synthesizer_model(settings)
        agent = Agent(
            model=model,
            output_type=TriageReport,
            model_settings=OpenAIChatModelSettings(max_tokens=budget),
        )
        await asyncio.wait_for(agent.run(_FITNESS_SO_PROMPT), timeout=_FITNESS_LEG_TIMEOUT_S)
        return _fitness_leg("reasoning_budget", "pass", f"produced output within {budget} tokens")
    except UnexpectedModelBehavior as exc:
        msg = str(exc).lower()
        if any(marker in msg for marker in _TRUNCATION_MARKERS):
            # THE target signal: thinking exhausted the budget before any JSON.
            return _fitness_leg(
                "reasoning_budget",
                "degraded",
                f"reasoning truncated at {budget} tokens before emitting output — "
                "raise synthesizer_max_response_tokens or pick a lighter-reasoning model",
                ok=True,
            )
        # A non-truncation UnexpectedModelBehavior here (e.g. schema exhaustion)
        # is a real failure of the same class as leg 1.
        return _fitness_leg("reasoning_budget", "fail", _safe_reason(exc))
    except TimeoutError:
        return _fitness_leg("reasoning_budget", "fail", "timed out under the tight budget")
    except Exception as exc:  # any error → graded FAIL, never a raise
        return _fitness_leg("reasoning_budget", "fail", _safe_reason(exc))


def _reduce_fitness(legs: list[dict[str, Any]]) -> str:
    """Grade reducer: FAIL if ANY leg failed; else DEGRADED if any degraded; else PASS.

    Worst-wins — the model is only as trustworthy as its weakest required
    behaviour. A single failing leg (can't do structured output) makes the whole
    model unfit even if the others pass.
    """
    grades = {leg["grade"] for leg in legs}
    if "fail" in grades:
        return "fail"
    if "degraded" in grades:
        return "degraded"
    return "pass"


async def probe_model_fitness(settings: Any) -> dict[str, Any]:
    """Grade whether ``settings.analyst_model`` can actually do the pipeline's job.

    Runs three legs (structured output, tool loop, reasoning budget) against the
    real provider path via :func:`build_synthesizer_model`, wraps each so a failure
    is a GRADED result (never a raise), and reduces to one overall grade. The whole
    probe is bounded by :data:`_FITNESS_TOTAL_TIMEOUT_S`; each leg by
    :data:`_FITNESS_LEG_TIMEOUT_S`. NEVER issues a Security-Onion write — the only
    tool it registers is an in-process ``echo``.

    Returns ``{"grade": "pass"|"degraded"|"fail", "model": <id>, "legs":
    [{name, ok, grade, detail}], "detail": <one-line>}``. Every ``detail`` string
    is scrubbed of credential-shaped substrings.
    """
    model_id = str(getattr(settings, "analyst_model", "") or "")

    async def _run_all() -> list[dict[str, Any]]:
        # Sequential (not concurrent): the legs share the single gateway and a
        # burst of 3 structured-output calls at once can trip the very
        # concurrency limits we're trying to characterise. Order is cheapest-
        # signal-first: structured output is the load-bearing gate.
        return [
            await _leg_structured_output(settings),
            await _leg_tool_loop(settings),
            await _leg_reasoning_budget(settings),
        ]

    try:
        legs = await asyncio.wait_for(_run_all(), timeout=_FITNESS_TOTAL_TIMEOUT_S)
    except TimeoutError:
        # The overall cap tripped — treat as a hard FAIL with a clear reason
        # rather than leaving the operator with a spinner.
        return {
            "grade": "fail",
            "model": model_id,
            "legs": [],
            "detail": _scrub(f"model-fitness probe exceeded {int(_FITNESS_TOTAL_TIMEOUT_S)}s"),
        }

    grade = _reduce_fitness(legs)
    if grade == "pass":
        detail = f"{model_id or 'analyst model'} passed all fitness checks"
    else:
        # Lead with the worst legs so the one-line detail names what's wrong.
        bad = [leg for leg in legs if leg["grade"] != "pass"]
        parts = ", ".join(f"{leg['name']}={leg['grade']}" for leg in bad)
        detail = f"{model_id or 'analyst model'}: {parts}"
    return {"grade": grade, "model": model_id, "legs": legs, "detail": _scrub(detail)[:200]}


async def probe_pcap(settings: Any) -> dict[str, Any]:
    """Probe the PCAP fetch path WITHOUT capturing packets.

    SSHes to the sensor as the de-privileged user and runs ``sudo tcpdump
    --version``, which exercises the whole chain — SSH auth (is the user still
    there? is the key valid?) and the NOPASSWD sudo-tcpdump grant — and fails
    loudly with a re-creation hint when the grid operator has nuked the user.
    Never raises; returns ``ok``/``detail``. Secret-free.
    """
    if not getattr(settings, "pcap_enabled", False):
        return {"ok": True, "detail": "PCAP disabled (pcap_enabled=false)"}
    if settings.so_ssh_key is None:
        return {"ok": False, "detail": "no SO_SSH_KEY configured — set it to the sensor pcap key"}

    from soc_ai.tools.get_pcap import _ssh_base_args  # noqa: PLC0415  (avoid import cycle)

    sudo = (getattr(settings, "so_ssh_sudo", "") or "").strip()
    remote = f"{sudo + ' ' if sudo else ''}tcpdump --version"
    args = [*_ssh_base_args(settings), remote]
    timeout = _PROBE_TIMEOUT_S + float(getattr(settings, "so_ssh_timeout_s", 120))
    try:
        # Demo guard inside the try: a blocked probe reports a normal ✗ result
        # (this function never raises), before the SSH subprocess is spawned —
        # process-based egress needs the same refusal as HTTP clients.
        assert_egress_allowed(settings, "sensor ssh probe")
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            out_b, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            proc.kill()
            host = getattr(settings, "so_ssh_host", "?")
            return {"ok": False, "detail": f"timed out reaching {host} — sensor unreachable?"}
        text = _scrub((out_b or b"").decode("utf-8", "replace")).strip()
        # Skip the benign ssh "Permanently added ... known hosts" warning
        # (UserKnownHostsFile=/dev/null + accept-new) when choosing the detail.
        lines = [ln for ln in text.splitlines() if "permanently added" not in ln.lower()]
        if proc.returncode == 0 and "tcpdump version" in text.lower():
            ver = next((ln for ln in lines if "tcpdump version" in ln.lower()), "")
            return {"ok": True, "detail": f"sensor reachable — {ver.strip()[:120] or 'tcpdump ok'}"}
        why = (lines[0].strip() if lines else "") or f"exit {proc.returncode}"
        return {"ok": False, "detail": f"{_PCAP_BROKEN_HINT} [{why[:120]}]"}
    except Exception as exc:  # a probe failure is a normal ✗ result, never a raise
        return {"ok": False, "detail": _safe_reason(exc)}
