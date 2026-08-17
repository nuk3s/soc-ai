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
import contextlib
import re
import time
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from soc_ai.demo.guard import assert_egress_allowed, is_demo

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
    could embed a credentialed URL. The type prefix is dropped when the message
    already carries it — elasticsearch's ApiError renders itself as
    ``ApiError(429, …)``, and prefixing produced the doubled
    ``ApiError: ApiError(429, …)`` an operator met on the banner (dogfood
    2026-08-14, D11).
    """
    name = type(exc).__name__
    msg = _scrub(str(exc)).strip()
    # Bound the length so a chatty upstream can't bloat the response.
    msg = msg[:160]
    if not msg:
        return name
    return msg if msg.lower().startswith(name.lower()) else f"{name}: {msg}"


# ── How a grid failure is CLASSIFIED ─────────────────────────────────────────
# Every surface that describes a down dependency used to hardcode one phrasing:
# "<dep> not reachable". A grid answering 429 IS reachable — it is up, replying,
# and shedding load — so that headline sent a 3am analyst to check connectivity
# and firewalls, none of which was the fault (dogfood 2026-08-14, D9). The probe
# is the only layer that sees the exception, so the probe classifies and the
# surfaces render the classification. "" means unclassified: the generic
# "not reachable" phrasing stands, exactly as before.
KIND_PARTIAL = "partial"  # answered, but did not read the whole grid
KIND_OVERLOADED = "overloaded"  # 429 / circuit breaker — up, shedding load
KIND_TIMEOUT = "timeout"  # took the query, never answered
KIND_REFUSED = "refused"  # no usable connection at all

# Byte sizes ES reports in a circuit-breaker message: "[7936000000/7.3gb]". The
# human half is the number an admin can act on, and the reason cap used to
# truncate the line immediately before the limit — leaking the internals AND
# dropping the one fact worth having.
_ES_BYTES_RE = re.compile(r"\[\d+/([\d.]+\s*[kmgtp]?b)\]", flags=re.IGNORECASE)


def _status_code(exc: BaseException) -> int | None:
    """HTTP status behind an elasticsearch ApiError, if there is one."""
    status = getattr(exc, "status_code", None)
    if isinstance(status, int):
        return status
    meta_status = getattr(getattr(exc, "meta", None), "status", None)
    return meta_status if isinstance(meta_status, int) else None


def _breaker_sizes(exc: BaseException) -> str:
    """The "needed X against a Y limit" half of a circuit-breaker message, or ""."""
    body = getattr(exc, "body", None)
    sizes = _ES_BYTES_RE.findall(str(body) if body else str(exc))
    if len(sizes) < 2:
        return ""
    return f" — the query needed {sizes[0].strip()} against a {sizes[1].strip()} limit"


def _cause_text(exc: BaseException) -> str:
    """The innermost transport reason, without the exception-chain scaffolding.

    elastic_transport nests the OS error in ``errors``; rendering the chain gave
    the operator ``ConnectionError: Connection error caused by:
    ConnectionError(ClientOSError([Errno 104] Connection reset by peer))``.
    """
    errors = getattr(exc, "errors", None)
    if isinstance(errors, list | tuple) and errors:
        return str(errors[0]).strip()
    return str(exc).strip()


def _grid_failure(exc: BaseException) -> tuple[str, str]:
    """``(kind, operator-facing reason)`` for a failed Elasticsearch read.

    The reason is what a tired admin reads on a banner at 3am, so it says what
    happened and whether waiting will help — not what Python called the class.
    An unrecognised exception keeps the old scrubbed summary: inventing a
    diagnosis is the failure this whole batch is about.
    """
    from soc_ai.so_client.elastic import GridPartialResultsError  # noqa: PLC0415

    if isinstance(exc, GridPartialResultsError):
        # An incomplete read has two causes and only one of them is the shards.
        # A busy grid answers 200 with `timed_out: true` and every shard healthy
        # — they all answered, the SEARCH ran out of time first — and the one
        # sentence covering both rendered that as "read only 4 of 4 shards …
        # check Elasticsearch shard health", which contradicts itself and sends
        # the admin to the one part of the system that is demonstrably fine
        # (review of batch A, 2026-08-14). Whether waiting helps is the whole
        # point of the line, and the two causes have opposite answers.
        total, failed = exc.shards_total, exc.shards_failed
        because = f" ({_scrub(str(exc.reason))[:100]})" if exc.reason else ""
        if failed:
            read = f"read only {total - failed} of {total} shards" if total else "read partially"
            timed_out = " and the search timed out" if exc.timed_out else ""
            return (
                KIND_PARTIAL,
                f"the grid {read}{timed_out}{because} — these results are incomplete, "
                "so check Elasticsearch shard health rather than retrying",
            )
        if exc.timed_out:
            return (
                KIND_PARTIAL,
                f"the search timed out before all shards answered{because} — these "
                "results are incomplete; retry, or narrow the time window",
            )
        return (
            KIND_PARTIAL,
            f"the grid did not read the whole index{because} — these results are incomplete",
        )
    status = _status_code(exc)
    if status == 429 or "circuit_breaking_exception" in str(exc):
        return (
            KIND_OVERLOADED,
            f"the grid is up but shedding load — HTTP {status or 429} circuit "
            f"breaker tripped{_breaker_sizes(exc)}; retryable once load drops",
        )
    name = type(exc).__name__
    if isinstance(exc, TimeoutError) or "timeout" in name.lower():
        return KIND_TIMEOUT, f"the grid took the query but did not answer in time ({name})"
    if isinstance(exc, ConnectionError | OSError) or "connection" in name.lower():
        return KIND_REFUSED, f"the grid could not be reached — {_scrub(_cause_text(exc))[:120]}"
    return "", _safe_reason(exc)


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
    # In demo mode the agent's answers are replayed from packaged fixtures and
    # there is no live gateway to reach. An egress probe would be (correctly)
    # refused by the demo guard, but reporting that refusal as a degraded
    # upstream lights up a false "AI gateway not reachable" banner on a demo
    # that is working exactly as designed. Report healthy-by-replay instead.
    if is_demo(settings):
        return {"ok": True, "detail": "demo mode — replayed responses (no live gateway)"}
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


# The read leg's query. ``ping()`` asks the cluster-info endpoint, which a
# cluster serving reads off two of its four shards answers perfectly well — so
# the one control whose whole job is to tell the truth about the grid went green
# while every alert query on the same instance was failing on a partial read
# (dogfood 2026-08-14, D1). Reachable is not readable, so the probe reads.
#
# This is the cheapest search ES can run: one document, no sort, no aggregation,
# no hit count. It is deliberately UNFILTERED — a time-range filter would let
# `can_match` skip cold shards, which is cheaper but skips exactly the shards
# whose failure this leg exists to catch. Frequency is bounded by the callers
# instead: /health caches the probe for 15s behind a single-flight lock, so it
# is a handful of these a minute however many tabs are open, and Diagnostics
# runs it on an admin's click.
_PROBE_SEARCH_QUERY: dict[str, Any] = {"match_all": {}}


def _probe_index_pattern(elastic: Any, settings: Any | None) -> str | None:
    """The events index pattern to read, or ``None`` when it can't be resolved.

    Prefers the caller's settings and falls back to the live settings object the
    :class:`ElasticClient` holds — the same one its own searches read, so a
    hot-applied ``events_index_pattern`` moves the probe with it, and the
    Diagnostics call site gets the read leg without having to pass settings.
    ``None`` means "not resolvable": the probe then reports the ping alone
    rather than inventing an index to read.
    """
    for source in (settings, getattr(elastic, "_settings", None)):
        pattern = getattr(source, "events_index_pattern", None)
        if isinstance(pattern, str) and pattern.strip():
            return pattern.strip()
    return None


async def probe_es(elastic: Any, settings: Any | None = None) -> dict[str, Any]:
    """Probe the Elasticsearch cluster: reachable AND readable.

    Two legs in a fixed order. :meth:`ElasticClient.ping` first, so a refused
    connection is still reported as a refused connection rather than as a failed
    read; then a ``size=1`` search against the events index pattern (see
    :data:`_PROBE_SEARCH_QUERY`). The client already raises
    ``GridPartialResultsError`` when a search did not read the whole grid, so
    this needs no shard parsing of its own.

    Never raises; returns ``ok``/``detail``/``kind`` — ``kind`` names the failure
    class (see :func:`_grid_failure`) for the surfaces that describe it. No
    password ever reaches ``detail``.
    """
    try:
        info = await elastic.ping()
    except Exception as exc:  # a probe failure is a normal ✗ result, never a raise
        kind, reason = _grid_failure(exc)
        return {"ok": False, "kind": kind, "detail": _scrub(reason)}
    cluster = str(info.get("cluster", "")) or "(unknown cluster)"
    version = str(info.get("version", "")) or "?"
    banner = f"{cluster} — ES {version}"
    index = _probe_index_pattern(elastic, settings)
    if index is None:
        # Nothing to read against — say what was actually checked instead of
        # letting a cluster-info tick stand in for a working grid.
        return {
            "ok": True,
            "kind": "",
            "detail": _scrub(f"{banner} — cluster info only (no index pattern)"),
        }
    try:
        await elastic.search(index, _PROBE_SEARCH_QUERY, size=1, track_total_hits=False)
    except Exception as exc:
        kind, reason = _grid_failure(exc)
        detail = _scrub(f"{banner} — reading {index}: {reason}")
        return {"ok": False, "kind": kind, "detail": detail}
    return {"ok": True, "kind": "", "detail": _scrub(f"{banner} — {index} readable")}


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

# Per-leg budget. This is the number the operator is shown, and — since
# 2026-08-07 — it is also the probe client's HTTP read timeout, so the deadline
# is enforced by the layer that owns the socket rather than by an outer cancel
# that the socket ignores (see :func:`_build_probe_model`).
# Raised 12 -> 30 (2026-08-05): V4 in tool mode under high reasoning effort
# measures 10-16s per structured call (battery data), so 12s sat on the knife's
# edge and the chip flickered UNFIT on the primary analyst model purely with
# load variance — while the battery proved the same model 2/2 on every config.
_FITNESS_LEG_TIMEOUT_S = 30.0
# Connect budget. Reaching the gateway is either fast or broken; keeping it well
# under the leg budget means a dead gateway is reported as such instead of
# eating a whole leg's clock.
_FITNESS_CONNECT_TIMEOUT_S = 5.0
# Slack between the client's own deadline and the outer wall-clock cancel. The
# client should always trip FIRST (it can name the phase and the elapsed time);
# the cancel is the belt for a transport that ignores its own deadline. Sized to
# cover a connect + read pair.
_FITNESS_LEG_GRACE_S = 7.0
# Hard ceiling on the whole probe so a wedged gateway can't hang the admin UI.
# It is the belt to the per-leg suspenders, so it MUST exceed the worst-case sum
# of the legs INCLUDING their grace (pinned by test). The original 30s total vs
# 3x12s legs was internally inconsistent: three slow-but-passing legs could not
# fit, and the overflow produced a hard "fail".
_FITNESS_TOTAL_TIMEOUT_S = 130.0

# Schema-retry budget for every leg's Agent. Matches EVERY production
# synthesizer (orchestrator.build_synth_first_agent / build_synthesizer /
# build_partial_triage_synthesizer, all ``retries=3``). The probe inherited
# pydantic-ai's default of 1, so a single stochastic schema wobble — the kind
# prod retries away without an operator ever seeing it — graded the analyst model
# UNFIT. A probe stricter than production manufactures failures production never
# sees.
_FITNESS_RETRIES = 3

# The tight cap for the reasoning-budget leg. Deliberately NOT the pipeline's
# response cap: that is ``synthesizer_max_response_tokens`` (32000), and the leg
# used to clamp it to 2048 while claiming to BE it. This is an experiment —
# "does thinking + JSON fit in a small budget?" — which is why the leg can only
# ever grade pass/degraded (see :func:`_leg_reasoning_budget`).
_FITNESS_TIGHT_BUDGET_TOKENS = 2048

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


def _fitness_leg(
    name: str,
    grade: str,
    detail: str,
    *,
    ok: bool | None = None,
    elapsed_s: float | None = None,
    backend: str | None = None,
) -> dict[str, Any]:
    """Build one leg result. ``ok`` defaults to (grade == 'pass'); ``detail`` is
    always scrubbed so a model/gateway error string can never leak a credential.

    ``elapsed_s`` and ``backend`` are the falsifiability fields: a bare "timed
    out" cannot be argued with, while "27.4s against a 30s budget on
    http://spark-a:8000/v1" tells the operator whether the model is unfit or the
    backend was busy. Both are None only when the leg never got far enough to
    measure (a builder error).
    """
    return {
        "name": name,
        "ok": ok if ok is not None else (grade == "pass"),
        "grade": grade,
        "detail": _scrub(detail)[:200],
        "elapsed_s": round(float(elapsed_s), 2) if elapsed_s is not None else None,
        "backend": _scrub(backend)[:120] if backend else None,
    }


# Exception type names that mean "the call was cut off", not "the model can't do
# this". anyio raises ClosedResourceError/BrokenResourceError when a cancelled
# read tears down a still-open connection — which is exactly what an outer
# asyncio cancel does to an httpx client mid-stream. Reporting those as model
# behaviour is how a saturated gateway got recorded as an unfit model on
# 2026-08-07. Matched by NAME so neither anyio nor the openai SDK has to be
# imported here.
_TEARDOWN_ARTIFACT_NAMES = frozenset(
    {
        "ClosedResourceError",
        "BrokenResourceError",
        "EndOfStream",
        "CancelledError",
        "APITimeoutError",
        "ReadTimeout",
        "ConnectTimeout",
        "PoolTimeout",
        "WriteTimeout",
    }
)


def _teardown_artifact(exc: BaseException, *, depth: int = 0) -> str | None:
    """Name the deadline/teardown artifact in *exc*'s chain, or None.

    Walks ``__cause__``/``__context__`` and exception-group members because the
    artifact is usually wrapped: pydantic-ai surfaces a transport error through
    the provider, and anyio's task groups bundle the teardown into a group. A
    depth bound keeps a cyclic chain from spinning.
    """
    if depth > 6:
        return None
    if isinstance(exc, TimeoutError | httpx.TimeoutException):
        return type(exc).__name__
    if type(exc).__name__ in _TEARDOWN_ARTIFACT_NAMES:
        return type(exc).__name__
    for member in getattr(exc, "exceptions", ()) or ():
        found = _teardown_artifact(member, depth=depth + 1)
        if found:
            return found
    for nested in (exc.__cause__, exc.__context__):
        if nested is not None:
            found = _teardown_artifact(nested, depth=depth + 1)
            if found:
                return found
    return None


def _timeout_detail(name: str, elapsed_s: float, artifact: str | None = None) -> str:
    """The one-line "how slow, against what budget" story for a cut-off leg."""
    budget = f"budget {_FITNESS_LEG_TIMEOUT_S:.0f}s"
    if artifact is None:
        return f"{name} timed out after {elapsed_s:.1f}s ({budget})"
    return (
        f"{name} cut off after {elapsed_s:.1f}s ({budget}) — {artifact} "
        "(client teardown, not a model capability failure)"
    )


def _build_probe_model(settings: Any) -> tuple[Any, httpx.AsyncClient]:
    """Model + the HTTP client it owns, for ONE fitness leg. The caller closes it.

    Deliberately NOT ``build_synthesizer_model``: production's provider is built
    for production's job — a 300s read timeout behind ``RetryingAsyncTransport``
    with ``litellm_max_retries`` (5) attempts. Under it the leg's
    ``asyncio.wait_for`` could not make the inner client hurry: the cancel landed
    mid-read, the connection tore down as an anyio ``ClosedResourceError``, and
    that got graded as a model capability failure. It is also how the 22:37:10
    run burned its whole 100s total inside leg 3 — arithmetically impossible if
    three 30s legs had actually held.

    So the probe owns its transport: read timeout == the leg budget, zero
    transport retries (the leg IS the single attempt being measured), and a
    client per leg that the leg closes — the old path leaked one
    ``httpx.AsyncClient`` per leg, three per probe, for the process lifetime.

    Everything the pipeline's behaviour depends on is kept: the same analyst
    profile (thinking field, tool_choice policy, json_schema capability) and the
    same ``synthesizer_max_response_tokens`` cap, so the probe grades the model
    production runs.
    """
    from openai import AsyncOpenAI  # noqa: PLC0415
    from pydantic_ai.models.openai import OpenAIChatModel, OpenAIChatModelSettings  # noqa: PLC0415
    from pydantic_ai.providers.openai import OpenAIProvider  # noqa: PLC0415

    from soc_ai.agent._gateway_retry import RetryingAsyncTransport  # noqa: PLC0415

    # The production profile itself — duplicating it here would silently drift
    # from the pipeline the probe claims to measure.
    from soc_ai.agent.models import _analyst_profile  # noqa: PLC0415

    assert_egress_allowed(settings, "model-fitness probe")
    verify = bool(getattr(settings, "litellm_verify_ssl", True))
    secret = getattr(settings, "litellm_api_key", None)
    api_key = secret.get_secret_value() if secret is not None else ""
    http_client = httpx.AsyncClient(
        verify=verify,
        timeout=httpx.Timeout(_FITNESS_LEG_TIMEOUT_S, connect=_FITNESS_CONNECT_TIMEOUT_S),
        # max_retries=0, but still this transport: it is the one place that reads
        # LiteLLM's backend-attribution headers into the capture sink.
        transport=RetryingAsyncTransport(max_retries=0, verify=verify),
    )
    openai_client = AsyncOpenAI(
        base_url=str(settings.litellm_base_url).rstrip("/") + "/v1",
        api_key=api_key or "dummy",
        http_client=http_client,
        max_retries=0,
    )
    model = OpenAIChatModel(
        settings.analyst_model,
        provider=OpenAIProvider(openai_client=openai_client),
        profile=_analyst_profile(settings),
        settings=OpenAIChatModelSettings(
            max_tokens=int(getattr(settings, "synthesizer_max_response_tokens", 32000)),
        ),
    )
    return model, http_client


def _probe_output_type(settings: Any) -> Any:
    """The output spec production runs, via production's own mapper.

    The probe built ``Agent(output_type=TriageReport)`` — pydantic-ai's default
    TOOL mode — while prod runs ``synthesizer_output_mode`` (native on the live
    deployment: server-side guided decoding, measured 4.3x faster on this exact
    backend by the app's own battery). Grading a model on a path it never runs,
    with a clock, is how a fit model kept coming back unfit.
    """
    from soc_ai.agent.orchestrator import _synth_output_type  # noqa: PLC0415

    return _synth_output_type(str(getattr(settings, "synthesizer_output_mode", "tool") or "tool"))


async def _aclose_quietly(client: Any) -> None:
    """Close a probe client; a close failure must never mask the leg's result."""
    if client is None:
        return
    with contextlib.suppress(Exception):  # teardown is best-effort by design
        await client.aclose()


# A leg body: given the model, run the exercise and return (grade, detail, ok).
_LegBody = Callable[[Any], Awaitable[tuple[str, str, "bool | None"]]]
# A leg's own error classifier: map an exception to (grade, detail, ok), or None
# to accept the default (a graded FAIL carrying the scrubbed reason).
_LegClassifier = Callable[[BaseException], "tuple[str, str, bool | None] | None"]


async def _run_leg(
    name: str,
    settings: Any,
    body: _LegBody,
    *,
    classify: _LegClassifier | None = None,
    timeout_grade: str = "fail",
    timeout_ok: bool | None = None,
) -> dict[str, Any]:
    """Run one leg: own the client, time it, attribute it, grade every failure.

    Everything the three legs share lives here so no leg can quietly diverge on
    the parts that made the probe untrustworthy — closing its client, recording
    elapsed time, capturing which backend served it, and mapping a cut-off call
    to the timeout outcome instead of a capability verdict.

    ``asyncio.CancelledError`` is NOT graded: it means the whole-probe cap fired
    and the caller is unwinding, so it propagates (the client still closes).
    """
    from soc_ai.agent._gateway_retry import capture_backend_attribution  # noqa: PLC0415

    started = time.monotonic()
    client: Any = None
    attribution: dict[str, Any] = {}
    try:
        with capture_backend_attribution() as sink:
            attribution = sink
            model, client = _build_probe_model(settings)
            grade, detail, ok = await asyncio.wait_for(
                body(model), timeout=_FITNESS_LEG_TIMEOUT_S + _FITNESS_LEG_GRACE_S
            )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        elapsed = time.monotonic() - started
        backend = str(attribution.get("api_base") or "") or None
        artifact = _teardown_artifact(exc)
        if artifact is not None:
            return _fitness_leg(
                name,
                timeout_grade,
                _timeout_detail(name, elapsed, None if isinstance(exc, TimeoutError) else artifact),
                ok=timeout_ok,
                elapsed_s=elapsed,
                backend=backend,
            )
        classified = classify(exc) if classify is not None else None
        if classified is None:
            classified = ("fail", _safe_reason(exc), None)
        grade, detail, ok = classified
        return _fitness_leg(name, grade, detail, ok=ok, elapsed_s=elapsed, backend=backend)
    finally:
        await _aclose_quietly(client)

    elapsed = time.monotonic() - started
    return _fitness_leg(
        name,
        grade,
        detail,
        ok=ok,
        elapsed_s=elapsed,
        backend=str(attribution.get("api_base") or "") or None,
    )


async def _leg_structured_output(settings: Any) -> dict[str, Any]:
    """PASS if the model returns a valid ``TriageReport`` on the canned prompt.

    This is the load-bearing capability: the synth-first pipeline's whole output
    is a structured ``TriageReport``. A model that can't produce one (schema
    exhaustion → ``UnexpectedModelBehavior``, or any validation failure) is unfit
    regardless of how good its prose is — it will fall back on every alert.

    Runs the pipeline's own output mode and retry budget: the failure this leg
    exists to catch only shows up on the path production actually takes.
    """

    async def _body(model: Any) -> tuple[str, str, bool | None]:
        # Local imports: the agent stack is heavy and only needed when a probe
        # runs (the config console imports probes.py at startup). Also avoids an
        # import cycle (agent.models → config → … ).
        from pydantic_ai import Agent  # noqa: PLC0415

        agent = Agent(
            model=model,
            output_type=_probe_output_type(settings),
            retries=_FITNESS_RETRIES,
        )
        result = await agent.run(_FITNESS_SO_PROMPT)
        # pydantic-ai guarantees a schema-valid TriageReport here or it would have
        # raised UnexpectedModelBehavior (graded below) — reaching here is a PASS.
        return ("pass", f"valid TriageReport (verdict={result.output.verdict})", None)

    return await _run_leg("structured_output", settings, _body)


async def _leg_tool_loop(settings: Any) -> dict[str, Any]:
    """PASS if the model calls the one trivial tool then answers.

    Mirrors the investigate loop's minimal shape (invoke a read tool, then
    synthesise). DEGRADED if the model answers WITHOUT calling the tool (it works
    but won't use tools — the loop can't gather evidence); FAIL on any error.
    """
    # A closure-captured flag is the cleanest in-process signal that the model
    # actually invoked the tool — pydantic-ai runs the tool body, flipping it.
    called = {"echo": False}

    async def echo(x: str) -> str:  # the single trivial, in-process tool
        """Echo the input back verbatim (probe-only; no side effects)."""
        called["echo"] = True
        return x

    async def _body(model: Any) -> tuple[str, str, bool | None]:
        from pydantic_ai import Agent  # noqa: PLC0415

        agent = Agent(model=model, tools=[echo], retries=_FITNESS_RETRIES)
        result = await agent.run(_FITNESS_TOOL_PROMPT)
        answered = bool((result.output or "").strip())
        if called["echo"] and answered:
            return ("pass", "tool invoked + final answer", None)
        if answered:
            # It produced an answer but skipped the tool — usable for one-shot
            # synth, but it won't drive the evidence-gathering loop.
            return ("degraded", "answered WITHOUT calling the tool", True)
        return ("fail", "no final answer", None)

    return await _run_leg("tool_loop", settings, _body)


async def _leg_reasoning_budget(settings: Any) -> dict[str, Any]:
    """Re-run the structured-output call under a TIGHT ``max_tokens`` and detect the
    "reasoning ate the whole budget" failure class.

    A reasoning model can burn its entire token budget on the thinking phase and
    emit ZERO output content — pydantic-ai then raises "token limit … exceeded
    before any response was generated".

    This leg is an EXPERIMENT and CANNOT grade FAIL. It runs a deliberately tight
    cap (:data:`_FITNESS_TIGHT_BUDGET_TOKENS`), not the pipeline's response cap —
    it used to clamp ``synthesizer_max_response_tokens`` to 2048 while claiming to
    be that cap, so it measured a model production never runs and then declared it
    unfit. Across the 50 recorded checks it produced ZERO of the truncation signal
    it was written for and a large share of the hard FAILs. Capability at the real
    cap is leg 1's job; everything adverse here is a DEGRADED hint.
    """

    budget = _FITNESS_TIGHT_BUDGET_TOKENS

    async def _body(model: Any) -> tuple[str, str, bool | None]:
        from pydantic_ai import Agent  # noqa: PLC0415
        from pydantic_ai.models.openai import OpenAIChatModelSettings  # noqa: PLC0415

        agent = Agent(
            model=model,
            output_type=_probe_output_type(settings),
            model_settings=OpenAIChatModelSettings(max_tokens=budget),
            retries=_FITNESS_RETRIES,
        )
        await agent.run(_FITNESS_SO_PROMPT)
        return ("pass", f"produced output within {budget} tokens", None)

    def _classify(exc: BaseException) -> tuple[str, str, bool | None] | None:
        from pydantic_ai.exceptions import UnexpectedModelBehavior  # noqa: PLC0415

        if isinstance(exc, UnexpectedModelBehavior) and any(
            marker in str(exc).lower() for marker in _TRUNCATION_MARKERS
        ):
            # THE target signal: thinking exhausted the budget before any JSON.
            return (
                "degraded",
                f"reasoning truncated at {budget} tokens before emitting output — "
                "raise synthesizer_max_response_tokens or pick a lighter-reasoning model",
                True,
            )
        return (
            "degraded",
            f"could not complete the {budget}-token experiment: {_safe_reason(exc)}",
            True,
        )

    return await _run_leg(
        "reasoning_budget",
        settings,
        _body,
        classify=_classify,
        timeout_grade="degraded",
        timeout_ok=True,
    )


def _served_backend(legs: list[dict[str, Any]]) -> dict[str, str] | None:
    """Which backend actually served this probe, from the legs' attribution.

    soc-ai asks LiteLLM for an ALIAS; the gateway may route it anywhere and the
    response body echoes the alias back either way. Without this, "model X is
    unfit" names what we asked for, not what ran — the exact trap that derailed
    the 2026-08-03 investigation. Last leg with an attribution wins (they only
    differ when the gateway re-routed mid-probe, which is itself the finding).
    """
    for leg in reversed(legs):
        backend = leg.get("backend")
        if backend:
            return {"api_base": str(backend)}
    return None


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

    Runs three legs (structured output, tool loop, reasoning budget) on the path
    PRODUCTION runs — the pipeline's output mode, retry budget and response cap —
    but through a probe-owned provider (:func:`_build_probe_model`) so the leg
    budget is enforced where the socket lives. Each leg is graded, never raised,
    and the worst grade wins. The whole probe is bounded by
    :data:`_FITNESS_TOTAL_TIMEOUT_S`; each leg by :data:`_FITNESS_LEG_TIMEOUT_S`
    plus its grace. NEVER issues a Security-Onion write — the only tool it
    registers is an in-process ``echo``.

    Returns ``{"grade": "pass"|"degraded"|"fail", "model": <id>, "legs":
    [{name, ok, grade, detail, elapsed_s, backend}], "detail": <one-line>,
    "served_backend": {…}|None}``. Every ``detail`` string is scrubbed of
    credential-shaped substrings.
    """
    model_id = str(getattr(settings, "analyst_model", "") or "")

    # In demo mode the analyst answers are replayed from packaged fixtures and
    # there is no live gateway. Every fitness leg builds the synthesizer model,
    # which hits the demo egress guard (build_synthesizer_model →
    # assert_egress_allowed → DemoEgressBlocked) and grades FAIL — lighting up a
    # false "analyst model unfit" chip on a demo working exactly as designed
    # (the same false-alarm class hotfixed for probe_llm). Report a non-alarming
    # PASS before any model is built.
    if is_demo(settings):
        return {
            "grade": "pass",
            "model": model_id,
            "legs": [],
            "detail": "demo mode — replayed responses (no live gateway)",
            "served_backend": None,
        }

    # Mutable accumulators so the total-timeout handler can report the legs
    # that DID complete and name the one in flight — legs=[] on a timeout is
    # the same undiagnosable-terminal-state class as a silent pipeline error.
    completed: list[dict[str, Any]] = []
    in_flight: list[str] = ["structured_output"]
    started = time.monotonic()

    async def _run_all() -> list[dict[str, Any]]:
        # Sequential (not concurrent): the legs share the single gateway and a
        # burst of 3 structured-output calls at once can trip the very
        # concurrency limits we're trying to characterise. Order is cheapest-
        # signal-first: structured output is the load-bearing gate.
        for name, leg_fn in (
            ("structured_output", _leg_structured_output),
            ("tool_loop", _leg_tool_loop),
            ("reasoning_budget", _leg_reasoning_budget),
        ):
            in_flight[0] = name
            completed.append(await leg_fn(settings))
        return completed

    try:
        legs = await asyncio.wait_for(_run_all(), timeout=_FITNESS_TOTAL_TIMEOUT_S)
    except TimeoutError:
        # The overall cap tripped — hard FAIL, but keep every finished leg and
        # mark WHERE the probe stopped so the chip's tooltip is a diagnosis.
        marker = _fitness_leg(
            "probe_timeout",
            "fail",
            f"probe exceeded {int(_FITNESS_TOTAL_TIMEOUT_S)}s during the {in_flight[0]} leg",
            elapsed_s=time.monotonic() - started,
        )
        return {
            "grade": "fail",
            "model": model_id,
            "legs": [*completed, marker],
            "detail": _scrub(
                f"model-fitness probe exceeded {int(_FITNESS_TOTAL_TIMEOUT_S)}s "
                f"(stopped during {in_flight[0]})"
            ),
            "served_backend": _served_backend(completed),
        }

    grade = _reduce_fitness(legs)
    if grade == "pass":
        detail = f"{model_id or 'analyst model'} passed all fitness checks"
    else:
        # Lead with the worst legs so the one-line detail names what's wrong.
        bad = [leg for leg in legs if leg["grade"] != "pass"]
        parts = ", ".join(f"{leg['name']}={leg['grade']}" for leg in bad)
        detail = f"{model_id or 'analyst model'}: {parts}"
    return {
        "grade": grade,
        "model": model_id,
        "legs": legs,
        "detail": _scrub(detail)[:200],
        "served_backend": _served_backend(legs),
    }


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
