"""Frontier-model adjudication client — the Oracle escalation path.

The Oracle is ONLY called after mandatory sanitization via the privacy gate in
:mod:`soc_ai.oracle.sanitize`.  The hard invariant:

1. Build a case dict from the alert enrichment + loop transcript + local report.
2. :func:`~soc_ai.oracle.sanitize.sanitize` replaces all private identifiers
   with opaque labels (``IP_01``, ``HOST_02``, …).
3. ``json.dumps`` the sanitized payload — this is the ACTUAL outbound bytes.
4. :func:`~soc_ai.oracle.sanitize.unsafe_residue` independently sweeps those
   bytes.  Any residue → **REFUSE**: log the leak categories, return ``None``.
   Never send a leaking payload.
5. Call the frontier model via the LiteLLM gateway using raw httpx (async) and
   a MINIMAL output schema ``OracleVerdict`` (verdict / confidence / summary /
   reasoning).  This avoids pydantic-ai strict structured-output validation
   failures caused by ``TriageReport``'s nested ``recommended_actions`` and
   ``gap_for_investigator`` objects, which the oracle (via LiteLLM) cannot reliably
   produce on the first pass.  We parse the JSON tolerantly (brace-balanced
   extraction, ``<think>``-strip), mirroring the proven pattern in
   :mod:`soc_ai.eval.oracle_client`.
6. :func:`~soc_ai.oracle.sanitize.desanitize` re-hydrates opaque labels in the
   verdict's text fields back to real identifiers for local display.
7. Map ``OracleVerdict`` → ``TriageReport`` for the orchestrator: verdict /
   confidence / summary from the oracle; citations / field_reconciliation
   carried forward from the LOCAL report (they document the examined evidence,
   which is verdict-neutral — an override must never strip a cited verdict to
   ``citations: []``); recommended_actions carried forward only when the Oracle
   agrees with the local verdict class (actions are verdict-specific);
   gap_for_investigator null.
8. Return an :class:`OracleResult`.  Any exception (timeout, parse, gateway
   error) → log + return ``None`` so the caller keeps the local verdict.

Evidence parity (the b3-rmm-admin-lateral fix): the case dict also carries the
investigation loop's TOOL RESULTS (``loop_tool_results``) and the investigator's
evidence bullets (``loop_evidence_bullets``), bounded by the ``_MAX_*`` budgets
below.  Tool results travel as STRUCTURED data, never flattened to a string,
because :func:`~soc_ai.oracle.redact.sanitize_case`'s field-aware harvest pass
tokenises identifiers by key path (``host.name: "filesrv"`` is internal by
field role even when no shape rule could know it) — flattening would silently
weaken the egress guard.  Every added field is assembled BEFORE ``sanitize_case``
and therefore passes through the same sanitize → independent-residue-sweep gate
as the rest of the payload.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, cast

from pydantic import BaseModel, Field

from soc_ai import metrics
from soc_ai.config import Settings
from soc_ai.demo.guard import assert_egress_allowed
from soc_ai.oracle.backstop import mask_unclassified_scalars
from soc_ai.oracle.redact import (
    _DOMAIN_FIELDS,
    Mapping,
    _is_internal_domain_like,
    _path_suffixes,
    sanitize_case,
)
from soc_ai.oracle.sanitize import (
    OracleUnknownLabelError,
    _resolve_suffixes,
    desanitize,
    find_unknown_oracle_labels,
    redaction_summary,
    unsafe_residue,
)
from soc_ai.triage_models import TriageReport

if TYPE_CHECKING:
    from soc_ai.agent.egress_guard import EgressGuard
    from soc_ai.agent.orchestrator import InvestigationContext

_LOGGER = logging.getLogger(__name__)

# Mirrors the Settings.oracle_internal_suffixes field default.  Used only to
# detect "operator left the privacy gate at defaults" for the egress warning.
_DEFAULT_INTERNAL_SUFFIXES: frozenset[str] = frozenset((".lan", ".local", ".internal", ".corp"))

# One-shot guard so the unconfigured-gate warning is logged once per process,
# not on every adjudication.  A 1-element list (not a bare bool) so the helper
# can flip it without a discouraged ``global`` rebind.  Reset in tests via
# ``_UNCONFIGURED_WARNED[0] = False``.
_UNCONFIGURED_WARNED: list[bool] = [False]


def _warn_if_privacy_gate_unconfigured(
    settings: Settings,
    *,
    effective_hosts: tuple[str, ...] | None = None,
    effective_suffixes: tuple[str, ...] | None = None,
) -> None:
    """Warn once if the Oracle is enabled but no org-specific internal names are set.

    The redacter catches private IPs/MACs, suffix-FQDNs, NetBIOS-shaped names,
    structured-field identifiers, and credential-context usernames automatically.
    It CANNOT know that an internal FQDN on a public-looking suffix
    (``dc01.ad.example.com``) or a bare codename (``WIN11-01``) is internal unless
    the operator enumerates it — those egress verbatim otherwise.  This nudges the
    operator to populate ``ORACLE_INTERNAL_SUFFIXES`` / ``ORACLE_EXTRA_HOSTS``.

    ``effective_hosts`` / ``effective_suffixes`` are the resolved *effective*
    sets (env-config unioned with active detected/manual DB identifiers, minus
    muted).  When provided (not ``None``) they are used instead of the raw
    ``settings`` reads, so a deployment that configured its internal names purely
    via the DB (empty ``.env``) does NOT get a spurious "no internal names
    configured" warning.  ``None`` ⇒ no DB session was available at the call site
    (CLI / eval / tests) → fall back to the raw settings reads (unchanged).
    """
    if _UNCONFIGURED_WARNED[0] or not settings.oracle_enabled:
        return
    hosts: tuple[str, ...] = (
        effective_hosts if effective_hosts is not None else tuple(settings.oracle_extra_hosts)
    )
    suffixes: tuple[str, ...] = (
        effective_suffixes
        if effective_suffixes is not None
        else tuple(settings.oracle_internal_suffixes)
    )
    has_extra_hosts = bool(hosts)
    has_custom_suffix = bool(set(suffixes) - _DEFAULT_INTERNAL_SUFFIXES)
    if has_extra_hosts or has_custom_suffix:
        return
    _UNCONFIGURED_WARNED[0] = True
    _LOGGER.warning(
        "oracle.client: Oracle is ENABLED but no organisation-specific internal "
        "names are configured (ORACLE_INTERNAL_SUFFIXES is at its default and "
        "ORACLE_EXTRA_HOSTS is empty). Internal FQDNs on public-looking suffixes "
        "(e.g. dc01.ad.example.com) and bare codenames (e.g. WIN11-01) will NOT be "
        "redacted before cloud egress. Set ORACLE_INTERNAL_SUFFIXES / "
        "ORACLE_EXTRA_HOSTS to your internal domains and hostnames. "
        "See SECURITY.md (Oracle egress sanitization)."
    )


ORACLE_SYSTEM_PROMPT = (
    "You are a senior SOC analyst adjudicating an alert the local triage was "
    "uncertain or possibly wrong about. The evidence is sanitized: internal IP "
    "addresses appear as IP_01, IP_02 etc.; internal hostnames appear as HOST_01 "
    "etc.; usernames as USER_01; MAC addresses as MAC_01; email addresses as "
    "EMAIL_01. Treat these opaque labels as real identifiers — cross-references "
    "between them are preserved and meaningful. "
    "Your task: review the alert summary, enriched context, local triage verdict, "
    "and any loop evidence provided, then produce a definitive verdict, confidence, "
    "and a concise summary citing specific evidence. "
    "Be direct. If the local verdict is wrong, say so and explain why. "
    "Respond with a single JSON object (no prose before or after) with keys: "
    '"verdict" (one of "true_positive", "false_positive", "needs_more_info"), '
    '"confidence" (float 0.0-1.0), '
    '"summary" (3-6 sentence plain-English narrative for the on-call analyst), '
    '"reasoning" (brief internal reasoning justifying the verdict).'
)


class OracleVerdict(BaseModel):
    """Minimal structured output expected from the Oracle LLM call.

    Using a minimal schema (four flat scalar fields) instead of ``TriageReport``
    (nested objects with list fields) dramatically increases the probability that
    the oracle (via LiteLLM) passes strict pydantic validation on the first try.
    The full ``TriageReport`` is then assembled from this verdict by
    :func:`_verdict_to_report`.
    """

    # The prompt asks for the first three; ``inconclusive`` is accepted so an
    # adjudication over a voted-inconclusive local report can echo the class
    # without a validation crash (kept in sync with soc_ai.triage_models.Verdict).
    verdict: Literal["true_positive", "false_positive", "needs_more_info", "inconclusive"]
    # Bounded here so a NaN, inf or percent-style value (json.loads accepts all
    # of them) fails validation and takes the unparseable-answer path instead of
    # being clamped downstream into a fabricated 1.0 that could clear the
    # auto-ack threshold.
    confidence: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    summary: str
    reasoning: str


@dataclass
class OracleResult:
    """Result from a successful Oracle adjudication."""

    report: TriageReport
    """Desanitized TriageReport from the frontier model."""

    redaction_summary: dict[str, int]
    """Per-category redaction counts (safe to log; never contains real values)."""

    oracle_model: str
    """The model alias that produced this result."""

    oracle_tool_calls: int = 0
    """Successful (evidence-bearing) tool calls the Oracle made in its own loop.
    Zero on the single-shot path (no tools). Surfaced on the ``oracle_adjudication``
    event (observability, design §8) and read by the override gate."""

    override_withheld: bool = False
    """True when the Oracle's verdict CHANGED the local class but was NOT backed
    by a tool call, so the override was withheld and the local verdict stands
    (design §6). The report already carries the local verdict; this flag lets the
    orchestrator record the withheld dissent on the event."""

    raw_oracle_verdict: str = ""
    """The class the Oracle actually returned, before the override gate — so a
    withheld dissent is still visible on the event even though ``report`` keeps
    the local verdict."""

    oracle_masked_values: int = 0
    """How many residual free-form scalars the allow-known-safe egress backstop
    masked across this adjudication — the INITIAL payload AND every tool result
    (design §"The wire gate is a blocklist"). Zero on the single-shot path.
    Surfaced on the ``oracle_adjudication`` event so the owner can measure the
    utility cost the backstop pays for a complete-by-construction boundary."""


# ---------------------------------------------------------------------------
# Tolerant JSON extraction helpers (mirrors soc_ai.eval.oracle_client pattern)
# ---------------------------------------------------------------------------

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)


def _strip_think(text: str) -> str:
    """Remove ``<think>…</think>`` blocks emitted by reasoning models."""
    return _THINK_RE.sub("", text).strip()


def _extract_json_object(text: str) -> str | None:
    """Extract the first brace-balanced JSON object from *text*.

    Handles:
    - Plain JSON responses.
    - JSON wrapped in a ```json ... ``` fence.
    - JSON embedded in prose before/after.
    - ``<think>`` preamble from reasoning models.

    Returns the raw JSON string, or ``None`` if no balanced object is found.
    """
    text = _strip_think(text)

    # Try a fenced block first — most reliable signal.
    m = _FENCE_RE.search(text)
    if m:
        candidate = m.group(1).strip()
        if candidate.startswith("{"):
            return candidate

    # Brace-balanced extraction: find the first ``{`` and walk forward.
    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_str = False
    escape_next = False
    for i, ch in enumerate(text[start:], start=start):
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_str:
            escape_next = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _parse_oracle_verdict(raw_text: str) -> OracleVerdict | None:
    """Parse a (possibly noisy) LLM response into an ``OracleVerdict``.

    Returns ``None`` when the text cannot be parsed into a valid verdict.
    """
    json_str = _extract_json_object(raw_text)
    if json_str is None:
        _LOGGER.debug("oracle.client: no JSON object found in response")
        return None
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as exc:
        _LOGGER.debug("oracle.client: JSON parse error: %s", exc)
        return None
    if not isinstance(data, dict):
        return None
    try:
        return OracleVerdict.model_validate(data)
    except Exception as exc:
        _LOGGER.debug("oracle.client: OracleVerdict validation error: %s", exc)
        return None


def _verdict_to_report(
    verdict: OracleVerdict,
    *,
    local_report: TriageReport,
    oracle_tool_calls: int = 0,
    gate_active: bool = False,
) -> TriageReport:
    """Map a minimal ``OracleVerdict`` → full ``TriageReport``.

    The Oracle produces only verdict / confidence / summary / reasoning.  The
    evidence fields the LOCAL investigation earned are carried forward instead
    of being reset (the b3-rmm-admin-lateral defect: a 10/10-cited local report
    shipped as an uncited Oracle override):

    - ``citations`` and ``field_reconciliation`` — ALWAYS carried.  They
      document the evidence that was examined, which is the same evidence the
      Oracle adjudicated over (the payload includes it); they are
      verdict-neutral, so they remain correct whichever way the Oracle rules.
    - ``recommended_actions`` — carried ONLY when the Oracle agrees with the
      local verdict class.  Actions are verdict-specific: an "ack as benign"
      action under a flipped ``true_positive`` verdict would be worse than no
      action at all.
    - ``gap_for_investigator`` — always ``None`` (adjudication is terminal;
      never recurse into Phase D off an Oracle verdict).

    The reasoning text is appended to the summary so it is visible in the
    analyst-facing output.

    **The override gate (design §6, DECIDED 2026-08-27).** When ``gate_active``
    (the tool-running Oracle), a verdict that CHANGES the local class must be
    backed by ≥1 successful tool call in the Oracle's own loop
    (``oracle_tool_calls``). An unbacked flip does NOT override — this returns
    the LOCAL report VERBATIM (its class, confidence, actions, citations, summary).
    The Oracle's dissent is on the record via the ``oracle_adjudication`` event
    (``raw_oracle_verdict`` + ``override_withheld``), not the summary — the
    orchestrator keeps the local report on a withheld override, so a summary edit
    here would be discarded. A zero-tool AGREEMENT still lands (adds confidence).
    ``gate_active`` is False on the single-shot path, so that shipped behaviour —
    where a flip lands with no tools — is unchanged.
    """
    combined_summary = verdict.summary
    if verdict.reasoning and verdict.reasoning.strip():
        combined_summary = f"{verdict.summary}\n\nOracle reasoning: {verdict.reasoning}"
    same_verdict = verdict.verdict == local_report.verdict

    if gate_active and not same_verdict and oracle_tool_calls < 1:
        # Withhold the override: the local verdict stands, UNCHANGED. The dissent
        # is recorded on the ``oracle_adjudication`` event (``raw_oracle_verdict``
        # + ``override_withheld``), NOT spliced into the summary — the orchestrator
        # keeps ``local_triage_final`` on a withheld override
        # (soc_ai/agent/orchestrator.py), so any summary edit here is dead. Return
        # the local report verbatim; code and docstring now agree.
        return local_report

    return TriageReport(
        verdict=verdict.verdict,
        confidence=verdict.confidence,
        summary=combined_summary,
        citations=list(local_report.citations),
        recommended_actions=list(local_report.recommended_actions) if same_verdict else [],
        field_reconciliation=local_report.field_reconciliation,
        gap_for_investigator=None,
    )


# ---------------------------------------------------------------------------
# Raw async LiteLLM call (mirrors soc_ai.eval.oracle_client.call_oracle)
# ---------------------------------------------------------------------------

_MAX_RETRIES = 3
# Full-jitter exponential backoff between gateway retries. The deterministic
# ceiling grows 0.5, 1.0, 2.0 … capped at 8s; the actual sleep is a uniform draw
# in [0, ceiling]. Jitter matters because Oracle is called from many concurrent
# investigations — a fixed schedule makes them all retry in lockstep and re-hammer
# the gateway the instant it starts to recover (thundering herd). This mirrors the
# transport-layer policy in soc_ai/agent/_gateway_retry.py.
_BACKOFF_BASE_S = 0.5
_BACKOFF_MAX_S = 8.0


def _backoff_s(attempt: int) -> float:
    ceiling = min(_BACKOFF_BASE_S * (2.0 ** (attempt - 1)), _BACKOFF_MAX_S)
    return float(random.random() * ceiling)  # noqa: S311 - jitter, not security-sensitive


class _OracleGatewayError(RuntimeError):
    """A LiteLLM gateway failure, tagged ``retryable``.

    5xx (server/gateway transient) and transport/timeout errors are retryable;
    4xx (auth / bad request) are terminal — retrying a 401/400 only wastes the
    budget and delays the inevitable, so the loop fails fast on those.
    """

    def __init__(self, message: str, *, retryable: bool) -> None:
        super().__init__(message)
        self.retryable = retryable


async def _call_oracle_raw(
    payload_text: str,
    *,
    settings: Settings,
) -> str:
    """POST the sanitized payload to LiteLLM and return the raw response text.

    Uses ``httpx.AsyncClient`` (async equivalent of the eval oracle's sync
    ``httpx.Client``) so we stay non-blocking inside the async orchestrator.

    Raises :class:`RuntimeError` on HTTP / transport failure.
    """
    assert_egress_allowed(settings, "oracle")
    import httpx  # noqa: PLC0415 — lazy; keep hot path light

    base_url = str(settings.litellm_base_url).rstrip("/") + "/v1/chat/completions"
    api_key = settings.litellm_api_key.get_secret_value() if settings.litellm_api_key else "dummy"

    request_body: dict[str, Any] = {
        "model": settings.oracle_model,
        "max_tokens": 2048,
        "messages": [
            {"role": "system", "content": ORACLE_SYSTEM_PROMPT},
            {"role": "user", "content": payload_text},
        ],
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(
        verify=settings.litellm_verify_ssl,
        timeout=settings.oracle_timeout_s,
    ) as client:
        try:
            resp = await client.post(base_url, headers=headers, json=request_body)
        except httpx.TransportError as exc:  # connect / read / timeout — transient
            raise _OracleGatewayError(f"transport error: {exc}", retryable=True) from exc
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code if exc.response is not None else 0
            body = exc.response.text[:500] if exc.response is not None else ""
            # 5xx = gateway/server transient → retry; 4xx = client error → terminal.
            raise _OracleGatewayError(
                f"LiteLLM returned {status}: {body}", retryable=status >= 500
            ) from exc
        data = resp.json()

    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError("LiteLLM response had no choices")
    msg = choices[0].get("message") or {}
    content = msg.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            part.get("text", "")
            for part in content
            if isinstance(part, dict) and part.get("type") == "text"
        )
    return ""


# ---------------------------------------------------------------------------
# Evidence-parity payload budgets (chars of serialized JSON, not tokens).
# The Oracle payload now carries the loop's tool results — the backing data the
# local verdict actually rests on — so a runaway tool history must not blow the
# request budget.  Worst case added by these budgets: ~40K (tool results)
# + ~20K (prose transcript) + ~10K (evidence bullets) ≈ 70K chars ≈ 18K tokens,
# comfortably inside a frontier-model context window.
# ---------------------------------------------------------------------------

_MAX_TOOL_RESULTS = 25
"""At most this many tool results travel; newest win (the loop converges
toward the decisive follow-up queries; the earliest calls are broad sweeps)."""

_MAX_TOOL_RESULT_CHARS = 6_000
"""Per-result serialized budget; an over-budget result is re-shrunk harder and
dropped (never string-flattened — see the structured-data invariant) if it
still does not fit."""

_MAX_TOOL_RESULTS_TOTAL_CHARS = 40_000
"""Total serialized budget across all included tool results."""

_MAX_TRANSCRIPT_CHARS = 20_000
"""Budget for the prose loop transcript (head + tail kept, middle elided)."""

_MAX_EVIDENCE_BULLETS = 50
_MAX_EVIDENCE_BULLET_CHARS = 500

_MAX_STR_LEAF_CHARS = 1_500
"""Per-string-leaf budget inside a tool result."""

_MAX_LIST_ITEMS = 15
"""Per-list budget inside a tool result (first N kept, count marker appended)."""

_MAX_SHRINK_DEPTH = 10

# Tool-result bookkeeping short-circuits that carry no evidence by construction
# (mirrors soc_ai.agent.evidence.count_successful_tool_calls).
_NON_EVIDENCE_RESULT_FLAGS = ("duplicate_call", "prefetch_already_has_this")


def _truncate_token_safe(text: str, limit: int) -> str:
    """Truncate *text* to ≤ *limit* chars, cutting at a whitespace boundary.

    Cutting mid-token could split an internal identifier (``10.0.0.`` …) into a
    fragment that neither the sanitizer's shape rules nor the residue sweep can
    recognise — a partial leak.  Identifiers never contain whitespace, so
    backing up to the last whitespace keeps every token whole.
    """
    if len(text) <= limit:
        return text
    cut = text[:limit]
    ws = cut.rfind(" ")
    # Only back up when a reasonably close boundary exists; a single giant
    # unbroken token is cut hard (nothing recognisable survives either way).
    if ws > limit - 200:
        cut = cut[:ws]
    return cut + " …[truncated]"


def _shrink_value(value: Any, *, str_limit: int, list_limit: int, _depth: int = 0) -> Any:
    """Structurally bound a tool result for the Oracle payload.

    Preserves dict keys and nesting — the sanitizer's field-aware harvest
    tokenises identifiers by key path (``host.name`` → HOST even for a bare
    codename no shape rule could catch), so flattening to a string would
    silently weaken the egress guard.  Long string leaves and long lists are
    truncated with explicit markers.
    """
    if _depth >= _MAX_SHRINK_DEPTH:
        return "…[nested content elided]"
    if isinstance(value, str):
        return _truncate_token_safe(value, str_limit)
    if isinstance(value, dict):
        return {
            str(k): _shrink_value(v, str_limit=str_limit, list_limit=list_limit, _depth=_depth + 1)
            for k, v in value.items()
        }
    if isinstance(value, list):
        shrunk = [
            _shrink_value(v, str_limit=str_limit, list_limit=list_limit, _depth=_depth + 1)
            for v in value[:list_limit]
        ]
        if len(value) > list_limit:
            shrunk.append(f"…[{len(value) - list_limit} more items elided]")
        return shrunk
    if isinstance(value, tuple):
        return _shrink_value(list(value), str_limit=str_limit, list_limit=list_limit, _depth=_depth)
    return value


def _extract_tool_results(loop_messages: list[Any] | None) -> list[dict[str, Any]]:
    """Extract the loop's tool results from a pydantic-ai message history, bounded.

    Duck-typed exactly like :func:`soc_ai.agent.evidence.count_successful_tool_calls`
    (``part_kind == "tool-return"`` / ``"builtin-tool-return"``): only actual tool
    RESULTS qualify — the model's prose, thinking and retry parts stay in the
    text transcript.  Dedup / prefetch short-circuits are skipped (no evidence by
    construction).  Str-content returns are skipped too: they already reach the
    payload via the prose transcript path.

    Budgeting: each result is structurally shrunk (:func:`_shrink_value`), then
    results are admitted NEWEST-first until ``_MAX_TOOL_RESULTS`` /
    ``_MAX_TOOL_RESULTS_TOTAL_CHARS`` is exhausted, and finally re-ordered back
    to chronological.  When anything was dropped, a count marker is prepended so
    the Oracle knows the history is elided, not complete.

    Every entry is round-tripped through ``json.dumps(default=str)`` so the case
    dict stays JSON-serialisable (a stray datetime must degrade to its string
    form here, not turn the whole adjudication into a fail-closed refusal).
    """
    if not loop_messages:
        return []
    candidates: list[dict[str, Any]] = []
    for msg in loop_messages:
        for part in getattr(msg, "parts", []) or []:
            if getattr(part, "part_kind", None) not in ("tool-return", "builtin-tool-return"):
                continue
            content = getattr(part, "content", None)
            if not isinstance(content, (dict, list)):
                continue
            if isinstance(content, dict) and any(
                content.get(flag) for flag in _NON_EVIDENCE_RESULT_FLAGS
            ):
                continue
            shrunk = _shrink_value(
                content, str_limit=_MAX_STR_LEAF_CHARS, list_limit=_MAX_LIST_ITEMS
            )
            serialized = json.dumps(shrunk, default=str)
            if len(serialized) > _MAX_TOOL_RESULT_CHARS:
                # Re-shrink harder rather than string-flattening (structure is
                # what the field-aware harvest needs).
                shrunk = _shrink_value(content, str_limit=300, list_limit=5)
                serialized = json.dumps(shrunk, default=str)
                if len(serialized) > _MAX_TOOL_RESULT_CHARS:
                    continue  # pathological single result — drop it, keep the rest
            candidates.append(
                {
                    "tool": str(getattr(part, "tool_name", None) or "unknown_tool"),
                    "result": json.loads(serialized),
                    "_size": len(serialized),
                }
            )

    # Admit newest-first under the count + total-size budgets.
    kept_rev: list[dict[str, Any]] = []
    total = 0
    for entry in reversed(candidates):
        size = int(entry["_size"])
        if len(kept_rev) >= _MAX_TOOL_RESULTS or total + size > _MAX_TOOL_RESULTS_TOTAL_CHARS:
            break
        total += size
        kept_rev.append(entry)

    kept = [{"tool": e["tool"], "result": e["result"]} for e in reversed(kept_rev)]
    dropped = len(candidates) - len(kept)
    if dropped > 0:
        kept.insert(
            0,
            {"note": f"{dropped} earlier tool results elided for size; newest kept"},
        )
    return kept


def _bound_transcript(text: str) -> str:
    """Bound the prose loop transcript: keep head + tail, elide the middle.

    The head carries the alert framing; the tail carries the loop's final,
    usually decisive turns.  Cuts are whitespace-safe so no identifier is split
    into an unrecognisable fragment (see :func:`_truncate_token_safe`).
    """
    if len(text) <= _MAX_TRANSCRIPT_CHARS:
        return text
    head_budget = _MAX_TRANSCRIPT_CHARS // 2
    tail_budget = _MAX_TRANSCRIPT_CHARS - head_budget
    head = _truncate_token_safe(text, head_budget)
    tail = text[-tail_budget:]
    ws = tail.find(" ")
    if 0 <= ws < 200:
        tail = tail[ws + 1 :]
    return f"{head}\n…[transcript middle elided for size]…\n{tail}"


def _bound_evidence_bullets(bullets: list[str] | None) -> list[str]:
    """Bound the investigator's evidence bullets (claim → id index)."""
    if not bullets:
        return []
    return [
        _truncate_token_safe(b, _MAX_EVIDENCE_BULLET_CHARS)
        for b in bullets[:_MAX_EVIDENCE_BULLETS]
        if isinstance(b, str) and b.strip()
    ]


def _assemble_case_dict(
    *,
    enriched: Any,
    local_report: TriageReport,
    transcript_text: str,
    tool_results: list[dict[str, Any]] | None = None,
    evidence_bullets: list[str] | None = None,
) -> dict[str, Any]:
    """Assemble the case payload from enriched context + local verdict + transcript.

    The dict is deliberately compact: a single JSON.dumps of this is what the
    residue check runs over, so every unnecessary field is a liability.

    ``loop_tool_results`` / ``loop_evidence_bullets`` are the evidence-parity
    fields (already bounded by the caller): the raw tool results the local
    verdict rests on, and the investigator's claim→id bullets that index them.
    They MUST stay structured (dicts, not flattened strings) so
    ``sanitize_case``'s field-aware harvest sees their key paths.
    """
    # Serialize enriched context compactly.  model_dump(mode="json") gives a plain
    # Python dict; mode="json" coerces non-JSON-native types (datetime, etc.) to
    # their JSON representations so json.dumps never raises on non-serialisable.
    enriched_compact: dict[str, Any]
    if hasattr(enriched, "model_dump"):
        enriched_compact = enriched.model_dump(mode="json")
    else:
        enriched_compact = dict(enriched)

    return {
        "alert_summary": enriched_compact,
        "loop_evidence": _bound_transcript(transcript_text or ""),
        "loop_tool_results": tool_results or [],
        "loop_evidence_bullets": _bound_evidence_bullets(evidence_bullets),
        "local_verdict": local_report.verdict,
        "local_confidence": local_report.confidence,
        "local_summary": local_report.summary,
        "local_citations": local_report.citations,
    }


# ===========================================================================
# The read-only tool loop (design 2026-08-27, gated by oracle_tools_enabled).
#
# The escalation trigger, the sanitize pipeline, and the None-on-failure
# contract all stay. New: a bounded tool loop between sanitize and verdict,
# sharing ONE per-adjudication Mapping. The single wire-level residue choke
# point sits on the adjudication httpx client's request hook — it sweeps EVERY
# actual outbound body (initial payload, each tool-result continuation, retries)
# and there is deliberately no second, weaker sweep anywhere else.
# ===========================================================================

ORACLE_TOOL_SYSTEM_PROMPT = ORACLE_SYSTEM_PROMPT + (
    " You ALSO have a set of READ-ONLY investigation tools: query the grid "
    "(OQL / Zeek), pull an event's raw document, decode payload bytes locally, "
    "and check host context, prevalence, rule noisiness and IOC enrichment. "
    "Use them to CHECK a claim you doubt rather than distrusting it in the "
    "abstract. A verdict that CHANGES the local one only counts when you back it "
    "with at least one successful tool call — an unbacked disagreement is "
    "discarded and the local verdict stands. Refer to identifiers ONLY by the "
    "opaque labels already present in the evidence (IP_01, HOST_02, USER_03, …); "
    "never invent a label that is not there. When you have gathered enough, stop "
    "calling tools and emit the final JSON verdict object described above as your "
    "last message, with no prose around it."
)


class OracleResidueError(RuntimeError):
    """A wire-level outbound body still carried internal identifiers.

    Raised by the adjudication client's httpx request hook when
    :func:`~soc_ai.oracle.sanitize.unsafe_residue` fires on an ACTUAL outbound
    request body. Carries the leak CATEGORIES only (never the values — an
    exception string that lands in a log must not itself become the leak). The
    loop catches it, aborts the adjudication, returns ``None`` (local verdict
    retained) and records the refusal — the single-shot residue doctrine, moved
    to the transport so it holds for every request the loop composes.
    """

    def __init__(self, categories: list[str]) -> None:
        self.categories = categories
        super().__init__(f"residue detected in an outbound oracle body: {categories}")


def _make_residue_hook(
    mapping: Mapping,
    *,
    allowlist: tuple[str, ...],
    extra_hosts: tuple[str, ...],
    extra_suffixes: tuple[str, ...],
    no_propagate: set[str],
) -> Callable[[Any], Awaitable[None]]:
    """Build the SINGLE wire-level residue choke point.

    The returned async httpx request hook runs on EVERY outbound body the
    adjudication client sends and sweeps the actual bytes with
    :func:`~soc_ai.oracle.sanitize.unsafe_residue`, reading ``known_values`` from
    the shared ``mapping`` AT CALL TIME (it grows as tool results harvest
    identifiers) with the same ``extra_hosts`` / ``extra_suffixes`` / ``allowlist``
    as ``sanitize_case``. Any leak → raise → abort. This is the ONLY residue
    sweep on the tool-loop path (design §1: no second, weaker sweep anywhere).
    """

    async def _hook(request: Any) -> None:
        body = getattr(request, "content", b"")
        if not body:
            return
        if isinstance(body, (bytes, bytearray)):
            text = body.decode("utf-8", "replace")
        else:
            text = str(body)
        leaks = unsafe_residue(
            text,
            allowlist=allowlist,
            extra_hosts=extra_hosts,
            extra_suffixes=extra_suffixes,
            # Exclude the short DOMAIN_LIKE values the sanitizer intentionally
            # left un-propagated (they would corrupt public FQDNs) — same
            # exclusion the single-shot gate applies.
            known_values=tuple(v for v in mapping.reverse.values() if v not in no_propagate),
            # Wire form: json.dumps doubles every real backslash, so a lone one is
            # a JSON escape, not a NetBIOS separator.
            wire_escaped=True,
        )
        if leaks:
            categories = sorted({leak.split(":")[0].strip() for leak in leaks})
            raise OracleResidueError(categories)

    return _hook


# ---------------------------------------------------------------------------
# Tool-aware result re-keying (finding oracle-tool-result-leak).
#
# The field-aware harvest in ``sanitize_case`` classifies a value by the ECS
# field PATH it sits on. The new oracle tools return internal identifiers under
# GENERIC keys the harvest cannot classify — ``t_field_values`` puts them in
# ``values[].value``, ``t_describe_dataset`` in ``fields[].example``, an OQL
# groupby in a bucket ``key``. A shapeless bare name (``filesrv``) has no regex
# shape either, so the wire residue gate STRUCTURALLY cannot catch it — the
# harvest must. For each KNOWN oracle envelope, re-key its identifier-bearing
# values onto the ECS path that describes them, so the harvest learns them (and
# Pass-2 global-replace then tokenises them everywhere they appear in the real
# result). The re-keyed view only ever holds values already present in the
# result; it is harvested, then dropped — it never rides the wire.
# ---------------------------------------------------------------------------

_ORACLE_REKEY_KEY = "__oracle_rekey__"

# ECS DOMAIN-category fields the oracle re-key may route a value onto. A superset
# of redact's ``_DOMAIN_FIELDS`` with the ``source``/``destination.domain`` ECS
# pair: the shared harvest treats those two as UNRECOGNISED, but a bare
# single-label internal value there has neither a field role NOR a regex shape,
# so it egresses raw exactly as the suffix-gated DOMAIN fields do. The reroute
# below tokenises the single-label case for ALL of them.
_ORACLE_DOMAIN_CATEGORY_FIELDS: frozenset[str] = _DOMAIN_FIELDS | {
    "source.domain",
    "destination.domain",
}


def _reroute_domain_singlelabel_to_host(rekey: dict[str, Any]) -> dict[str, Any]:
    """Route single-label values on DOMAIN-category re-key fields to HOST.

    Residual leak (found by re-verifying the tool-result-leak fix): the
    field-aware harvest gates DOMAIN fields (``dns.question.name`` /
    ``dns.query.name`` / ``domain`` / ``host.domain``, plus the unrecognised
    ``source``/``destination.domain``) on an internal SUFFIX. A bare single-label
    internal name (``filesrv``, a NetBIOS short domain ``ACMECORP``) ends in no
    configured suffix, so it is neither harvested (no suffix) NOR catchable at the
    wire (no regex shape, not yet a known value) — it egresses verbatim. The
    DOMAIN_LIKE category already resolves this via :func:`_is_internal_domain_like`
    (single-label ⇒ internal ⇒ HOST); mirror that here for the oracle re-key so the
    two categories stop disagreeing on single-label names.

    Single-label values MOVE (are copied) to a HOST path — ``host.name``, an
    unconditional-harvest field — so the harvest learns them and Pass-2 global
    replace tokenises them wherever they appear. Multi-label values are LEFT on
    their DOMAIN field, where the existing suffix rule (internal-suffix ⇒ HOST) and
    the Pass-2 suffix-FQDN shape rule still handle them, and a genuine public FQDN
    still passes through for the Oracle. This only ADDS coverage for the shapeless
    single-label case; it never weakens existing tokenisation.

    Passing empty ``suffixes`` to the predicate selects EXACTLY its single-label
    branch: a public domain is always multi-label, so a single-label value on a
    domain field is essentially always internal/NetBIOS (the same reasoning the
    DOMAIN_LIKE category relies on today).
    """
    host_names: list[str] = []
    for key, val in rekey.items():
        if not any(s in _ORACLE_DOMAIN_CATEGORY_FIELDS for s in _path_suffixes(key)):
            continue
        for v in val if isinstance(val, list) else [val]:
            if isinstance(v, str) and _is_internal_domain_like(v, ()):
                host_names.append(v)
    if not host_names:
        return rekey
    existing = rekey.get("host")
    if isinstance(existing, dict):
        names = existing.get("name")
        if isinstance(names, list):
            names.extend(host_names)
        elif isinstance(names, str):
            existing["name"] = [names, *host_names]
        else:
            existing["name"] = host_names
    else:
        rekey["host"] = {"name": host_names}
    return rekey


def _rekey_host_dossier(result: dict[str, Any]) -> dict[str, Any]:
    """Re-key a ``t_host_dossier`` result's identifier fields onto ECS paths.

    The dossier hides its identifiers under generic per-field ``value`` keys:
    ``fields.hostname.value`` (+ ``inferred_value`` beneath an override, and the
    ``evidence`` prose ``"filesrv (from dhcp)"``), ``fields.domain_membership.value``
    (a bare NetBIOS domain), and every field's ``operator_actor`` (the human who
    set an override). Learning the host/user values here lets Pass-2 global
    replace tokenise them wherever they appear — including the free-text
    ``evidence`` / ``operator_note`` prose.
    """
    fields = result.get("fields")
    if not isinstance(fields, dict):
        return {}
    hosts: list[str] = []
    users: list[str] = []
    for fname, payload in fields.items():
        if not isinstance(payload, dict):
            continue
        actor = payload.get("operator_actor")
        if isinstance(actor, str) and actor:
            users.append(actor)
        if fname in ("hostname", "domain_membership"):
            for key in ("value", "inferred_value"):
                v = payload.get(key)
                if isinstance(v, str) and v:
                    hosts.append(v)
    rekey: dict[str, Any] = {}
    if hosts:
        rekey["host"] = {"name": hosts}
    if users:
        rekey["user"] = {"name": users}
    return rekey


def _rekey_oql_aggregations(aggregations: Any) -> dict[str, Any]:
    """Re-key OQL groupby bucket keys onto the grouped field name.

    ``… | groupby host.name`` returns ``aggregations.by_host_name.buckets[].key``
    — internal hostnames verbatim under a generic ``key``. The agg name encodes
    the grouped field (``by_`` + ``_safe_agg_name``, which maps ``.``/``-`` → ``_``),
    so recover both the underscore form (``host_name`` — already an ``_HOST_FIELDS``
    alias) and a dotted candidate (``host.name``) and place the bucket keys under
    each. Nested (multi-field) groupbys recurse into each bucket's own ``by_*``.
    """
    if not isinstance(aggregations, dict):
        return {}
    rekey: dict[str, list[Any]] = {}
    for agg_name, agg_body in aggregations.items():
        if not (isinstance(agg_name, str) and agg_name.startswith("by_")):
            continue
        if not isinstance(agg_body, dict):
            continue
        buckets = agg_body.get("buckets")
        if not isinstance(buckets, list):
            continue
        keys = [b.get("key") for b in buckets if isinstance(b, dict) and b.get("key") is not None]
        if keys:
            field = agg_name[len("by_") :]
            rekey.setdefault(field, []).extend(keys)
            dotted = field.replace("_", ".")
            if dotted != field:
                rekey.setdefault(dotted, []).extend(keys)
        for b in buckets:
            if isinstance(b, dict):
                for sub_field, sub_vals in _rekey_oql_aggregations(b).items():
                    rekey.setdefault(sub_field, []).extend(sub_vals)
    return rekey


def _oracle_rekey_identifiers(tool_name: str | None, result: dict[str, Any]) -> dict[str, Any]:
    """Re-key a KNOWN oracle tool result's identifiers onto classifiable ECS paths.

    Returns ``{}`` for an unknown envelope — the field-coverage sets and shape
    rules still apply to it. The re-key only surfaces values ALREADY in *result*.
    """
    if tool_name == "t_field_values":
        field = result.get("field")
        values = result.get("values")
        if isinstance(field, str) and field and isinstance(values, list):
            vals = [
                v.get("value") for v in values if isinstance(v, dict) and v.get("value") is not None
            ]
            if vals:
                return _reroute_domain_singlelabel_to_host({field: vals})
        return {}
    if tool_name == "t_describe_dataset":
        rekey: dict[str, Any] = {}
        for f in result.get("fields") or []:
            if isinstance(f, dict) and isinstance(f.get("field"), str) and f["field"]:
                example = f.get("example")
                if example is not None:
                    rekey[f["field"]] = example
        return _reroute_domain_singlelabel_to_host(rekey)
    if tool_name == "t_host_dossier":
        return _rekey_host_dossier(result)
    if tool_name == "t_query_events_oql":
        return _reroute_domain_singlelabel_to_host(
            _rekey_oql_aggregations(result.get("aggregations"))
        )
    if tool_name == "t_get_rule_content":
        author = result.get("author")
        if isinstance(author, str) and author:
            # A custom-detection author is an internal analyst username; tokenise
            # as USER. Over-redacting a public author name (ET/Sigma) is a utility
            # cost, not a leak — safe side of the exact-egress bar.
            return {"user": {"name": author}}
        return {}
    return {}


class OracleToolGuard:
    """Reversible redaction tunnel bound to ONE adjudication's :class:`Mapping`.

    Duck-types the two methods ``register_read_tools``' ``_guarded`` wrapper
    calls — :meth:`desanitize_obj` for inbound tool arguments,
    :meth:`sanitize_obj` for outbound tool results. Two deltas from the analyst
    :class:`~soc_ai.agent.egress_guard.EgressGuard` (design §1):

    1. Results are sanitized FIELD-AWARE through :func:`sanitize_case` (not plain
       ``sanitize``): ``host.name: "filesrv"`` is internal by field role even
       when no shape rule could know it. Same parity the payload already carries;
       the tool-result path must not be the weaker one. It shares the
       adjudication mapping (labels stay stable across tools) and merges each
       result's ``no_propagate`` set into the one the wire gate reads.
    2. The desanitize direction REFUSES a hallucinated label rather than querying
       a literal placeholder (design §3) — the new risk of applying the map to
       model-controlled input.

    It is its OWN guard bound to its OWN mapping, deliberately NOT a shared
    ``ctx.egress_guard``: when the analyst model is also cloud there are two
    mappings alive at once.
    """

    def __init__(
        self,
        *,
        mapping: Mapping,
        extra_hosts: tuple[str, ...],
        extra_suffixes: tuple[str, ...],
        allowlist: tuple[str, ...],
        no_propagate: set[str],
    ) -> None:
        self._mapping = mapping
        self._extra_hosts = extra_hosts
        self._extra_suffixes = extra_suffixes
        self._allowlist = allowlist
        self._no_propagate = no_propagate
        # The effective internal-suffix tuple the backstop uses to recognise a
        # public FQDN/URL/email (an internal-suffixed one is masked, matching the
        # sanitizer). Resolved once — same source as ``sanitize_case``.
        self._resolved_suffixes = _resolve_suffixes(extra_suffixes)
        self.masked_count = 0
        """Running total of scalars the allow-known-safe backstop masked for this
        adjudication — the initial payload (via :meth:`_backstop`, called directly
        by the tool loop) plus every tool result this guard sanitized (design
        §"The wire gate is a blocklist"). Read into
        ``OracleResult.oracle_masked_values``."""

    def _backstop(self, sanitized: Any) -> Any:
        """Apply the allow-known-safe egress backstop to a sanitized result.

        The FINAL pass after ``sanitize_case``: mask any residual free-form scalar
        that could still be a bare internal identifier on a field neither the
        harvest nor the allowlist recognises — the shapeless class the wire gate
        cannot catch. Counts what it masks so the utility cost is observable.
        """
        masked, n = mask_unclassified_scalars(sanitized, suffixes=self._resolved_suffixes)
        self.masked_count += n
        return masked

    def desanitize_obj(self, obj: Any) -> Any:
        # Scan the MODEL'S emitted labels (before restoring) for tokens no case
        # allocated; refuse rather than run a query against a literal placeholder.
        unknown = find_unknown_oracle_labels(obj, self._mapping)
        if unknown:
            raise OracleUnknownLabelError(unknown)
        return desanitize(obj, self._mapping)

    def sanitize_obj(self, obj: Any, *, tool_name: str | None = None) -> Any:
        if isinstance(obj, dict):
            rekey = _oracle_rekey_identifiers(tool_name, obj)
            if rekey:
                # Splice a re-keyed VIEW of obj's own identifiers under a private
                # key so the Pass-1 harvest LEARNS them (they now sit on
                # classifiable ECS paths) and Pass-2 global-replace tokenises them
                # wherever they appear in the real result — under the generic keys
                # the harvest alone could not reach. Dropped after; never on the wire.
                wrapped = sanitize_case(
                    {_ORACLE_REKEY_KEY: rekey, **obj},
                    self._mapping,
                    allowlist=self._allowlist,
                    extra_hosts=self._extra_hosts,
                    extra_suffixes=self._extra_suffixes,
                    no_propagate_out=self._no_propagate,
                )
                wrapped.pop(_ORACLE_REKEY_KEY, None)
                # Allow-known-safe backstop: mask any residual UNrecognised
                # free-form scalar the harvest could not classify (design §"The
                # wire gate is a blocklist").
                return self._backstop(wrapped)
            return self._backstop(
                sanitize_case(
                    obj,
                    self._mapping,
                    allowlist=self._allowlist,
                    extra_hosts=self._extra_hosts,
                    extra_suffixes=self._extra_suffixes,
                    no_propagate_out=self._no_propagate,
                )
            )
        # A non-dict result (list / scalar) is wrapped so the field-aware harvest
        # still walks its inner key paths, then unwrapped.
        wrapped = sanitize_case(
            {"result": obj},
            self._mapping,
            allowlist=self._allowlist,
            extra_hosts=self._extra_hosts,
            extra_suffixes=self._extra_suffixes,
            no_propagate_out=self._no_propagate,
        )
        return self._backstop(wrapped["result"])


def _is_residue_error(exc: BaseException) -> bool:
    """Whether :class:`OracleResidueError` is anywhere in *exc*'s cause chain.

    The wire hook raises inside the httpx/openai/pydantic-ai stack, which may
    wrap it; walk ``__cause__`` / ``__context__`` so a wrapped residue refusal is
    still recognised as one (and never mis-filed as a generic gateway error).
    """
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        if isinstance(cur, OracleResidueError):
            return True
        seen.add(id(cur))
        cur = cur.__cause__ or cur.__context__
    return False


def _build_oracle_model(
    settings: Settings,
    hook: Callable[[Any], Awaitable[None]],
    *,
    transport: Any = None,
) -> tuple[Any, Any]:
    """Build the OpenAI-compatible model for the tool loop over an httpx client
    carrying the wire hook, plus the client (so the caller can close it).

    The hook is attached to the client's ``event_hooks`` so it fires on every
    request the loop composes. ``transport`` is a test seam (an
    ``httpx.MockTransport`` serving canned gateway responses); production leaves
    it ``None`` for the real transport. Split out from the loop so tests can
    substitute a pydantic-ai ``FunctionModel`` while production code still
    registers the real oracle tools on the agent.
    """
    import httpx  # noqa: PLC0415 — lazy; keep the single-shot hot path light
    from openai import AsyncOpenAI  # noqa: PLC0415
    from pydantic_ai.models.openai import OpenAIChatModel  # noqa: PLC0415
    from pydantic_ai.providers.openai import OpenAIProvider  # noqa: PLC0415

    api_key = settings.litellm_api_key.get_secret_value() if settings.litellm_api_key else "dummy"
    client_kwargs: dict[str, Any] = {
        "verify": settings.litellm_verify_ssl,
        "timeout": settings.oracle_timeout_s,
        "event_hooks": {"request": [hook]},
    }
    if transport is not None:
        client_kwargs["transport"] = transport
    http_client = httpx.AsyncClient(**client_kwargs)
    openai_client = AsyncOpenAI(
        base_url=str(settings.litellm_base_url).rstrip("/") + "/v1",
        api_key=api_key,
        http_client=http_client,
        max_retries=0,
    )
    model = OpenAIChatModel(
        settings.oracle_model, provider=OpenAIProvider(openai_client=openai_client)
    )
    return model, http_client


async def _adjudicate_with_tools(  # noqa: PLR0915 - one linear egress-gated pipeline
    ctx: InvestigationContext,
    *,
    enriched: Any,
    local_report: TriageReport,
    transcript_text: str,
    loop_messages: list[Any] | None,
    evidence_bullets: list[str] | None,
    extra_hosts: tuple[str, ...] | None,
    extra_suffixes: tuple[str, ...] | None,
    failure_out: dict[str, str] | None,
    http_transport: Any,
) -> OracleResult | None:
    """The tool-running Oracle: sanitize → bounded read-only loop → verdict.

    Shares ONE :class:`Mapping` across the initial payload, tool arguments, tool
    results, the wire gate and the final verdict. Returns ``None`` (local verdict
    retained) on residue refusal, budget/timeout exhaustion, or a parse/gateway
    failure — the same contract as the single-shot path.
    """
    settings = ctx.settings

    def _fail(reason: str) -> None:
        if failure_out is not None:
            failure_out["reason"] = reason

    # 1. Assemble + sanitize the initial payload under the shared mapping.
    case_dict = _assemble_case_dict(
        enriched=enriched,
        local_report=local_report,
        transcript_text=transcript_text,
        tool_results=_extract_tool_results(loop_messages),
        evidence_bullets=evidence_bullets,
    )
    mapping = Mapping()
    allowlist: tuple[str, ...] = ()
    resolved_hosts: tuple[str, ...] = (
        extra_hosts if extra_hosts is not None else tuple(settings.oracle_extra_hosts)
    )
    resolved_suffixes: tuple[str, ...] = (
        extra_suffixes if extra_suffixes is not None else tuple(settings.oracle_internal_suffixes)
    )
    _warn_if_privacy_gate_unconfigured(
        settings, effective_hosts=resolved_hosts, effective_suffixes=resolved_suffixes
    )
    no_propagate: set[str] = set()

    # The shared guard is built BEFORE the initial sanitize so the SAME
    # allow-known-safe backstop — the same policy, resolved suffixes and masked-
    # count accumulator it runs over every tool result — also covers the INITIAL
    # payload. The initial body ALWAYS egresses, so this is the more important
    # half of the boundary: without it a bare internal name on a field neither the
    # field-aware harvest nor the wire residue gate can catch (shapeless, not yet
    # a known value) would ride the first outbound body raw. ``no_propagate`` is
    # held by reference, so the mutation the sanitize below performs is still seen.
    guard = OracleToolGuard(
        mapping=mapping,
        extra_hosts=resolved_hosts,
        extra_suffixes=resolved_suffixes,
        allowlist=allowlist,
        no_propagate=no_propagate,
    )
    sanitized_case = sanitize_case(
        case_dict,
        mapping,
        allowlist=allowlist,
        extra_hosts=resolved_hosts,
        extra_suffixes=resolved_suffixes,
        no_propagate_out=no_propagate,
    )
    # Allow-known-safe backstop over the initial payload — the FINAL pass after
    # sanitize_case, identical to OracleToolGuard.sanitize_obj's tool-result pass:
    # mask any residual free-form scalar the harvest could not classify. The
    # count folds into guard.masked_count so oracle_masked_values reports the FULL
    # utility cost (initial payload + tool results), not just the tool-result half.
    sanitized_case = guard._backstop(sanitized_case)
    try:
        payload_text = json.dumps(sanitized_case)
    except (TypeError, ValueError) as exc:
        _LOGGER.error(
            "oracle.client: payload serialization failed (non-JSON type): %s",
            type(exc).__name__,
        )
        _fail("payload_serialization")
        return None

    # Demo mode blocks the oracle egress outright — a tool-running Oracle gets no
    # egress because it gets no Oracle at all.
    try:
        assert_egress_allowed(settings, "oracle")
    except Exception:
        _LOGGER.info("oracle.client: egress not allowed for the tool loop; local verdict retained")
        _fail("egress_blocked")
        return None

    # 2. The single wire-level residue choke point (the shared guard is built
    # above, before the initial sanitize).
    hook = _make_residue_hook(
        mapping,
        allowlist=allowlist,
        extra_hosts=resolved_hosts,
        extra_suffixes=resolved_suffixes,
        no_propagate=no_propagate,
    )

    # Lazy agent-layer imports: soc_ai.agent.__init__ imports the orchestrator,
    # which imports THIS module, so importing agent submodules at module load
    # would risk a cycle. Deferring to call time sidesteps it entirely.
    import dataclasses  # noqa: PLC0415

    from pydantic_ai import Agent  # noqa: PLC0415
    from pydantic_ai.usage import UsageLimits  # noqa: PLC0415

    from soc_ai.agent.context import _DedupTracker  # noqa: PLC0415
    from soc_ai.agent.evidence import count_successful_tool_calls  # noqa: PLC0415
    from soc_ai.agent.toolset import register_read_tools  # noqa: PLC0415

    # 3. A child context: same elastic/auth/settings/include_synth/time-anchor as
    # the investigation, FRESH dedup, and the oracle guard (so register_read_tools'
    # _guarded wraps every tool with this adjudication's mapping). The guard is
    # not an EgressGuard subclass — it duck-types the two methods _guarded calls —
    # so the assignment is cast (runtime uses only those two methods).
    oracle_ctx = dataclasses.replace(
        ctx,
        egress_guard=cast("EgressGuard", guard),
        dedup=_DedupTracker(),
    )

    model, http_client = _build_oracle_model(settings, hook, transport=http_transport)
    try:
        agent: Agent[None, str] = Agent(model, system_prompt=ORACLE_TOOL_SYSTEM_PROMPT, retries=3)
        register_read_tools(agent, oracle_ctx, role="oracle")

        raw_text: str | None = None
        result_messages: list[Any] = []
        try:
            async with asyncio.timeout(settings.oracle_adjudication_timeout_s):
                run = await agent.run(
                    payload_text,
                    usage_limits=UsageLimits(
                        request_limit=settings.oracle_request_limit,
                        tool_calls_limit=settings.oracle_tool_calls_limit,
                    ),
                )
            raw_text = run.output
            result_messages = run.all_messages()
        except asyncio.CancelledError:
            raise
        except BaseException as exc:
            if _is_residue_error(exc):
                # The one unacceptable outcome, caught at the wire: refuse the
                # whole adjudication, keep the local verdict, count the refusal.
                categories = getattr(exc, "categories", None) or _residue_categories(exc)
                _LOGGER.error(
                    "oracle.client: REFUSE — residue at the wire gate (categories: %s); "
                    "local verdict retained",
                    categories,
                )
                await metrics.get_metrics().record_oracle_refusal()
                _fail("residue_refusal")
                return None
            _LOGGER.warning(
                "oracle.client: tool loop failed (%s: %s); local verdict retained",
                type(exc).__name__,
                exc,
            )
            _fail("tool_loop_error")
            return None
    finally:
        try:
            await http_client.aclose()
        except Exception:  # never let client teardown mask the verdict
            _LOGGER.debug("oracle.client: http client close failed", exc_info=True)

    raw_verdict = _parse_oracle_verdict(raw_text) if raw_text is not None else None
    if raw_verdict is None:
        _LOGGER.warning("oracle.client: tool loop produced no parseable verdict; local retained")
        _fail("no_parseable_verdict")
        return None

    # 4. Count the loop's successful (evidence-bearing) tool calls — the override
    # gate's input — and desanitize the verdict text for local display.
    successful_tool_calls = count_successful_tool_calls(result_messages)
    rehydrated_summary = str(desanitize(raw_verdict.summary, mapping))
    rehydrated_reasoning = str(desanitize(raw_verdict.reasoning, mapping))
    desanitized_verdict = OracleVerdict(
        verdict=raw_verdict.verdict,
        confidence=raw_verdict.confidence,
        summary=rehydrated_summary,
        reasoning=rehydrated_reasoning,
    )

    # 5. Override gate at the _verdict_to_report seam (design §6): an unbacked
    # class-changing verdict does NOT override; a zero-tool agreement still lands.
    same_verdict = desanitized_verdict.verdict == local_report.verdict
    override_withheld = (not same_verdict) and successful_tool_calls < 1
    desanitized_report = _verdict_to_report(
        desanitized_verdict,
        local_report=local_report,
        oracle_tool_calls=successful_tool_calls,
        gate_active=True,
    )

    if guard.masked_count:
        _LOGGER.info(
            "oracle.client: allow-known-safe backstop masked %d unclassified "
            "scalar(s) across this adjudication (initial payload + tool results)",
            guard.masked_count,
        )

    return OracleResult(
        report=desanitized_report,
        redaction_summary=redaction_summary(mapping),
        oracle_model=settings.oracle_model,
        oracle_tool_calls=successful_tool_calls,
        override_withheld=override_withheld,
        raw_oracle_verdict=desanitized_verdict.verdict,
        oracle_masked_values=guard.masked_count,
    )


def _residue_categories(exc: BaseException) -> list[str]:
    """Recover the leak categories from a wrapped :class:`OracleResidueError`."""
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        if isinstance(cur, OracleResidueError):
            return cur.categories
        seen.add(id(cur))
        cur = cur.__cause__ or cur.__context__
    return []


async def adjudicate(  # noqa: PLR0915 - one linear pipeline; splitting hides the egress-gate order
    ctx: InvestigationContext,
    *,
    enriched: Any,
    local_report: TriageReport,
    transcript_text: str,
    loop_messages: list[Any] | None = None,
    evidence_bullets: list[str] | None = None,
    extra_hosts: tuple[str, ...] | None = None,
    extra_suffixes: tuple[str, ...] | None = None,
    failure_out: dict[str, str] | None = None,
    _http_transport: Any = None,
) -> OracleResult | None:
    """Send a sanitized case to the frontier Oracle for adjudication.

    Args:
        ctx: :class:`~soc_ai.agent.orchestrator.InvestigationContext` — used
            to access ``ctx.settings`` (type-only import; the runtime
            dependency flows orchestrator → oracle, never back).
        enriched: :class:`~soc_ai.tools.get_alert_context.EnrichedAlertContext`
            — the full prefetched + enriched alert context.
        local_report: The local :class:`~soc_ai.triage_models.TriageReport` from
            the investigation loop.  Its text fields (summary/citations) are
            included in the payload so the Oracle has the local reasoning.
        transcript_text: Raw text transcript from the investigation loop
            (e.g. the concatenated evidence bullets or the serialized
            ``InvestigationTranscript``).  Pass ``""`` when no loop ran.
        loop_messages: The pydantic-ai message history from the investigation
            loop, when one ran.  The dict-shaped TOOL RESULTS in it — the
            backing data the local verdict actually rests on — are extracted
            (:func:`_extract_tool_results`, bounded) into the payload's
            ``loop_tool_results`` field.  Without them the Oracle sees only the
            investigator's prose assertions and rationally distrusts them (the
            b3-rmm-admin-lateral finding).  The extraction happens BEFORE
            ``sanitize_case``, so the results go through the same sanitize →
            residue-sweep gate as every other field.
        evidence_bullets: The investigator's ``InvestigationTranscript.evidence``
            bullets (claim → supporting-id index), when the loop completed.
            Included bounded as ``loop_evidence_bullets``.
        extra_hosts: The resolved *effective* internal bare-hostname tuple
            (env-config ``oracle_extra_hosts`` unioned with active
            detected/manual ``host`` identifiers, minus muted), computed by the
            caller via
            :func:`~soc_ai.oracle.identifiers.effective_internal_identifiers`.
            ``None`` ⇒ the caller had no DB session; fall back to the raw
            ``settings.oracle_extra_hosts`` tuple so behavior is unchanged.
        extra_suffixes: The resolved *effective* internal-suffix tuple
            (env-config ``oracle_internal_suffixes`` unioned with active
            detected/manual ``suffix`` identifiers, minus muted). ``None`` ⇒
            fall back to the raw ``settings.oracle_internal_suffixes`` tuple.
        failure_out: Optional out-param (the ``no_propagate_out`` precedent —
            the ``None`` return contract stays untouched). On a ``None``
            return, ``failure_out["reason"]`` names which failure class it
            was: ``payload_serialization``, ``residue_refusal``,
            ``gateway_error``, or ``no_parseable_verdict``. The orchestrator
            surfaces it in the ``oracle_adjudication_failed`` event so a
            failed second opinion is distinguishable from one that never
            happened.

    Returns:
        An :class:`OracleResult` on success; ``None`` on refusal (residue
        detected) or any exception (timeout, gateway error, parse failure).
        The caller MUST keep the local verdict when ``None`` is returned.
    """
    settings: Settings = ctx.settings

    # Tool-loop opt-in (design 2026-08-27): an adjudicator that doubts a claim
    # runs the read-only oracle tool surface between sanitize and verdict. Off by
    # default, so the single-shot pipeline below is byte-for-byte unchanged until
    # the owner flips ``oracle_tools_enabled``.
    if settings.oracle_tools_enabled:
        return await _adjudicate_with_tools(
            ctx,
            enriched=enriched,
            local_report=local_report,
            transcript_text=transcript_text,
            loop_messages=loop_messages,
            evidence_bullets=evidence_bullets,
            extra_hosts=extra_hosts,
            extra_suffixes=extra_suffixes,
            failure_out=failure_out,
            http_transport=_http_transport,
        )

    def _fail(reason: str) -> None:
        if failure_out is not None:
            failure_out["reason"] = reason

    # 1. Assemble the raw case dict — INCLUDING the loop's tool results and
    # evidence bullets, so everything below (sanitize_case + the independent
    # residue sweep) covers them.  Never add payload content after this point.
    case_dict = _assemble_case_dict(
        enriched=enriched,
        local_report=local_report,
        transcript_text=transcript_text,
        tool_results=_extract_tool_results(loop_messages),
        evidence_bullets=evidence_bullets,
    )

    # 2. Sanitize — replace internal identifiers with opaque labels.
    mapping = Mapping()
    # The allowlist is empty by default (no settings field for it yet — the
    # operator can add one later).  extra_hosts lists bare internal hostnames
    # (DESKTOP-AB12, FINANCE-PC) that are not FQDNs and would otherwise egress
    # verbatim; extra_suffixes lists internal DNS suffixes
    # (dc01.ad.example.com → suffix .ad.example.com) that the shape rules cannot
    # otherwise know are internal.
    #
    # Both are the *effective* sets resolved by the caller (orchestrator) from
    # the internal_identifier table: env-config (settings.oracle_extra_hosts /
    # oracle_internal_suffixes) unioned with active detected/manual identifiers,
    # minus muted (see soc_ai.oracle.identifiers.effective_internal_identifiers).
    # DB access stays in the caller — this function remains pure. When the caller
    # has no DB session (CLI / eval / tests), it passes None and we fall back to
    # the raw settings tuples, so behavior is unchanged for an empty/absent table.
    #
    # Thread the SAME params into both sanitize_case() and unsafe_residue() below —
    # a mismatch would create a gap where residue passes the check but sanitize
    # didn't cover it (the invariant: both calls receive identical extra_hosts /
    # extra_suffixes / allowlist).
    allowlist: tuple[str, ...] = ()
    resolved_hosts: tuple[str, ...] = (
        extra_hosts if extra_hosts is not None else tuple(settings.oracle_extra_hosts)
    )
    resolved_suffixes: tuple[str, ...] = (
        extra_suffixes if extra_suffixes is not None else tuple(settings.oracle_internal_suffixes)
    )

    # Operator-awareness: warn once if the privacy gate is unconfigured.  Pass the
    # resolved *effective* sets (which already include any DB-configured internal
    # names) so a DB-only deployment with an empty .env does not false-alarm.
    _warn_if_privacy_gate_unconfigured(
        settings,
        effective_hosts=resolved_hosts,
        effective_suffixes=resolved_suffixes,
    )

    # ``no_propagate`` collects the short (≤3 char) DOMAIN_LIKE values the
    # sanitizer intentionally did NOT globally propagate (they would corrupt
    # public FQDNs).  They must be excluded from the residue gate's known_values
    # below — otherwise the gate flags the same substring inside a legitimate
    # public FQDN and refuses by construction (finding oracle-refuse-by-design).
    no_propagate: set[str] = set()
    sanitized_case = sanitize_case(
        case_dict,
        mapping,
        allowlist=allowlist,
        extra_hosts=resolved_hosts,
        extra_suffixes=resolved_suffixes,
        no_propagate_out=no_propagate,
    )

    # 3. Serialize to the ACTUAL outbound bytes.
    # Plain json.dumps — it raises TypeError on non-JSON-serialisable types,
    # which is exactly what we want: fail closed rather than silently drop data.
    try:
        payload_text = json.dumps(sanitized_case)
    except (TypeError, ValueError) as exc:
        _LOGGER.error(
            "oracle.client: payload serialization failed (non-JSON type in case dict): %s",
            type(exc).__name__,
        )
        _fail("payload_serialization")
        return None

    # 4. GUARDRAIL — independent residue sweep on the actual outbound bytes.
    # Must use IDENTICAL params as sanitize_case() so the two paths cover the
    # same identifier space.  Pass known_values so any bare hostname/username
    # learned during the harvest pass is also checked verbatim.  Any leaks → REFUSE.
    leaks = unsafe_residue(
        payload_text,
        allowlist=allowlist,
        extra_hosts=resolved_hosts,
        extra_suffixes=resolved_suffixes,
        # Exclude the no_propagate values (short DOMAIN_LIKE labels the sanitizer
        # intentionally left un-propagated to protect public FQDNs) — see above.
        known_values=tuple(v for v in mapping.reverse.values() if v not in no_propagate),
        # payload_text is json.dumps output — every real backslash is doubled, so
        # a lone single backslash is a JSON escape (``\n``), not a NetBIOS
        # separator.  WIRE mode rejects that multi-line-transcript false positive.
        wire_escaped=True,
    )
    if leaks:
        # Log categories only — never log the actual leaked values.
        categories = sorted({leak.split(":")[0].strip() for leak in leaks})
        _LOGGER.error(
            "oracle.client: REFUSE — residue detected in outbound payload "
            "(categories: %s); local verdict retained",
            categories,
        )
        # Count it so a silently-disabled Oracle (a gate refusing every real
        # transcript) is visible on the next /metrics scrape, not just in the log.
        await metrics.get_metrics().record_oracle_refusal()
        _fail("residue_refusal")
        return None

    # 5. Call the frontier model via the LiteLLM gateway (raw async httpx).
    #
    # WHY raw httpx instead of pydantic-ai Agent(output_type=TriageReport):
    # The strict pydantic-ai structured-output path exhausts its retry budget
    # (UnexpectedModelBehavior) because the oracle (via LiteLLM) does not reliably
    # produce output that passes TriageReport's nested-object validation
    # (recommended_actions list of objects, gap_for_investigator nested model).
    # The eval oracle (soc_ai.eval.oracle_client) has the proven pattern: raw
    # httpx POST + tolerant JSON extraction.  We mirror it here with async.
    raw_verdict: OracleVerdict | None = None
    last_exc: str = ""
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            raw_text = await _call_oracle_raw(payload_text, settings=settings)
        except _OracleGatewayError as exc:
            last_exc = f"{type(exc).__name__}: {exc}"
            if not exc.retryable:
                # 4xx — auth/bad-request won't fix on retry; fail fast, keep local.
                _LOGGER.error(
                    "oracle.client: non-retryable gateway error (%s); local verdict retained",
                    last_exc,
                )
                _fail("gateway_error")
                return None
            _LOGGER.warning(
                "oracle.client: gateway attempt %d/%d failed (%s); %s",
                attempt,
                _MAX_RETRIES,
                last_exc,
                "retrying" if attempt < _MAX_RETRIES else "giving up",
            )
            if attempt < _MAX_RETRIES:
                await asyncio.sleep(_backoff_s(attempt))
            continue
        except Exception as exc:
            last_exc = f"{type(exc).__name__}: {exc}"
            _LOGGER.warning(
                "oracle.client: gateway attempt %d/%d failed (%s); %s",
                attempt,
                _MAX_RETRIES,
                last_exc,
                "retrying" if attempt < _MAX_RETRIES else "giving up",
            )
            if attempt < _MAX_RETRIES:
                await asyncio.sleep(_backoff_s(attempt))
            continue

        raw_verdict = _parse_oracle_verdict(raw_text)
        if raw_verdict is not None:
            break
        _LOGGER.warning(
            "oracle.client: attempt %d/%d — could not parse verdict from response; %s",
            attempt,
            _MAX_RETRIES,
            "retrying" if attempt < _MAX_RETRIES else "giving up",
        )
        if attempt < _MAX_RETRIES:
            await asyncio.sleep(_backoff_s(attempt))

    if raw_verdict is None:
        _LOGGER.error(
            "oracle.client: all %d attempts failed to produce a parseable verdict "
            "(%s); local verdict retained",
            _MAX_RETRIES,
            last_exc or "unparseable response",
        )
        # Retryable gateway failures land here too (the loop gave up), so the
        # recorded class is "no parseable verdict came back", whatever mixed
        # the attempts were. The log above has the per-attempt detail.
        _fail("no_parseable_verdict")
        return None

    # 6. Desanitize the verdict's text fields back to real identifiers.
    # desanitize() walks str / dict / list / tuple recursively.
    rehydrated_summary = str(desanitize(raw_verdict.summary, mapping))
    rehydrated_reasoning = str(desanitize(raw_verdict.reasoning, mapping))

    desanitized_verdict = OracleVerdict(
        verdict=raw_verdict.verdict,
        confidence=raw_verdict.confidence,
        summary=rehydrated_summary,
        reasoning=rehydrated_reasoning,
    )

    # 7. Map OracleVerdict → TriageReport for the orchestrator, carrying the
    # local report's earned evidence fields forward (see _verdict_to_report).
    desanitized_report = _verdict_to_report(desanitized_verdict, local_report=local_report)

    return OracleResult(
        report=desanitized_report,
        redaction_summary=redaction_summary(mapping),
        oracle_model=settings.oracle_model,
        # Single-shot path: no tool loop, so the override gate is inactive and a
        # flip lands as it always has. Record the raw verdict for event parity
        # with the tool-loop path.
        oracle_tool_calls=0,
        override_withheld=False,
        raw_oracle_verdict=desanitized_verdict.verdict,
    )


__all__ = [
    "ORACLE_SYSTEM_PROMPT",
    "ORACLE_TOOL_SYSTEM_PROMPT",
    "OracleResidueError",
    "OracleResult",
    "OracleToolGuard",
    "OracleVerdict",
    "adjudicate",
]
