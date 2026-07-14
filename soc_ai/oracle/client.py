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
   confidence / summary from the oracle; citations / recommended_actions empty;
   field_reconciliation / gap_for_investigator null.
8. Return an :class:`OracleResult`.  Any exception (timeout, parse, gateway
   error) → log + return ``None`` so the caller keeps the local verdict.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel

from soc_ai.config import Settings
from soc_ai.demo.guard import assert_egress_allowed
from soc_ai.oracle.redact import Mapping, sanitize_case
from soc_ai.oracle.sanitize import (
    desanitize,
    redaction_summary,
    unsafe_residue,
)
from soc_ai.triage_models import TriageReport

if TYPE_CHECKING:
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
    confidence: float
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


def _verdict_to_report(verdict: OracleVerdict) -> TriageReport:
    """Map a minimal ``OracleVerdict`` → full ``TriageReport``.

    Fields not produced by the Oracle (citations, recommended_actions,
    field_reconciliation, gap_for_investigator) are left at their defaults
    (empty list / None).  The reasoning text is prepended to the summary so
    it is visible in the analyst-facing output.
    """
    combined_summary = verdict.summary
    if verdict.reasoning and verdict.reasoning.strip():
        combined_summary = f"{verdict.summary}\n\nOracle reasoning: {verdict.reasoning}"
    return TriageReport(
        verdict=verdict.verdict,
        confidence=max(0.0, min(1.0, verdict.confidence)),
        summary=combined_summary,
        citations=[],
        recommended_actions=[],
        field_reconciliation=None,
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


def _assemble_case_dict(
    *,
    enriched: Any,
    local_report: TriageReport,
    transcript_text: str,
) -> dict[str, Any]:
    """Assemble the case payload from enriched context + local verdict + transcript.

    The dict is deliberately compact: a single JSON.dumps of this is what the
    residue check runs over, so every unnecessary field is a liability.
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
        "loop_evidence": transcript_text or "",
        "local_verdict": local_report.verdict,
        "local_confidence": local_report.confidence,
        "local_summary": local_report.summary,
        "local_citations": local_report.citations,
    }


async def adjudicate(
    ctx: InvestigationContext,
    *,
    enriched: Any,
    local_report: TriageReport,
    transcript_text: str,
    extra_hosts: tuple[str, ...] | None = None,
    extra_suffixes: tuple[str, ...] | None = None,
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

    Returns:
        An :class:`OracleResult` on success; ``None`` on refusal (residue
        detected) or any exception (timeout, gateway error, parse failure).
        The caller MUST keep the local verdict when ``None`` is returned.
    """
    settings: Settings = ctx.settings

    # 1. Assemble the raw case dict.
    case_dict = _assemble_case_dict(
        enriched=enriched,
        local_report=local_report,
        transcript_text=transcript_text,
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

    sanitized_case = sanitize_case(
        case_dict,
        mapping,
        allowlist=allowlist,
        extra_hosts=resolved_hosts,
        extra_suffixes=resolved_suffixes,
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
        known_values=tuple(mapping.reverse.values()),
    )
    if leaks:
        # Log categories only — never log the actual leaked values.
        categories = sorted({leak.split(":")[0].strip() for leak in leaks})
        _LOGGER.error(
            "oracle.client: REFUSE — residue detected in outbound payload "
            "(categories: %s); local verdict retained",
            categories,
        )
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

    # 7. Map OracleVerdict → TriageReport for the orchestrator.
    desanitized_report = _verdict_to_report(desanitized_verdict)

    return OracleResult(
        report=desanitized_report,
        redaction_summary=redaction_summary(mapping),
        oracle_model=settings.oracle_model,
    )


__all__ = [
    "ORACLE_SYSTEM_PROMPT",
    "OracleResult",
    "OracleVerdict",
    "adjudicate",
]
