"""Opt-in outbound notification webhook (the ONLY new outbound egress path).

On-call gets pinged when a high-confidence true-positive lands, a hunt turns up a
threat finding, or the analyst model grades UNFIT. Everything else in soc-ai is
zero-egress; this feature is the one exception, so it is treated like the Oracle:

    * DEFAULT OFF. :func:`fire` returns BEFORE constructing any HTTP client unless
      ``notify_enabled`` is on, the relevant per-trigger toggle is on, and a
      ``notify_webhook_url`` is configured. When off, NO ``httpx`` call is ever
      made — proven by ``tests/test_notify.py``.
    * The webhook URL is a SECRET (``SecretStr``; Fernet-encrypted at rest, never
      rendered back through the config console).
    * Every attempted send is AUDITED (``"notification"`` audit kind), best-effort
      — an audit failure never breaks the send, and a webhook failure never breaks
      the investigation/hunt that triggered it (fail-soft, log + swallow).

The payload shape is selected by ``notify_format``:

    * ``json``   — a compact generic dict ``{kind,title,body,url,severity}``.
    * ``slack``  — ``{"text": "<title> — <body> <url>"}``.
    * ``matrix`` — ``{"msgtype":"m.text","body":"<title> — <body> <url>"}``.

Sends are deduped in-process by ``(kind, entity, current-hour)`` so a re-fired
trigger inside the same hour posts once. The dedup is a bounded best-effort LRU —
not durable across a restart (that is acceptable: a missed dedup at most double-
pings on-call once).
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

_LOGGER = logging.getLogger(__name__)

# Valid ``notify_format`` values (kept here so config.py + the route + tests share
# one source of truth).
NOTIFY_FORMATS: tuple[str, ...] = ("json", "slack", "matrix")

# Trigger kinds a NotifyEvent may carry. ``test`` is the canned validation event
# fired by the Test button — it bypasses the per-trigger toggles (below) but still
# requires a configured webhook URL.
NOTIFY_KINDS: tuple[str, ...] = ("tp", "hunt_threat", "model_fitness_fail", "test")

# Per-send bound. Short: a webhook is fire-and-forget on-call plumbing, not on the
# investigation's critical path — a slow endpoint must not stall the trigger.
_SEND_TIMEOUT_S = 5.0
# Retries AFTER the first attempt (so 2 = up to 3 total). Only transient failures
# (connect/read/5xx) are retried; a 4xx is terminal (misconfigured webhook).
_MAX_RETRIES = 2
_RETRY_BACKOFF_S = 0.5

# In-process dedup ring. Bounded so a long-running process can't leak memory: an
# OrderedDict used as an LRU set (value is unused). Best-effort only.
_DEDUP_MAX = 512
_dedup_seen: OrderedDict[str, None] = OrderedDict()


@dataclass
class NotifyEvent:
    """One thing worth pinging on-call about.

    ``kind`` is one of :data:`NOTIFY_KINDS`. ``url`` is a permalink into the app
    (e.g. ``/app/investigation/<id>``) so the recipient can jump straight to it.
    ``severity`` is advisory (``info``/``warning``/``critical``) — it rides in the
    generic-JSON payload but is not otherwise load-bearing.
    """

    kind: str
    title: str
    body: str
    url: str
    severity: str = "info"


def _entity_key(event: NotifyEvent) -> str:
    """A stable per-entity dedup key for an event.

    The permalink URL uniquely identifies the entity (an investigation id, a hunt
    id) for the tp / hunt_threat kinds; model-fitness has no permalink entity, so
    its title (which names the model + grade) is the stable key. Falls back to the
    title when the URL is empty.
    """
    return event.url.strip() or event.title.strip()


def _dedup_should_send(event: NotifyEvent, *, now: datetime | None = None) -> bool:
    """True iff this (kind, entity, hour) hasn't been sent this hour.

    Records the key when it returns True. Best-effort + bounded (an LRU set): a
    process restart clears it, so at most one duplicate ping can slip through per
    restart. Never raises.
    """
    now = now or datetime.now(UTC)
    hour = now.strftime("%Y%m%dT%H")
    key = f"{event.kind}:{_entity_key(event)}:{hour}"
    if key in _dedup_seen:
        # Refresh recency so a repeatedly-fired key stays warm in the LRU.
        _dedup_seen.move_to_end(key)
        return False
    _dedup_seen[key] = None
    while len(_dedup_seen) > _DEDUP_MAX:
        _dedup_seen.popitem(last=False)
    return True


def _build_payload(event: NotifyEvent, fmt: str) -> dict[str, Any]:
    """Render *event* into the wire body for *fmt*.

    ``slack``/``matrix`` collapse to a single human line; ``json`` (and any
    unknown format, defensively) is the generic structured dict.
    """
    line = f"{event.title} — {event.body}"
    if event.url:
        line = f"{line} {event.url}"
    if fmt == "slack":
        return {"text": line}
    if fmt == "matrix":
        return {"msgtype": "m.text", "body": line}
    # json (default) — a compact structured dict.
    return {
        "kind": event.kind,
        "title": event.title,
        "body": event.body,
        "url": event.url,
        "severity": event.severity,
    }


def _webhook_url(settings: Any) -> str:
    """The configured webhook URL as a plain string, or '' when unset.

    ``notify_webhook_url`` is a ``SecretStr | None``; unwrap it. Never logged.
    """
    secret = getattr(settings, "notify_webhook_url", None)
    if secret is None:
        return ""
    try:
        return str(secret.get_secret_value()).strip()
    except AttributeError:
        # A test double may hand us a bare string.
        return str(secret).strip()


def _trigger_enabled(settings: Any, kind: str) -> bool:
    """Whether the per-trigger toggle for *kind* is on.

    The ``test`` kind bypasses the per-trigger toggles (it's an explicit operator
    validation, gated only on enabled+url by the caller). All others map to their
    ``notify_on_*`` flag; an unknown kind is refused (no toggle → no send).
    """
    if kind == "test":
        return True
    flag = {
        "tp": "notify_on_tp",
        "hunt_threat": "notify_on_hunt_threat",
        "model_fitness_fail": "notify_on_model_fitness_fail",
    }.get(kind)
    if flag is None:
        return False
    return bool(getattr(settings, flag, False))


async def _post_with_retries(url: str, payload: dict[str, Any], *, verify: bool) -> int:
    """POST *payload* to *url* with a short timeout + bounded transient retries.

    Returns the final HTTP status code. Raises on a transport error that outlives
    the retry budget (the caller swallows it). A 4xx is terminal (returned as-is);
    a 5xx is retried up to :data:`_MAX_RETRIES`.
    """
    import asyncio  # noqa: PLC0415 - local; keeps module import cheap

    attempt = 0
    async with httpx.AsyncClient(timeout=_SEND_TIMEOUT_S, verify=verify) as client:
        while True:
            resp = await client.post(url, json=payload)
            if resp.status_code < 500 or attempt >= _MAX_RETRIES:
                return resp.status_code
            attempt += 1
            await asyncio.sleep(_RETRY_BACKOFF_S * attempt)


async def fire(event: NotifyEvent, settings: Any, audit: Any = None) -> None:
    """Send *event* to the configured webhook — fail-soft, zero-egress when off.

    THE ZERO-EGRESS GUARANTEE: this returns BEFORE constructing any ``httpx``
    client unless ALL of these hold:

        * ``settings.notify_enabled`` is True (the master switch), AND
        * the per-trigger toggle for ``event.kind`` is on (``test`` bypasses this),
          AND
        * ``settings.notify_webhook_url`` is set.

    When any is false, NO network I/O happens (no client is built) and the
    function returns immediately. A duplicate within the same hour is also a
    no-op (dedup), with no egress.

    Every ATTEMPTED send (one that passes the gates + dedup) is audited under the
    ``"notification"`` kind, best-effort — an audit failure is logged and
    swallowed. A webhook failure (timeout, 5xx after retries, transport error) is
    logged and swallowed too: a webhook must NEVER break the investigation or hunt
    that fired it.
    """
    if not bool(getattr(settings, "notify_enabled", False)):
        return  # master switch off → zero egress
    if not _trigger_enabled(settings, event.kind):
        return  # per-trigger toggle off (or unknown kind) → zero egress
    url = _webhook_url(settings)
    if not url:
        return  # no destination → zero egress
    if not _dedup_should_send(event):
        return  # already pinged this (kind, entity) this hour → zero egress

    fmt = str(getattr(settings, "notify_format", "json") or "json").lower()
    if fmt not in NOTIFY_FORMATS:
        fmt = "json"
    payload = _build_payload(event, fmt)
    verify = bool(getattr(settings, "notify_verify_ssl", True))

    status: int | None = None
    error: str | None = None
    try:
        status = await _post_with_retries(url, payload, verify=verify)
    except Exception as exc:  # a webhook failure must never break the caller
        error = type(exc).__name__
        _LOGGER.warning("notification webhook send failed: %s", error)

    # Audit EVERY attempted send (success or failure), best-effort. The URL is a
    # secret — it is NEVER placed in the audit payload; only the format + outcome.
    if audit is not None:
        try:
            await audit.log_kind(
                session_id=f"notify:{event.kind}",
                kind="notification",
                payload={
                    "notify_kind": event.kind,
                    "format": fmt,
                    "severity": event.severity,
                    "ok": error is None and status is not None and status < 400,
                    "status": status,
                    "error": error,
                },
            )
        except Exception:  # audit is best-effort — never break a send on it
            _LOGGER.warning("notification audit write failed (continuing)", exc_info=True)


async def fire_safe(event: NotifyEvent, settings: Any, audit: Any = None) -> None:
    """:func:`fire`, wrapped so it can NEVER raise into the primary flow.

    The trigger sites (investigation finalize, hunt finalize, model-fitness) call
    THIS from inside the recorded-run/probe path. ``fire`` is already fail-soft on
    webhook + audit errors, but this belt-and-suspenders wrapper also swallows a
    misconfiguration bug (a bad settings double, a programming error building the
    event) so a webhook can never break an investigation or hunt.
    """
    try:
        await fire(event, settings, audit)
    except Exception:  # a notification must NEVER break the primary flow
        _LOGGER.warning("notify.fire_safe swallowed an unexpected error", exc_info=True)


def event_for_investigation(
    *, investigation_id: str, report: dict[str, Any], settings: Any
) -> NotifyEvent | None:
    """Build a TP NotifyEvent from a finalized investigation report, or None.

    Returns None (no notification) unless the verdict is ``true_positive`` AND the
    confidence is at/above ``notify_tp_confidence_threshold`` AND ``notify_on_tp``
    is on. Pure + side-effect-free — the caller decides whether to fire. The body
    carries the verdict/confidence + a short summary; the permalink is
    ``/app/investigation/<id>``.
    """
    if not bool(getattr(settings, "notify_on_tp", False)):
        return None
    if str(report.get("verdict") or "") != "true_positive":
        return None
    try:
        confidence = float(report.get("confidence") or 0.0)
    except (TypeError, ValueError):
        return None
    threshold = float(getattr(settings, "notify_tp_confidence_threshold", 0.9))
    if confidence < threshold:
        return None
    summary = str(report.get("summary") or "").strip()
    body = f"Confidence {confidence:.2f}. {summary}".strip()
    return NotifyEvent(
        kind="tp",
        title="High-confidence true positive",
        body=body[:500],
        url=f"/app/investigation/{investigation_id}",
        severity="critical",
    )


def event_for_hunt(*, hunt_id: str, report: dict[str, Any], settings: Any) -> NotifyEvent | None:
    """Build a hunt-threat NotifyEvent from a finalized hunt report, or None.

    Returns None unless ``notify_on_hunt_threat`` is on AND the report has at least
    one finding with ``category == 'threat'``. The body names the threat count +
    the worst finding's title; the permalink is ``/app/hunts/<id>``.
    """
    if not bool(getattr(settings, "notify_on_hunt_threat", False)):
        return None
    findings = report.get("findings")
    if not isinstance(findings, list):
        return None
    threats = [
        f for f in findings if isinstance(f, dict) and str(f.get("category") or "") == "threat"
    ]
    if not threats:
        return None
    lead = str(threats[0].get("title") or "").strip()
    n = len(threats)
    body = f"{n} threat finding{'s' if n != 1 else ''}. {lead}".strip()
    return NotifyEvent(
        kind="hunt_threat",
        title="Hunt found a threat",
        body=body[:500],
        url=f"/app/hunts/{hunt_id}",
        severity="critical",
    )


def event_for_model_fitness(*, result: dict[str, Any], settings: Any) -> NotifyEvent | None:
    """Build a model-fitness-FAIL NotifyEvent from a probe result, or None.

    Returns None unless ``notify_on_model_fitness_fail`` is on AND the probe graded
    ``fail``. No permalink (config is not a per-entity resource) — the dedup key
    then falls back to the title, which names the model, so repeated FAILs on the
    same model dedup within the hour. ``detail`` is already scrubbed by probes.py.
    """
    if not bool(getattr(settings, "notify_on_model_fitness_fail", False)):
        return None
    if str(result.get("grade") or "") != "fail":
        return None
    model = str(result.get("model") or "analyst model")
    detail = str(result.get("detail") or "").strip()
    return NotifyEvent(
        kind="model_fitness_fail",
        title=f"Analyst model unfit: {model}",
        body=(detail or "Model-fitness probe graded FAIL.")[:500],
        url="",
        severity="warning",
    )


def canned_test_event() -> NotifyEvent:
    """The synthetic event the Test button sends.

    Contains NO internal identifier — a fixed, unmistakably-synthetic body — so an
    operator validating the webhook before enabling notifications never leaks a
    real alert/hunt/host into the destination channel.
    """
    return NotifyEvent(
        kind="test",
        title="soc-ai notification test",
        body=(
            "This is a test notification from soc-ai. If you received it, the "
            "webhook is configured correctly."
        ),
        url="",
        severity="info",
    )


def webhook_configured(settings: Any) -> bool:
    """True iff a non-empty webhook URL is configured. No egress."""
    return bool(_webhook_url(settings))


async def send_test(settings: Any, audit: Any = None) -> tuple[bool, str]:
    """Send the canned test event NOW, bypassing the master toggle + dedup.

    The Test button is an explicit operator validation: it sends regardless of
    ``notify_enabled`` (so the operator can prove the destination works BEFORE
    switching routing on) and regardless of dedup, but it STILL requires a
    configured webhook URL. The audited outcome uses the same ``"notification"``
    kind as a real send. Returns ``(ok, detail)`` where ``detail`` is a short,
    secret-free human string — it NEVER contains the webhook URL.

    Never raises: a transport/timeout error becomes ``(False, "<ExcType>")``.
    """
    url = _webhook_url(settings)
    if not url:
        return False, "No webhook URL configured."

    fmt = str(getattr(settings, "notify_format", "json") or "json").lower()
    if fmt not in NOTIFY_FORMATS:
        fmt = "json"
    event = canned_test_event()
    payload = _build_payload(event, fmt)
    verify = bool(getattr(settings, "notify_verify_ssl", True))

    status: int | None = None
    error: str | None = None
    try:
        status = await _post_with_retries(url, payload, verify=verify)
    except Exception as exc:  # never raise into the route
        error = type(exc).__name__
        _LOGGER.warning("notification test send failed: %s", error)

    ok = error is None and status is not None and status < 400
    if audit is not None:
        try:
            await audit.log_kind(
                session_id="notify:test",
                kind="notification",
                payload={
                    "notify_kind": "test",
                    "format": fmt,
                    "ok": ok,
                    "status": status,
                    "error": error,
                },
            )
        except Exception:  # audit is best-effort
            _LOGGER.warning("notification test audit write failed (continuing)", exc_info=True)

    if ok:
        return True, f"Test sent — webhook returned HTTP {status}."
    if error is not None:
        return False, f"Test send failed: {error}."
    return False, f"Webhook returned HTTP {status}."
