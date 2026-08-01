"""Shared routers, auth deps and tiny formatting helpers for the /api/v1 webui API."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from soc_ai.api.security import require_api_auth, require_csrf_safe
from soc_ai.webui.deps import current_user

_LOGGER = logging.getLogger(__name__)

router = APIRouter(dependencies=[Depends(require_api_auth), Depends(require_csrf_safe)])

# Pre-auth endpoints (login / logout) — NOT covered by require_api_auth.
# Mounted under the same /api/v1 prefix in main.py but on a separate router
# so the blanket auth dependency above doesn't apply.
open_router = APIRouter()


def _request_is_https(request: Request, settings: Any = None) -> bool:
    """True when the client connection is HTTPS, honoring a TLS-terminating proxy.

    The canonical deployment terminates TLS in uvicorn (``request.url.scheme`` is
    already ``https``). When the app sits behind a reverse proxy that terminates
    TLS and forwards over plain HTTP, ``request.url.scheme`` reports ``http`` but
    the proxy sets ``X-Forwarded-Proto: https`` — honor that so the ``Secure``
    cookie flag is still applied. Plain-HTTP dev (no forwarded header, scheme
    ``http``) stays False so local login isn't broken by an unsendable Secure
    cookie.

    ``X-Forwarded-Proto`` is trusted ONLY from a peer in ``proxy_trusted_ips`` —
    same rule ``client_ip`` applies to ``X-Forwarded-For``. An arbitrary client
    could otherwise send ``X-Forwarded-Proto: https`` over plain HTTP and flip the
    ``Secure`` flag. When no proxy list is configured, no forwarded header is
    trusted (only the real socket scheme counts).
    """
    if request.url.scheme == "https":
        return True
    trusted = set(getattr(settings, "proxy_trusted_ips", None) or ())
    peer = request.client.host if request.client else "?"
    if peer not in trusted:
        return False
    forwarded = request.headers.get("x-forwarded-proto", "")
    # Take the LEFT-most entry. Unlike X-Forwarded-For — where the left-most hop is
    # the forgeable client IP and we must walk in from the right — X-Forwarded-Proto's
    # left-most value is the protocol the client used at the trust boundary (the edge
    # proxy), which is exactly what decides whether the end-user connection is secure.
    # Forgery is already prevented by the trusted-peer guard above: an untrusted
    # client's header never reaches this line.
    return forwarded.split(",")[0].strip().lower() == "https"


def client_ip(request: Request, settings: Any) -> str:
    """The caller's IP for per-IP throttling / rate-limiting.

    Normally the socket peer. When the app runs behind a reverse proxy whose IP is
    listed in ``proxy_trusted_ips``, trust the right-most untrusted ``X-Forwarded-For`` entry
    so per-IP controls attribute to the real client, not the shared proxy IP.
    ``X-Forwarded-For`` is NEVER trusted from a peer that is not allowlisted — any
    client could otherwise forge it and evade (or poison) the throttles.
    """
    peer = request.client.host if request.client else "?"
    trusted = set(getattr(settings, "proxy_trusted_ips", None) or ())
    if peer in trusted:
        # Append-style reverse proxies (nginx ``$proxy_add_x_forwarded_for``,
        # Caddy, Traefik, HAProxy) put the REAL peer at the RIGHT and leave the
        # left-most entries fully client-forgeable. Walk right-to-left, skipping
        # hops that are themselves trusted proxies, and return the first remaining
        # value — the closest address we did not add. Taking ``[0]`` (the
        # left-most) would let a client forge its own throttling key.
        for hop in reversed(request.headers.get("x-forwarded-for", "").split(",")):
            candidate = hop.strip()
            if candidate and candidate not in trusted:
                return candidate
    return peer


async def require_admin_api(request: Request) -> None:
    """Admin gate for sensitive reads (config). No-op when API auth is off (dev)."""
    if not request.app.state.settings.api_auth_required:
        return
    user = await current_user(request)
    if user is None or user.role != "admin":
        raise HTTPException(status_code=403, detail={"reason": "admin_required"})


# The React unions are narrower than what the backend can emit; coerce to them
# so the client never sees a value outside its TypeScript types.
_FE_SEV = {"critical", "high", "medium", "low"}
_FE_KIND = {"suricata", "sigma", "notice"}


def _sev(value: str | None) -> str:
    v = (value or "").lower()
    return v if v in _FE_SEV else "low"


def _kind(value: str | None) -> str:
    v = (value or "").lower()
    return v if v in _FE_KIND else "suricata"


def _verdict(value: str | None) -> str:
    return value or "untriaged"


def _inv_ago(inv: Any) -> str | None:
    """Short relative label for when an investigation ran (its created_at)."""
    return _ago(inv.created_at.isoformat()) if inv.created_at else None


def _ago(ts: str) -> str:
    """ES ``@timestamp`` (ISO-8601) → a short relative label (now/3m/2h/5d)."""
    if not ts:
        return ""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return ts
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    secs = (datetime.now(UTC) - dt).total_seconds()
    if secs < 60:
        return "now"
    if secs < 3600:
        return f"{int(secs // 60)}m"
    if secs < 86400:
        return f"{int(secs // 3600)}h"
    return f"{int(secs // 86400)}d"


def _iso_utc(dt: datetime | None) -> str:
    """Serialize a stored timestamp as a TIMEZONE-AWARE ISO-8601 string.

    Store timestamps are naive UTC (``store.auth.utcnow`` / SQLite ``func.now()``
    both produce UTC). A NAIVE ISO string (``2026-07-02T11:23:49``) has no offset,
    so a browser parses it as LOCAL time — off by the client's UTC offset (the
    "1h-old run shows 8h ago" bug). Stamping ``+00:00`` lets the browser localize
    it correctly. An already-aware datetime is passed through unchanged.
    """
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.isoformat()
