"""Session-or-bearer auth for the JSON API, gated by API_AUTH_REQUIRED.

401 bodies always carry a machine-readable ``reason`` plus a human hint so
callers (userscript included) never see an opaque failure.

Also hosts the CSRF Origin/Referer guard (:func:`require_csrf_safe`) for
cookie-authenticated mutating requests — see that function's docstring.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from fastapi import HTTPException, Request

from soc_ai.config import Settings
from soc_ai.store import auth as auth_svc
from soc_ai.webui.deps import current_user

# Methods that can change SO/app state and so require a CSRF check when the
# caller is authenticated by an ambient session cookie.
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _normalize_origin(value: str) -> str | None:
    """Return ``scheme://host[:port]`` for ``value`` (a URL or Origin), or None.

    Folds away an explicit default port (``:443`` for https, ``:80`` for http)
    so ``https://h`` and ``https://h:443`` compare equal. Lower-cases scheme and
    host. Returns None when there is no scheme+host to compare (e.g. ``"null"``,
    an opaque Origin, or a bare path).
    """
    if not value:
        return None
    parts = urlsplit(value.strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if not scheme or not host:
        return None
    port = parts.port
    if port is not None and not (
        (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    ):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


def _allowed_origins(request: Request, settings: Settings) -> set[str]:
    """The CSRF allowlist: the app's own origin + CORS + csrf_trusted_origins.

    The app origin is derived from the inbound request (scheme+host+port as the
    browser sees it) and from ``SO_HOST``/``soc_ai_host`` as a fallback so the
    check works behind a proxy or before the first SPA request. Reuses the same
    CSV allowlist shape as the CORS config.
    """
    allowed: set[str] = set()
    # The origin the browser actually reached us on (most reliable for a
    # same-origin SPA served by this app).
    base = str(request.base_url).rstrip("/")
    norm_base = _normalize_origin(base)
    if norm_base:
        allowed.add(norm_base)
    # Configured hosts as a fallback (proxy / pre-first-request).
    for raw in (str(settings.so_host) if settings.so_host else "", settings.soc_ai_host):
        norm = _normalize_origin(raw)
        if norm:
            allowed.add(norm)
    # CORS allowlist (cross-origin callers) + explicit CSRF trusted origins.
    for csv in (settings.cors_allow_origins, settings.csrf_trusted_origins):
        for raw_entry in csv.split(","):
            entry = raw_entry.strip()
            if not entry or entry == "*":
                continue
            norm = _normalize_origin(entry)
            if norm:
                allowed.add(norm)
    return allowed


def _has_valid_bearer(request: Request) -> bool:
    """True if the request carries a Bearer ``scai_`` token shape.

    Token *validity* is enforced by :func:`require_api_auth`; here we only need
    to know the caller is using bearer auth (not an ambient cookie) so we can
    exempt it from CSRF — a cross-origin page cannot read and replay a bearer
    token the way it can ride along on a cookie.
    """
    authz = request.headers.get("authorization", "")
    return authz.lower().startswith("bearer ") and authz[7:].strip().startswith(
        auth_svc.TOKEN_PREFIX
    )


async def require_csrf_safe(request: Request) -> None:
    """Reject cookie-authenticated cross-origin mutating requests (CSRF guard).

    Rule, applied only to the gated ``/api/v1`` router:

    - GET/HEAD/OPTIONS are exempt (non-mutating).
    - Bearer-``scai_`` requests are exempt: the userscript runs cross-origin in
      the SO web UI and authenticates by token, not an ambient cookie, so it is
      not CSRF-able.
    - Requests carrying NO session cookie are exempt: with no ambient credential
      there is nothing for a forged cross-site request to ride on. (In dev,
      ``api_auth_required=False`` and the SPA sends no cookie → skipped. But if a
      session cookie IS present it is still enforced.)
    - Otherwise (a mutating request authenticated by the session cookie) require
      an ``Origin`` (or, if absent, ``Referer``) header whose scheme+host+port is
      in the allowlist (the app's own origin + ``cors_allow_origins`` +
      ``csrf_trusted_origins``). A missing or mismatched origin is rejected with
      ``403 {"reason": "bad_origin"}``.

    Login/logout live on the open router and are never gated by this dependency.
    """
    if request.method not in _MUTATING_METHODS:
        return
    if _has_valid_bearer(request):
        return
    # No ambient cookie ⇒ not CSRF-able (covers dev-mode open API).
    if request.cookies.get(auth_svc.SESSION_COOKIE) is None:
        return

    settings: Settings = request.app.state.settings
    origin = request.headers.get("origin")
    candidate = origin if origin else request.headers.get("referer")
    norm = _normalize_origin(candidate) if candidate else None
    if norm is not None and norm in _allowed_origins(request, settings):
        return
    raise HTTPException(
        status_code=403,
        detail={
            "reason": "bad_origin",
            "hint": (
                "Cross-origin cookie-authenticated write rejected. Send the request "
                "from the app's own origin, or use 'Authorization: Bearer scai_…'."
            ),
        },
    )


async def identify_caller(request: Request) -> str:
    """Best-effort caller attribution for investigation records (non-enforcing)."""
    authz = request.headers.get("authorization", "")
    if authz.lower().startswith("bearer "):
        async with request.app.state.db_sessionmaker() as db:
            token = await auth_svc.check_api_token(db, authz[7:].strip())
        if token is not None:
            return f"token:{token.name}"
    user = await current_user(request)
    if user is not None:
        return user.username
    return "anonymous"


async def require_api_auth(request: Request) -> None:
    settings = request.app.state.settings
    if not settings.api_auth_required:
        return
    authz = request.headers.get("authorization", "")
    if authz.lower().startswith("bearer "):
        raw = authz[7:].strip()
        async with request.app.state.db_sessionmaker() as db:
            token = await auth_svc.check_api_token(db, raw)
        if token is not None:
            return
        raise HTTPException(
            status_code=401,
            detail={
                "reason": "invalid_token",
                "hint": (
                    "API token unknown or revoked; create one in the Config screen "
                    "(Settings → API Tokens)."
                ),
            },
        )
    if await current_user(request) is not None:
        return
    raise HTTPException(
        status_code=401,
        detail={
            "reason": "no_session",
            "hint": "Log in at /app/login or send 'Authorization: Bearer scai_…'.",
        },
    )
