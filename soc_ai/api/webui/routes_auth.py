"""Pre-auth login/logout endpoints (open_router)."""

from __future__ import annotations

import logging
import math

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from soc_ai.api.webui._shared import (
    _request_is_https,
    client_ip,
    open_router,
)
from soc_ai.store import auth as auth_svc

_LOGGER = logging.getLogger(__name__)

# Warn on the sign-in form when this many failed attempts or fewer remain
# before the lock. Silence until the lock was the dogfood complaint
# (2026-10-19, H1-D17): tries 1 to 5 gave no warning.
_WARN_AT_FAILURES_LEFT = 2


def _minutes(seconds: float) -> str:
    """'5 minutes' / '1 minute' for a wait, rounded up to the next minute."""
    n = max(1, math.ceil(seconds / 60))
    return f"{n} minute" if n == 1 else f"{n} minutes"


def _locked_response(seconds: float, scope: str) -> HTTPException:
    """The 429 a locked key gets: how long, and what the lock holds."""
    return HTTPException(
        status_code=429,
        detail={
            "reason": "too_many_attempts",
            "hint": f"Too many failed sign-ins {scope}. Try again in {_minutes(seconds)}.",
        },
        headers={"Retry-After": str(max(1, math.ceil(seconds)))},
    )


def _failed_hint(throttle: auth_svc.LoginThrottle, ip: str, username: str, locked: bool) -> str:
    """The 401 hint: the generic sentence, then the lock warning near the limit.

    The count is per (address, username) and grows for a username that does
    not exist exactly as for one that does, so it reveals no account.
    """
    base = "The username or the password is wrong."
    lock = _minutes(throttle.cooldown_s)
    if locked:
        return f"{base} soc-ai locked this username for {lock}."
    left = throttle.failures_left(ip, username)
    if 0 < left <= _WARN_AT_FAILURES_LEFT:
        verb = "locks" if left == 1 else "lock"
        noun = "sign-in" if left == 1 else "sign-ins"
        return f"{base} {left} more failed {noun} {verb} this username for {lock}."
    return base


class LoginIn(BaseModel):
    # Bounded so an unauthenticated caller can't force this pre-auth endpoint
    # to buffer/process an arbitrarily large credential string; mirrors the
    # admin-create-user bounds (routes_admin.CreateUserIn).
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


@open_router.post("/login")
async def api_login(body: LoginIn, request: Request) -> JSONResponse:
    """Authenticate and set the session cookie.  No auth gate — this IS the gate.

    A per-(client IP, username) sliding-window throttle locks out further
    attempts after repeated failures to blunt online password brute-forcing.
    """
    settings = request.app.state.settings
    caller_ip = client_ip(request, settings)
    throttle = auth_svc.login_throttle
    ip_throttle = auth_svc.login_ip_throttle  # per-IP across all usernames (spray)
    user_locked = throttle.is_locked(caller_ip, body.username)
    ip_locked = ip_throttle.is_locked(caller_ip, "")
    if user_locked or ip_locked:
        _LOGGER.warning(
            "login locked out for user=%r from ip=%s (too many failed attempts)",
            body.username,
            caller_ip,
        )
        if user_locked:
            raise _locked_response(
                throttle.retry_after(caller_ip, body.username), "for this username"
            )
        raise _locked_response(ip_throttle.retry_after(caller_ip, ""), "from this address")
    async with request.app.state.db_sessionmaker() as db:
        user = await auth_svc.authenticate(db, body.username, body.password)
        if user is None:
            locked = throttle.record_failure(caller_ip, body.username)
            ip_throttle.record_failure(caller_ip, "")  # count toward the per-IP spray limit
            if locked:
                _LOGGER.warning(
                    "login throttle engaged for user=%r from ip=%s after repeated failures",
                    body.username,
                    caller_ip,
                )
            raise HTTPException(
                status_code=401,
                detail={
                    "reason": "invalid_credentials",
                    "hint": _failed_hint(throttle, caller_ip, body.username, locked),
                },
            )
        throttle.clear(caller_ip, body.username)
        # Also FULLY drain the per-IP spray bucket. That bucket aggregates every
        # failure from this apparent source across all usernames — behind one NAT
        # egress (or with proxy_trusted_ips unset behind a reverse proxy, which
        # collapses every client to the proxy's socket IP) that is a whole SOC's
        # worth of teammates' typos, and without the drain it only ever grows
        # until a VALID credential is refused 429 for the cooldown. A successful
        # login is proof this source is a legitimate egress, so a full clear (not
        # a decrement) is right: a decrement still locks the shared IP whenever
        # typos merely outpace logins inside one window, while the spray defence
        # loses nothing — the per-(ip,username) throttle above independently caps
        # guessing per account, and a source that only ever fails (a real spray
        # bot) never reaches this line to clear anything.
        ip_throttle.clear(caller_ip, "")
        raw = await auth_svc.create_session(db, user, settings.session_ttl_hours)
    resp = JSONResponse({"ok": True, "username": user.username, "role": user.role})
    resp.set_cookie(
        auth_svc.SESSION_COOKIE,
        raw,
        httponly=True,  # always: keep the session token out of reach of JS / XSS
        samesite="lax",  # blocks cross-site cookie replay (CSRF) on state-changing nav
        # HTTPS-only flag, gated on the scheme so plain-HTTP dev login still works.
        secure=_request_is_https(request, settings),
        max_age=settings.session_ttl_hours * 3600,
        path="/",
    )
    return resp


class AuthStatusOut(BaseModel):
    auth_required: bool


@open_router.get("/auth-status", response_model=AuthStatusOut)
async def auth_status(request: Request) -> AuthStatusOut:
    """Whether this server asks for a sign-in. Open (pre-auth), boolean only.

    The sign-in page reads it before it draws the form. With authentication
    off every visitor already has admin access, and a full form there read as
    a gate that did not exist (dogfood 2026-10-19, R1-D20).
    """
    return AuthStatusOut(auth_required=bool(request.app.state.settings.api_auth_required))


@open_router.post("/logout")
async def api_logout(request: Request) -> JSONResponse:
    """Delete the current session cookie (best-effort — no CSRF needed to log yourself out)."""
    raw = request.cookies.get(auth_svc.SESSION_COOKIE)
    if raw is not None:
        async with request.app.state.db_sessionmaker() as db:
            await auth_svc.delete_session(db, raw)
    settings = request.app.state.settings
    resp = JSONResponse({"ok": True})
    # The same attributes the login set. A browser matches a cookie on its
    # attributes when it clears it.
    resp.delete_cookie(
        auth_svc.SESSION_COOKIE,
        path="/",
        httponly=True,
        samesite="lax",
        secure=_request_is_https(request, settings),
    )
    return resp
