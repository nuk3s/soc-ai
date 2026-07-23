"""Pre-auth login/logout endpoints (open_router)."""

from __future__ import annotations

import logging

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
    if throttle.is_locked(caller_ip, body.username) or ip_throttle.is_locked(caller_ip, ""):
        _LOGGER.warning(
            "login locked out for user=%r from ip=%s (too many failed attempts)",
            body.username,
            caller_ip,
        )
        raise HTTPException(
            status_code=429,
            detail={
                "reason": "too_many_attempts",
                "hint": "Too many failed logins; try again later.",
            },
        )
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
                detail={"reason": "invalid_credentials", "hint": "Invalid username or password"},
            )
        throttle.clear(caller_ip, body.username)
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


@open_router.post("/logout")
async def api_logout(request: Request) -> JSONResponse:
    """Delete the current session cookie (best-effort — no CSRF needed to log yourself out)."""
    raw = request.cookies.get(auth_svc.SESSION_COOKIE)
    if raw is not None:
        async with request.app.state.db_sessionmaker() as db:
            await auth_svc.delete_session(db, raw)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(auth_svc.SESSION_COOKIE, path="/")
    return resp
