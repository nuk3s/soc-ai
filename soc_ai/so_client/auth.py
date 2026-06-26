"""Security Onion authentication strategies.

Two strategies, picked at runtime by :func:`make_auth`:

- :class:`KratosAuth` - session-cookie auth via the Kratos
  ``/self-service/login/api`` endpoint. Works against any SO grid
  (OSS or Pro). The default.
- :class:`ConnectAuth` - OAuth2 client-credentials via ``/oauth2/token``.
  Requires SO Pro with the Hydra OAuth component
  (set ``SO_CLIENT_ID`` and ``SO_CLIENT_SECRET``).

Both implement :class:`SoAuthClient`: ``request(method, url, ...)`` returning
:class:`httpx.Response` and ``aclose()`` to release the underlying client.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, runtime_checkable

import httpx

from soc_ai.config import Settings
from soc_ai.errors import SoAuthError

_LOGGER = logging.getLogger(__name__)


@runtime_checkable
class SoAuthClient(Protocol):
    """Protocol for an authenticated SO HTTP client."""

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Send an authenticated request, refreshing credentials on 401."""
        ...

    async def aclose(self) -> None:
        """Release the underlying HTTP client and any held tokens."""
        ...


def _make_async_client(settings: Settings) -> httpx.AsyncClient:
    """Construct an :class:`httpx.AsyncClient` with TLS + timeout config."""
    verify: bool | str = settings.so_verify_ssl
    if settings.so_ca_bundle:
        verify = str(settings.so_ca_bundle)
    return httpx.AsyncClient(
        base_url=str(settings.so_host).rstrip("/"),
        verify=verify,
        timeout=httpx.Timeout(30.0, connect=10.0),
        follow_redirects=True,
    )


class KratosAuth:
    """Session-cookie auth via Kratos ``/self-service/login/api``.

    The Kratos API flow:

    1. ``GET /self-service/login/api`` returns a flow document with an
       ``id`` and a ``ui.action`` URL.
    2. ``POST {ui.action}`` with ``{method, identifier, password}`` sets a
       session cookie that httpx auto-stores in its jar; subsequent
       requests carry it transparently.

    On 401 we drop the cached state and re-login once before retrying.
    """

    def __init__(self, settings: Settings) -> None:
        self._username = settings.so_username
        self._password = settings.so_password
        # SO 3.0.0 mounts Kratos under /auth/... — the v1 default of bare
        # /self-service/login/api 302-redirects (and breaks the API flow).
        self._login_path = settings.so_kratos_path_prefix.rstrip("/") + "/self-service/login/api"
        self._client = _make_async_client(settings)
        self._logged_in = False
        self._session_token: str | None = None
        # SO 3.0.0 also CSRF-gates POSTs to /api/* with an "X-Srv-Token" header
        # whose value comes from GET /api/info.srvToken. Without it, every
        # POST to /api/events/ack etc. returns 400 "request could not be
        # processed" (logged server-side as "Missing SRV token on request").
        self._srv_token: str | None = None
        self._lock = asyncio.Lock()
        # Separate lock to serialize mutating (non-GET) requests.
        # Must NOT reuse self._lock — request() calls login() which acquires
        # self._lock, so nesting them would deadlock.
        self._write_lock = asyncio.Lock()

    async def login(self) -> None:
        """Establish a session. Idempotent under concurrent callers."""
        async with self._lock:
            if self._logged_in:
                return
            try:
                init = await self._client.get(self._login_path)
                init.raise_for_status()
                flow = init.json()
                action_url = flow["ui"]["action"]
            except (httpx.HTTPError, KeyError, ValueError) as e:
                raise SoAuthError(f"Kratos login flow init failed: {e}") from e

            try:
                resp = await self._client.post(
                    action_url,
                    json={
                        "method": "password",
                        "identifier": self._username,
                        "password": self._password.get_secret_value(),
                    },
                )
            except httpx.HTTPError as e:
                raise SoAuthError(f"Kratos credential submit failed: {e}") from e

            if resp.status_code == httpx.codes.BAD_REQUEST:
                raise SoAuthError("Kratos rejected credentials (HTTP 400)")
            if resp.status_code >= httpx.codes.BAD_REQUEST:
                raise SoAuthError(
                    f"Kratos credential submit returned {resp.status_code}",
                    status_code=resp.status_code,
                )

            # SO 3.0.0's Kratos API flow returns the session token in JSON
            # rather than setting a cookie; capture it and resend as
            # X-Session-Token on every follow-up request to /api/...
            try:
                payload = resp.json()
                self._session_token = payload.get("session_token")
            except ValueError:
                self._session_token = None

            self._logged_in = True
            _LOGGER.info(
                "Kratos session established for user=%s (token_set=%s)",
                self._username,
                self._session_token is not None,
            )

            # Bootstrap the CSRF srv-token by hitting /api/info — INSIDE the
            # login lock so login() never returns without it. (Previously this
            # ran outside the lock; concurrent first-callers could then fire a
            # write before srv_token was set and get a 400 — a cold-start race.)
            if self._session_token and not self._srv_token:
                await self._refresh_srv_token()

    async def _refresh_srv_token(self) -> None:
        """Fetch /api/info to capture the X-Srv-Token CSRF value."""
        if not self._session_token:
            return
        try:
            resp = await self._client.get(
                "/api/info",
                headers={"X-Session-Token": self._session_token},
            )
            if resp.status_code == httpx.codes.OK:
                self._srv_token = resp.json().get("srvToken")
                _LOGGER.info("SO srvToken refreshed (set=%s)", self._srv_token is not None)
        except (httpx.HTTPError, ValueError) as e:
            _LOGGER.warning("could not refresh srv-token: %s", e)

    def _clear_session(self) -> None:
        """Forget the current session so the next call re-authenticates."""
        self._logged_in = False
        self._session_token = None
        self._srv_token = None

    async def _send(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Build headers and send, retrying once on 401.

        Callers are responsible for ensuring login() has been called before
        invoking this helper.  The write-lock (if needed) must be acquired by
        the caller.
        """
        headers = dict(kwargs.pop("headers", None) or {})
        if self._session_token:
            headers.setdefault("X-Session-Token", self._session_token)
        if self._srv_token:
            headers.setdefault("X-Srv-Token", self._srv_token)
        resp = await self._client.request(method, url, headers=headers, **kwargs)
        if resp.status_code == httpx.codes.UNAUTHORIZED:
            _LOGGER.info("Kratos session rejected (401); re-authenticating")
            # Reset via a method call (not inline `= None`) so mypy doesn't
            # narrow the token attrs to None and dead-code-eliminate the
            # post-login re-reads — the async `login()` repopulates them.
            self._clear_session()
            await self.login()
            if self._session_token:
                headers["X-Session-Token"] = self._session_token
            if self._srv_token:
                headers["X-Srv-Token"] = self._srv_token
            resp = await self._client.request(method, url, headers=headers, **kwargs)
        return resp

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        if not self._logged_in:
            await self.login()
        # SO 3.0's X-Srv-Token CSRF/session can't process concurrent writes
        # (empirically 1/12 concurrent POSTs succeed; 12/12 sequential succeed),
        # so serialize mutating requests. Reads stay concurrent (GETs are safe).
        if method.upper() not in ("GET", "HEAD", "OPTIONS"):
            async with self._write_lock:
                return await self._send(method, url, **kwargs)
        return await self._send(method, url, **kwargs)

    async def aclose(self) -> None:
        await self._client.aclose()


class ConnectAuth:
    """OAuth2 client-credentials auth via ``/oauth2/token`` (SO Pro).

    Acquires a bearer token at first request and refreshes proactively
    one minute before expiry.
    """

    _REFRESH_LEEWAY = timedelta(seconds=60)

    def __init__(self, settings: Settings) -> None:
        if settings.so_client_id is None or settings.so_client_secret is None:
            raise SoAuthError("ConnectAuth requires SO_CLIENT_ID and SO_CLIENT_SECRET")
        self._client_id = settings.so_client_id
        self._client_secret = settings.so_client_secret
        self._client = _make_async_client(settings)
        self._token: str | None = None
        self._expires_at: datetime | None = None
        self._lock = asyncio.Lock()
        # Separate write-serialization lock (same rationale as KratosAuth).
        self._write_lock = asyncio.Lock()

    async def _refresh_token(self, *, force: bool = False) -> None:
        async with self._lock:
            now = datetime.now(UTC)
            if (
                not force
                and self._token
                and self._expires_at
                and now + self._REFRESH_LEEWAY < self._expires_at
            ):
                return
            try:
                resp = await self._client.post(
                    "/oauth2/token",
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self._client_id,
                        "client_secret": self._client_secret.get_secret_value(),
                    },
                )
                resp.raise_for_status()
                payload = resp.json()
            except (httpx.HTTPError, ValueError) as e:
                raise SoAuthError(f"OAuth token request failed: {e}") from e

            try:
                token = payload["access_token"]
                expires_in = int(payload.get("expires_in", 3600))
            except (KeyError, TypeError, ValueError) as e:
                raise SoAuthError(f"OAuth token response malformed: {e}") from e

            self._token = token
            self._expires_at = now + timedelta(seconds=expires_in)
            _LOGGER.info("Connect API token acquired; expires=%s", self._expires_at)

    async def _send(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Build Authorization header and send, retrying once on 401.

        Token refresh must be done by the caller before invoking this helper.
        """
        headers = dict(kwargs.pop("headers", None) or {})
        headers["Authorization"] = f"Bearer {self._token}"
        resp = await self._client.request(method, url, headers=headers, **kwargs)
        if resp.status_code == httpx.codes.UNAUTHORIZED:
            _LOGGER.info("Connect API token rejected (401); refreshing")
            await self._refresh_token(force=True)
            headers["Authorization"] = f"Bearer {self._token}"
            resp = await self._client.request(method, url, headers=headers, **kwargs)
        return resp

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        await self._refresh_token()
        # Serialize mutating requests for the same reason as KratosAuth —
        # SO 3.0's CSRF mechanism rejects concurrent writes through one session.
        if method.upper() not in ("GET", "HEAD", "OPTIONS"):
            async with self._write_lock:
                return await self._send(method, url, **kwargs)
        return await self._send(method, url, **kwargs)

    async def aclose(self) -> None:
        await self._client.aclose()


def make_auth(settings: Settings) -> SoAuthClient:
    """Pick the right auth strategy based on settings.

    Returns :class:`ConnectAuth` if ``SO_CLIENT_ID`` and ``SO_CLIENT_SECRET``
    are both set; otherwise falls back to :class:`KratosAuth`.
    """
    if settings.use_connect_api:
        _LOGGER.info("Using Connect API OAuth (SO Pro)")
        return ConnectAuth(settings)
    _LOGGER.info("Using Kratos session-cookie auth")
    return KratosAuth(settings)
