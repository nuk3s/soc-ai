"""Security Onion authentication strategies.

Two strategies, picked at runtime by :func:`make_auth`:

- :class:`KratosAuth` - session auth via a Kratos login flow, browser or
  API, picked by ``so_login_flow``. Works against any SO grid (OSS or Pro).
  The default.
- :class:`ConnectAuth` - OAuth2 client-credentials via ``/oauth2/token``.
  Requires SO Pro with the Hydra OAuth component
  (set ``SO_CLIENT_ID`` and ``SO_CLIENT_SECRET``).

Both implement :class:`SoAuthClient`: ``request(method, url, ...)`` returning
:class:`httpx.Response` and ``aclose()`` to release the underlying client.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, runtime_checkable

import httpx

from soc_ai.config import Settings
from soc_ai.demo.guard import assert_loopback_only
from soc_ai.errors import SoAuthError

_LOGGER = logging.getLogger(__name__)

# SO 3.0 expires the X-Srv-Token CSRF value 600s after issuance and signals
# an expired token with a generic HTTP 400 (NOT a 401), so the 401-relogin
# path never catches it. Refresh proactively well under that deadline —
# SO's own web UI re-fetches its srv-token roughly every 60s.
_SRV_TOKEN_TTL_S = 240.0

# The cookie the Kratos browser flow sets. The httpx cookie jar holds it and
# sends it on every later request to the grid.
_SESSION_COOKIE = "ory_kratos_session"

# Headers a browser sends. "Accept: application/json" makes Kratos answer with
# the flow document and the session JSON instead of a redirect to its own
# login page.
_BROWSER_HEADERS = {"Accept": "application/json"}

# SOC can accept a session from Kratos and then refuse it. A new login gets the
# same answer, so soc-ai holds the login and backs off. The delay starts at 30s
# and doubles to a 10 minute ceiling. Without this ceiling one auth fault made
# 32,420 logins in three days, hid its own cause and inflated the SO audit
# index sixteenfold.
_LOGIN_BACKOFF_MIN_S = 30.0
_LOGIN_BACKOFF_MAX_S = 600.0

# The login flows ``so_login_flow`` picks between. The strings match
# soc_ai.config.SO_LOGIN_FLOWS, which the Config console renders.
_FLOW_BROWSER = "browser"
_FLOW_API = "api"


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
    # Demo mode: only a loopback SO API (the bundled mock) may be reached.
    assert_loopback_only(settings, str(settings.so_host), "security onion api")
    verify: bool | str = settings.so_verify_ssl
    if settings.so_ca_bundle:
        verify = str(settings.so_ca_bundle)
    return httpx.AsyncClient(
        base_url=str(settings.so_host).rstrip("/"),
        verify=verify,
        timeout=httpx.Timeout(30.0, connect=10.0),
        follow_redirects=True,
    )


class _FlowEndpointMissing(SoAuthError):
    """The grid serves no Kratos login flow at that path (HTTP 404 or 405)."""


class _BrowserFlowUnavailable(Exception):
    """The grid cannot complete a Kratos browser login.

    This is the signal for the API-flow fallback. A credential rejection is
    NOT this signal, because the same password fails on both flows.
    """


class KratosAuth:
    """Session auth through a Kratos login flow, with two flows to pick from.

    The BROWSER flow, which is the flow the SO web interface itself uses:

    1. ``GET <prefix>/self-service/login/browser`` with
       ``Accept: application/json`` answers with the login flow document.
       The document holds the flow id and a ``csrf_token`` node. If the grid
       answers with a redirect instead, the flow id is in the ``Location``
       query and the document comes from
       ``GET <prefix>/self-service/login/flows``.
    2. ``POST <prefix>/self-service/login?flow=<id>`` carries the method, the
       identifier, the password and the CSRF token. Kratos sets the
       ``ory_kratos_session`` cookie. The httpx cookie jar holds that cookie
       and sends it on every later request to the grid.

    The API flow:

    1. ``GET <prefix>/self-service/login/api`` answers with the flow document.
    2. ``POST <prefix>/self-service/login?flow=<id>`` carries the method, the
       identifier and the password. Kratos answers with a session token in
       JSON and sets no cookie. soc-ai sends that token in an
       ``X-Session-Token`` header on every later request.

    SO 3.3 refuses the API-flow session token: SOC resolves no identity for the
    call and answers HTTP 401. SO 2.4 and SO 3.0 to 3.2 accept both flows.
    ``so_login_flow`` picks: ``auto`` runs the browser flow and falls back to
    the API flow, ``browser`` and ``api`` force one flow. soc-ai keeps the flow
    that worked for the life of the process, so a fallback costs one extra
    login and not one for every request.

    On 401 soc-ai drops the session and logs in once more. If SOC refuses the
    new session too, soc-ai holds the login and backs off.
    """

    def __init__(self, settings: Settings) -> None:
        self._username = settings.so_username
        self._password = settings.so_password
        # SO 3.0.0 and later mount Kratos under /auth/... The v1 default of a
        # bare /self-service/... path redirects and breaks the flow.
        prefix = settings.so_kratos_path_prefix.rstrip("/")
        self._login_init_path = f"{prefix}/self-service/login/browser"
        self._login_api_path = f"{prefix}/self-service/login/api"
        self._login_flow_path = f"{prefix}/self-service/login/flows"
        self._login_submit_path = f"{prefix}/self-service/login"
        self._flow_mode = settings.so_login_flow
        # The flow that worked. None until the first login that SOC accepts.
        self._strategy: str | None = None
        self._client = _make_async_client(settings)
        self._logged_in = False
        # The API flow answers with this token and sets no cookie. None on the
        # browser flow, where the cookie jar carries the session.
        self._session_token: str | None = None
        # SO 3.0.0 also CSRF-gates POSTs to /api/* with an "X-Srv-Token" header
        # whose value comes from GET /api/info.srvToken. Without it, every
        # POST to /api/events/ack etc. returns 400 "request could not be
        # processed" (logged server-side as "Missing SRV token on request").
        self._srv_token: str | None = None
        # monotonic() timestamp of the last successful srv-token fetch;
        # writes older than _SRV_TOKEN_TTL_S trigger a proactive refresh.
        self._srv_token_at: float = 0.0
        # Count of consecutive sessions that SOC refused, and the monotonic()
        # deadline until which soc-ai holds the login.
        self._refusal_count = 0
        self._refusal_until = 0.0
        self._lock = asyncio.Lock()
        # Separate lock to serialize mutating (non-GET) requests.
        # Must NOT reuse self._lock — request() calls login() which acquires
        # self._lock, so nesting them would deadlock.
        self._write_lock = asyncio.Lock()

    @property
    def login_flow(self) -> str | None:
        """The flow that SOC accepted, or None before the first login."""
        return self._strategy

    # ── reading a login flow document ────────────────────────────────────

    def _has_session_cookie(self) -> bool:
        """True when the jar holds the Kratos browser session cookie."""
        return any(cookie.name == _SESSION_COOKIE for cookie in self._client.cookies.jar)

    @staticmethod
    def _csrf_token(flow: dict[str, Any]) -> str | None:
        """Read the ``csrf_token`` value out of the flow document nodes."""
        for node in (flow.get("ui") or {}).get("nodes") or []:
            attrs = node.get("attributes") or {}
            if attrs.get("name") == "csrf_token":
                value = attrs.get("value")
                return str(value) if value else None
        return None

    async def _fetch_login_flow(self, path: str) -> dict[str, Any]:
        """Start a login flow at ``path`` and return the flow document.

        Raises :class:`SoAuthError` with a plain reason when the grid answers
        with a page instead of the flow document. SO throttles repeated logins
        and redirects them to its own login page, which is not JSON.
        """
        try:
            init = await self._client.get(
                path,
                headers=_BROWSER_HEADERS,
                follow_redirects=False,
            )
        except httpx.HTTPError as e:
            raise SoAuthError(f"Kratos login flow init failed: {e}") from e

        if init.status_code in (
            httpx.codes.MOVED_PERMANENTLY,
            httpx.codes.FOUND,
            httpx.codes.SEE_OTHER,
            httpx.codes.TEMPORARY_REDIRECT,
        ):
            flow_id = httpx.URL(init.headers.get("location") or "").params.get("flow")
            if not flow_id:
                raise self._throttled_error(init.status_code)
            return await self._fetch_flow_by_id(flow_id)

        if init.status_code != httpx.codes.OK:
            if init.status_code == httpx.codes.TOO_MANY_REQUESTS:
                raise self._throttled_error(init.status_code)
            # An older or a newer grid can serve no flow at this path at all.
            # The caller decides whether the other flow is worth a try.
            if init.status_code in (httpx.codes.NOT_FOUND, httpx.codes.METHOD_NOT_ALLOWED):
                raise _FlowEndpointMissing(
                    f"the login endpoint answered HTTP {init.status_code}",
                    status_code=init.status_code,
                )
            raise SoAuthError(
                f"Kratos login flow init failed: the login endpoint answered "
                f"HTTP {init.status_code}",
                status_code=init.status_code,
            )
        return self._parse_flow(init)

    async def _fetch_flow_by_id(self, flow_id: str) -> dict[str, Any]:
        """Read a started login flow by its id."""
        try:
            resp = await self._client.get(
                self._login_flow_path,
                params={"id": flow_id},
                headers=_BROWSER_HEADERS,
            )
        except httpx.HTTPError as e:
            raise SoAuthError(f"Kratos login flow init failed: {e}") from e
        if resp.status_code != httpx.codes.OK:
            raise self._throttled_error(resp.status_code)
        return self._parse_flow(resp)

    @staticmethod
    def _throttled_error(status_code: int) -> SoAuthError:
        """The error for a login answer that holds no flow document."""
        return SoAuthError(
            f"SO throttled the login. The login endpoint answered HTTP {status_code} "
            "and sent no login flow.",
            status_code=status_code,
        )

    def _parse_flow(self, resp: httpx.Response) -> dict[str, Any]:
        """Read the flow document out of a response body.

        A non-JSON body is the throttled-login page. Name that, rather than
        leak a JSON parse error that reads like a broken endpoint.
        """
        try:
            flow = resp.json()
        except ValueError as e:
            raise self._throttled_error(resp.status_code) from e
        if not isinstance(flow, dict) or not flow.get("id"):
            raise self._throttled_error(resp.status_code)
        return flow

    def _credential_form(self, csrf_token: str | None = None) -> dict[str, str]:
        """The password-method form both flows submit."""
        form = {
            "method": "password",
            "identifier": self._username,
            "password": self._password.get_secret_value(),
        }
        if csrf_token:
            form["csrf_token"] = csrf_token
        return form

    # ── the two login flows ──────────────────────────────────────────────

    async def _browser_login(self) -> None:
        """Run the Kratos browser flow and leave the session cookie in the jar.

        Raises :class:`_BrowserFlowUnavailable` when the grid cannot complete
        the flow. Raises :class:`SoAuthError` when Kratos rejects the password,
        because the API flow would reject the same password.
        """
        try:
            flow = await self._fetch_login_flow(self._login_init_path)
        except _FlowEndpointMissing as e:
            raise _BrowserFlowUnavailable(
                f"the browser login endpoint answered HTTP {e.status_code}"
            ) from e

        csrf_token = self._csrf_token(flow)
        if not csrf_token:
            raise _BrowserFlowUnavailable("the login flow document holds no csrf_token")

        try:
            resp = await self._client.post(
                self._login_submit_path,
                params={"flow": flow["id"]},
                json=self._credential_form(csrf_token),
                headers=_BROWSER_HEADERS,
                follow_redirects=False,
            )
        except httpx.HTTPError as e:
            raise SoAuthError(f"Kratos credential submit failed: {e}") from e

        if resp.status_code == httpx.codes.BAD_REQUEST:
            raise SoAuthError("Kratos rejected credentials (HTTP 400)")
        if resp.status_code >= httpx.codes.BAD_REQUEST:
            raise _BrowserFlowUnavailable(f"the login answered HTTP {resp.status_code}")

        # The browser flow answers 200 with the session, or redirects to the
        # return_to page. Either way the cookie is what carries the session,
        # so the cookie is what we check.
        if not self._has_session_cookie():
            raise _BrowserFlowUnavailable(
                f"the login answered HTTP {resp.status_code} and set no session cookie"
            )

    async def _api_login(self) -> None:
        """Run the Kratos API flow and hold the session token it answers with."""
        flow = await self._fetch_login_flow(self._login_api_path)
        try:
            resp = await self._client.post(
                self._login_submit_path,
                params={"flow": flow["id"]},
                json=self._credential_form(),
                headers=_BROWSER_HEADERS,
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

        try:
            self._session_token = resp.json().get("session_token")
        except ValueError:
            self._session_token = None
        if not self._session_token:
            raise SoAuthError(
                f"The login answered HTTP {resp.status_code} and returned no session token.",
                status_code=resp.status_code,
            )

    # ── picking a flow ───────────────────────────────────────────────────

    def _strategy_order(self) -> list[str]:
        """The flows to try, in order.

        A remembered flow is the only flow: soc-ai learns the answer once and
        a later login does not pay for the fallback again.
        """
        if self._strategy:
            return [self._strategy]
        if self._flow_mode == _FLOW_BROWSER:
            return [_FLOW_BROWSER]
        if self._flow_mode == _FLOW_API:
            return [_FLOW_API]
        return [_FLOW_BROWSER, _FLOW_API]

    def _reset_credentials(self) -> None:
        """Drop every credential, so one flow cannot carry another's session."""
        self._session_token = None
        self._srv_token = None
        self._srv_token_at = 0.0
        self._client.cookies.clear()

    async def _probe_info(self) -> tuple[int, dict[str, Any] | None]:
        """Read /api/info with the credentials in hand.

        Returns the status and the body. Status 0 means the call did not
        complete. /api/info is the read every write path depends on, so it is
        the honest test of whether SOC accepts the session.
        """
        headers: dict[str, str] = {}
        if self._session_token:
            headers["X-Session-Token"] = self._session_token
        try:
            resp = await self._client.get("/api/info", headers=headers)
        except httpx.HTTPError as e:
            _LOGGER.warning("could not read /api/info: %s", e)
            return 0, None
        if resp.status_code != httpx.codes.OK:
            return resp.status_code, None
        try:
            body = resp.json()
        except ValueError as e:
            _LOGGER.warning("could not read the /api/info body: %s", e)
            return resp.status_code, None
        return resp.status_code, body if isinstance(body, dict) else None

    async def _establish(self, strategy: str) -> tuple[int, dict[str, Any] | None]:
        """Run one login flow, then read /api/info with the session it made."""
        self._reset_credentials()
        if strategy == _FLOW_BROWSER:
            await self._browser_login()
        else:
            await self._api_login()
        return await self._probe_info()

    def _adopt(self, strategy: str, info: dict[str, Any] | None, *, accepted: bool) -> None:
        """Keep the session the last flow made."""
        self._logged_in = True
        if not accepted:
            return
        if self._strategy != strategy:
            self._strategy = strategy
            _LOGGER.info("SO login strategy: %s", strategy)
        if info is not None:
            self._srv_token = info.get("srvToken")
            self._srv_token_at = time.monotonic()
            _LOGGER.info("SO srvToken refreshed (set=%s)", self._srv_token is not None)
        self._session_accepted()

    async def login(self) -> None:
        """Establish a session. Idempotent under concurrent callers."""
        async with self._lock:
            if self._logged_in:
                return
            held = self._refusal_until - time.monotonic()
            if held > 0:
                raise SoAuthError(
                    "SOC refused the last session. soc-ai holds the login for "
                    f"{held:.0f} more seconds. Check the SO version and the login flow.",
                    status_code=int(httpx.codes.UNAUTHORIZED),
                )

            order = self._strategy_order()
            for strategy in order:
                is_last = strategy == order[-1]
                try:
                    status, info = await self._establish(strategy)
                except _BrowserFlowUnavailable as exc:
                    if is_last:
                        raise SoAuthError(
                            f"The Kratos browser flow could not complete: {exc}"
                        ) from exc
                    _LOGGER.info(
                        "the Kratos browser flow is not available (%s). soc-ai tries the API flow.",
                        exc,
                    )
                    continue

                if status == httpx.codes.OK:
                    self._adopt(strategy, info, accepted=True)
                    return
                if status == httpx.codes.UNAUTHORIZED and not is_last:
                    _LOGGER.info(
                        "SOC refused the %s session (GET /api/info answered HTTP 401). "
                        "soc-ai tries the API flow.",
                        strategy,
                    )
                    continue

                # The last flow. Keep the session, so the caller reads the real
                # answer from SOC rather than an exception from soc-ai.
                self._adopt(strategy, info, accepted=False)
                if status == httpx.codes.UNAUTHORIZED:
                    self._session_refused(
                        f"GET /api/info answered HTTP 401 with a new {strategy} session"
                    )
                return

    # ── the srv-token and the refusal ceiling ────────────────────────────

    async def _refresh_srv_token(self) -> None:
        """Fetch /api/info to capture the X-Srv-Token CSRF value."""
        if not self._logged_in:
            return
        # While soc-ai holds the login, /api/info answers 401 like every other
        # call. Asking again costs a request and extends the hold for a fault
        # soc-ai has already reported.
        if self._session_is_held():
            return
        status, info = await self._probe_info()
        if status == httpx.codes.OK:
            self._session_accepted()
            if info is not None:
                self._srv_token = info.get("srvToken")
                self._srv_token_at = time.monotonic()
                _LOGGER.info("SO srvToken refreshed (set=%s)", self._srv_token is not None)
        elif status == httpx.codes.UNAUTHORIZED:
            self._session_refused("GET /api/info answered HTTP 401")

    def _session_refused(self, detail: str) -> None:
        """Hold the login after SOC refused a session soc-ai just established."""
        self._refusal_count += 1
        delay = min(
            _LOGIN_BACKOFF_MIN_S * (2 ** (self._refusal_count - 1)),
            _LOGIN_BACKOFF_MAX_S,
        )
        self._refusal_until = time.monotonic() + delay
        _LOGGER.error(
            "SOC refused the Security Onion session (%s). Check the SO version and the "
            "login flow. soc-ai holds the login for %.0f s. Refusals in a row: %d.",
            detail,
            delay,
            self._refusal_count,
        )

    def _session_accepted(self) -> None:
        """Clear the hold after SOC accepted a call."""
        if self._refusal_count:
            _LOGGER.info("SOC accepted the Security Onion session again")
        self._refusal_count = 0
        self._refusal_until = 0.0

    def _session_is_held(self) -> bool:
        """True while soc-ai holds the login after a refused session."""
        return time.monotonic() < self._refusal_until

    def _clear_session(self) -> None:
        """Forget the current session so the next call re-authenticates."""
        self._logged_in = False
        self._reset_credentials()

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
        if resp.status_code != httpx.codes.UNAUTHORIZED:
            self._session_accepted()
            return resp
        if self._session_is_held():
            # SOC refuses this session. A new login gets the same answer, so
            # soc-ai returns the 401 rather than feeding a login storm.
            return resp
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
        if resp.status_code == httpx.codes.UNAUTHORIZED:
            if not self._session_is_held():
                self._session_refused(f"{method.upper()} {url} answered HTTP 401 after a login")
        else:
            self._session_accepted()
        return resp

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        if not self._logged_in:
            await self.login()
        # SO 3.0's X-Srv-Token CSRF/session can't process concurrent writes
        # (empirically 1/12 concurrent POSTs succeed; 12/12 sequential succeed),
        # so serialize mutating requests. Reads stay concurrent (GETs are safe).
        if method.upper() not in ("GET", "HEAD", "OPTIONS"):
            async with self._write_lock:
                # Snapshot the caller's headers up front: _send pops "headers"
                # out of its kwargs copy, so passing **kwargs to a retry would
                # silently drop them. Pass the snapshot explicitly to BOTH
                # sends (_send makes its own dict copy; the snapshot is never
                # mutated).
                caller_headers = dict(kwargs.pop("headers", None) or {})
                # Proactive refresh: SO expires the srv-token after 600s and
                # signals it with a 400 (not 401), so refresh on age here
                # rather than waiting for a failure the 401 path can't see.
                if self._logged_in and (
                    not self._srv_token or time.monotonic() - self._srv_token_at > _SRV_TOKEN_TTL_S
                ):
                    await self._refresh_srv_token()
                resp = await self._send(method, url, headers=caller_headers, **kwargs)
                # Reactive safety net: an expired srv-token still surfaces as
                # a generic 400 "The request could not be processed". Refresh
                # and retry ONCE — SO writes like ack are idempotent, so the
                # retry is harmless even if the 400 was a benign zero-match /
                # already-acknowledged response.
                if resp.status_code == httpx.codes.BAD_REQUEST and resp.text.startswith(
                    "The request could not be processed"
                ):
                    _LOGGER.info(
                        "SO write %s %s returned 400 (possible expired srv-token); "
                        "refreshing srv-token and retrying once",
                        method,
                        url,
                    )
                    await self._refresh_srv_token()
                    resp = await self._send(method, url, headers=caller_headers, **kwargs)
                return resp
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
