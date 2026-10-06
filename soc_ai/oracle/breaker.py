"""The Oracle route pause: stop calling a route that cannot answer.

From 2026-09-10 20:47 to 2026-09-14 05:00 UTC the Claude subscription behind
the production Oracle route had hit its weekly limit. The gateway answered
every call with HTTP 500 and said so in the message, with the reset time. The
client retried each escalation three times: 69 calls went to a route that
could not answer, and nothing on the console said why.

The breaker opens on either of two signals:

- a quota answer (:data:`soc_ai.oracle.failures.QUOTA`): HTTP 429, or a usage,
  rate or weekly limit in the gateway message. It stays open until the reset
  time that the message or the ``Retry-After`` header names, or for
  :data:`BACKOFF` when neither names one;
- :data:`OPEN_AFTER_5XX` server errors in a row from the route, with no answer
  between them. It stays open for :data:`BACKOFF`.

While it is open the client makes no call, and the orchestrator records each
skipped escalation as ``oracle_skipped`` with the reason and the reset time.
A route is the gateway URL and the Oracle model, so a change of the Oracle
model is a new route and calls again at once.

The state lives in the process. The doctor of another process reads the same
facts from the stored events (:func:`soc_ai.store.oracle_ledger.latest_route_outcome`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any

from soc_ai.oracle import failures

BACKOFF = timedelta(hours=1)
"""The pause when the gateway names no reset time."""

MIN_PAUSE = timedelta(minutes=1)
MAX_PAUSE = timedelta(days=8)
"""A named reset beyond this is not believed: a weekly limit resets within 7
days. The pause is cut to this length."""

OPEN_AFTER_5XX = 3
"""Server errors in a row, with no answer between them, that open the breaker."""

PAUSE_QUOTA = "quota"
PAUSE_5XX = "5xx"


def _now() -> datetime:
    """The clock. Tests patch this."""
    return datetime.now(UTC)


@dataclass(frozen=True)
class RouteState:
    """The breaker state of one Oracle route."""

    open_until: datetime | None = None
    opened_at: datetime | None = None
    reason: str = ""
    message: str = ""
    reset_named: bool = False
    consecutive_5xx: int = 0
    last_answer_at: datetime | None = None

    def is_open(self, now: datetime) -> bool:
        return self.open_until is not None and now < self.open_until


def route_key(settings: Any) -> str:
    """One Oracle route: the gateway URL and the Oracle model."""
    base = str(getattr(settings, "litellm_base_url", "") or "").rstrip("/")
    return f"{base}|{getattr(settings, 'oracle_model', '')}"


# ---------------------------------------------------------------------------
# Reset time parsing
# ---------------------------------------------------------------------------

_MONTHS = {
    m: i
    for i, m in enumerate(
        ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1
    )
}

_TZ = r"\(?\s*(?P<tz>UTC|GMT|Z|[A-Za-z_]+/[A-Za-z_]+)?\s*\)?"

# "resets Sep 14, 5am (UTC)", "reset on Sep 14 at 05:00 UTC", "resets Sep 14 5:30 pm"
_DATE_TIME_RE = re.compile(
    r"resets?\s+(?:on\s+|at\s+)?(?P<mon>jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+"
    r"(?P<day>\d{1,2})(?:st|nd|rd|th)?,?\s+(?:at\s+)?(?P<hour>\d{1,2})(?::(?P<min>\d{2}))?"
    r"\s*(?P<ampm>am|pm)?\s*" + _TZ,
    re.IGNORECASE,
)
# "resets at 2026-09-14T05:00:00Z", "retry after 2026-09-14 05:00 UTC"
_ISO_RE = re.compile(
    r"(?:resets?|retry|try again)\w*\s*(?:at|after|on|:)?\s*"
    r"(?P<iso>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?)\s*"
    r"(?P<off>Z|UTC|[+-]\d{2}:?\d{2})?",
    re.IGNORECASE,
)
# "resets at 5am (UTC)": a time with no date, the next one to come.
_TIME_RE = re.compile(
    r"resets?\s+(?:at\s+)?(?P<hour>\d{1,2})(?::(?P<min>\d{2}))?\s*(?P<ampm>am|pm)\s*" + _TZ,
    re.IGNORECASE,
)
# "try again in 37 seconds", "retry after 5 minutes", "resets in 2 hours"
_RELATIVE_RE = re.compile(
    r"(?:try again|retry|resets?)\s+(?:in|after)\s+(?P<n>\d+(?:\.\d+)?)\s*"
    r"(?P<unit>seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h)\b",
    re.IGNORECASE,
)


def _tzinfo(name: str | None) -> Any:
    if not name or name.upper() in ("UTC", "GMT", "Z"):
        return UTC
    try:
        from zoneinfo import ZoneInfo  # noqa: PLC0415 - rare path

        return ZoneInfo(name)
    except Exception:
        return None


def _hour24(hour: int, ampm: str | None) -> int:
    if not ampm:
        return hour
    if ampm.lower() == "pm" and hour < 12:
        return hour + 12
    if ampm.lower() == "am" and hour == 12:
        return 0
    return hour


def _from_date_time(m: re.Match[str], now: datetime) -> datetime | None:
    tz = _tzinfo(m.group("tz"))
    if tz is None:
        return None
    try:
        found = datetime(
            now.astimezone(tz).year,
            _MONTHS[m.group("mon").lower()[:3]],
            int(m.group("day")),
            _hour24(int(m.group("hour")), m.group("ampm")),
            int(m.group("min") or 0),
            tzinfo=tz,
        )
    except ValueError:
        return None
    if found < now - timedelta(days=1):
        found = found.replace(year=found.year + 1)
    return found


def _from_iso(m: re.Match[str]) -> datetime | None:
    raw = m.group("iso").replace(" ", "T")
    off = (m.group("off") or "").upper()
    try:
        if off in ("", "Z", "UTC"):
            return datetime.fromisoformat(raw).replace(tzinfo=UTC)
        return datetime.fromisoformat(f"{raw}{off}")
    except ValueError:
        return None


def _from_time(m: re.Match[str], now: datetime) -> datetime | None:
    tz = _tzinfo(m.group("tz"))
    if tz is None:
        return None
    local_now = now.astimezone(tz)
    found = local_now.replace(
        hour=_hour24(int(m.group("hour")), m.group("ampm")) % 24,
        minute=int(m.group("min") or 0),
        second=0,
        microsecond=0,
    )
    return found if found > local_now else found + timedelta(days=1)


def _from_relative(m: re.Match[str], now: datetime) -> datetime:
    n = float(m.group("n"))
    unit = m.group("unit").lower()
    if unit.startswith("h"):
        return now + timedelta(hours=n)
    if unit.startswith("m"):
        return now + timedelta(minutes=n)
    return now + timedelta(seconds=n)


def parse_reset_time(text: str, now: datetime | None = None) -> datetime | None:
    """The reset time a gateway message names, in UTC, or None.

    Reads a month and day with a clock time, an ISO time stamp, a clock time
    alone, or a relative "in N minutes", in that order. A time zone other than
    UTC must be an IANA name. A time that is already past, or a name that does
    not resolve, returns None, and the caller backs off for :data:`BACKOFF`.
    """
    if not text:
        return None
    now = now or _now()
    found: datetime | None = None
    if m := _DATE_TIME_RE.search(text):
        found = _from_date_time(m, now)
    elif m := _ISO_RE.search(text):
        found = _from_iso(m)
    elif m := _TIME_RE.search(text):
        found = _from_time(m, now)
    elif m := _RELATIVE_RE.search(text):
        found = _from_relative(m, now)
    if found is None:
        return None
    found = found.astimezone(UTC)
    return found if found > now else None


def parse_retry_after(value: str | None, now: datetime | None = None) -> datetime | None:
    """The time a ``Retry-After`` header names: seconds or an HTTP date."""
    if not value:
        return None
    now = now or _now()
    value = value.strip()
    if value.isdigit():
        return now + timedelta(seconds=int(value))
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    when = when.astimezone(UTC)
    return when if when > now else None


def iso(when: datetime | None) -> str | None:
    """A UTC time stamp as ``2026-09-14T05:00:00Z``."""
    if when is None:
        return None
    return when.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# The breaker
# ---------------------------------------------------------------------------


class OracleRouteBreaker:
    """The pause state of every Oracle route this process called."""

    def __init__(self) -> None:
        self._routes: dict[str, RouteState] = {}

    def reset(self) -> None:
        """Forget every route (tests)."""
        self._routes.clear()

    def state(self, route: str) -> RouteState:
        return self._routes.get(route, RouteState())

    def open_until(self, route: str, *, now: datetime | None = None) -> datetime | None:
        """The end of the pause, or None when the route may be called."""
        now = now or _now()
        st = self._routes.get(route)
        if st is None or not st.is_open(now):
            return None
        return st.open_until

    def record_answer(self, route: str, *, now: datetime | None = None) -> None:
        """The route answered (HTTP 200): clear the 5xx run and any ended pause."""
        now = now or _now()
        st = self.state(route)
        cleared = not st.is_open(now)
        self._routes[route] = replace(
            st,
            consecutive_5xx=0,
            last_answer_at=now,
            open_until=None if cleared else st.open_until,
            opened_at=None if cleared else st.opened_at,
        )

    def record_failure(
        self,
        route: str,
        *,
        error_class: str,
        message: str = "",
        reset_text: str | None = None,
        retry_after: str | None = None,
        now: datetime | None = None,
    ) -> bool:
        """Record one failed call. True when this failure opened the breaker.

        Only a transition returns True, so a caller can notify once per pause.
        A quota answer while the breaker is open moves the reset time and
        returns False. ``message`` is stored and shown, so the caller scrubs
        it first. ``reset_text`` is the raw text the reset time is read from;
        it defaults to ``message`` and is never stored.
        """
        now = now or _now()
        st = self.state(route)
        was_open = st.is_open(now)
        if error_class == failures.QUOTA:
            named = parse_reset_time(
                reset_text if reset_text is not None else message, now
            ) or parse_retry_after(retry_after, now)
            until = named or now + BACKOFF
            until = min(max(until, now + MIN_PAUSE), now + MAX_PAUSE)
            self._routes[route] = replace(
                st,
                open_until=until,
                opened_at=st.opened_at if was_open else now,
                reason=PAUSE_QUOTA,
                message=message,
                reset_named=named is not None,
                consecutive_5xx=0,
            )
            return not was_open
        if error_class == failures.SERVER:
            run = st.consecutive_5xx + 1
            if run >= OPEN_AFTER_5XX and not was_open:
                self._routes[route] = replace(
                    st,
                    open_until=now + BACKOFF,
                    opened_at=now,
                    reason=PAUSE_5XX,
                    message=message,
                    reset_named=False,
                    consecutive_5xx=run,
                )
                return True
            self._routes[route] = replace(st, consecutive_5xx=run)
        return False


BREAKER = OracleRouteBreaker()
"""The process-wide breaker. The client, the orchestrator, the doctor and the
bell read this one instance."""


__all__ = [
    "BACKOFF",
    "BREAKER",
    "MAX_PAUSE",
    "OPEN_AFTER_5XX",
    "PAUSE_5XX",
    "PAUSE_QUOTA",
    "OracleRouteBreaker",
    "RouteState",
    "iso",
    "parse_reset_time",
    "parse_retry_after",
    "route_key",
]
