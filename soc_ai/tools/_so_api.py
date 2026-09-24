"""Request-shape helpers shared by the Security Onion write tools.

Security Onion's web API takes a human date range on the routes that resolve a
document set server-side (``/api/events/ack``, ``/api/case/events``) because the
web UI builds one from its date picker. soc-ai has no picker, so it sends a
range wide enough to cover anything the agent could be triaging and lets the
per-document pin do the narrowing.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

# The SO server parses the range with Go's ``time.Parse``, so the FORMAT it
# expects is the canonical Go reference time (2006-01-02T15:04:05) projected
# through the layout the web UI uses (i18n.timePickerSample, en-us). Sending a
# moment.js-style format string here returns 400 "could not be processed".
DATE_RANGE_FORMAT = "2006/01/02 3:04:05 PM"

# The strftime layout that produces a value SO can parse with DATE_RANGE_FORMAT.
_STRFTIME_LAYOUT = "%Y/%m/%d %I:%M:%S %p"

# SO's default timezone when the caller has no configured one.
DEFAULT_TIMEZONE = "America/New_York"


def wide_date_range(now: datetime | None = None, *, days: int = 365) -> str:
    """A ``days``-wide date range string in the format SO expects."""
    now = now or datetime.now(UTC)
    start = now - timedelta(days=days)
    return f"{start.strftime(_STRFTIME_LAYOUT)} - {now.strftime(_STRFTIME_LAYOUT)}"


__all__ = ["DATE_RANGE_FORMAT", "DEFAULT_TIMEZONE", "wide_date_range"]
