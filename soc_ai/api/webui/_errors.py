"""One shape for every 4xx this API answers with.

A refusal carries two things. ``reason`` is the stable identifier the SPA
switches on. ``hint`` is one or two sentences that tell the analyst what to do
next. The second dogfood found eleven refusals with a reason and no hint, and
a bare ``lead_not_found`` on a red toast tells nobody what to try.

Import :func:`api_error` rather than raising ``HTTPException`` with a hand-built
detail. The helper is the one place the shape is written down.
"""

from __future__ import annotations

from fastapi import HTTPException


def api_error(status_code: int, reason: str, hint: str) -> HTTPException:
    """One refusal, with the identifier the app reads and the sentence a person reads."""
    return HTTPException(status_code=status_code, detail={"reason": reason, "hint": hint})
