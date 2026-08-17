"""Demo hunt-start selection — pick the canned hunt the demo answers with.

In demo mode ``POST /api/v1/hunts/chat`` neither runs nor replays a hunt: the
egress guard blocks the model, and persisting a fresh Hunt row (plus a background
task) per anonymous POST would let a visitor grow the store without bound —
finding ``demo-readonly-contract-violated-by-hunt-start``. Instead the route
returns the id of a SEEDED canned hunt: already a complete store row
(``seed_fixtures`` at startup) carrying its narrative + timeline + report, so the
SPA polls ``GET /api/v1/hunts/{id}`` and renders a finished hunt. The return is a
read — the hunt-side mirror of ``routes_chat._demo_thread``. This module owns the
selection of that canned hunt.
"""

from __future__ import annotations

from typing import Any, cast


def pick_canned_hunt(fixtures: dict[str, Any] | None) -> dict[str, Any] | None:
    """The first seeded hunt whose events include a ``hunt_report`` — the hunt the
    demo hunt-start answers with.

    *fixtures* is the cached fixture document (``app.state.demo_fixtures``) —
    ``None`` when the fixture file was missing/invalid at startup (fail-soft
    boot). A ``hunt_report`` event is REQUIRED, not merely any event: only a hunt
    that carries a report was seeded as a complete row worth showing; a
    report-less row renders as an empty/errored hunt.
    """
    for hunt in (fixtures or {}).get("hunts") or []:
        if not isinstance(hunt, dict):
            continue
        events = hunt.get("events") or []
        if any(isinstance(e, dict) and e.get("kind") == "hunt_report" for e in events):
            return cast("dict[str, Any]", hunt)
    return None
