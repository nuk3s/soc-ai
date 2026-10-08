"""Per-user Dashboard layout: where each Dashboard panel sits on the grid.

The console draws the Dashboard on a grid of :data:`GRID_COLS` columns and
keeps one layout per user. A layout is a list of slots, one per panel:
``{"id", "x", "y", "w", "h"}``. ``x`` and ``w`` count columns; ``y`` and ``h``
count grid rows. The console decides what a row is; the store checks only that
each slot names a panel the console has and fits the grid.

Every function here takes ``user_id`` and puts it in the WHERE clause, the same
model as :mod:`soc_ai.store.saved_views`: another user's layout is not
forbidden, it is not there.

:data:`PANEL_IDS` is a contract with ``frontend/src/lib/dashboardLayout.ts``.
``tests/test_dashboard_layout.py`` fails when the two lists differ.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, TypedDict, TypeGuard

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.models import DashboardLayout

PANEL_IDS: tuple[str, ...] = (
    "kpi-alert-events",
    "kpi-awaiting",
    "kpi-true-positives",
    "kpi-running",
    "kpi-shadow-hits",
    "outcomes",
    "recent",
    "setup-health",
    "assistant",
    "auto-investigate",
    "verdict-quality",
    "enrichment",
    "detection-tuning",
    "host-dossier",
)

GRID_COLS = 12
# A row is 4 px in the console, so these allow a panel 4,000 px tall and a
# layout 40,000 px deep. Both are far past any real Dashboard; they exist so a
# write cannot store an unbounded number.
MAX_Y = 10_000
MAX_H = 1_000


class PanelSlot(TypedDict):
    id: str
    x: int
    y: int
    w: int
    h: int


class LayoutInvalidError(ValueError):
    """A layout the grid cannot place. The route turns it into the house 400."""

    def __init__(self, reason: str, hint: str) -> None:
        super().__init__(hint)
        self.reason = reason
        self.hint = hint


def _is_int(value: Any) -> TypeGuard[int]:
    # bool is an int subclass, and True is not a column.
    return isinstance(value, int) and not isinstance(value, bool)


def _fits(x: int, y: int, w: int, h: int) -> bool:
    return x >= 0 and w >= 1 and x + w <= GRID_COLS and 0 <= y <= MAX_Y and 1 <= h <= MAX_H


def validate_panels(panels: list[PanelSlot]) -> list[PanelSlot]:
    """Refuse a layout the grid cannot place; return it as plain slots.

    Raises :class:`LayoutInvalidError` for a panel id the console does not
    have, a second slot for one panel, or a slot outside the grid. An empty
    list is valid: the console then places every panel in its shipped slot.
    """
    if len(panels) > len(PANEL_IDS):
        raise LayoutInvalidError(
            "too_many_panels",
            f"A layout holds at most {len(PANEL_IDS)} panels.",
        )
    seen: set[str] = set()
    out: list[PanelSlot] = []
    for slot in panels:
        pid = slot["id"]
        if pid not in PANEL_IDS:
            raise LayoutInvalidError(
                "unknown_panel",
                f"The Dashboard has no panel {pid!r}.",
            )
        if pid in seen:
            raise LayoutInvalidError(
                "duplicate_panel",
                f"The layout names the panel {pid!r} two times.",
            )
        seen.add(pid)
        x, y, w, h = slot["x"], slot["y"], slot["w"], slot["h"]
        if not all(_is_int(v) for v in (x, y, w, h)) or not _fits(x, y, w, h):
            raise LayoutInvalidError(
                "outside_grid",
                f"The panel {pid!r} must fit the grid: x from 0, w from 1, "
                f"x plus w at most {GRID_COLS}, y from 0 to {MAX_Y}, h from 1 to {MAX_H}.",
            )
        out.append({"id": pid, "x": x, "y": y, "w": w, "h": h})
    return out


def sanitize_panels(raw: Any) -> list[PanelSlot]:
    """A stored layout made safe to serve.

    A slot for a panel a later release removed, a malformed slot and a second
    slot for one panel are dropped. The console places each panel the layout
    does not name in its shipped slot.
    """
    out: list[PanelSlot] = []
    if not isinstance(raw, list):
        return out
    seen: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        pid = entry.get("id")
        if not isinstance(pid, str) or pid not in PANEL_IDS or pid in seen:
            continue
        x, y, w, h = entry.get("x"), entry.get("y"), entry.get("w"), entry.get("h")
        if _is_int(x) and _is_int(y) and _is_int(w) and _is_int(h) and _fits(x, y, w, h):
            seen.add(pid)
            out.append({"id": pid, "x": x, "y": y, "w": w, "h": h})
    return out


async def get_layout(db: AsyncSession, user_id: int) -> DashboardLayout | None:
    """This user's layout row, or None when the user keeps the shipped one."""
    row: DashboardLayout | None = await db.scalar(
        select(DashboardLayout).where(DashboardLayout.user_id == user_id)
    )
    return row


async def put_layout(db: AsyncSession, user_id: int, panels: list[PanelSlot]) -> DashboardLayout:
    """Store this user's layout, replacing the one before.

    The caller validates first (:func:`validate_panels`). Two saves at once
    for one user race on the primary key; the loser updates the winner's row.
    """
    now = datetime.now(UTC).replace(tzinfo=None)
    stored = [dict(p) for p in panels]
    row = await get_layout(db, user_id)
    if row is None:
        row = DashboardLayout(user_id=user_id, panels_json=stored, updated_at=now)
        db.add(row)
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
            row = await get_layout(db, user_id)
            if row is None:  # pragma: no cover - the user row itself is gone
                raise
        else:
            await db.refresh(row)
            return row
    row.panels_json = stored
    row.updated_at = now
    await db.commit()
    await db.refresh(row)
    return row


async def delete_layout(db: AsyncSession, user_id: int) -> bool:
    """Drop this user's layout. False when the user had none."""
    result = await db.execute(delete(DashboardLayout).where(DashboardLayout.user_id == user_id))
    await db.commit()
    return bool(getattr(result, "rowcount", 0))
