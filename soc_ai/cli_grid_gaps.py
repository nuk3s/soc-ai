"""``soc-ai grid-gaps``: record a grid gap soc-ai did not see, and list the ledger.

soc-ai records a gap when its health probe or its profile sweep sees one. It
sees nothing while it is down itself, and it saw nothing before the ledger
existed. The range outage of 2026-10-15 to 2026-10-19 has no row for that
reason (dogfood 2026-10-19, R1-I5). ``add`` records such a gap with the
source ``operator``. Every reader then treats the hours as unknown: the
profile sweep and the baseline skip them, the hit limit leaves out their hits,
and the pages show the gap strip.

The command reads and writes the local store only, so it works while the grid
is down. It writes no audit record: the audit trail lives on the grid. The
route ``POST /api/v1/grid/gaps`` writes one.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import UTC, datetime, timedelta
from typing import Any

__all__ = ["register_subparser"]

# How far back ``list`` reads when the operator names no window.
_DEFAULT_LIST_DAYS = 30


def _moment(raw: str, *, flag: str) -> datetime:
    """An ISO-8601 value as aware UTC. A time with no zone is UTC."""
    try:
        value = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            f"{flag} must be an ISO 8601 timestamp, for example 2026-10-15T13:36:00Z."
        ) from exc
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _add(args: argparse.Namespace) -> int:
    """Record one operator gap.

    Exit codes:
      0   the gap is on record
      1   the store write failed
      2   a value is wrong, or the ledger refused the gap
    """
    from soc_ai.config import get_settings  # noqa: PLC0415 - lazy
    from soc_ai.store import grid_gaps  # noqa: PLC0415 - lazy
    from soc_ai.store.db import (  # noqa: PLC0415 - lazy
        make_engine,
        make_sessionmaker,
        run_migrations,
    )

    try:
        start = _moment(str(args.start), flag="--start")
        end = _moment(str(args.end), flag="--end")
        grid_gaps.check_operator_span(start, end)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    settings = get_settings()

    async def _go() -> tuple[Any, bool]:
        engine = make_engine(settings)
        await run_migrations(engine)
        try:
            async with make_sessionmaker(engine)() as db:
                return await grid_gaps.record_operator_gap(
                    db, started_at=start, ended_at=end, detail=str(args.detail or "")
                )
        finally:
            await engine.dispose()

    try:
        row, created = asyncio.run(_go())
    except grid_gaps.GapRefused as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"The store did not record the gap: {type(exc).__name__}.", file=sys.stderr)
        return 1
    if created:
        print(f"Recorded grid gap {row.id}. {grid_gaps.describe(row)}")
    else:
        print(f"Grid gap {row.id} holds these hours already. soc-ai recorded nothing new.")
    print(
        "soc-ai reads these hours as unknown. "
        "Open a page that shows the gap to review the hits it wrote."
    )
    return 0


def _list(args: argparse.Namespace) -> int:
    """Print the gaps that overlap the last ``--days`` days, oldest first.

    Exit codes:
      0   the list printed
    """
    from soc_ai.config import get_settings  # noqa: PLC0415 - lazy
    from soc_ai.store import grid_gaps  # noqa: PLC0415 - lazy
    from soc_ai.store.db import (  # noqa: PLC0415 - lazy
        make_engine,
        make_sessionmaker,
        run_migrations,
    )

    settings = get_settings()
    now = datetime.now(UTC)
    days = max(1, int(args.days))

    async def _go() -> list[Any]:
        engine = make_engine(settings)
        await run_migrations(engine)
        try:
            async with make_sessionmaker(engine)() as db:
                return await grid_gaps.overlapping(db, since=now - timedelta(days=days), until=now)
        finally:
            await engine.dispose()

    rows = asyncio.run(_go())
    if not rows:
        print(f"The ledger holds no grid gap in the last {days} days.")
        return 0
    for row in rows:
        end = grid_gaps.stamp(row.ended_at) if row.ended_at is not None else "open"
        hours = grid_gaps.gap_hours(row, now=now)
        detail = f"  {row.detail}" if row.detail else ""
        print(
            f"{row.id:>5}  {row.source:<8}  {grid_gaps.stamp(row.started_at)} to {end}  "
            f"{hours:.1f} h{detail}"
        )
    return 0


def register_subparser(sub: Any) -> None:
    """Register the ``grid-gaps`` command group: ``add`` and ``list``."""
    p_gaps = sub.add_parser(
        "grid-gaps",
        help="The grid-gap ledger. Subcommands: `add` records a gap that soc-ai did not "
        "see. `list` prints the gaps",
    )
    gaps_sub = p_gaps.add_subparsers(dest="grid_gaps_cmd")
    p_add = gaps_sub.add_parser(
        "add",
        help="Record a grid gap that soc-ai did not see",
        description="Record a grid gap that soc-ai did not see. soc-ai then reads the hours "
        "as unknown. The ledger refuses an end at or before the start, a span over 30 days, "
        "and a start or an end in the future. Exit codes: 0 the gap is on record. 1 the "
        "store write failed. 2 a value is wrong, or the ledger refused the gap.",
    )
    p_add.add_argument(
        "--start",
        required=True,
        help="When the grid data stopped, as ISO 8601. A time with no zone is UTC",
    )
    p_add.add_argument(
        "--end",
        required=True,
        help="When the grid data came back, as ISO 8601. A time with no zone is UTC",
    )
    p_add.add_argument(
        "--detail",
        default="",
        help="What happened, for example: The sensor VM was down",
    )
    p_add.set_defaults(func=_add)
    p_list = gaps_sub.add_parser("list", help="Print the grid gaps, oldest first")
    p_list.add_argument(
        "--days",
        type=int,
        default=_DEFAULT_LIST_DAYS,
        help=f"How many days back to read. The default is {_DEFAULT_LIST_DAYS}",
    )
    p_list.set_defaults(func=_list)
    # `soc-ai grid-gaps` with no subcommand: print the group help instead of serving.
    p_gaps.set_defaults(func=lambda _a: (p_gaps.print_help(), 2)[1])
