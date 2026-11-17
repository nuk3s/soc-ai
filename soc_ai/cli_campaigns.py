"""``soc-ai campaigns``: build the campaigns from the stored runs, and list them.

``rebuild`` reads the true positive runs that stand and the runs on their
sessions, and writes the campaigns. A campaign keeps its id over a rebuild.
``--dry-run`` builds the campaigns and writes no row. ``list`` prints the
stored campaigns.

The command reads and writes the local store only. It makes no grid query
and calls no model.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any

__all__ = ["count_line", "register_subparser"]


def _plural(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


def count_line(result: Any, *, dry_run: bool = False) -> str:
    """The one line that a rebuild prints."""
    k = int(result.unresolved_runs)
    verb = "investigation has" if k == 1 else "investigations have"
    line = (
        f"{_plural(int(result.campaigns), 'campaign')}, "
        f"{_plural(int(result.members), 'investigation')}. "
        f"{k} true positive {verb} an end that soc-ai cannot resolve to one machine."
    )
    if dry_run:
        line += " This is a dry run. soc-ai wrote no row."
    return line


def _draft_json(draft: Any) -> dict[str, Any]:
    from soc_ai.campaigns import words  # noqa: PLC0415 - lazy

    return {
        "title": words.title(draft),
        "bottom_line": words.bottom_line(draft),
        "stage": draft.stage,
        "parties": [
            {"machine_key": p.machine_key, "name": p.name, "role": p.role} for p in draft.parties
        ],
        "members": [
            {"run_id": m.run.run_id, "link": m.link.type, "stage": m.stage} for m in draft.members
        ],
    }


def _rebuild(args: argparse.Namespace) -> int:
    """Build the campaigns from the stored runs.

    Exit codes:
      0   the rebuild ran
      1   the store read or the store write failed
    """
    from soc_ai.campaigns import service  # noqa: PLC0415 - lazy
    from soc_ai.config import get_settings  # noqa: PLC0415 - lazy
    from soc_ai.store.db import (  # noqa: PLC0415 - lazy
        make_engine,
        make_sessionmaker,
        run_migrations,
    )

    settings = get_settings()
    dry_run = bool(args.dry_run)
    refresh = bool(getattr(args, "refresh_facts", False))

    async def _go() -> Any:
        engine = make_engine(settings)
        await run_migrations(engine)
        try:
            async with make_sessionmaker(engine)() as db:
                return await service.rebuild(db, dry_run=dry_run, refresh_facts=refresh)
        finally:
            await engine.dispose()

    try:
        result = asyncio.run(_go())
    except Exception as exc:
        print(f"soc-ai could not rebuild the campaigns: {type(exc).__name__}.", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps([_draft_json(d) for d in result.drafts], indent=2))
        return 0
    print(count_line(result, dry_run=dry_run))
    return 0


def _decision_word(row: Any) -> str:
    """The decision of a campaign row: the decision, ``waits`` for an active campaign with
    none, else ``none``."""
    if row.decision:
        return str(row.decision)
    return "waits" if row.waits_since is not None else "none"


def _expiry_words(row: Any) -> str:
    """The expiry of an authorized campaign, after its title. Empty for any other decision."""
    at = getattr(row, "authorization_expires_at", None)
    if row.decision != "authorized" or at is None:
        return ""
    verb = "expired" if getattr(row, "authorization_state", None) == "expired" else "expires"
    return f"  {verb} {at.strftime('%Y-%m-%d %H:%M')} UTC"


def _case_words(row: Any) -> str:
    """The Security Onion case of a campaign with the decision ``case``, after its title."""
    case_id = getattr(row, "case_id", None)
    if row.decision != "case" or not case_id:
        return ""
    return f"  case {case_id}"


def _list(_args: argparse.Namespace) -> int:
    """Print the id, the status, the stage, the decision, the period and the title of each
    campaign. An authorized campaign states its expiry after the title. A campaign with a
    case states the case id after the title.

    Exit codes:
      0   the list printed
    """
    from soc_ai.campaigns import service  # noqa: PLC0415 - lazy
    from soc_ai.config import get_settings  # noqa: PLC0415 - lazy
    from soc_ai.store.db import (  # noqa: PLC0415 - lazy
        make_engine,
        make_sessionmaker,
        run_migrations,
    )

    settings = get_settings()

    async def _go() -> list[Any]:
        engine = make_engine(settings)
        await run_migrations(engine)
        try:
            async with make_sessionmaker(engine)() as db:
                return list(await service.list_campaigns(db, active_only=False))
        finally:
            await engine.dispose()

    rows = asyncio.run(_go())
    if not rows:
        print("The store holds no campaign. Run `soc-ai campaigns rebuild` to build them.")
        return 0
    for row in rows:
        first, last = row.first_event.date().isoformat(), row.last_event.date().isoformat()
        period = first if first == last else f"{first} to {last}"
        print(
            f"{row.id:>5}  {row.status:<9}  {row.stage or 'none':<14}  "
            f"{_decision_word(row):<10}  {period}  {row.title}{_expiry_words(row)}"
            f"{_case_words(row)}"
        )
    return 0


def register_subparser(sub: Any) -> None:
    """Register the ``campaigns`` command group: ``rebuild`` and ``list``."""
    p_campaigns = sub.add_parser(
        "campaigns",
        help="The campaigns. Subcommands: `rebuild` builds the campaigns from the stored "
        "investigations. `list` prints them",
    )
    campaigns_sub = p_campaigns.add_subparsers(dest="campaigns_cmd")
    p_rebuild = campaigns_sub.add_parser(
        "rebuild",
        help="Build the campaigns from the stored investigations",
        description="Build the campaigns from the stored investigations. A campaign keeps its id. "
        "Exit codes: 0 the rebuild ran. 1 the store read or the store write failed.",
    )
    p_rebuild.add_argument(
        "--dry-run",
        action="store_true",
        help="Build the campaigns and write no row",
    )
    p_rebuild.add_argument(
        "--refresh-facts",
        action="store_true",
        help="Read the facts of every investigation again. Use it after the Hosts data changed",
    )
    p_rebuild.add_argument(
        "--json",
        action="store_true",
        help="Print each campaign as JSON: the title, the bottom line, the stage, the parties "
        "with their roles, and the investigations with their links and stages",
    )
    p_rebuild.set_defaults(func=_rebuild)
    p_list = campaigns_sub.add_parser(
        "list",
        help="Print the id, the status, the stage, the decision, the period and the title of "
        "each campaign. The decision is closed, authorized or case. An authorized campaign "
        "states its expiry after the title, and a campaign with a case states the case id. "
        "An active campaign with no decision reads waits",
    )
    p_list.set_defaults(func=_list)
    # `soc-ai campaigns` with no subcommand: print the group help instead of serving.
    p_campaigns.set_defaults(func=lambda _a: (p_campaigns.print_help(), 2)[1])
