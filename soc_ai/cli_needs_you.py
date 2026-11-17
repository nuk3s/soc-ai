"""``soc-ai needs-you``: list the investigations that wait, and clear the old ones.

``list`` prints each investigation of Needs you: the set of
``GET /needs-you/items`` of the type investigation. A lead and a campaign have
their own decisions, and the list holds neither. ``clear`` takes each
investigation of that list whose event is before ``--before``, with the reason
of ``--reason``. ``--dry-run`` prints what a clear takes and writes nothing.
With no ``--yes`` the command prints the count and asks for a typed "yes".
``restore`` undoes the clear of one investigation.

The rules are in :mod:`soc_ai.webui.needs_you_clear`. The command works on
the store of the install. It writes nothing to Security Onion. A clear and a
restore write their audit records to the audit index first, and a failed
record stops them. The action rule reads the alert anchors of hunt findings
from the grid, as the console does.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import getpass
import json
import sys
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

__all__ = ["register_subparser"]

_VERDICT_WORDS = {"true_positive": "true positive", "needs_more_info": "needs more info"}


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _date(text: str) -> datetime:
    """A date or an ISO-8601 time, as naive UTC. A date is its midnight, UTC."""
    try:
        at = datetime.fromisoformat(text.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"{text!r} is not a date. Write the date as YYYY-MM-DD."
        ) from exc
    if at.tzinfo is not None:
        at = at.astimezone(UTC).replace(tzinfo=None)
    return at


def _day(at: datetime | None) -> str:
    return at.date().isoformat() if at is not None else "unknown"


def _line(item: Any) -> str:
    verdict = _VERDICT_WORDS.get(item.verdict, item.verdict)
    machines = f"{item.source or 'unknown'} to {item.destination or 'unknown'}"
    actions = f"  {_plural(item.actions, 'action waits', 'actions wait')}" if item.actions else ""
    return (
        f"{item.id}  {verdict:<15}  event {_day(item.event_at)}  waits since "
        f"{_day(item.since)}  {item.title}  {machines}{actions}"
    )


def _json(item: Any) -> dict[str, Any]:
    return {
        "id": item.id,
        "verdict": item.verdict,
        "event_at": item.event_at.isoformat() if item.event_at else None,
        "waits_since": item.since.isoformat() if item.since else None,
        "title": item.title,
        "source": item.source,
        "destination": item.destination,
        "waiting_actions": item.actions,
    }


def _audit_logger(settings: Any, elastic: Any) -> Any:
    """The audit logger of a clear. A test replaces it."""
    from soc_ai.audit.logger import AuditLogger  # noqa: PLC0415 - lazy

    return AuditLogger(settings, elastic)


def _with_store[T](work: Callable[[Any, Any, Any], Awaitable[T]]) -> T:
    """Open the store and the grid client, and give ``work`` the session, the state
    and the settings."""
    from soc_ai.config import get_settings  # noqa: PLC0415 - lazy
    from soc_ai.so_client.elastic import ElasticClient  # noqa: PLC0415 - lazy
    from soc_ai.store.db import (  # noqa: PLC0415 - lazy
        make_engine,
        make_sessionmaker,
        run_migrations,
    )

    settings = get_settings()

    async def go() -> T:
        engine = make_engine(settings)
        elastic = ElasticClient(settings)
        # The action rule reads the grid client and the settings from the app state.
        state = SimpleNamespace(settings=settings, elastic=elastic)
        try:
            await run_migrations(engine)
            async with make_sessionmaker(engine)() as db:
                return await work(db, state, settings)
        finally:
            with contextlib.suppress(Exception):
                await elastic.aclose()
            await engine.dispose()

    return asyncio.run(go())


def _read(before: datetime | None, only: str | None) -> list[Any]:
    from soc_ai.webui import needs_you_clear  # noqa: PLC0415 - lazy

    async def work(db: Any, state: Any, _settings: Any) -> list[Any]:
        return await needs_you_clear.waiting_investigations(
            db, state=state, before=before, only=only
        )

    return _with_store(work)


def _list(args: argparse.Namespace) -> int:
    """Print each investigation that waits, the oldest event first.

    Exit codes:
      0   the list printed
      1   the store read failed
    """
    try:
        items = _read(args.before, None)
    except Exception as exc:
        print(f"soc-ai could not read Needs you: {type(exc).__name__}.", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps([_json(i) for i in items], indent=2))
        return 0
    for item in items:
        print(_line(item))
    verb = "investigation waits" if len(items) == 1 else "investigations wait"
    print(f"{len(items)} {verb}.")
    return 0


def _user(args: argparse.Namespace) -> str:
    """The user of the audit record: ``--by``, else the user of the shell."""
    if args.by and str(args.by).strip():
        return str(args.by).strip()
    try:
        return getpass.getuser() or "operator"
    except (KeyError, OSError):
        return "operator"


def _confirmed(count: int) -> bool:
    noun = _plural(count, "investigation", "investigations")
    print(f"Type yes to clear {noun} from Needs you: ", end="", flush=True)
    try:
        answer = sys.stdin.readline()
    except (OSError, ValueError):
        return False
    return answer.strip() == "yes"


def _clear(args: argparse.Namespace) -> int:
    """Clear the investigations of Needs you with an event before ``--before``.

    Exit codes:
      0   the clear is done, or there is nothing to clear, or --dry-run
      1   the store or the audit record failed. The clear stopped there
      2   soc-ai refused: no reason, a date that has not come, or no "yes"
    """
    from soc_ai.webui import needs_you_clear  # noqa: PLC0415 - lazy

    try:
        reason = needs_you_clear.check_reason(args.reason)
        before = needs_you_clear.check_before(args.before)
    except ValueError as exc:
        print(f"soc-ai cleared nothing. {exc}", file=sys.stderr)
        return 2
    try:
        items = _read(before, args.only)
    except Exception as exc:
        print(f"soc-ai could not read Needs you: {type(exc).__name__}.", file=sys.stderr)
        return 1
    if not items:
        print(f"No investigation of Needs you has an event before {before.isoformat()}.")
        return 0
    for item in items:
        print(_line(item))
    noun = _plural(len(items), "investigation", "investigations")
    if args.dry_run:
        print(f"soc-ai wrote nothing. Without --dry-run, soc-ai clears these {noun}.")
        return 0
    if not args.yes and not _confirmed(len(items)):
        print("soc-ai cleared nothing.")
        return 2
    shown = {item.id for item in items}
    by = _user(args)

    async def work(db: Any, state: Any, settings: Any) -> Any:
        # The investigations that still wait, and only the ones the list showed.
        now = await needs_you_clear.waiting_investigations(
            db, state=state, before=before, only=args.only
        )
        return await needs_you_clear.clear_items(
            db,
            [item for item in now if item.id in shown],
            reason=reason,
            by=by,
            audit=_audit_logger(settings, state.elastic),
            state=state,
        )

    try:
        result = _with_store(work)
    except Exception as exc:
        print(f"soc-ai could not clear Needs you: {type(exc).__name__}.", file=sys.stderr)
        return 1
    cleared = _plural(len(result.cleared), "investigation", "investigations")
    dismissed = _plural(result.dismissed, "waiting action", "waiting actions")
    print(f"soc-ai cleared {cleared} from Needs you and dismissed {dismissed}.")
    if result.failed is not None:
        print(
            f"soc-ai could not write the audit record for {result.failed}: {result.error}. "
            "The clear stopped there. The investigations after it still wait.",
            file=sys.stderr,
        )
        return 1
    return 0


def _restore(args: argparse.Namespace) -> int:
    """Undo the clear of one investigation.

    Exit codes:
      0   the investigation waits again
      1   the store or the audit record failed
      2   the investigation holds no clear
    """
    from soc_ai.webui import needs_you_clear  # noqa: PLC0415 - lazy

    by = _user(args)

    async def work(db: Any, state: Any, settings: Any) -> Any:
        return await needs_you_clear.restore(
            db, args.investigation_id, by=by, audit=_audit_logger(settings, state.elastic)
        )

    try:
        result = _with_store(work)
    except needs_you_clear.NotClearedError:
        print(
            f"Investigation {args.investigation_id} holds no clear from Needs you.",
            file=sys.stderr,
        )
        return 2
    except Exception as exc:
        print(f"soc-ai could not restore the investigation: {type(exc).__name__}.", file=sys.stderr)
        return 1
    waits = _plural(result.restored_actions, "action waits", "actions wait")
    print(f"soc-ai restored investigation {result.investigation_id} to Needs you. {waits} again.")
    return 0


def register_subparser(sub: Any) -> None:
    """Register the ``needs-you`` command group: ``list``, ``clear`` and ``restore``."""
    from soc_ai.webui.needs_you_clear import ONLY_VERDICTS  # noqa: PLC0415 - lazy

    p_group = sub.add_parser(
        "needs-you",
        help="The investigations of Needs you. Subcommands: `list` prints them. `clear` "
        "clears the old ones. `restore` undoes the clear of one investigation",
    )
    group_sub = p_group.add_subparsers(dest="needs_you_cmd")
    p_list = group_sub.add_parser(
        "list",
        help="Print the investigations that wait, the oldest event first",
        description="Print the id, the verdict, the event date, the date it started to wait, "
        "the title and the two machines of each investigation that waits. Exit codes: 0 the "
        "list printed. 1 the store read failed.",
    )
    p_list.add_argument(
        "--before",
        type=_date,
        default=None,
        help="Print only the investigations with an event before this date, YYYY-MM-DD in UTC",
    )
    p_list.add_argument("--json", action="store_true", help="Print the list as JSON")
    p_list.set_defaults(func=_list)
    p_clear = group_sub.add_parser(
        "clear",
        help="Clear the investigations with an event before a date from Needs you",
        description="Clear the investigations with an event before --before from Needs you. "
        "The verdict does not change. A true positive gets a dismissal of each waiting action. "
        "Each clear writes its audit record first. Exit codes: 0 the clear is done. 1 the "
        "store or the audit record failed. 2 soc-ai refused the command.",
    )
    p_clear.add_argument(
        "--before",
        type=_date,
        required=True,
        help="Clear the investigations with an event before this date, YYYY-MM-DD in UTC",
    )
    p_clear.add_argument(
        "--reason",
        required=True,
        help="The reason of the clear. The audit record and the investigation page show it",
    )
    p_clear.add_argument(
        "--only",
        choices=ONLY_VERDICTS,
        default=None,
        help="Clear the investigations with this verdict only",
    )
    p_clear.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the investigations that a clear takes, and write nothing",
    )
    p_clear.add_argument("--yes", action="store_true", help="Clear with no question")
    p_clear.add_argument(
        "--by",
        default=None,
        help="The user of the audit record. The default is the user of the shell",
    )
    p_clear.set_defaults(func=_clear)
    p_restore = group_sub.add_parser(
        "restore",
        help="Undo the clear of one investigation",
        description="Remove the clear record of the investigation and undo the dismissals "
        "of that clear. Exit codes: 0 the investigation waits again. 1 the store or the "
        "audit record failed. 2 the investigation holds no clear.",
    )
    p_restore.add_argument("investigation_id", help="The id of the investigation")
    p_restore.add_argument(
        "--by",
        default=None,
        help="The user of the audit record. The default is the user of the shell",
    )
    p_restore.set_defaults(func=_restore)
    # `soc-ai needs-you` with no subcommand: print the group help instead of serving.
    p_group.set_defaults(func=lambda _a: (p_group.print_help(), 2)[1])
