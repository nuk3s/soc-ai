"""One catalog from two tiers.

Shipped analytics are YAML files on disk, versioned in the repository. Local
analytics are rows with spec text. A shipped analytic is live unless a state
row retires it. A local analytic runs only in shadow or live.

The sweeps read ``specs`` and ``shadow_ids``. The routes read ``listed`` and
``status_of``. The two sets differ on purpose: an analytic the analyst must see
is not the same as an analytic the loop must run, and a catalog that returned
one list for both questions either hid a retirement or ran it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.hunting.spec import CATALOG_DIR, HuntSpec, load_catalog, parse_spec
from soc_ai.store import analytics as analytics_store

__all__ = ["Catalog", "effective_catalog"]

_LOGGER = logging.getLogger(__name__)

# The local ids this process has already refused. The catalog is composed on
# every sweep, so a warning per composition would fill the log with one fact.
_REFUSED: set[str] = set()


@dataclass(frozen=True)
class Catalog:
    """The catalog as the sweeps and the routes each need to read it."""

    # The runnable analytics: shipped live, local shadow, and local live.
    specs: dict[str, HuntSpec]
    # Every analytic the app lists, runnable or not, with its parsed spec.
    listed: dict[str, HuntSpec]
    tiers: dict[str, tuple[str, str]] = field(default_factory=dict)
    shadow_ids: frozenset[str] = frozenset()

    def status_of(self, analytic_id: str) -> tuple[str, str]:
        """The tier and the status of one analytic.

        A shipped analytic with no state row is shipped and live. That is the
        default for the whole catalog, which is why the table holds only the
        analytics that depart from it.
        """
        return self.tiers.get(analytic_id, ("shipped", "live"))


async def effective_catalog(db: AsyncSession | None) -> Catalog:
    """Compose the catalog from the files on disk and the state table.

    ``db`` is None for a caller with no store, for example the CLI. The
    catalog is then the shipped tier, every analytic live. A local tier with
    no table to read it from is empty, and that is the honest answer.
    """
    shipped = load_catalog(CATALOG_DIR)
    states = await analytics_store.states(db) if db is not None else {}
    specs: dict[str, HuntSpec] = {}
    listed: dict[str, HuntSpec] = {}
    tiers: dict[str, tuple[str, str]] = {}
    shadow: set[str] = set()

    for spec_id, spec in shipped.items():
        state = states.get(spec_id)
        # Only a SHIPPED state row speaks for a shipped analytic. A local row
        # that took the id would otherwise retire the file on disk, or run its
        # own logic under the shipped title.
        status = state.status if state is not None and state.tier == "shipped" else "live"
        tiers[spec_id] = ("shipped", status)
        listed[spec_id] = spec
        if status == "live":
            specs[spec_id] = spec

    for spec_id, state in states.items():
        if state.tier != "local":
            continue
        if spec_id in shipped:
            if spec_id not in _REFUSED:
                _REFUSED.add(spec_id)
                _LOGGER.warning(
                    "local analytic %s has the id of a shipped analytic. soc-ai "
                    "ignores the local row and runs the shipped file.",
                    spec_id,
                )
            continue
        tiers[spec_id] = ("local", state.status)
        try:
            spec = parse_spec(state.spec_text or "")
        except ValueError as exc:
            # A row that no longer parses is listed so the analyst can repair
            # or retire it. It never runs. Dropping it from the list instead
            # would make an analytic disappear with no record of why.
            _LOGGER.warning("local analytic %s does not parse: %s", spec_id, exc)
            stand_in = _placeholder(spec_id, str(exc))
            if stand_in is not None:
                listed[spec_id] = stand_in
            continue
        listed[spec_id] = spec
        if state.status in ("shadow", "live"):
            specs[spec_id] = spec
        if state.status == "shadow":
            shadow.add(spec_id)

    return Catalog(specs=specs, listed=listed, tiers=tiers, shadow_ids=frozenset(shadow))


# A detection clause no document carries, so a placeholder cannot match if a
# caller ever hands one to the query path.
_NEVER_MATCHES = "soc-ai: this analytic does not parse"


def _placeholder(spec_id: str, detail: str) -> HuntSpec | None:
    """A listable stand-in for a local row whose text no longer parses.

    The row was dropped from the list, so the detail route raised a KeyError
    and the analyst could neither read the error nor retire the analytic. The
    placeholder carries the id, says so in its title and puts the parser's
    message in the description.
    """
    try:
        return HuntSpec.model_validate(
            {
                "id": spec_id,
                "title": f"{spec_id} (does not parse)",
                "description": f"soc-ai could not read this analytic. {detail}",
                "detection": {"all": [{"field": "event.code", "value": _NEVER_MATCHES}]},
            }
        )
    except ValueError as exc:
        # An id that is not a slug cannot even be a placeholder. It is logged
        # and dropped, which is the one case where the list loses a row.
        _LOGGER.warning("local analytic %s cannot be listed at all: %s", spec_id, exc)
        return None
