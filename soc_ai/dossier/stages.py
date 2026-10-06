"""Per-stage wall time and search counts for the long sweeps.

The dossier sweep and the profile build run for minutes on a large estate,
and the run row held a start and a finish only. Nobody could say which stage
the minutes went to, or how many searches each one sent to the grid. Every
statement about cost at scale was an estimate from log stamps, with other
loops running in the same window.

Two small pieces fix that:

* :class:`CountingGrid` wraps the grid client and counts the searches made
  through it. Everything else passes through untouched.
* :class:`StageClock` times named stages, reads the search count before and
  after each one, and logs one INFO line per stage.

Neither changes what a sweep does. A stage that raises is still timed and
logged, and the exception goes on to the caller.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

__all__ = ["CountingGrid", "Stage", "StageClock", "counting"]

_LOGGER = logging.getLogger(__name__)


class CountingGrid:
    """The grid client, with a count of the searches made through it.

    Delegates every attribute it does not define, so a caller that reads
    ``max_buckets`` or any other method gets the wrapped client's own. A
    wrapped client that lacks an attribute still lacks it here, and
    ``getattr(grid, name, None)`` still answers ``None``.
    """

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.searches = 0

    @property
    def inner(self) -> Any:
        return self._inner

    async def search(self, *args: Any, **kwargs: Any) -> Any:
        self.searches += 1
        return await self._inner.search(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def counting(grid: Any) -> CountingGrid:
    """``grid`` as a :class:`CountingGrid`. One already wrapped is returned as is."""
    return grid if isinstance(grid, CountingGrid) else CountingGrid(grid)


@dataclass
class Stage:
    """One timed stage."""

    name: str
    seconds: float = 0.0
    searches: int = 0
    # A short fact about the stage: "200 hosts", "4 batches".
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "seconds": round(self.seconds, 3),
            "searches": self.searches,
            "detail": self.detail,
        }


@dataclass
class StageClock:
    """Times the stages of one run and logs one line per stage.

    ``label`` opens each log line: ``dossier sweep stage census: 0.41 s,
    1 search``. ``grid`` is the counting client the run sends its searches
    through. Without one, every stage reports 0 searches.
    """

    label: str
    grid: CountingGrid | None = None
    stages: list[Stage] = field(default_factory=list)
    logger: logging.Logger = _LOGGER

    @contextmanager
    def stage(self, name: str) -> Iterator[Stage]:
        """Time the block. The yielded :class:`Stage` takes a ``detail``."""
        record = Stage(name=name)
        before = self.grid.searches if self.grid is not None else 0
        started = time.perf_counter()
        try:
            yield record
        finally:
            record.seconds = time.perf_counter() - started
            record.searches = (self.grid.searches if self.grid is not None else 0) - before
            self.stages.append(record)
            self.logger.info(
                "%s stage %s: %.2f s, %d search%s%s",
                self.label,
                record.name,
                record.seconds,
                record.searches,
                "" if record.searches == 1 else "es",
                f", {record.detail}" if record.detail else "",
            )

    def as_dicts(self) -> list[dict[str, Any]]:
        return [s.as_dict() for s in self.stages]

    @property
    def total_seconds(self) -> float:
        return sum(s.seconds for s in self.stages)

    @property
    def total_searches(self) -> int:
        return sum(s.searches for s in self.stages)
