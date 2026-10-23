"""A load-tolerant check that a cost grows linearly with its input.

The ReDoS tests use it. A stopwatch bound measures the machine, so it passes on
an idle box and fails on a loaded CI runner. This check times the same work on a
small input and on an input :data:`SCALE_STEP` times larger, and returns the
ratio. A linear cost reads about 4, and a quadratic cost reads about 16.
:data:`LINEAR_BOUND` sits between them with room for runner noise on both sides.

The runs are interleaved and the best of each is kept, so both inputs see the
same load. A doubled input with a bound of 3.0 read 3.07 and 3.16 for a linear
pattern on a loaded GitHub runner. The control in
tests/test_narrative_grounding.py proves that the same check fails a quadratic
pattern.
"""

from __future__ import annotations

import time
from collections.abc import Callable

SCALE_STEP = 4
LINEAR_BOUND = 8.0


def scaling[T](run: Callable[[T], object], small: T, large: T, *, rounds: int = 7) -> float:
    """How much longer ``run`` takes on ``large`` than on ``small``.

    The best of ``rounds`` interleaved runs: each round times the small input
    and then the large one. One run measures the scheduler as much as the work.
    """
    best_small = best_large = float("inf")
    for _ in range(rounds):
        start = time.perf_counter()
        run(small)
        best_small = min(best_small, time.perf_counter() - start)
        start = time.perf_counter()
        run(large)
        best_large = min(best_large, time.perf_counter() - start)
    return best_large / max(best_small, 1e-6)
