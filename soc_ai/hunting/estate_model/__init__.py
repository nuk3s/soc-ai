"""The estate model: tier 3 peer groups and an estate outlier score, in shadow.

Decision 3 of the four-tier design (docs/dev/specs/2026-10-04-four-tier-
detection-methodology.md) allows scikit-learn and numpy for the work pure
Python cannot do at corporate scale. Nobody declares 20,000 roles, so the
model discovers peer groups by clustering one behaviour vector per host, and
it scores every host against the whole estate in one pass.

The parts:

* :mod:`.features`: one numeric vector per host from the stored profiles.
  Pure Python.
* :mod:`.fit`: standardize, cluster, score, explain, and the drift index.
  numpy and scikit-learn. Imported only after :func:`load_ml` succeeded.
* :mod:`.artifact`: the JSON model file, its sha256, and the loader that
  refuses a file whose hash the store does not record. Pure Python.
* :mod:`.job`: one daily run. Fit, record, append the hash to the audit chain,
  write the groups and the shadow observations.
* :mod:`.schedule`: the daily loop beside the profile build.

The extra is optional. This module imports neither numpy nor scikit-learn, and
nothing outside :mod:`.fit` does at import time. With the extra absent the job
logs one line and does nothing.
"""

from __future__ import annotations

import importlib
import importlib.util
from dataclasses import dataclass
from typing import Any

__all__ = [
    "ML_MODULES",
    "SPEC_ID",
    "STATISTIC",
    "MlModules",
    "load_ml",
    "ml_installed",
]

# The analytic id the observations carry, and the statistic they state.
SPEC_ID = "model-estate-outlier"
STATISTIC = "estate_outlier"

# The top-level packages the extra provides. scipy comes with scikit-learn.
ML_MODULES: tuple[str, ...] = ("numpy", "scipy", "sklearn")


def ml_installed() -> bool:
    """Whether the extra is installed, without importing it.

    The doctor and the Config console ask this inside the app process. An
    import of scikit-learn costs tens of megabytes of memory for as long as
    the process lives, so only the job, with the model switched on, imports it.
    A module blocked in ``sys.modules`` raises ``ValueError`` here, and that
    reads as absent too.
    """
    for name in ML_MODULES:
        try:
            if importlib.util.find_spec(name) is None:
                return False
        except (ImportError, ValueError):
            return False
    return True


@dataclass(frozen=True)
class MlModules:
    """The imported extra. The job passes it to :mod:`.fit`."""

    numpy: Any
    sklearn: Any


def load_ml() -> MlModules | None:
    """Import the extra, or None when it is absent or broken.

    A broken install raises something other than ImportError on import (a
    missing shared library raises OSError). Either way the model cannot run,
    and the caller says so in one line.
    """
    try:
        numpy = importlib.import_module("numpy")
        sklearn = importlib.import_module("sklearn")
        for name in ("sklearn.cluster", "sklearn.ensemble", "sklearn.metrics", "scipy.optimize"):
            importlib.import_module(name)
    except (ImportError, OSError):
        return None
    return MlModules(numpy=numpy, sklearn=sklearn)
