"""What the package tree may carry into the wheel and the image.

hatch packages ``soc_ai`` wholesale and the Dockerfile copies the directory,
so anything that lands under it ships. A SQLite store is the one file that
must never: an empty one is noise next to the package, a real one is triage
history in a public artifact.
"""

from __future__ import annotations

from pathlib import Path

import soc_ai

_STORE_SUFFIXES = (".db", ".db-wal", ".db-shm", ".db-journal")


def test_no_sqlite_store_in_the_package_tree() -> None:
    root = Path(soc_ai.__file__).parent
    stray = sorted(
        str(p.relative_to(root)) for p in root.rglob("*") if p.name.endswith(_STORE_SUFFIXES)
    )
    assert stray == []
