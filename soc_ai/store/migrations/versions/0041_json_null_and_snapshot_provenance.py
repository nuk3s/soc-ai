"""Two things a NULL could not say, and one a snapshot could not

**Part 1 — ten nullable JSON columns held the text ``null``, not SQL NULL.**

SQLAlchemy's ``JSON`` type defaults to ``none_as_null=False``, so a Python
``None`` goes through ``json.dumps`` and lands as the two-byte string ``null``:
a JSON value, not an absence. It deserialises back to ``None``, which is why it
survived years of review — every assertion in the suite spelled
``row.col is None`` and every one of them passed. SQL is where it shows.
``WHERE col IS NOT NULL`` matched every row, ``WHERE col IS NULL`` matched none,
in ten tables at once.

Nothing was broken at the time, because every reader coalesces (``or []``,
``or {}``). That is the whole problem: the columns were a loaded trap for the
first query that asked whether a lane held anything, and one subsystem had
already stepped in it — a cleared dossier override stored as ``'null'`` reads as
still held forever, which is why :mod:`soc_ai.store.host_dossier` carries a
per-statement ``null()`` workaround for three of these columns. It never covered
``dossier_run.errors``/``notes`` in the same subsystem. The fix moved to the
type (:data:`soc_ai.store.models.NULLABLE_JSON`), where it cannot be forgotten.

**Existing rows are normalised, and here is why.** The type change only governs
writes from here on. Leaving history as ``'null'`` would make the table
inconsistent rather than merely wrong: the query that motivated all this would
work on this month's rows and silently skip everything older, which is a worse
trap than the uniform one it replaces — a half-true answer does not announce
itself. Doing nothing was the alternative, and it fails the one test that
matters, which is whether the next person's ``IS NOT NULL`` returns the truth.

The predicate is exact and cannot take a legitimate value with it. A Python
string ``"null"`` serialises to ``'"null"'``, five characters with the quotes;
only a ``None`` bound under the old default produces the bare four-byte
``null``. So ``WHERE col = 'null'`` selects the defect and nothing else.

Sizes: nine of the ten tables are small (``quality_snapshots`` is capped at 90
rows, ``model_battery_results`` at one per model, the dossier tables at one row
per field per host). ``investigations``/``hunts``/``chat_messages`` grow, but
this is one unindexed full-table UPDATE per column, once, on a local SQLite
file. Measured shape rather than measured time: the largest observed store holds
low hundreds of investigations.

The downgrade does NOT put ``'null'`` back. Once a row is SQL NULL there is no
way to tell it from one that was always NULL, and rewriting all of them would
invent history. Reverting the code is enough to restore the old behaviour for
new writes, which is the only thing a downgrade can honestly promise.

**Part 2 — quality snapshots could not say what was running.**

Three nullable columns on ``quality_snapshots``. The trend recorded the numbers
and nothing about the instrument, so a regression could not be attributed to a
change: ``app_version`` for the running release, ``code_commit`` for the build
inside it (both deployments run the image as ``:latest``, so the version alone
cannot tell two builds of 1.5.0 apart — the commit is stamped into the image at
build time via ``ARG SOC_AI_COMMIT``), and ``analyst_model`` for the route the
batch actually ran against, because the failure this subsystem exists to catch
is a model bump, which changes no code at all.

NULL and no backfill, for the reason 0026 and 0027 gave before it: a pre-0040
row genuinely does not know what produced it. Inventing a version for old rows
would say the trend has been on this build all along, and the one question these
columns exist to answer is exactly where it changed.

Both parts ride one revision because both are bookkeeping on the same
deployment step and neither is worth a restart of its own.

SQLite ADD COLUMN is metadata-only for nullable columns without a default, so
Part 2 is O(1) regardless of table size.

Revision ID: 0040
Revises: 0039
Create Date: 2026-09-10
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0041"
down_revision = "0040"
branch_labels = None
depends_on = None

# (table, column) for every JSON column declared nullable in
# soc_ai/store/models.py. Written out rather than reflected: a migration must
# describe the schema AT THIS REVISION, and reading the live model would silently
# change what this migration does the next time a column is added or removed.
_JSON_COLUMNS: tuple[tuple[str, str], ...] = (
    ("investigations", "report"),
    ("hunts", "report"),
    ("backtests", "results"),
    ("chat_messages", "meta"),
    ("internal_identifier", "evidence"),
    ("quality_snapshots", "alarm_reasons"),
    ("model_battery_results", "fitness_result"),
    ("host_dossier_field", "inferred_value_json"),
    ("host_dossier_field", "inferred_evidence"),
    ("host_dossier_field", "operator_value_json"),
    ("dossier_run", "errors"),
    ("dossier_run", "notes"),
    ("general_chat_messages", "meta"),
)

_SNAPSHOT_COLUMNS: tuple[tuple[str, sa.types.TypeEngine[str]], ...] = (
    ("app_version", sa.String(64)),
    ("code_commit", sa.String(64)),
    ("analyst_model", sa.String(256)),
)


def upgrade() -> None:
    for table, column in _JSON_COLUMNS:
        op.execute(
            sa.text(
                f"UPDATE {table} SET {column} = NULL "  # noqa: S608 - fixed literals above
                f"WHERE {column} = 'null'"
            )
        )
    for name, coltype in _SNAPSHOT_COLUMNS:
        op.add_column("quality_snapshots", sa.Column(name, coltype, nullable=True))


def downgrade() -> None:
    for name, _coltype in reversed(_SNAPSHOT_COLUMNS):
        op.drop_column("quality_snapshots", name)
    # The JSON normalisation is deliberately NOT reversed — see the module
    # docstring. A NULL that was rewritten and a NULL that was always there are
    # the same value, so re-writing 'null' everywhere would fabricate rows that
    # never held it.
