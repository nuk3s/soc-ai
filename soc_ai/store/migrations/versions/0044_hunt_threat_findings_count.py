"""Denormalize how many of a hunt's findings are threats.

The bell already had ``findings_count`` so it never deserializes a report to
say "N findings". It could not tell what KIND of finding. A catalog hunt whose
one finding was "could not run" — a visibility gap from a timed-out query — was
announced as "Hunt finished — 1 finding: RC4 service ticket issued in an AES…",
which is the most alarming line the app can print, over nothing.

Backfilled from the report JSON for existing rows using the same title
heuristic the hunt page applies to legacy reports.

Revision ID: 0044
Revises: 0043
Create Date: 2026-09-16
"""

from __future__ import annotations

import json

import sqlalchemy as sa
from alembic import op

revision = "0044"
down_revision = "0043"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("hunts", sa.Column("threat_findings_count", sa.Integer(), nullable=True))

    # Backfill in Python rather than SQL: the classification reads a title
    # regex for legacy rows, which SQLite's JSON functions cannot express.
    from soc_ai.hunting.findings import threat_finding_count  # noqa: PLC0415 - lazy, avoids a cycle

    conn = op.get_bind()
    rows = conn.execute(sa.text("SELECT id, report FROM hunts WHERE report IS NOT NULL")).all()
    for hunt_id, report in rows:
        try:
            data = json.loads(report) if isinstance(report, str) else report
            findings = (data or {}).get("findings") if isinstance(data, dict) else None
        except (TypeError, ValueError):
            continue
        conn.execute(
            sa.text("UPDATE hunts SET threat_findings_count = :n WHERE id = :id"),
            {"n": threat_finding_count(findings), "id": hunt_id},
        )


def downgrade() -> None:
    op.drop_column("hunts", "threat_findings_count")
