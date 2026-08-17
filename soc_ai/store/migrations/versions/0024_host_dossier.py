"""host_dossier: durable, system-inferred asset context, in two separate lanes

The investigator repeatedly judged *what a host did* with no idea *what the host
is* — a management-plane responder on tcp/8006 reads exactly like a workstation
if nothing durable records that it is a hypervisor. This schema is that record:
one row per internal host, one row per host x field, plus a run table.

Design notes:

* **No ``value`` column, deliberately.** ``host_dossier_field`` has an inference
  lane (``inferred_*``, written only by the builder) and an operator lane
  (``operator_*``, written only by an explicit override). The effective value is
  computed at READ time by ``soc_ai.dossier.resolve``, so a rebuild cannot
  clobber an operator override — there is no stored current value to clobber.
  The rejected alternative (store the effective value, have the builder skip
  overridden fields) is the ``InternalIdentifier.dismissed`` trap: skipping stops
  the system recording what it currently believes, which makes "prod the operator
  when the evidence keeps disagreeing" impossible. An override suppresses
  EFFECT, never OBSERVATION.
* **Per-field rows (EAV), not one wide row or a JSON facts blob.** The prod
  throttle is inherently per-field — five conflict columns x 12 fields is 60
  columns flattened, and inside JSON it becomes unqueryable: the conflicts
  endpoint would degrade to a full-table scan plus Python filtering, and every
  conflict update would be a read-modify-write race. ~12 rows per host, 60k at
  the 5,000-host cap, which SQLite handles without comment.
* **Conflict state is persisted, not in-memory.** The prod interval is measured
  in weeks; a restart must neither reset the clock nor re-fire the prod.
* **``dossier_run`` exists so the sweep's last-run stamp survives a restart.**
  The discovery job keeps its equivalent on ``app.state`` and treats ``None`` as
  due, so a restart loop re-sweeps the whole network every boot.

Revision ID: 0024
Revises: 0023
Create Date: 2026-08-06
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "host_dossier",
        sa.Column("id", sa.Integer(), primary_key=True),
        # v1: the normalized IP string. Kept separate from `ip` so re-keying on a
        # stable per-machine identifier later is a backfill, not a rewrite.
        sa.Column("host_key", sa.String(64), nullable=False),
        sa.Column("ip", sa.String(64), nullable=False),
        # Monotone across all builds: a narrower window widens, never resets.
        sa.Column("first_seen", sa.DateTime(), nullable=True),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        # NULL = never built, and therefore first in the staleness queue.
        sa.Column("last_built_at", sa.DateTime(), nullable=True),
        sa.Column("last_observed_at", sa.DateTime(), nullable=True),
        sa.Column("event_count", sa.Integer(), nullable=False, server_default="0"),
        # sha256(hostname + "|" + mac)[:32] as of the last build; a change from
        # one non-null value to a DIFFERENT non-null value stamps
        # identity_rebound_at — "a different machine holds this address now".
        sa.Column("identity_fingerprint", sa.String(64), nullable=True),
        sa.Column("identity_rebound_at", sa.DateTime(), nullable=True),
        sa.Column("build_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    # Unique INDEX rather than a bare constraint: this is both the identity
    # guarantee and the per-alert lookup path.
    op.create_index("uq_host_dossier_host_key", "host_dossier", ["host_key"], unique=True)
    op.create_index("ix_host_dossier_ip", "host_dossier", ["ip"])
    op.create_index("ix_host_dossier_last_built_at", "host_dossier", ["last_built_at"])

    op.create_table(
        "host_dossier_field",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "dossier_id",
            sa.Integer(),
            sa.ForeignKey("host_dossier.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # One of soc_ai.dossier.types.DOSSIER_FIELDS.
        sa.Column("field", sa.String(32), nullable=False),
        # --- inference lane: written ONLY by upsert_inferred() ---
        sa.Column("inferred_value", sa.Text(), nullable=True),
        sa.Column("inferred_value_json", sa.JSON(), nullable=True),
        sa.Column("inferred_confidence", sa.Float(), nullable=True),
        sa.Column("inferred_source", sa.String(16), nullable=True),
        # Keyed BY SOURCE ({"banner": {...}, "telemetry": {...}}) so a stronger
        # signal arriving later refines the value without erasing the weaker
        # belief that supported it.
        sa.Column("inferred_evidence", sa.JSON(), nullable=True),
        sa.Column("inferred_first_seen", sa.DateTime(), nullable=True),
        sa.Column("inferred_last_seen", sa.DateTime(), nullable=True),
        # The last build that EVALUATED this field, even when it concluded
        # nothing — how the resolver tells "still true" from "nobody has looked".
        sa.Column(
            "inferred_last_run_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("inferred_retracted_at", sa.DateTime(), nullable=True),
        # --- operator lane: written ONLY by set_override() / clear_override() ---
        sa.Column("operator_value", sa.Text(), nullable=True),
        sa.Column("operator_value_json", sa.JSON(), nullable=True),
        sa.Column("operator_set_at", sa.DateTime(), nullable=True),
        sa.Column("operator_actor", sa.String(64), nullable=True),
        sa.Column("operator_note", sa.Text(), nullable=True),
        # --- conflict / prod state ---
        sa.Column("conflict_kind", sa.String(16), nullable=True),  # mismatch|retracted|rebound
        sa.Column("conflict_first_seen_at", sa.DateTime(), nullable=True),
        # Consecutive DISAGREEING builds — the continued-evidence gate.
        sa.Column("conflict_observations", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("conflict_last_prompted_at", sa.DateTime(), nullable=True),
        # Never reset; doubles as the notification cycle id so dismissing one
        # prod does not hide the next.
        sa.Column("conflict_prompt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("conflict_snoozed_until", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("dossier_id", "field", name="uq_host_dossier_field"),
    )
    op.create_index("ix_host_dossier_field_dossier_id", "host_dossier_field", ["dossier_id"])
    op.create_index(
        "ix_host_dossier_field_conflict", "host_dossier_field", ["conflict_first_seen_at"]
    )

    op.create_table(
        "dossier_run",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        # NULL while in flight, or if the process died mid-sweep.
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("trigger", sa.String(16), nullable=False),  # schedule|manual|inline
        sa.Column("hosts_seen", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("hosts_built", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("fields_written", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("conflicts_detected", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("conflicts_prompted", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("errors", sa.JSON(), nullable=True),
    )
    op.create_index("ix_dossier_run_started_at", "dossier_run", ["started_at"])


def downgrade() -> None:
    op.drop_index("ix_dossier_run_started_at", table_name="dossier_run")
    op.drop_table("dossier_run")
    op.drop_index("ix_host_dossier_field_conflict", table_name="host_dossier_field")
    op.drop_index("ix_host_dossier_field_dossier_id", table_name="host_dossier_field")
    op.drop_table("host_dossier_field")
    op.drop_index("ix_host_dossier_last_built_at", table_name="host_dossier")
    op.drop_index("ix_host_dossier_ip", table_name="host_dossier")
    op.drop_index("uq_host_dossier_host_key", table_name="host_dossier")
    op.drop_table("host_dossier")
