"""SQLAlchemy models for the soc-ai local store.

Timestamps are naive UTC throughout (SQLite has no timezone type);
``soc_ai.store.auth.utcnow`` is the one producer of comparison values.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    false,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base for all store tables."""


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(16), default="analyst")
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(), server_default=func.now())
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(), default=None)


class UserSession(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime())


class ApiToken(Base):
    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(64))
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(), server_default=func.now())
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(), default=None)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class Investigation(Base):
    __tablename__ = "investigations"
    # Composite similarity index created by migration 0003. Declared here so the
    # ORM metadata matches the DB — otherwise `alembic revision --autogenerate`
    # would propose DROPPING the index it can't see in the model.
    __table_args__ = (Index("ix_investigations_similarity", "rule_name", "src_ip", "dest_ip"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)  # ULID
    alert_es_id: Mapped[str] = mapped_column(String(128), index=True)
    rule_name: Mapped[str | None] = mapped_column(String(512), default=None, index=True)
    verdict: Mapped[str | None] = mapped_column(String(32), default=None)
    confidence: Mapped[float | None] = mapped_column(Float, default=None)
    rationale: Mapped[str | None] = mapped_column(Text, default=None)
    summary: Mapped[str | None] = mapped_column(Text, default=None)
    report: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
    src_ip: Mapped[str | None] = mapped_column(String(64), default=None)
    dest_ip: Mapped[str | None] = mapped_column(String(64), default=None)
    status: Mapped[str] = mapped_column(String(16), default="running")
    started_by: Mapped[str] = mapped_column(String(64), default="anonymous")
    created_at: Mapped[datetime] = mapped_column(DateTime(), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(), default=None)


class InvestigationEvent(Base):
    __tablename__ = "investigation_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(String(40))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class Hunt(Base):
    """A broad, multi-alert / multi-host threat hunt.

    Unlike an :class:`Investigation` (which dispositions ONE alert into a
    verdict), a hunt investigates across hosts/time or a free-form objective and
    lands **findings + a narrative** (the :class:`~soc_ai.agent.hunt.HuntReport`
    stored in ``report``). Shares the investigation lifecycle statuses
    (running/complete/error/cancelled/interrupted). Read-only in this phase —
    hunts never ack/escalate/open a case. ``hunt_events`` holds the agent trace,
    exactly like ``investigation_events``.
    """

    __tablename__ = "hunts"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)  # ULID
    objective: Mapped[str] = mapped_column(Text)
    # Content hash of the NORMALIZED objective (lowercase, whitespace-collapsed).
    # Re-runs of the same objective share a hash, so a later run can diff its
    # findings against the previous COMPLETE run with the same hash. Computed on
    # write in ``soc_ai.store.hunts.create``; NULL on legacy rows (they just
    # won't diff). Indexed — ``previous_completed_run`` filters on it.
    objective_hash: Mapped[str | None] = mapped_column(String(64), default=None, index=True)
    kind: Mapped[str] = mapped_column(String(16), default="chat")  # chat | scheduled | triggered
    status: Mapped[str] = mapped_column(String(16), default="running")
    narrative: Mapped[str | None] = mapped_column(Text, default=None)
    report: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)  # HuntReport
    started_by: Mapped[str] = mapped_column(String(64), default="anonymous")
    created_at: Mapped[datetime] = mapped_column(DateTime(), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(), default=None)


class HuntEvent(Base):
    __tablename__ = "hunt_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hunt_id: Mapped[str] = mapped_column(ForeignKey("hunts.id"), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(String(40))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class Backtest(Base):
    """A "prove it on my last N days" replay of the agent over already-dispositioned alerts.

    Points soc-ai at a historical window of alerts an analyst already dispositioned
    in Security Onion (``event.escalated`` ⇒ a real true-positive; acknowledged-and-
    not-escalated ⇒ a proxy false-positive), replays the agent's triage over a
    sampled subset, and compares soc-ai's verdicts to the human disposition. The
    ``results`` JSON holds the aggregated metrics (agreement_rate, fp_reduction,
    the confusion matrix, and the CRITICAL ``missed_tp`` list) plus the per-alert
    rows. Shares the running/complete/error lifecycle; a single-flight background
    job on ``app.state`` drives it (see :mod:`soc_ai.webui.backtest`). Read-only:
    a backtest never acks/escalates/opens a case — it only measures.
    """

    __tablename__ = "backtests"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)  # ULID
    # The run's inputs: {"window_days": int, "sample_size": int, "min_severity": str|None}.
    params: Mapped[dict[str, Any]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16), default="running")
    # How many alerts were actually sampled + replayed (may be < requested if the
    # window held fewer dispositioned alerts).
    sampled: Mapped[int] = mapped_column(Integer, default=0)
    # The metrics + per-alert comparison rows (the BacktestResults shape).
    results: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
    started_by: Mapped[str] = mapped_column(String(64), default="anonymous")
    created_at: Mapped[datetime] = mapped_column(DateTime(), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(), default=None)


class ChatMessage(Base):
    """One message in an investigation's follow-up chat thread.

    A ``user`` row is the analyst's question; an ``assistant`` row is the chat
    agent's answer, created ``pending`` and filled in by a background task (so the
    UI can poll live progress, like a hunt). ``meta`` carries a compact tool-call
    trace for the turn. Read-only agent (v1): no write tools, no Oracle.
    """

    __tablename__ = "chat_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), index=True)
    role: Mapped[str] = mapped_column(String(16))  # "user" | "assistant"
    content: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="done")  # pending|done|error
    meta: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(), server_default=func.now())


class ChatMemory(Base):
    """One completed chat message, projected for cross-source FTS retrieval.

    The chat-transcript memory feature ("prior discussion excerpts") searches
    past analyst↔AI chats from BOTH sources — investigation follow-up threads
    (``chat_messages`` rows) and hunt follow-up threads (``hunt_events`` rows
    with the chat kinds). Their shapes are incompatible (real columns vs JSON
    payload fields, which FTS5 cannot index), so completed messages are
    projected here at write time (:func:`soc_ai.store.chat_memory.record_message`)
    and indexed by the ``chat_memory_fts`` external-content FTS5 table via SQL
    triggers (migration 0018).

    Append-only from the app's perspective; rows are removed only when their
    investigation/hunt is deleted (the delete paths cascade here). ``thread_id``
    is the investigation or hunt ULID — globally unique across both sources,
    so exclusion filters need no ``source`` qualifier.
    """

    __tablename__ = "chat_memory"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(16))  # "investigation" | "hunt"
    thread_id: Mapped[str] = mapped_column(String(32), index=True)  # inv/hunt ULID
    role: Mapped[str] = mapped_column(String(16))  # "user" | "assistant"
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(), server_default=func.now())


class AlertAssignment(Base):
    """Persisted owner assignment for a detection rule.

    Assignment is per ``rule_name`` (the detection, not a single alert).
    ``owner`` is the username (or ``token:<name>``) returned by
    :func:`~soc_ai.api.security.identify_caller`.  Only one owner per rule;
    upserted on assign, deleted on unassign.

    ``state`` is the human triage state layered on top of ownership:
    ``owned`` (default on assign) → ``in_review`` → ``done``. The fourth
    conceptual state, ``unassigned``, is the ABSENCE of a row — so a persisted
    ``state`` is always one of the three above, never ``unassigned``.
    """

    __tablename__ = "alert_assignments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_name: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    owner: Mapped[str] = mapped_column(String(128))
    state: Mapped[str] = mapped_column(String(16), default="owned", server_default="owned")
    assigned_at: Mapped[datetime] = mapped_column(DateTime(), server_default=func.now())


class ConfigOverride(Base):
    """Admin-set overrides for a whitelisted subset of Settings.

    ``value`` holds a JSON-encoded scalar (bool/str/float). The whitelist and
    type coercion live in ``soc_ai.store.config_overrides`` — this table never
    holds secrets (no password/api-key keys are whitelisted).
    """

    __tablename__ = "config_overrides"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
    updated_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), default=None)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(), server_default=func.now(), onupdate=func.now()
    )


class InternalIdentifier(Base):
    """A deployment's internal identifier tracked in a managed list.

    Each row is one internal domain ``suffix`` (".corp.acme.com"), bare
    ``host`` name ("WIN11-01"), or ``cidr`` ("10.50.0.0/24"). ``source`` is
    ``detected`` (mined from ES discovery) or ``manual`` (operator-entered);
    ``state`` is ``active``, ``muted``, or ``dismissed``. The Oracle egress
    sanitizer consumes the *effective* merged set = env-config union active
    minus muted (see ``soc_ai.oracle.identifiers``). A muted detected row is a
    tombstone -- an operator's mute survives re-scans (detected rows are muted
    or dismissed, never deleted). ``dismissed`` is a TERMINAL tombstone for
    detected rows: hidden from listings, never refreshed/resurrected by a scan;
    only an explicit manual add reactivates it (see
    ``soc_ai.store.internal_identifiers``). ``evidence`` carries discovery
    provenance for detected rows; it is ``null`` for manual rows.
    """

    __tablename__ = "internal_identifier"
    __table_args__ = (UniqueConstraint("kind", "value", name="uq_internal_identifier_kind_value"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))  # 'suffix' | 'host' | 'cidr'
    value: Mapped[str] = mapped_column(String(256))  # normalized, unique per kind
    source: Mapped[str] = mapped_column(String(16))  # 'detected' | 'manual'
    state: Mapped[str] = mapped_column(String(16))  # 'active' | 'muted' | 'dismissed'
    evidence: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(), server_default=func.now(), onupdate=func.now()
    )


class DetectionOverride(Base):
    """An operator's soft, reversible suppression of a noisy detection rule.

    Detection tuning: when a Suricata rule fires constantly and triage keeps
    coming back false-positive, the operator can *mute* it — a soc-ai-side
    suppression that hides the rule's alerts from the default feed. This NEVER
    touches Security Onion / Elasticsearch: nothing is written upstream, no rule
    is disabled in SO. The mute is reversible (``active`` flips to False on
    un-mute, the row is kept for audit), and global (no per-host scope in this
    MVP). The default alerts feed subtracts ``muted_rule_names`` (see
    ``soc_ai.store.detection_overrides``); ``?include_muted=true`` shows them
    again.
    """

    __tablename__ = "detection_override"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_name: Mapped[str] = mapped_column(String(512), index=True)
    action: Mapped[str] = mapped_column(String(16), default="mute")  # 'mute'
    reason: Mapped[str | None] = mapped_column(String(512), default=None)
    created_by: Mapped[str] = mapped_column(String(128), default="anonymous")
    created_at: Mapped[datetime] = mapped_column(DateTime(), server_default=func.now())
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Runbook(Base):
    """An operator-authored runbook: a procedure / note the triage agent can cite.

    Runbooks are the org's *own* guidance — how *this* team wants a class of
    alert handled, what "normal" looks like on *this* network, which hosts are
    known-benign, the exact steps to confirm/dismiss a detection. The triage
    agent's ``lookup_runbook`` tool searches these so an investigation can ground
    itself in real operator knowledge instead of hallucinating a false-positive
    from thin data. Purely local — nothing here is ever written to Security Onion.

    ``tags`` and ``linked_rules`` are stored as JSON string lists. ``linked_rules``
    names the detection rules (Suricata rule names / SO rule UUIDs) a runbook
    applies to; a rule-link match is the strongest search signal, ahead of a tag
    match, ahead of plain keyword overlap in the title/content.
    """

    __tablename__ = "runbook"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(512))
    content: Mapped[str] = mapped_column(Text, default="")  # markdown / plain text
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    linked_rules: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_by: Mapped[str] = mapped_column(String(128), default="anonymous")
    created_at: Mapped[datetime] = mapped_column(DateTime(), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(), server_default=func.now(), onupdate=func.now()
    )


class RunbookEmbedding(Base):
    """One gateway-produced embedding vector per runbook (the OPT-IN semantic tier).

    Empty until the operator configures ``rag_embed_model`` — the default
    retrieval path (FTS5 BM25, migration 0017) never reads this table. When the
    tier is on, runbook writes embed fail-soft (a gateway outage just leaves the
    row absent until the next write or an admin re-embed), and
    :func:`soc_ai.rag.runbook_embeddings.semantic_search` cosines the stored
    vectors in pure Python (the corpus is small; no numpy, no vector DB).

    ``model`` records WHICH embeddings model produced the vector: rows whose
    model no longer matches the configured ``rag_embed_model`` are STALE —
    skipped at query time (mixing vector spaces produces garbage cosines) and
    refreshed by ``POST /config/rag/reembed``. ``vector`` is the raw float32
    little-endian bytes (``dim`` * 4); ``dim`` is kept alongside so a corrupt
    blob is detectable without decoding.
    """

    __tablename__ = "runbook_embedding"

    runbook_id: Mapped[int] = mapped_column(
        ForeignKey("runbook.id", ondelete="CASCADE"), primary_key=True
    )
    model: Mapped[str] = mapped_column(String(128))
    dim: Mapped[int] = mapped_column(Integer)
    vector: Mapped[bytes] = mapped_column(LargeBinary)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(), server_default=func.now(), onupdate=func.now()
    )


class HuntSchedule(Base):
    """A recurring hunt: an ``objective`` re-run every ``interval_minutes``.

    The in-process ``_hunt_schedule_loop`` (see :mod:`soc_ai.main`) wakes on a
    fixed cadence and, when ``hunt_schedules_enabled`` is on, spawns a normal hunt
    (``kind="scheduled"``) for every DUE schedule — one whose ``last_run_at`` is
    NULL (never run) or older than ``interval_minutes`` ago. Spawning stamps
    ``last_run_at`` immediately (the interval clock), which is the loop's
    single-flight guard: the same schedule won't re-fire on the next wake until
    the interval elapses again. So the interval must be ≥ the hunt's own runtime
    (enforced as a sane floor at the store, e.g. 60 minutes).

    Self-contained for now — a ``template_id`` FK is E3.2's job (the template
    library); a schedule today carries its full objective text. Read/writes are
    plain small-table CRUD (see :mod:`soc_ai.store.hunt_schedules`).
    """

    __tablename__ = "hunt_schedules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    objective: Mapped[str] = mapped_column(Text)
    interval_minutes: Mapped[int] = mapped_column(Integer, default=60)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # NULL until the first run — a fresh schedule is immediately due.
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(), default=None)
    created_by: Mapped[str] = mapped_column(String(128), default="anonymous")
    created_at: Mapped[datetime] = mapped_column(DateTime(), server_default=func.now())


class HuntTemplate(Base):
    """A curated, parameterized hunt starter filtered by the grid's telemetry (E3.2).

    Where a :class:`HuntSchedule` re-runs an objective on a clock, a HuntTemplate
    is a REUSABLE objective the operator picks to seed a new hunt — the evolution
    of the six static "canned pill" strings in the Hunt Console. Each carries the
    ``required_datasets`` it needs (``["zeek.rdp", "zeek.smb_files", …]``); the
    ``GET /hunt-templates`` route annotates each template with
    ``available``/``missing_datasets`` against the LIVE, TTL-cached grid inventory
    (:func:`soc_ai.so_client.inventory.discover_datasets`) so a template that needs
    telemetry this grid doesn't have renders FLAGGED ("missing telemetry: zeek.rdp"),
    never hidden — honesty over hiding.

    ``builtin`` rows ship with soc-ai and are seeded IDEMPOTENTLY at startup
    (upsert-by-name, see :func:`soc_ai.store.hunt_templates.seed_builtins`); an
    operator's custom templates are ``builtin=False``. Deleting a builtin is
    refused (409); custom templates delete freely. Small-table CRUD in the
    runbooks/schedules mould (see :mod:`soc_ai.store.hunt_templates`).
    """

    __tablename__ = "hunt_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(256))
    objective_template: Mapped[str] = mapped_column(Text, default="")
    # JSON list of ``event.dataset`` names this hunt needs (["zeek.conn", …]).
    required_datasets: Mapped[list[str]] = mapped_column(JSON, default=list)
    default_window_minutes: Mapped[int] = mapped_column(Integer, default=1440)
    builtin: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    created_by: Mapped[str] = mapped_column(String(128), default="anonymous")
    created_at: Mapped[datetime] = mapped_column(DateTime(), server_default=func.now())
