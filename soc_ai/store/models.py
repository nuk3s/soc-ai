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
    # Composite similarity index created by migration 0003; the (status,
    # created_at) index by migration 0028 (it serves the /notifications
    # status-filtered created_at scan, query_page's ORDER BY, and
    # reap_stale_running). Declared here so the ORM metadata matches the DB —
    # otherwise `alembic revision --autogenerate` would propose DROPPING an index
    # it can't see in the model.
    __table_args__ = (
        Index("ix_investigations_similarity", "rule_name", "src_ip", "dest_ip"),
        Index("ix_investigations_status_created", "status", "created_at"),
    )

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
    # Operator acknowledgement of a pipeline-error run (the fallback marker in
    # ``report`` — see ``is_pipeline_fallback``). Non-NULL silences the run in
    # the Dashboard's "N pipeline errors" KPI; the row itself stays a fallback
    # (the flag is history, the ack is presentation). Migration 0021.
    error_dismissed_at: Mapped[datetime | None] = mapped_column(DateTime(), default=None)
    # Persisted twin of ``is_pipeline_fallback(report)`` — stamped at
    # finalize/resolve (this module writes the report in both places) and
    # backfilled by migration 0028. Lets ``query_page`` aggregate the fallback /
    # true-positive counts over the whole filter set on each 10s poll WITHOUT a
    # per-row ``json_extract`` over every report blob. NULL only on legacy /
    # not-yet-finalized rows, which ``.isnot(True)`` treats as not-a-fallback.
    is_fallback: Mapped[bool | None] = mapped_column(Boolean, default=None)


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
    # (status, created_at) composite from migration 0028 — serves the
    # /notifications completed-hunt scan and previous_completed_run. Declared so
    # the ORM metadata matches the DB (see the Investigation note).
    __table_args__ = (Index("ix_hunts_status_created", "status", "created_at"),)

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
    # Persisted ``len(report["findings"])`` — stamped at finalize, backfilled by
    # migration 0028. Lets the /notifications bell show a hunt's finding count
    # without deserializing its report blob. NULL only on legacy / unfinished
    # rows (rendered as 0).
    findings_count: Mapped[int | None] = mapped_column(Integer, default=None)
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

    ``draft`` (migration 0020) marks a machine-authored promotion draft
    (:mod:`soc_ai.webui.runbook_promotion`): visible + editable in the Runbooks
    page, but EXCLUDED from every agent retrieval path until the operator
    approves it — a draft can never shape a verdict. Operator-authored rows are
    always ``False``.
    """

    __tablename__ = "runbook"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(512))
    content: Mapped[str] = mapped_column(Text, default="")  # markdown / plain text
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    linked_rules: Mapped[list[str]] = mapped_column(JSON, default=list)
    draft: Mapped[bool] = mapped_column(Boolean, default=False)
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


class QualitySnapshot(Base):
    """One ``soc-ai eval-nightly`` run's quality metrics (I4 — measured always).

    The nightly micro-eval converts "the verdicts were validated once" into a
    LOCAL TREND: each run investigates a handful of real alerts through the
    normal pipeline and lands one row here, so a silent verdict regression
    (an inference-engine swap, a bad model bump) shows up as a bend in the
    dashboard's Quality card instead of going unnoticed for weeks.

    ``mode`` records HOW the point was measured — the two modes are not
    comparable and are never blended:

    * ``"graded"`` — the cloud oracle critiqued each investigation, so
      ``agreement_rate`` is populated (the strong signal, costs egress).
    * ``"local"`` — zero-egress: ``agreement_rate`` is NULL and the trend
      leans on the local proxies (fallback/error rates, verdict distribution,
      latency) that need no oracle.

    ``alarmed``/``alarm_reasons`` persist the regression-detector outcome for
    THIS point (vs the trailing same-mode history — see
    :func:`soc_ai.eval.quality.detect_regression`) so the Quality card can
    flag the latest run without re-deriving the rule client-side, and
    ``alarm_key``/``alarm_since`` say WHICH condition it is and how long it has
    held, which is what lets the writer alarm on the transition into a
    condition instead of on every run that re-observes it. The table is
    pruned to the newest 90 rows on every insert (~3 months of nightlies) —
    a trend, not an archive; the full batch artifacts live on disk at
    ``batch_dir``.
    """

    __tablename__ = "quality_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(), server_default=func.now())
    mode: Mapped[str] = mapped_column(String(8))  # "local" | "graded"
    n_ok: Mapped[int] = mapped_column(Integer, default=0)
    n_error: Mapped[int] = mapped_column(Integer, default=0)
    # NULL in local mode (no oracle → no agreement signal) and on graded runs
    # where the oracle classified nothing — an honest "unknown", never 0.0.
    agreement_rate: Mapped[float | None] = mapped_column(Float, default=None)
    # Fraction of OK runs whose report was a pipeline-failure fallback
    # (is_pipeline_fallback) — infra noise, not model reasoning. NULL when no
    # run succeeded (no denominator).
    fallback_rate: Mapped[float | None] = mapped_column(Float, default=None)
    # The grade counts BEHIND agreement_rate (migration 0026). A rate with no
    # denominator can't be significance-tested and can't be explained: at the
    # default n=5 an agreement_rate is quantised to 0.2 steps, so comparing one
    # to a median of other rates fires on ordinary sampling noise (the false
    # alarm of 2026-08-07). The detector pools THESE across the trailing
    # history instead. They also carry the honesty the rate can't: ``partial``
    # ("right verdict, thin reasoning") sits in the rate's denominator but not
    # its numerator, so 3 yes + 2 partial and 3 yes + 2 no are both 0.60.
    # NULL on pre-0026 rows — "never recorded" is not "nothing agreed", and
    # the detector keys its median fallback on exactly that NULL.
    n_yes: Mapped[int | None] = mapped_column(Integer, default=None)
    n_partial: Mapped[int | None] = mapped_column(Integer, default=None)
    n_no: Mapped[int | None] = mapped_column(Integer, default=None)
    # yes + partial + no. Persisted rather than derived because it is the
    # denominator the detector reads, and `unknown` critiques (counted in n_ok,
    # never in the rate) must not be able to creep into it later.
    n_classified: Mapped[int | None] = mapped_column(Integer, default=None)
    error_rate: Mapped[float] = mapped_column(Float, default=0.0)
    # {"true_positive": 2, "false_positive": 3, ...} over the OK runs — the
    # verdict-distribution-drift signal for local mode.
    verdict_counts: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    latency_p50_ms: Mapped[int | None] = mapped_column(Integer, default=None)
    # Where the run's full artifacts (index.jsonl, bundles, report.md) live.
    batch_dir: Mapped[str | None] = mapped_column(String(512), default=None)
    alarmed: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    # Human-readable detector reasons (JSON list of strings); NULL when clean.
    alarm_reasons: Mapped[list[str] | None] = mapped_column(JSON, default=None)
    # The alarm's IDENTITY (migration 0027): the rule codes that fired, sorted
    # and joined ("agreement_drop", "agreement_drop+error_ceiling"). NULL when
    # clean, and NULL on pre-0027 rows. The reasons above cannot serve as an
    # identity — each embeds the run's live numbers, so one unchanged condition
    # reads as a different string every night, which is why every re-observation
    # of it paged (rows 9/10/11 of prod's own trend: one condition, three
    # alarms, 27 hours). The writer fires side effects only when this changes.
    alarm_key: Mapped[str | None] = mapped_column(Text, default=None)
    # When the CURRENT condition started: carried forward from the previous
    # same-mode snapshot while the key is unchanged, re-stamped when it changes.
    # Stored rather than derived because the history it would be derived from is
    # pruned to 90 rows. NULL whenever alarm_key is.
    alarm_since: Mapped[datetime | None] = mapped_column(DateTime(), default=None)


class ModelBatteryResult(Base):
    """Last fitness-battery run per analyst model (design spec 2026-08-05).

    One row per model route name, replaced on every completed battery — the
    battery measures CONTRACT behavior, which only changes when the backend
    behind the route changes, so history has no value the audit trail doesn't
    already provide (a ``model_battery`` audit event is written per run).
    ``result`` holds the whole ``run_battery`` report: per-config probe
    outcomes, the recommendation, timings.
    """

    __tablename__ = "model_battery_results"

    model: Mapped[str] = mapped_column(String(256), primary_key=True)
    result: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(), server_default=func.now())
    # Quick 3-leg fitness cache (migration 0023): separate columns because the
    # two measurements have independent cadences — a battery run must not clobber
    # the fitness timestamp and vice versa. Nullable: rows created by either path.
    fitness_result: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
    fitness_at: Mapped[datetime | None] = mapped_column(DateTime(), default=None)


class HostDossier(Base):
    """One internal host the network sweep knows about (migration 0024).

    The dossier answers "what IS this host?" durably, so an investigation can
    weigh *what the host is* alongside what it did. This row is the per-host
    header — identity lifetime, build bookkeeping — while the beliefs themselves
    live one per field in :class:`HostDossierField`.

    Keyed on the **IP**, not on a MAC or a hostname. On a network-only grid
    (which is what most deployments are) the majority of hosts never emit DHCP
    or NTLM, so a MAC/hostname key would leave half the network unkeyed — and it
    is the IP that the alert joins on, and the IP whose egress-guard label the
    prompt block has to collapse onto. ``host_key`` is stored separately from
    ``ip`` so re-keying on a stable per-machine identifier later is a data
    backfill rather than a schema rewrite.

    The cost of an IP key is that an address outlives the machine behind it.
    That is mitigated rather than designed away: ``identity_fingerprint`` hashes
    the hostname+MAC seen at the last build, and ``identity_rebound_at`` is
    stamped when it changes from one non-null value to a *different* non-null
    value — the tripwire that tells an operator "the machine behind this address
    appears to have changed; your override may no longer apply".

    ``first_seen`` is MONOTONE: a build over a narrower window must widen it, never
    reset it. ``last_built_at`` is the staleness sort key the sweep orders by, so
    a network larger than one run's budget is drained across runs from durable
    state instead of a cursor that a restart would lose.
    """

    __tablename__ = "host_dossier"
    __table_args__ = (
        # Unique INDEX rather than a bare constraint: this is both the identity
        # guarantee and the lookup path (`GET /dossiers/{ip}` and the per-alert
        # prompt block both fetch by key).
        Index("uq_host_dossier_host_key", "host_key", unique=True),
        Index("ix_host_dossier_ip", "ip"),
        Index("ix_host_dossier_last_built_at", "last_built_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # v1: the normalized IP string. Named for what it IS (the key) so a future
    # MAC/hostname key needs no rename.
    host_key: Mapped[str] = mapped_column(String(64))
    ip: Mapped[str] = mapped_column(String(64))
    # Lifetime across ALL builds: min(stored, observed) / max(stored, observed).
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(), default=None)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(), default=None)
    # When a build last COMPLETED for this host (NULL = never built, and
    # therefore first in the staleness queue).
    last_built_at: Mapped[datetime | None] = mapped_column(DateTime(), default=None)
    # Newest event @timestamp inside the last build window — distinct from
    # last_built_at, which is about the builder rather than the host.
    last_observed_at: Mapped[datetime | None] = mapped_column(DateTime(), default=None)
    event_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    # sha256(hostname + "|" + mac)[:32] as of the last build.
    identity_fingerprint: Mapped[str | None] = mapped_column(String(64), default=None)
    identity_rebound_at: Mapped[datetime | None] = mapped_column(DateTime(), default=None)
    # Last per-host failure, NULL on success. A host that fails to build keeps
    # its previous beliefs and reports why the refresh didn't happen.
    build_error: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(), server_default=func.now(), onupdate=func.now()
    )


class HostDossierField(Base):
    """One belief about one host, in two physically separate lanes.

    **There is no ``value`` column, and that is the design.** The inference lane
    (``inferred_*``) is written only by the builder; the operator lane
    (``operator_*``) only by an explicit override. The effective value is
    computed at read time by ``soc_ai.dossier.resolve``, so an operator's
    override cannot be clobbered by a rebuild — there is nothing for a rebuild
    to clobber.

    The alternative — store the effective value and have the builder skip
    overridden fields — is the ``InternalIdentifier.dismissed`` trap: skipping
    stops the system recording what it currently believes, which makes "prod the
    operator when the evidence keeps disagreeing" impossible to implement. Here
    an override suppresses **effect**, never **observation**. The builder keeps
    writing what it sees into the inference lane forever, and the disagreement
    that accumulates in the ``conflict_*`` columns is what eventually earns a
    single, rate-limited prod.

    ``inferred_evidence`` is keyed BY SOURCE (``{"banner": {...},
    "telemetry": {...}}``) so a stronger signal arriving later refines the value
    without erasing the weaker belief that supported it — the same reason
    ``host_summary`` keeps both sides of an OS disagreement.

    ``inferred_last_run_at`` records the last build that *evaluated* this field
    even when it concluded nothing, which is what lets the resolver distinguish
    "still true" from "nobody has looked in three days". ``inferred_retracted_at``
    marks the opposite case: a build that found no evidence for a value it used
    to hold, which nulls ``inferred_value`` in the same write rather than leaving
    a fact standing on evidence that has gone.

    Conflict state is persisted rather than held in memory because the prod
    interval is measured in weeks and a restart must not reset the clock (or
    re-fire the prod).
    """

    __tablename__ = "host_dossier_field"
    __table_args__ = (
        UniqueConstraint("dossier_id", "field", name="uq_host_dossier_field"),
        Index("ix_host_dossier_field_dossier_id", "dossier_id"),
        # GET /dossiers/conflicts scans for open disagreements across the network.
        Index("ix_host_dossier_field_conflict", "conflict_first_seen_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dossier_id: Mapped[int] = mapped_column(
        ForeignKey("host_dossier.id", ondelete="CASCADE"),
    )
    # One of soc_ai.dossier.types.DOSSIER_FIELDS.
    field: Mapped[str] = mapped_column(String(32))

    # --- inference lane: written ONLY by upsert_inferred() ---
    inferred_value: Mapped[str | None] = mapped_column(Text, default=None)
    # Structured payload for services_offered / activity_profile /
    # management_plane, which a scalar cannot carry.
    inferred_value_json: Mapped[Any | None] = mapped_column(JSON, default=None)
    inferred_confidence: Mapped[float | None] = mapped_column(Float, default=None)
    # Provenance ladder rung — see soc_ai.dossier.types.PROVENANCE_LADDER.
    inferred_source: Mapped[str | None] = mapped_column(String(16), default=None)
    inferred_evidence: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
    inferred_first_seen: Mapped[datetime | None] = mapped_column(DateTime(), default=None)
    inferred_last_seen: Mapped[datetime | None] = mapped_column(DateTime(), default=None)
    inferred_last_run_at: Mapped[datetime] = mapped_column(DateTime(), server_default=func.now())
    inferred_retracted_at: Mapped[datetime | None] = mapped_column(DateTime(), default=None)

    # --- operator lane: written ONLY by set_override() / clear_override() ---
    operator_value: Mapped[str | None] = mapped_column(Text, default=None)
    operator_value_json: Mapped[Any | None] = mapped_column(JSON, default=None)
    operator_set_at: Mapped[datetime | None] = mapped_column(DateTime(), default=None)
    operator_actor: Mapped[str | None] = mapped_column(String(64), default=None)
    operator_note: Mapped[str | None] = mapped_column(Text, default=None)

    # --- conflict / prod state ---
    # 'mismatch' | 'retracted' | 'rebound'
    conflict_kind: Mapped[str | None] = mapped_column(String(16), default=None)
    # NULL whenever the two lanes agree; set on the build that first disagrees.
    conflict_first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(), default=None)
    # Consecutive DISAGREEING builds — the "continued evidence" gate that stops
    # one anomalous sweep from nagging an operator.
    conflict_observations: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    conflict_last_prompted_at: Mapped[datetime | None] = mapped_column(DateTime(), default=None)
    # Never reset — history, and the notification cycle id, so dismissing one
    # prod does not hide the next.
    conflict_prompt_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    conflict_snoozed_until: Mapped[datetime | None] = mapped_column(DateTime(), default=None)


class DossierRun(Base):
    """One network sweep: the durable last-run stamp plus its counters.

    Durable because the discovery job's equivalent (``_DiscoveryStatus.last_scan``)
    lives on ``app.state`` and its due-check treats ``None`` as due — so a restart
    loop re-sweeps the whole network every boot. The row is written on **every**
    sweep, including one that found nothing: gating the stamp on "did some work"
    is what made auto-triage re-run full ES planning every 60 seconds, and a
    stable network finds nothing new almost every time.

    Pruned to the newest 50 rows at the end of each run — an operations trail,
    not an archive.
    """

    __tablename__ = "dossier_run"
    __table_args__ = (Index("ix_dossier_run_started_at", "started_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime())
    # NULL while the sweep is in flight, or if the process died mid-run.
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(), default=None)
    trigger: Mapped[str] = mapped_column(String(16))  # 'schedule' | 'manual' | 'inline'
    hosts_seen: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    hosts_built: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    fields_written: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    conflicts_detected: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    conflicts_prompted: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    # Per-host failures collected during the sweep; NULL on a clean run.
    errors: Mapped[list[str] | None] = mapped_column(JSON, default=None)
    # Advisory notes from a healthy sweep — a truncated cap, a cadence ceiling.
    # Kept in their own column so a run that hit zero failures still reads as
    # clean (errors NULL) while the caps it ran into stay visible: folding these
    # into `errors` made every nightly sweep report a nonzero error count.
    notes: Mapped[list[str] | None] = mapped_column(JSON, default=None)


class GeneralChatMessage(Base):
    """One message in the dashboard's general chat — a rolling thread per analyst.

    Column-for-column :class:`ChatMessage` with ``investigation_id`` swapped for
    ``thread_key``, and that is the point: the API serializes both through the
    same ``ChatThreadOut`` shape, so the SPA's chat transport does not have to
    learn a second wire format. A merge of the two stores later should be a
    rename.

    ``thread_key`` is the caller string ``identify_caller`` produces (the same
    actor value ``started_by`` records) — one durable thread per analyst, no
    thread list, no naming. There is no FK: the thread outlives any row it could
    point at, including the user account being renamed.

    ``status`` runs pending → done|error exactly as investigation chat does, and
    for the same reason: the answer is written by a background task the UI polls.
    Unlike investigation chat, completed turns are NOT projected into
    ``chat_memory`` — see :mod:`soc_ai.store.general_chat`.
    """

    __tablename__ = "general_chat_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    thread_key: Mapped[str] = mapped_column(String(64), index=True)
    role: Mapped[str] = mapped_column(String(16))  # "user" | "assistant"
    content: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="done")  # pending|done|error
    meta: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(), server_default=func.now())


class SavedView(Base):
    """One analyst's named filter set for one list screen.

    Server-side rather than ``localStorage`` by the owner's explicit choice, so
    a view an analyst builds at one workstation is there at the next one. That
    is also what makes ``user_id`` load-bearing: every read and every delete is
    scoped by it, so a view belongs to exactly one person and is invisible —
    not merely forbidden — to everyone else.

    ``query_json`` is the screen's own filter state, opaque to the backend. The
    four list screens disagree about what a filter IS (a verdict multi-select, a
    role string, an OQL clause), and a column per facet would have to be
    migrated every time one of them grew a control. The screen that wrote a view
    is the screen that reads it, and it is the only thing that has to understand
    the shape.

    ``(user_id, screen, name)`` is unique: saving "Beacons" twice updates the
    filters instead of growing a second identical chip.
    """

    __tablename__ = "saved_view"
    __table_args__ = (
        UniqueConstraint("user_id", "screen", "name", name="uq_saved_view_name"),
        Index("ix_saved_view_user_screen", "user_id", "screen"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # The view dies with the account — a filter set has no meaning without the
    # analyst it belongs to, and an orphan row would be unreachable anyway.
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    # One of soc_ai.store.saved_views.SAVED_VIEW_SCREENS.
    screen: Mapped[str] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(String(64))
    query_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(), server_default=func.now())
