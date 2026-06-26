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
    String,
    Text,
    UniqueConstraint,
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


class AlertAssignment(Base):
    """Persisted owner assignment for a detection rule.

    Assignment is per ``rule_name`` (the detection, not a single alert).
    ``owner`` is the username (or ``token:<name>``) returned by
    :func:`~soc_ai.api.security.identify_caller`.  Only one owner per rule;
    upserted on assign, deleted on unassign.
    """

    __tablename__ = "alert_assignments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_name: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    owner: Mapped[str] = mapped_column(String(128))
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
    ``state`` is ``active`` or ``muted``. The Oracle egress sanitizer consumes
    the *effective* merged set = env-config union active minus muted (see
    ``soc_ai.oracle.identifiers``). A muted detected row is a tombstone -- an
    operator's mute survives re-scans (detected rows are muted, never deleted).
    ``evidence`` carries discovery provenance for detected rows; it is ``null``
    for manual rows.
    """

    __tablename__ = "internal_identifier"
    __table_args__ = (UniqueConstraint("kind", "value", name="uq_internal_identifier_kind_value"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))  # 'suffix' | 'host' | 'cidr'
    value: Mapped[str] = mapped_column(String(256))  # normalized, unique per kind
    source: Mapped[str] = mapped_column(String(16))  # 'detected' | 'manual'
    state: Mapped[str] = mapped_column(String(16))  # 'active' | 'muted'
    evidence: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(), server_default=func.now(), onupdate=func.now()
    )
