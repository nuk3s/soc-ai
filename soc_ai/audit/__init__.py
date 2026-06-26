"""Audit event schemas, redactor, ES logger, tamper-evident hash chain."""

from soc_ai.audit.chain import compute_hash, verify_chain
from soc_ai.audit.logger import AuditLogger, AuditWriteError
from soc_ai.audit.redact import redact_text, redact_value
from soc_ai.audit.schemas import AuditEvent, AuditKind

__all__ = [
    "AuditEvent",
    "AuditKind",
    "AuditLogger",
    "AuditWriteError",
    "compute_hash",
    "redact_text",
    "redact_value",
    "verify_chain",
]
