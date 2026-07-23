"""Regex-based redactor for audit event payloads.

ON by default (``AUDIT_REDACT=true``). soc-ai's audit log lands in a *shared* ES
cluster, so secret-shaped strings are redacted before the write. Set
``AUDIT_REDACT=false`` only if you need verbatim audit bodies and accept that
secret-shaped values will be written to the shared cluster.
"""

from __future__ import annotations

import re
from typing import Any

# Pattern -> replacement label
#
# Order matters: the soc-ai-specific secret shapes (token, bearer, session,
# key=value) are listed BEFORE the broad email pattern so a credential carrying
# an "@" is redacted as a credential, not as an email. The key=value pattern is
# last among the secret shapes so a more specific token shape wins first.
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # AWS access key
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED:aws_access_key]"),
    # GitHub PAT (classic + fine-grained)
    (re.compile(r"\bgh[ps]_[A-Za-z0-9]{36,}\b"), "[REDACTED:github_token]"),
    # Slack incoming-webhook
    (
        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
        "[REDACTED:slack_webhook]",
    ),
    # JWT (header.payload.signature)
    (
        re.compile(r"\beyJ[A-Za-z0-9+/_-]{10,}\.[A-Za-z0-9+/_-]{10,}\.[A-Za-z0-9+/_-]{10,}\b"),
        "[REDACTED:jwt]",
    ),
    # soc-ai API token (scai_… — issued by store.auth.create_api_token).
    (re.compile(r"\bscai_[A-Za-z0-9_-]{20,}"), "[REDACTED:scai_token]"),
    # Authorization: Bearer <token>
    (re.compile(r"\bBearer\s+[A-Za-z0-9._-]+"), "Bearer [REDACTED:bearer]"),
    # X-Session-Token header value (header name + its value).
    (
        re.compile(r"(?i)(X-Session-Token)\s*[=:]\s*\S+"),
        r"\1: [REDACTED:session_token]",
    ),
    # Generic key=value / key: value secrets (password, secret, api_key, …).
    # Capture the whole value up to a natural field delimiter (comma, semicolon,
    # or newline), NOT just the first \S+ token — a passphrase with spaces
    # ("correct horse battery staple") must be masked in full, not half-leaked.
    (
        re.compile(r"(?i)(password|passwd|pwd|secret|api[_-]?key)\s*[=:]\s*[^\n,;]+"),
        r"\1=[REDACTED:secret]",
    ),
    # RFC 5322 email
    (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "[REDACTED:email]",
    ),
]


def redact_text(s: str) -> tuple[str, bool]:
    """Apply every redaction pattern. Returns ``(text, was_modified)``."""
    modified = False
    for pat, repl in _PATTERNS:
        new_s, n = pat.subn(repl, s)
        if n:
            s = new_s
            modified = True
    return s, modified


def redact_value(value: Any) -> tuple[Any, bool]:
    """Recursively redact strings inside a dict/list/scalar tree."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        modified = False
        out: dict[str, Any] = {}
        for k, v in value.items():
            new_v, m = redact_value(v)
            out[k] = new_v
            modified = modified or m
        return out, modified
    if isinstance(value, list):
        modified = False
        out_list: list[Any] = []
        for item in value:
            new_item, m = redact_value(item)
            out_list.append(new_item)
            modified = modified or m
        return out_list, modified
    return value, False
