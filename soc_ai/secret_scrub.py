"""Scrub credential values out of model-written text before it is stored or exported.

The model quotes telemetry. When the telemetry carries a credential (a command
line with ``--password=...``, a config dump, a URL with ``user:pass@``), the
model can lift it into the rationale, the summary or a chat answer, and every
console user then reads it (dogfood 2026-10-01, P1). This module masks the
VALUE and keeps the key, so the analyst still sees that a credential was there
and where it came from.

Deliberately narrow: only a value that sits after a credential-shaped key
(``password``, ``secret``, ``token``, ``api_key`` ...) with a ``:`` or ``=``
separator, an ``Authorization`` header value, the password half of URL
userinfo, and AWS access key ids. Field names, usernames, hostnames and prose
that merely mentions passwords ("the password policy requires ...") pass
through unchanged.

The audit redactor (``soc_ai.audit.redact``) is a different contract: it also
masks emails and writes typed labels for a shared ES cluster. This one keeps the
analyst's report readable.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[redacted]"

# The credential-shaped key names. ``secret_access_key`` comes before
# ``secret`` so the AWS secret key name is matched whole.
_KEY_WORDS = r"(?:password|passwd|pwd|secret[_-]?access[_-]?key|secret|token|api[_-]?key|apikey)"

# key <sep> value, where the key may carry a prefix (``db_password``,
# ``client_secret``, ``X-Auth-Token``, ``--password``). The key must END at the
# credential word, so ``tokens: 12`` and ``password policy`` do not match.
# The separator tolerates a closing quote on the key (JSON, YAML, escaped JSON
# inside a JSON string) and spaces, but no newline.
_KV_RE = re.compile(
    r"(?P<key>(?<![A-Za-z0-9_.\-])[A-Za-z0-9_.\-]*?" + _KEY_WORDS + r")"
    r"(?P<sep>(?:\\?[\"'])?[ \t]*[:=][ \t]*)"
    r"(?:"
    r"(?P<q>\\?[\"'])(?P<qval>[^\"'\n\\]+)(?P=q)"
    r"|(?P<bval>[^\s\"'\[\\][^\s\"'\\]*)"
    r")",
    re.IGNORECASE,
)

# A long command-line flag with a space before its value: ``--password hunter2``.
_FLAG_RE = re.compile(
    r"(?P<key>(?<![A-Za-z0-9_\-])--[A-Za-z0-9_\-]*?"
    r"(?:password|passwd|secret|token|api[_-]?key|apikey))"
    r"(?P<sep>[ \t]+)"
    r"(?:(?P<q>\\?[\"'])(?P<qval>[^\"'\n\\]+)(?P=q)|(?P<bval>[^\s\"'\\-][^\s\"'\\]*))",
    re.IGNORECASE,
)

# Authorization header with a scheme: keep the header name and the scheme.
_AUTH_RE = re.compile(
    r"(?P<key>Authorization(?:\\?[\"'])?[ \t]*[:=][ \t]*(?:\\?[\"'])?[ \t]*"
    r"(?:Basic|Bearer|Token|Digest|NTLM|Negotiate)[ \t]+)"
    r"(?P<val>[A-Za-z0-9._~+/=\-]+)",
    re.IGNORECASE,
)

# A bare bearer token outside a header. The value must look like a token
# (16+ characters) so prose such as "Bearer token" passes through.
_BEARER_RE = re.compile(r"(?P<key>\bBearer[ \t]+)(?P<val>[A-Za-z0-9._~+/=\-]{16,})")

# URL userinfo: scheme://user:pass@host -> keep the user, mask the password.
_URL_USERINFO_RE = re.compile(
    r"(?P<key>\b[A-Za-z][A-Za-z0-9+.\-]*://[^\s/:@\"'<>]+:)(?P<val>[^\s/@\"'<>]+)(?=@)"
)

# AWS access key ids (long-term AKIA, temporary ASIA).
_AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")


# Punctuation that ends a sentence or closes a structure. A bare value runs to
# the next space (a password may hold ``&``, ``,`` or ``;``), and these trailing
# characters are handed back to the text so the prose and the brackets survive.
_TRAILING = ".,;:)]}>"


def _kv_sub(m: re.Match[str]) -> str:
    if m.group("q") is not None:
        q = m.group("q")
        return f"{m.group('key')}{m.group('sep')}{q}{REDACTED}{q}"
    bval = m.group("bval")
    tail = bval[len(bval.rstrip(_TRAILING)) :]
    if tail == bval:
        # Nothing but punctuation: not a value.
        return m.group(0)
    return f"{m.group('key')}{m.group('sep')}{REDACTED}{tail}"


def scrub_secrets(text: str) -> str:
    """Return *text* with every credential value replaced by ``[redacted]``.

    Idempotent: ``[redacted]`` itself never matches a value pattern.
    """
    if not text:
        return text
    out = _AUTH_RE.sub(lambda m: m.group("key") + REDACTED, text)
    out = _BEARER_RE.sub(lambda m: m.group("key") + REDACTED, out)
    out = _URL_USERINFO_RE.sub(lambda m: m.group("key") + REDACTED, out)
    out = _KV_RE.sub(_kv_sub, out)
    out = _FLAG_RE.sub(_kv_sub, out)
    return _AWS_KEY_RE.sub(REDACTED, out)


def scrub_value(value: Any) -> Any:
    """Recursively scrub every string in a dict / list tree. Keys stay unchanged."""
    if isinstance(value, str):
        return scrub_secrets(value)
    if isinstance(value, dict):
        return {k: scrub_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub_value(v) for v in value]
    if isinstance(value, tuple):
        return tuple(scrub_value(v) for v in value)
    return value


def scrub_optional(text: str | None) -> str | None:
    """:func:`scrub_secrets` that passes ``None`` through."""
    return None if text is None else scrub_secrets(text)


# Timeline event kinds whose payload is model-written text (the report and the
# raw model response). The store scrubs these the same way it scrubs the
# row's rationale and summary. Tool-result events stay verbatim evidence.
MODEL_TEXT_EVENT_KINDS = frozenset(
    {"triage_report", "model_response", "hunt_report", "hunt_finding"}
)
