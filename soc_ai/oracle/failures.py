"""Name an Oracle failure truthfully: HTTP status, error class, gateway message.

Production filed 23 gateway HTTP 500 answers as ``no_parseable_verdict`` from
2026-09-10 to 2026-09-14. The gateway's message said the Claude subscription
behind the Oracle route had hit its weekly limit. The failure event carried no
status and no text, and the container logs were gone after the next deploy,
so the store could not tell a gateway failure from a bad answer. Every failed
adjudication now records what the gateway said.

Error classes:

- ``quota``: a usage, rate or weekly limit (HTTP 429, or a limit message in
  any status).
- ``5xx``: any other gateway or upstream server error.
- ``4xx``: any other client error (authentication, a bad request).
- ``timeout``: the call timed out.
- ``transport``: the gateway did not answer (connect error, reset).
- ``refused``: the egress guard refused the payload. No call was made.
- ``unparseable``: the gateway answered 200 and the body held no verdict.
- ``serialization``: the payload could not be serialized. No call was made.
- ``blocked``: demo mode blocks the Oracle egress. No call was made.
- ``paused``: the quota pause was open. No call was made.
"""

from __future__ import annotations

import json
import re
from typing import Any

from soc_ai.secret_scrub import REDACTED, scrub_secrets

QUOTA = "quota"
SERVER = "5xx"
CLIENT = "4xx"
TIMEOUT = "timeout"
TRANSPORT = "transport"
REFUSED = "refused"
UNPARSEABLE = "unparseable"
SERIALIZATION = "serialization"
BLOCKED = "blocked"
PAUSED = "paused"

# A usage, rate or weekly limit, in the words the gateways and the providers
# behind them use. Production's text: "You've hit your weekly limit · resets
# Sep 14, 5am (UTC)". Matched on the gateway's message only, never on a model
# answer.
_QUOTA_RE = re.compile(
    r"weekly limit|daily limit|monthly limit|usage limit|rate[ _-]?limit|"
    r"quota|too many requests|hit your (?:\w+ )?limit|limit reached|"
    r"credit balance|insufficient[ _]credits?|resource[ _]exhausted",
    re.IGNORECASE,
)

# Bearer and API-key shaped tokens that scrub_secrets does not anchor on a key
# name: a bare ``sk-...`` key or a long opaque token after ``Bearer``.
_TOKEN_RE = re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_\-]{8,}\b|(?<=Bearer )[A-Za-z0-9._\-]{8,}")

MESSAGE_LIMIT = 300


def is_quota_message(text: str) -> bool:
    """True when *text* names a usage, rate or weekly limit."""
    return bool(_QUOTA_RE.search(text or ""))


def classify_http_failure(status: int, message: str) -> str:
    """The error class of a gateway answer with HTTP *status* and *message*."""
    if status == 429 or is_quota_message(message):
        return QUOTA
    if status >= 500:
        return SERVER
    return CLIENT


def gateway_message(body: str) -> str:
    """The human message inside a gateway error body.

    LiteLLM answers ``{"error": {"message": "...", ...}}``. Any other body is
    returned as it is. The caller scrubs and bounds the result.
    """
    text = (body or "").strip()
    if not text.startswith("{"):
        return text
    try:
        data: Any = json.loads(text)
    except ValueError:
        return text
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, dict) and isinstance(err.get("message"), str):
            return str(err["message"])
        if isinstance(err, str):
            return err
        if isinstance(data.get("message"), str):
            return str(data["message"])
        if isinstance(data.get("detail"), str):
            return str(data["detail"])
    return text


def scrub_message(text: str, *, secrets: tuple[str, ...] = (), limit: int = MESSAGE_LIMIT) -> str:
    """Secret-scrub and bound a gateway message for the store and the console.

    Masks credential values (:func:`soc_ai.secret_scrub.scrub_secrets`), bare
    API-key and bearer tokens, and every literal in *secrets* (the configured
    gateway key). Collapses whitespace and cuts at *limit* characters.
    """
    out = scrub_secrets(text or "")
    for secret in secrets:
        if secret and len(secret) >= 6:
            out = out.replace(secret, REDACTED)
    out = _TOKEN_RE.sub(REDACTED, out)
    out = " ".join(out.split())
    if len(out) > limit:
        out = out[: limit - 3].rstrip() + "..."
    return out


__all__ = [
    "BLOCKED",
    "CLIENT",
    "MESSAGE_LIMIT",
    "PAUSED",
    "QUOTA",
    "REFUSED",
    "SERIALIZATION",
    "SERVER",
    "TIMEOUT",
    "TRANSPORT",
    "UNPARSEABLE",
    "classify_http_failure",
    "gateway_message",
    "is_quota_message",
    "scrub_message",
]
