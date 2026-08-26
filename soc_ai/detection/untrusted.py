"""Neutralization + demarcation helpers for untrusted telemetry in prompts.

The detection drafter is a no-tools model fed a composed prompt whose
"ground truth" section is built from attacker-controllable Elasticsearch
field values (2026-08-25 security audit, finding M1). Two hardening layers
live here, shared by the evidence builder
(:mod:`soc_ai.api.webui.routes_detection`) and the prompt composer
(:mod:`soc_ai.detection.drafter`):

* :func:`neutralize_untrusted` — escapes control characters (so a
  newline-bearing value cannot break out of its ``- id: path=value`` list
  item and render injected sentences as their own lines), defuses the fence
  marker punctuation (so untrusted content cannot forge or close the fence),
  and applies a hard length cap. Clean single-line values pass through
  byte-identical, so the legitimate grounding intent is untouched.
* :data:`UNTRUSTED_BEGIN` / :data:`UNTRUSTED_END` — the explicit delimiters
  the drafter prompt fences the untrusted finding + evidence block with. The
  block is labelled as observed DATA that must never be treated as
  instructions; the ``<<<``/``>>>`` runs cannot appear in neutralized
  content (a space is inserted so the run breaks: ``< <<`` / ``>> >``), so
  the markers are unforgeable from inside the fence.
"""

from __future__ import annotations

import re

# The fence delimiters. Deliberately built from ``<<<``/``>>>`` runs, which
# :func:`neutralize_untrusted` rewrites inside untrusted content — a payload
# carrying the literal end marker cannot close the fence early.
UNTRUSTED_BEGIN = "<<<BEGIN UNTRUSTED TELEMETRY>>>"
UNTRUSTED_END = "<<<END UNTRUSTED TELEMETRY>>>"

# C0 controls, DEL, C1 controls, and the Unicode line/paragraph separators
# (which many renderers treat as newlines). Two variants: the single-line one
# escapes newlines too; the multi-line one (finding *detail* — legitimate
# prose) keeps ``\n`` (a bare CR is still escaped, so no other line break
# survives).
_CTRL_RE = re.compile("[\\x00-\\x1f\\x7f-\\x9f\\u2028\\u2029]")
_CTRL_KEEP_NL_RE = re.compile("[\\x00-\\x09\\x0b-\\x1f\\x7f-\\x9f\\u2028\\u2029]")

_CTRL_NAMED = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _escaped_ctrl(match: re.Match[str]) -> str:
    ch = match.group(0)
    named = _CTRL_NAMED.get(ch)
    if named is not None:
        return named
    code = ord(ch)
    return f"\\x{code:02x}" if code <= 0xFF else f"\\u{code:04x}"


def neutralize_untrusted(text: str, *, cap: int, keep_newlines: bool = False) -> str:
    """Render one untrusted string safe to splice into a drafter prompt.

    Escapes control characters to visible ``\\n``/``\\x1b``-style sequences
    (evidence fidelity: the model still sees that the byte was there),
    defuses fence-marker punctuation, and truncates to *cap* characters with
    a visible ellipsis. ``keep_newlines=True`` preserves ``\\n`` for
    multi-line prose (the finding detail) while still escaping everything
    else — safe only INSIDE the fence, where the markers are unforgeable.
    """
    pattern = _CTRL_KEEP_NL_RE if keep_newlines else _CTRL_RE
    out = pattern.sub(_escaped_ctrl, text)
    # Defuse marker punctuation AFTER escaping (escaping never mints ``<``).
    out = out.replace("<<<", "< <<").replace(">>>", ">> >")
    if len(out) > cap:
        out = out[:cap] + "…"
    return out
