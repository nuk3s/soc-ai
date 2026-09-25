"""Reversible tokenisation of internal identifiers — Oracle privacy gate.

Every case payload MUST be sanitized here before being sent to a frontier
cloud model.  Internal network identifiers are replaced with stable opaque
labels (``IP_01``, ``HOST_02``, ``USER_03``, ``EMAIL_04``, ``MAC_05``).
The same real value always maps to the same label within one
:class:`Mapping`, so multi-field cross-references in the model's reasoning
remain consistent.

After the Oracle responds, :func:`desanitize` replaces labels with their
original values for local display.  :func:`unsafe_residue` is an INDEPENDENT
final sweep — it must not share code paths with :func:`sanitize` so that a
bug in one cannot mask a leak in the other.

WHAT IS REDACTED
----------------
- Private / internal IPv4 (RFC 1918, CGNAT 100.64/10, link-local, loopback,
  multicast, reserved) — determined via :mod:`ipaddress`.
- Private / internal IPv6 (private, link-local, loopback).
- Internal hostnames — FQDNs ending in a configured internal suffix
  (``oracle_internal_suffixes`` setting, default ``.lan .local .internal
  .corp``) or bare hostnames provided via ``extra_hosts``.
- Internal-domain emails — ``local@internal-suffix-domain``.
- ``/home/<user>/`` paths — only the ``<user>`` component.
- Windows user-profile paths (``C:\\Users\\<user>\\``,
  ``\\Documents and Settings\\<user>\\``) — only the ``<user>`` component.
- UNC share paths (``\\<host>\\<share>``) — only the ``<host>`` component.
- MAC addresses (always — they identify physical hardware).

WHAT PASSES THROUGH (load-bearing — do NOT touch)
-------------------------------------------------
Public IPs, public domains, URLs, file hashes (MD5/SHA-*), CVE IDs, ATT&CK
technique IDs, port numbers, rule names, and payload byte patterns are NOT
redacted — the Oracle needs them to reason about real threats.  A public IP
in ``allowlist`` also passes through verbatim.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from re import Pattern
from typing import Any

from soc_ai.config import get_settings
from soc_ai.oracle._cred_data import (
    CRED_KEYS,
    CRED_VALUE_STOPSET,
    plausible_credential_value,
    plausible_netbios_domain,
)

# ---------------------------------------------------------------------------
# Compiled patterns  (module-level — compiled once, reused everywhere)
# ---------------------------------------------------------------------------

# IPv4 — broad capture; each match is validated via ipaddress before redacting.
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# IPv6 — matches both full 8-group and any ::-compressed form.
# Lookarounds replace \b, which doesn't fire around ':'.
_IPV6_RE = re.compile(
    r"(?<![:\w.])"
    r"(?:"
    r"[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4}){7}"
    r"|(?:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4}){0,6})?::"
    r"(?:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4}){0,6})?"
    r")"
    r"(?![:\w.])"
)

# MAC addresses (colon or hyphen separated).
_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")

# Email — broad capture; internal-ness tested against suffix list.
# Quantifiers are bounded to RFC limits (local-part ≤64, domain ≤255, TLD a DNS
# label ≤63) so a long ``a-a-a…`` run with no ``@`` cannot cause catastrophic
# backtracking (ReDoS) on attacker-controlled free text.  No valid email exceeds
# these, so matching is unchanged for real input.
_EMAIL_RE = re.compile(r"\b[\w.+-]{1,64}@([\w.-]{1,255}\.[A-Za-z]{2,63})\b")

# /home/<user>/ — redact username only, preserve path tail.
_HOMEPATH_RE = re.compile(r"(/home/)([A-Za-z_][A-Za-z0-9_-]{0,31})(/|\b)")

# Windows user-profile paths — redact the <user> component only (the Windows
# analogue of _HOMEPATH_RE).  Covers modern ``C:\Users\<user>\`` and legacy
# ``\Documents and Settings\<user>\``.  The username runs up to the next path
# separator (Windows account names may contain spaces).
_WINPROFILE_RE = re.compile(
    r"([A-Za-z]:\\Users\\|\\Documents and Settings\\)"
    r"([^\\/:*?\"<>|\r\n]+)",
    re.IGNORECASE,
)

# UNC network share paths (``\\<host>\<share>\…``) — redact the <host> only.
# Structural: two backslashes at a boundary, a host label, then the share
# separator.  Independent of the credential ``DOMAIN\user`` rule (redact.py,
# which deliberately rejects a preceding backslash), so an SMB file-server name
# that appears only in free text still cannot egress.
_UNC_HOST_RE = re.compile(r"(?<![\w\\])\\\\([A-Za-z0-9](?:[A-Za-z0-9._-]{0,61}[A-Za-z0-9])?)(?=\\)")

# Opaque-label shape (USER_01, HOST_02, …) — used to avoid re-tokenising an
# already-redacted value on a second pass over the Windows-path rules.
_LABEL_FULLMATCH_RE = re.compile(r"(?:USER|HOST|IP|MAC|EMAIL)_\d+")

# Pre-existing label-shaped tokens in UNTRUSTED input (2026-08-25 audit, L3):
# an attacker who plants ``IP_01`` in a telemetry field collides with this
# module's own allocation namespace — ``desanitize`` would then splice the
# REAL value behind the allocated ``IP_01`` into the attacker's string (e.g.
# ``IP_01.attacker.example`` → ``10.x.y.z.attacker.example``) in locally
# stored/exported artifacts. ``_reserve_planted_labels`` scans for any such
# token the current mapping did NOT allocate and RESERVES its index (bumping
# the category counter past it) BEFORE any allocation rule runs: the mapping
# can then never mint that label for a real value, so the planted token stays
# textually intact but permanently absent from ``mapping.reverse`` — inert at
# ``desanitize``, which only replaces labels the mapping allocated. This is
# deliberately a reservation, NOT a rewrite (the wave-3 ``IP_01`` → ``IP-01``
# defusal): rewriting mangled ALREADY-LABELLED text re-sanitized under a
# FRESH mapping (the Oracle/eval ``sanitize_case`` path over pre-redacted
# corpus data — ``USER_01`` → ``USER-01``), corrupting labels the earlier
# pass legitimately allocated. With reservation, pre-labelled text is
# byte-stable under ANY mapping — same-mapping replay (labels are in
# ``reverse`` → exempt) and fresh-mapping re-sanitize (labels reserved,
# untouched) alike. Residual window (accepted, unchanged from wave 3): a
# planted token arriving AFTER the same label was genuinely allocated is
# textually indistinguishable from that label and passes through.
_PLANTED_LABEL_RE = re.compile(r"(?<!\w)(USER|HOST|IP|MAC|EMAIL)_(\d+)(?!\w)")

# An index wider than this can never be reached by real allocation (payloads
# are bounded), so it needs no reservation — and skipping it keeps a hostile
# thousand-digit index away from int() (CPython's int/str conversion limit).
_MAX_RESERVED_LABEL_DIGITS = 7


def _reserve_planted_labels(text: str, mapping: Mapping) -> None:
    """Reserve the index of every label-shaped token *this mapping did not
    allocate* so no later allocation can collide with it (see the note above).
    Scan-only: the text itself is never modified."""
    for match in _PLANTED_LABEL_RE.finditer(text):
        if match.group(0) in mapping.reverse:
            continue  # this mapping's own label — legitimate, nothing to do
        digits = match.group(2)
        if len(digits) > _MAX_RESERVED_LABEL_DIGITS:
            continue  # unreachable by real allocation; also int()-safe
        category, idx = match.group(1), int(digits)
        if idx > mapping.counters.get(category, 0):
            mapping.counters[category] = idx


# Well-known Windows profile folders / universal built-in accounts that are NOT
# user-identifying — never redact these (mirrors the credential rule's built-in
# stopset; the Oracle benefits from seeing e.g. the common ``C:\Users\Public``
# malware drop path verbatim).
_WINPROFILE_STOPSET: frozenset[str] = frozenset(
    {"public", "default", "default user", "all users", "administrator", "guest"}
)

# CGNAT range — Python's IPv4Address.is_private omits this on 3.12.
_CGNAT_NETWORK = ipaddress.IPv4Network("100.64.0.0/10")

# Placeholder used to park allowlisted tokens while sanitize() runs.
# NUL bytes are not valid in the identifiers we redact, so this cannot
# collide with real data.
_ALLOW_PLACEHOLDER = "\x00ALLOW{}\x00"


# ---------------------------------------------------------------------------
# Mapping
# ---------------------------------------------------------------------------


@dataclass
class Mapping:
    """Per-case bidirectional, deterministic redaction map.

    The same real value always receives the same label within one Mapping
    instance, so cross-field references stay consistent in the Oracle's
    reasoning.

    Attributes:
        forward: real value → opaque label (``IP_01``, …).
        reverse: opaque label → real value (for rehydration).
        counters: per-category allocation counter.
    """

    forward: dict[str, str] = field(default_factory=dict)
    reverse: dict[str, str] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=dict)

    def label_for(self, original: str, category: str) -> str:
        """Return (and allocate if needed) the opaque label for *original*."""
        if original in self.forward:
            return self.forward[original]
        idx = self.counters.get(category, 0) + 1
        self.counters[category] = idx
        label = f"{category}_{idx:02d}"
        self.forward[original] = label
        self.reverse[label] = original
        return label


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _is_private_ipv4(addr: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(addr)
    except ValueError:
        return False
    if ip in _CGNAT_NETWORK:
        return True
    return bool(
        ip.is_private or ip.is_link_local or ip.is_loopback or ip.is_multicast or ip.is_reserved
    )


def _is_private_ipv6(addr: str) -> bool:
    try:
        ip = ipaddress.IPv6Address(addr)
    except ValueError:
        return False
    return bool(ip.is_private or ip.is_link_local or ip.is_loopback)


def _build_host_re(suffixes: Iterable[str], extra_hosts: Iterable[str]) -> Pattern[str]:
    """Build a compiled regex that matches internal hostnames.

    Matches FQDNs ending in any *suffix* and bare *extra_hosts*.
    Negative-lookahead ``(?![\\w-])`` prevents partial matches on
    ``evil.local-ai.com``; negative-lookbehind ``(?<![\\w@])`` prevents
    matching the domain part of an email address (the first-label
    alternation additionally rejects a preceding ``.`` unless the label is
    underscore-led — see below).

    INVARIANT (suffix-FQDN class): every string :func:`unsafe_residue` can
    flag as a residual internal host MUST be matched here first (detector ⊆
    replacer).  The residue detector deliberately re-declares this pattern
    (the two paths must not fail together); keep the accepted label
    alphabets aligned when editing either.  Enforced by
    ``tests/test_oracle_sanitize.py::TestSuffixFqdnDetectorReplacerInvariant``.
    """
    parts: list[str] = []
    for suffix in suffixes:
        # Label quantifiers bounded to DNS limits (label ≤63, ≤127 labels) so a
        # long ``a-a-a…`` run cannot trigger catastrophic backtracking (ReDoS).
        # First label: ``(?<!\.)[A-Za-z0-9_]`` (no preceding dot — email-domain
        # / mid-FQDN guard) OR ``_`` even after a dot: DNS-SD service labels
        # (``_aaplcache._tcp.corp.lan``, incident 2026-07-08) are underscore-led
        # and appear after dot-runs when nonprintable bytes render as ``.``.
        parts.append(
            rf"(?<![\w@])(?:(?<!\.)[A-Za-z0-9_]|_)[\w-]{{0,62}}(?:\.[\w-]{{1,63}}){{0,126}}"
            rf"{re.escape(suffix)}(?!\.?[\w-])"
        )
    for host in extra_hosts:
        parts.append(rf"(?<![\w@.]){re.escape(host)}(?![\w-])")
    return re.compile("|".join(parts), re.IGNORECASE)


def _sanitize_str(
    text: str,
    mapping: Mapping,
    *,
    suffixes: tuple[str, ...],
    extra_hosts: tuple[str, ...],
    orig_to_ph: dict[str, str],
) -> str:
    """Apply all redaction rules to a single string.

    ``orig_to_ph`` maps allowlisted tokens (original value) → NUL-bracketed
    placeholder.  Parking replaces originals with placeholders before any
    redaction rule runs; the restoration step swaps them back after all rules.
    """

    # --- Park allowlisted tokens (replace original with placeholder) -----
    for original, ph in orig_to_ph.items():
        text = re.sub(rf"(?<!\w){re.escape(original)}(?!\w)", ph, text)

    # 0. Reserve the indices of PLANTED / pre-existing label-shaped tokens
    # (IP_01 …) the mapping did not allocate, BEFORE any rule below can
    # allocate a colliding label — an inbound-integrity guard, not a
    # redaction rule (audit L3). The text is not modified: an unallocated
    # label is inert at desanitize, and the reservation keeps it that way.
    _reserve_planted_labels(text, mapping)

    # 1. IPv4 (private only)
    def _v4(m: re.Match[str]) -> str:
        addr = m.group(0)
        return mapping.label_for(addr, "IP") if _is_private_ipv4(addr) else addr

    text = _IPV4_RE.sub(_v4, text)

    # 2. IPv6 (private only)
    def _v6(m: re.Match[str]) -> str:
        addr = m.group(0)
        return mapping.label_for(addr, "IP") if _is_private_ipv6(addr) else addr

    text = _IPV6_RE.sub(_v6, text)

    # 3. MAC — always redact (hardware identifier)
    def _mac(m: re.Match[str]) -> str:
        return mapping.label_for(m.group(0).lower(), "MAC")

    text = _MAC_RE.sub(_mac, text)

    # 4. Internal hostnames (FQDNs and bare names)
    host_re = _build_host_re(suffixes, extra_hosts)

    def _host(m: re.Match[str]) -> str:
        return mapping.label_for(m.group(0).lower(), "HOST")

    text = host_re.sub(_host, text)

    # 5. Internal-domain emails
    def _email(m: re.Match[str]) -> str:
        domain = m.group(1).lower()
        if any(domain.endswith(s.lstrip(".")) for s in suffixes):
            return mapping.label_for(m.group(0).lower(), "EMAIL")
        return m.group(0)

    text = _EMAIL_RE.sub(_email, text)

    # 6. /home/<user>/ — username only; skip if user is already a label
    def _home(m: re.Match[str]) -> str:
        head, user, tail = m.group(1), m.group(2), m.group(3)
        # If the username is already an opaque label (USER_01, IP_03, etc.),
        # don't re-tokenize it — that would create double redaction on a
        # second sanitize pass over an already-sanitized string.
        if re.fullmatch(r"(?:USER|HOST|IP|MAC|EMAIL)_\d+", user):
            return m.group(0)
        return f"{head}{mapping.label_for(user, 'USER')}{tail}"

    text = _HOMEPATH_RE.sub(_home, text)

    # 7. Windows user-profile paths — username component only (mirror of /home).
    def _winprofile(m: re.Match[str]) -> str:
        head, user = m.group(1), m.group(2)
        if _LABEL_FULLMATCH_RE.fullmatch(user) or user.lower() in _WINPROFILE_STOPSET:
            return m.group(0)
        return f"{head}{mapping.label_for(user, 'USER')}"

    text = _WINPROFILE_RE.sub(_winprofile, text)

    # 8. UNC share host — \\<host>\<share>; host component only.
    def _unc(m: re.Match[str]) -> str:
        host = m.group(1)
        if _LABEL_FULLMATCH_RE.fullmatch(host):
            return m.group(0)
        return f"\\\\{mapping.label_for(host, 'HOST')}"

    text = _UNC_HOST_RE.sub(_unc, text)

    # --- Restore allowlisted tokens (replace placeholder with original) --
    for original, ph in orig_to_ph.items():
        text = text.replace(ph, original)

    return text


# ---------------------------------------------------------------------------
# Settings helper (lazy — not called at import time)
# ---------------------------------------------------------------------------


def _settings_suffixes() -> tuple[str, ...]:
    """Return ``oracle_internal_suffixes`` from the cached settings singleton."""
    return get_settings().oracle_internal_suffixes


# Module-level defaults that mirror the Settings field default.  Used ONLY
# when the settings singleton cannot be loaded (e.g. missing required env
# vars in an isolated test that still wants the standard suffix set).
_DEFAULT_SUFFIXES: tuple[str, ...] = (".lan", ".local", ".internal", ".corp")


def _resolve_suffixes(extra_suffixes: Iterable[str]) -> tuple[str, ...]:
    """Return the effective suffix tuple for this call.

    Tries to read from settings; falls back to ``_DEFAULT_SUFFIXES`` if
    the settings singleton is not loadable (required fields missing).

    Every suffix is canonicalised to lowercase with a leading dot (the form
    ``store.internal_identifiers.normalize("suffix", ...)`` produces) and
    repeats are dropped.  The suffix-FQDN regexes below embed the suffix
    verbatim after a label that cannot end in ``.``, and the email/domain
    rules lowercase the value but not the suffix, so a caller passing
    ``"acme.example"`` or ``".ACME.EXAMPLE"`` would otherwise defeat both the
    replacer and the residue detector at once — nothing would refuse.
    """
    try:
        base = _settings_suffixes()
    except Exception:
        base = _DEFAULT_SUFFIXES
    out: list[str] = []
    for raw in (*base, *extra_suffixes):
        lowered = raw.strip().lower().lstrip(".")
        if lowered and "." + lowered not in out:
            out.append("." + lowered)
    return tuple(out)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def sanitize(
    obj: Any,
    mapping: Mapping,
    *,
    allowlist: Iterable[str] = (),
    extra_hosts: Iterable[str] = (),
    extra_suffixes: Iterable[str] = (),
) -> Any:
    """Recursively redact internal identifiers in *obj*.

    Walks ``str``, ``dict`` (keys and values), ``list``, and ``tuple``
    recursively.  All other types are returned unchanged.

    Args:
        obj: The object to sanitize.  Typically a ``dict`` deserialized from
            the case JSON, but can be a bare ``str`` for testing.
        mapping: Per-case :class:`Mapping` instance.  Allocates stable labels;
            reuse the same instance across multiple ``sanitize()`` calls in one
            case so labels stay consistent.
        allowlist: Iterable of tokens that MUST pass through verbatim even if
            they would otherwise be redacted (e.g. a compromised internal IP
            the analyst wants the Oracle to see as-is).
        extra_hosts: Additional single-label hostnames to redact (beyond the
            defaults in :attr:`~soc_ai.config.Settings.oracle_internal_suffixes`).
        extra_suffixes: Additional internal DNS suffixes beyond the settings
            default (e.g. ``.myco.example``).

    Returns:
        A sanitized copy of *obj* with the same structure.
    """
    suffixes: tuple[str, ...] = _resolve_suffixes(extra_suffixes)
    hosts: tuple[str, ...] = tuple(extra_hosts)

    # Build the allowlist map: original → placeholder. The placeholder is a
    # NUL-bracketed string that cannot appear in real data, so no redaction
    # rule will match it; we swap it back after all rules have run.
    allow_tokens = tuple(t for t in allowlist if t)
    orig_to_ph: dict[str, str] = {
        tok: _ALLOW_PLACEHOLDER.format(i) for i, tok in enumerate(allow_tokens)
    }

    def _walk(node: Any) -> Any:
        if isinstance(node, str):
            return _sanitize_str(
                node, mapping, suffixes=suffixes, extra_hosts=hosts, orig_to_ph=orig_to_ph
            )
        if isinstance(node, dict):
            return {_walk(k): _walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [_walk(item) for item in node]
        if isinstance(node, tuple):
            return tuple(_walk(item) for item in node)
        return node

    return _walk(obj)


def desanitize(obj: Any, mapping: Mapping) -> Any:
    """Recursively replace opaque labels in *obj* with their real values.

    Mirrors :func:`sanitize` — walks the same types (``str``, ``dict``,
    ``list``, ``tuple``) and is safe to call on an Oracle response string
    or a structured dict.

    Args:
        obj: The object containing opaque labels to restore.
        mapping: The same :class:`Mapping` instance used during sanitization.

    Returns:
        A copy of *obj* with all known labels replaced by real values.
    """
    if not mapping.reverse:
        return obj

    # Build a single pattern that matches all known labels (longest first to
    # avoid partial matches when one label is a prefix of another).  Word-boundary
    # guards (mirroring redact._build_learned_re) stop a label-shaped SUBSTRING
    # inside a longer token (e.g. ``IP_01`` within ``SHIP_0142``) from being
    # spliced into a real identifier — every label has the fixed ``CATEGORY_\d+``
    # shape, so the guards cannot break a legitimate whole-token match.
    pattern = re.compile(
        r"(?<!\w)(?:"
        + "|".join(re.escape(k) for k in sorted(mapping.reverse, key=len, reverse=True))
        + r")(?!\w)",
        re.IGNORECASE,
    )

    def _restore(label: str) -> str:
        # Labels are minted in canonical UPPER form (Mapping.label_for). Fold a
        # differently-cased occurrence the model emitted (``ip_01``) to that form
        # so it still rehydrates — kept SYMMETRIC with the case-insensitive
        # hallucination guard (find_unknown_oracle_labels): a case-variant label
        # is either restored here or refused there, never passed through as a
        # literal that runs as a confidently-wrong empty query (finding
        # oracle-lowercase-label-evasion).
        return mapping.reverse.get(label) or mapping.reverse.get(label.upper(), label)

    def _subst(text: str) -> str:
        return pattern.sub(lambda m: _restore(m.group(0)), text)

    def _walk(node: Any) -> Any:
        if isinstance(node, str):
            return _subst(node)
        if isinstance(node, dict):
            return {_walk(k): _walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [_walk(item) for item in node]
        if isinstance(node, tuple):
            return tuple(_walk(item) for item in node)
        return node

    return _walk(obj)


# ---------------------------------------------------------------------------
# The desanitize direction (Oracle tool loop) — hallucinated-label guard.
#
# When the reversible map is applied to MODEL-controlled input (the Oracle emits
# tool arguments carrying labels, which are desanitized to real grid values
# before execution — the 2026-08-27 design §3), a label the case never allocated
# is a new risk unique to that direction. ``desanitize`` substitutes only labels
# present in ``mapping.reverse``, so a hallucinated ``IP_47`` would flow into the
# query VERBATIM and return zero hits — not a leak, but a silent empty result,
# and a silent empty is indistinguishable from "no data" (the ``_index`` refusal
# rationale). The guard: scan the model's emitted arguments — BEFORE restoring —
# for label-shaped tokens the mapping never minted, and refuse rather than run a
# query against a literal placeholder. Same fixed ``CATEGORY_\d+`` alphabet the
# mapping mints (:meth:`Mapping.label_for`).
# ---------------------------------------------------------------------------

# IGNORECASE so a label the model emitted in the wrong case (``ip_47``) is still
# SEEN as label-shaped and put through the known/unknown test below — a
# case-sensitive net let ``source.ip:ip_47`` slip past as a literal, which then
# ran as a confidently-wrong empty query (finding oracle-lowercase-label-evasion).
_UNKNOWN_LABEL_RE = re.compile(r"(?<!\w)(?:USER|HOST|IP|MAC|EMAIL)_\d+(?!\w)", re.IGNORECASE)


class OracleUnknownLabelError(ValueError):
    """A model-emitted tool argument referenced an opaque label no case allocated.

    Raised by the Oracle tool loop's desanitize step when an argument carries a
    ``CATEGORY_NN`` token absent from ``mapping.reverse`` — a hallucinated
    identifier. The tool wrapper turns it into a structured, self-correcting tool
    error (:meth:`tool_error`) INSTEAD of executing the query, so the model gets
    "not an identifier in this case" back rather than a misleading empty result.
    The offending labels name what to fix; they are model-invented tokens, never
    real values, so they are safe to echo.
    """

    def __init__(self, labels: list[str]) -> None:
        self.labels = labels
        super().__init__("tool argument referenced unknown opaque label(s): " + ", ".join(labels))

    def tool_error(self) -> dict[str, Any]:
        """Render a structured tool result the model can read and correct from."""
        joined = ", ".join(self.labels)
        return {
            "error": True,
            "type": "UnknownLabel",
            "reason": "unknown_label",
            "message": (
                f"The argument referenced {joined}, which is not an identifier in "
                "this case. Use only the opaque labels (IP_01, HOST_02, USER_03, …) "
                "that actually appear in the evidence you were given; do not invent "
                "new ones. Re-issue the call with a label present in the case, or a "
                "literal public value."
            ),
        }


def find_unknown_oracle_labels(obj: Any, mapping: Mapping) -> list[str]:
    """Return the sorted, de-duplicated label-shaped tokens in *obj* that
    *mapping* never allocated (i.e. hallucinated by the model).

    Walks ``str`` / ``dict`` (keys and values) / ``list`` / ``tuple`` — the same
    shapes :func:`desanitize` walks — and matches only whole ``CATEGORY_NN``
    tokens (word-boundary-guarded, so ``SHIP_01`` is not read as ``IP_01``). A
    token already in ``mapping.reverse`` is a legitimate allocated label and is
    NOT flagged; everything else of that shape is unknown.
    """
    found: set[str] = set()

    def _walk(node: Any) -> None:
        if isinstance(node, str):
            for m in _UNKNOWN_LABEL_RE.finditer(node):
                tok = m.group(0)
                # Case-fold the membership test: labels are minted UPPER, so a
                # real label emitted in another case (``ip_01``) is KNOWN and NOT
                # flagged, while a true hallucination (``ip_47``, no IP_47
                # allocated) is. Symmetric with desanitize's case-insensitive
                # restore, so a case-variant label never slips through untouched.
                if tok.upper() not in mapping.reverse:
                    found.add(tok)
        elif isinstance(node, dict):
            for k, v in node.items():
                _walk(k)
                _walk(v)
        elif isinstance(node, (list, tuple)):
            for item in node:
                _walk(item)

    _walk(obj)
    return sorted(found)


def unsafe_residue(
    text: str,
    *,
    allowlist: Iterable[str] = (),
    extra_suffixes: Iterable[str] = (),
    extra_hosts: Iterable[str] = (),
    known_values: Iterable[str] = (),
    wire_escaped: bool = False,
) -> list[str]:
    """Independent sweep for internal identifiers that survived sanitization.

    This function deliberately does NOT call :func:`sanitize` or share its
    internal helpers — it re-implements detection from scratch so that a
    bug in the sanitize path cannot simultaneously blind the safety net.

    The caller MUST invoke this on the final outbound string and refuse to
    transmit if the returned list is non-empty.

    Args:
        text: The final outbound string (e.g. ``json.dumps(payload)``).
        allowlist: Tokens the caller deliberately allowed through; these will
            NOT be flagged even if they look like private identifiers.
        extra_suffixes: Additional internal DNS suffixes to check.
        extra_hosts: Additional bare hostnames to check.
        known_values: Real values that were learned by
            :func:`~soc_ai.oracle.redact.sanitize_case` during the harvest
            pass (i.e. ``mapping.reverse.values()``).  Any of these that
            still appear verbatim in *text* are flagged as residue — this
            catches bare hostnames / usernames that survived both passes.
        wire_escaped: Whether *text* is a ``json.dumps``-escaped blob (the
            cloud Oracle client, ``True``) versus a RAW un-serialized string
            (the demo publish leak gate and the analyst egress guard, the
            default ``False``).  It selects the NetBIOS ``DOMAIN\\user``
            separator: on the WIRE every real backslash is doubled, so a lone
            single backslash is a JSON escape (``\\n``) and must NOT be read as
            a separator (fixes the multi-line-transcript false positive); on RAW
            input a genuine down-level logon carries a single backslash, so a
            single backslash MUST stay a separator (catches ``DOMAIN\\nancy``).
            See :func:`_residue_credentials`.

    Returns:
        A list of human-readable leak descriptions.  Empty list means clean.
    """
    issues: list[str] = []
    allow: set[str] = set(allowlist)

    # --- 1. Private IPv4 (independent from sanitize._is_private_ipv4) -----
    # Re-implement the check without calling the sanitize helper so a change
    # to that function cannot simultaneously break both paths.
    _cgnat = ipaddress.IPv4Network("100.64.0.0/10")

    def _private_v4(addr: str) -> bool:
        try:
            ip = ipaddress.IPv4Address(addr)
        except ValueError:
            return False
        if ip in _cgnat:
            return True
        return bool(
            ip.is_private or ip.is_link_local or ip.is_loopback or ip.is_multicast or ip.is_reserved
        )

    for mat in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        addr = mat.group(0)
        if addr not in allow and _private_v4(addr):
            issues.append(f"residual private IPv4: {addr}")

    # --- 2. Private IPv6 ---------------------------------------------------
    _ipv6_re = re.compile(
        r"(?<![:\w.])"
        r"(?:"
        r"[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4}){7}"
        r"|(?:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4}){0,6})?::"
        r"(?:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4}){0,6})?"
        r")"
        r"(?![:\w.])"
    )

    def _private_v6(addr: str) -> bool:
        try:
            ip = ipaddress.IPv6Address(addr)
        except ValueError:
            return False
        return bool(ip.is_private or ip.is_link_local or ip.is_loopback)

    for mat in _ipv6_re.finditer(text):
        addr = mat.group(0)
        if addr not in allow and _private_v6(addr):
            issues.append(f"residual private IPv6: {addr}")

    # --- 3. MAC addresses --------------------------------------------------
    for mat in re.finditer(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b", text):
        tok = mat.group(0)
        if tok not in allow and tok.lower() not in allow:
            issues.append(f"residual MAC: {tok}")

    # --- 4. Internal hostnames ---------------------------------------------
    suffixes: tuple[str, ...] = _resolve_suffixes(extra_suffixes)
    hosts: tuple[str, ...] = tuple(extra_hosts)
    host_parts: list[str] = []
    for suffix in suffixes:
        # Bounded label quantifiers (DNS limits) — ReDoS-safe; see _build_host_re.
        # Deliberately re-declared (NOT shared with _build_host_re) so the two
        # detection paths cannot fail together.  INVARIANT: this detector must
        # accept a SUBSET of what _build_host_re's replacer matches (same label
        # alphabet, incl. underscore-led DNS-SD first labels) — anything flagged
        # here must have been redacted there first.  Keep the alphabets aligned;
        # enforced by tests/test_oracle_sanitize.py::
        # TestSuffixFqdnDetectorReplacerInvariant.
        host_parts.append(
            rf"(?<![\w@])(?:(?<!\.)[A-Za-z0-9_]|_)[\w-]{{0,62}}(?:\.[\w-]{{1,63}}){{0,126}}"
            rf"{re.escape(suffix)}(?!\.?[\w-])"
        )
    for host in hosts:
        host_parts.append(rf"(?<![\w@.]){re.escape(host)}(?![\w-])")
    if host_parts:
        host_re = re.compile("|".join(host_parts), re.IGNORECASE)
        for mat in host_re.finditer(text):
            tok = mat.group(0)
            if tok not in allow and tok.lower() not in allow:
                issues.append(f"residual internal host: {tok}")

    # --- 5. Internal-domain emails -----------------------------------------
    for mat in re.finditer(r"\b[\w.+-]{1,64}@([\w.-]{1,255}\.[A-Za-z]{2,63})\b", text):
        domain = mat.group(1).lower()
        if any(domain.endswith(s.lstrip(".")) for s in suffixes):
            tok = mat.group(0)
            if tok not in allow and tok.lower() not in allow:
                issues.append(f"residual internal email: {tok}")

    # --- 6. /home/<user>/ --------------------------------------------------
    _home_re = re.compile(r"(/home/)([A-Za-z_][A-Za-z0-9_-]{0,31})(/|\b)")
    for mat in _home_re.finditer(text):
        username = mat.group(2)
        # Labels like USER_01 or IP_03 placed by sanitize() are NOT leaks.
        if re.fullmatch(r"(?:USER|HOST|IP|MAC|EMAIL)_\d+", username):
            continue
        tok = mat.group(0)
        if tok not in allow and username not in allow:
            issues.append(f"residual /home/<user>: {tok}")

    # --- 7. Learned known values (bare hostnames / usernames) ---------------
    issues.extend(_residue_known_values(text, known_values, allow))

    # --- 8. NetBIOS / Windows-style bare hostnames (independent net) --------
    # Last-resort safety net for a structurally-shaped internal computer name
    # (DESKTOP-AB12, FINANCE-PC) that survived BOTH sanitize passes — e.g. it
    # appeared only in a free-text field the redacter's pattern somehow missed,
    # or known_values was not threaded.  Re-implemented from scratch here (NOT
    # importing redact.py) so a bug in the redacter cannot blind this gate.
    issues.extend(_residue_netbios_hosts(text, allow))

    # --- 9. Credential-context usernames (independent net) ------------------
    # A bare username in an explicit credential context (user=jdoe, DOMAIN\jdoe)
    # that survived the redacter's free-text credential pass.  Independent regex
    # so a redacter bug cannot blind this; a subset of the redacter's key set so
    # it never fires on a value the redacter already tokenised to a label.  The
    # NetBIOS separator is raw/wire mode-aware (see ``wire_escaped``).
    issues.extend(_residue_credentials(text, allow, wire_escaped=wire_escaped))

    # --- 10. Windows user-profile paths (independent net) -------------------
    # A profile username (``C:\Users\<user>\``) that survived the redacter's
    # Windows-path pass.  Anchored on the literal ``Users`` segment (zero FP).
    issues.extend(_residue_winprofile(text, allow))

    # --- 11. UNC share hosts (independent net) ------------------------------
    # An SMB file-server host (``\\<host>\<share>``) that survived.  Four-
    # backslash UNC prefix in JSON output → never trips on hex-escape shellcode.
    issues.extend(_residue_unc_hosts(text, allow))

    return issues


_OPAQUE_LABEL_RE = re.compile(r"(?:USER|HOST|IP|MAC|EMAIL)_\d+")

# Independent (do-not-share-with-redact) NetBIOS/Windows bare-hostname patterns.
# Mirrors the conservative shape used by the redacter but is re-declared here so
# the two detection paths cannot fail together.  Same affix allow-set, same
# dot-disqualification (a dot ⇒ FQDN ⇒ suffix rules' job, not this net).
#
# The boundaries reject a preceding BACKSLASH (``\\`` added to the lookbehind).
# This net runs over a ``json.dumps`` blob too, where a real newline/tab renders
# as a JSON escape (``\n`` = ``\`` + ``n``); without the guard the escape LETTER
# started a spurious match — a static tool-description phrase like
# ``…role guess, a\nserver-vs-workstation…`` was flagged as the bare hostname
# ``nserver-vs-workstation`` and refused EVERY tool-loop adjudication at the wire
# (surfaced by the real-wire test; the tool schemas ride the body but are never
# sanitized, so only this gate sees them). A genuine NetBIOS name is never
# preceded by a backslash (that is a UNC / path context, its own net's job), so
# the guard is a strict tightening — detector still ⊆ replacer, no leak opened.
_RESIDUE_NETBIOS_PREFIX_RE = re.compile(
    r"(?<![\w.\\-])"
    r"(?:DESKTOP|LAPTOP|WIN|WORKSTATION|PC|WKS|SRV|DC)-[A-Z0-9-]*[A-Z0-9]"
    r"(?![\w.-])",
    re.IGNORECASE,
)
_RESIDUE_NETBIOS_SUFFIX_RE = re.compile(
    r"(?<![\w.\\-])"
    r"[A-Z0-9][A-Z0-9-]*-(?:PC|LAPTOP|DESKTOP|WKS|WS|WORKSTATION|SRV)"
    r"(?![\w.-])",
    re.IGNORECASE,
)


def _residue_netbios_hosts(text: str, allow: set[str]) -> list[str]:
    """Flag NetBIOS/Windows-style bare hostnames that survived sanitization.

    Conservative by construction (structural affix + no dot), matching the
    redacter's intent but implemented independently.  Opaque labels and
    allowlisted tokens are never flagged.
    """
    issues: list[str] = []
    seen: set[str] = set()
    for rx in (_RESIDUE_NETBIOS_PREFIX_RE, _RESIDUE_NETBIOS_SUFFIX_RE):
        for mat in rx.finditer(text):
            tok = mat.group(0)
            key = tok.lower()
            if key in seen:
                continue
            seen.add(key)
            # Never flag an opaque label (e.g. a hypothetical SRV-… collision)
            # or an explicitly allowlisted token.
            if _OPAQUE_LABEL_RE.fullmatch(tok):
                continue
            if tok in allow or key in allow:
                continue
            issues.append(f"residual bare hostname: {tok}")
    return issues


# Independent (do-not-share-with-redact) credential-context patterns.  The key
# set MATCHES the redacter's (redact.py:_CRED_KEYS) so this fail-closed net is at
# least as broad as the redacter — in normal operation the redacter has already
# tokenised the value (so this sees an opaque label and stays silent); it only
# fires on a genuine redacter MISS.  Re-declared independently so the two paths
# cannot fail together.
_RESIDUE_CRED_VALUE = r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?"
# The credential key alternation is SHARED with the redacter via
# :mod:`soc_ai.oracle._cred_data` (``CRED_KEYS``) so a redacter MISS on any of
# those shapes is still caught by this independent net (detector ⊆ replacer) and
# the two key lists cannot silently diverge (finding oracle-cred-twin-nets).  The
# ENGINE stays independent: this net adds ``\\?`` before each optional quote so
# the json.dumps'd wire form ``\"key\": \"val\"`` is tolerated too.
_RESIDUE_CRED_KV_RE = re.compile(
    r"(?<![\w.])(?:" + CRED_KEYS + r")"
    # The backslash is allowed ONLY before a quote (the json.dumps'd ``\"``).
    # A bare optional backslash swallowed the ``\`` of a ``\n`` and read the
    # next line's first word as the value (``user:\npaths`` -> ``npaths``).
    r"\s*(?:\\?\")?\s*[:=]\s*(?:\\?\")?"
    r"(?P<val>" + _RESIDUE_CRED_VALUE + r")(?![\w@/-])",
    re.IGNORECASE,
)
# The 4624/4625 ``Account Name:`` (a username) / ``Account Domain:`` (a NetBIOS
# domain) message rendering — the space-joined label matches no key alternation,
# so these are separate nets (mirror redact.py:_CRED_ACCOUNT_NAME_RE /
# _CRED_ACCOUNT_DOMAIN_RE).
_RESIDUE_CRED_ACCOUNT_NAME_RE = re.compile(
    r"Account Name\s*:\s+(?P<val>" + _RESIDUE_CRED_VALUE + r")(?![\w@/-])",
    re.IGNORECASE,
)
_RESIDUE_CRED_ACCOUNT_DOMAIN_RE = re.compile(
    r"Account Domain\s*:\s+(?P<val>" + _RESIDUE_CRED_VALUE + r")(?![\w@/-])",
    re.IGNORECASE,
)
# NetBIOS ``DOMAIN\user`` down-level logon — mode-aware separator, because this net
# runs on BOTH raw and json.dumps'd input and a backslash means different things in
# each (finding residue-gate-json-newline-fp; raw-regression remediation).
#
# RAW (the default, ``wire_escaped=False``): un-serialized string values — the demo
# publish leak gate and the analyst egress guard.  A genuine down-level logon here
# carries a SINGLE literal backslash, so the separator is ``\\{1,4}`` (the batch-1
# safe-broad behavior): ``DOMAIN\nancy`` / ``DOMAIN\frank`` are caught.  A real
# newline in raw input is a real newline byte, never ``\`` + ``n``, so there is no
# escaped-newline artifact to false-positive on.
#
# WIRE (``wire_escaped=True``): ``json.dumps`` output — the cloud Oracle client.
# Every real backslash is DOUBLED here, so a genuine separator is ALWAYS ≥2 and the
# separator is ``\\{2,4}``.  A real newline/tab/quote is a JSON escape carrying a
# LONE single backslash (``\n`` = ``\`` + ``n``); dropping the single-backslash arm
# entirely rejects that ``…a CDN\nVerdict…`` false positive while still catching a
# genuine ``DOMAIN\user`` (2 wire backslashes) and a doubled winlog ``DOMAIN\\user``
# (4).  This is cleaner than a per-escape-letter lookahead — which also swallowed a
# raw ``DOMAIN\nancy`` — and needs no such carve-out.
#
# Both: domain requires ≥2 chars (``[A-Za-z0-9]`` + ``{1,62}``) so a single-letter
# drive letter (``C\…``) is not mis-read as a NetBIOS domain, and the caller applies
# the hive-prefix skip (``HKLM\…``) in both modes.
_RESIDUE_CRED_NETBIOS_RE_RAW = re.compile(
    r"(?<![\w.\\])(?P<dom>[A-Za-z0-9][A-Za-z0-9._-]{1,62})\\{1,4}"
    r"(?P<val>" + _RESIDUE_CRED_VALUE + r")(?![\w.\\@-])"
)
_RESIDUE_CRED_NETBIOS_RE_WIRE = re.compile(
    r"(?<![\w.\\])(?P<dom>[A-Za-z0-9][A-Za-z0-9._-]{1,62})\\{2,4}"
    r"(?P<val>" + _RESIDUE_CRED_VALUE + r")(?![\w.\\@-])"
)
# NetBIOS authorities / registry hives that are NOT internal-identifying: the bare
# ``nt`` (the ``Account Domain:  NT AUTHORITY`` capture stops at the first space),
# and the ``HIVE\Subkey`` path prefixes that share the ``TOKEN\TOKEN`` shape of a
# down-level logon.  Re-declared independently of redact.py.
_RESIDUE_NT_DOMAIN_STOPSET: frozenset[str] = frozenset({"nt", "authority", "builtin", "service"})
_RESIDUE_NONDOMAIN_PREFIXES: frozenset[str] = frozenset({"hklm", "hkcu", "hkcr", "hku", "hkcc"})


def _residue_is_nondomain_prefix(tok: str) -> bool:
    """True iff *tok* is a registry hive / non-domain technical prefix, so a
    ``tok\\segment`` residue match is a PATH, not a logon name."""
    low = tok.lower()
    return low in _RESIDUE_NONDOMAIN_PREFIXES or low.startswith("hkey")


# Tokens that are not internal-identifying usernames — SHARED with the redacter
# via :mod:`soc_ai.oracle._cred_data` so a stopword added to the redacter cannot
# diverge from this net and cause a permanent refusal (finding
# oracle-cred-twin-nets).  The regex engine above stays independent.
_RESIDUE_CRED_STOPSET: frozenset[str] = CRED_VALUE_STOPSET


def _residue_credentials(text: str, allow: set[str], *, wire_escaped: bool = False) -> list[str]:
    """Flag credential-context usernames/domains that survived the redacter.

    Independent of :mod:`redact` (own regex, own stopset).  Opaque labels,
    allowlisted tokens, built-in accounts, booleans/status words, and numeric
    ids are never flagged.  The username-context nets (KV / Account Name /
    NetBIOS) use the username stopset; the domain-context net (``Account
    Domain:``) uses the NT-authority stopset — mirroring how the redacter stops
    ``NT``/``BUILTIN`` for domains but tokenises the same word as a username.

    ``wire_escaped`` picks the NetBIOS ``DOMAIN\\user`` separator: ``\\{2,4}``
    for a ``json.dumps`` blob (every real backslash doubled — a lone one is a
    JSON escape, not a separator) versus ``\\{1,4}`` for a RAW string (a genuine
    single-backslash logon must still be caught).  The hive-prefix skip applies
    in BOTH modes.
    """
    issues: list[str] = []
    seen: set[str] = set()

    def _emit_username(val: str) -> None:
        key = val.lower()
        if key in seen:
            return
        seen.add(key)
        if _OPAQUE_LABEL_RE.fullmatch(val):
            return
        if val in allow or key in allow:
            return
        if key in _RESIDUE_CRED_STOPSET or val.isdigit():
            return
        if not any(c.isalpha() for c in val):
            return
        if not plausible_credential_value(val):
            return
        issues.append(f"residual credential username: {val}")

    # KV + Account Name → username context.
    for rx in (_RESIDUE_CRED_KV_RE, _RESIDUE_CRED_ACCOUNT_NAME_RE):
        for mat in rx.finditer(text):
            _emit_username(mat.group("val"))

    # NetBIOS ``DOMAIN\user`` → username, UNLESS the left token is a registry
    # hive / non-domain prefix (``HKLM\Software`` is a path, not a logon) — the
    # hive skip applies in BOTH modes.  RAW input uses the single-backslash-safe
    # separator; a json.dumps blob uses the doubled-backslash one.
    netbios_re = _RESIDUE_CRED_NETBIOS_RE_WIRE if wire_escaped else _RESIDUE_CRED_NETBIOS_RE_RAW
    for mat in netbios_re.finditer(text):
        if _residue_is_nondomain_prefix(mat.group("dom")):
            continue
        if not plausible_netbios_domain(mat.group("dom")):
            continue
        _emit_username(mat.group("val"))

    # Account Domain → domain context: the NT-authority stopset, not the username
    # one (``NT`` / ``BUILTIN`` / ``AUTHORITY`` pass; a real NetBIOS domain flags).
    for mat in _RESIDUE_CRED_ACCOUNT_DOMAIN_RE.finditer(text):
        val = mat.group("val")
        key = val.lower()
        if key in seen:
            continue
        seen.add(key)
        if _OPAQUE_LABEL_RE.fullmatch(val):
            continue
        if val in allow or key in allow:
            continue
        if key in _RESIDUE_NT_DOMAIN_STOPSET:
            continue
        if not any(c.isalpha() for c in val):
            continue
        issues.append(f"residual credential domain: {val}")

    return issues


# Independent (do-not-share-with-redact) Windows-native path nets.  Re-declared
# from scratch so a bug in the redacter cannot blind the safety net.  These run
# on ``json.dumps`` output where every backslash is doubled: a real UNC ``\\``
# (two raw backslashes) becomes four, while a single-backslash hex escape
# (``\x90``) becomes only two — so ``\\{4}`` on the UNC prefix never trips on
# shellcode, while ``\\{1,2}`` on the profile separators tolerates both the raw
# dict value and the JSON-escaped form.
_RESIDUE_WINPROFILE_RE = re.compile(
    r"(?:[A-Za-z]:\\{1,2}Users|\\{1,2}Documents and Settings)\\{1,2}"
    r"([^\\/:*?\"<>|\r\n]+)",
    re.IGNORECASE,
)
_RESIDUE_UNC_HOST_RE = re.compile(r"\\{4}([A-Za-z0-9](?:[A-Za-z0-9._-]{0,61}[A-Za-z0-9])?)\\{2}")


def _residue_winprofile(text: str, allow: set[str]) -> list[str]:
    """Flag Windows user-profile paths whose ``<user>`` component survived.

    Anchored on the literal ``Users`` / ``Documents and Settings`` segment, so
    it never fires on arbitrary text.  Opaque labels and allowlisted tokens are
    never flagged.
    """
    issues: list[str] = []
    seen: set[str] = set()
    for mat in _RESIDUE_WINPROFILE_RE.finditer(text):
        user = mat.group(1)
        key = user.lower()
        if key in seen:
            continue
        seen.add(key)
        if _OPAQUE_LABEL_RE.fullmatch(user) or key in _WINPROFILE_STOPSET:
            continue
        if user in allow or key in allow:
            continue
        issues.append(f"residual Windows profile user: {user}")
    return issues


def _residue_unc_hosts(text: str, allow: set[str]) -> list[str]:
    """Flag UNC share hosts (``\\\\<host>\\<share>``) that survived.

    Structural and conservative (four-backslash UNC prefix in JSON output).
    Opaque labels and allowlisted tokens are never flagged.
    """
    issues: list[str] = []
    seen: set[str] = set()
    for mat in _RESIDUE_UNC_HOST_RE.finditer(text):
        host = mat.group(1)
        key = host.lower()
        if key in seen:
            continue
        seen.add(key)
        if _OPAQUE_LABEL_RE.fullmatch(host):
            continue
        if host in allow or key in allow:
            continue
        issues.append(f"residual UNC host: {host}")
    return issues


def _residue_known_values(
    text: str,
    known_values: Iterable[str],
    allow: set[str],
) -> list[str]:
    """Scan *text* for real values that were learned during the harvest pass
    but survived to the outbound payload (a redaction failure).

    Deliberately separate from the rest of ``unsafe_residue`` so the main
    function stays within branch/statement limits.
    """
    issues: list[str] = []
    for kv in known_values:
        if not kv or not isinstance(kv, str):
            continue
        # Skip if explicitly in the allowlist.
        if kv in allow or kv.lower() in allow:
            continue
        # Skip opaque labels (HOST_01, USER_02, etc.) — those are the desired
        # output, not a leak.
        # A learned value that fails the shared shape rule was learned by an
        # older build or from a structured field the rule does not gate; a
        # one-character value matches everywhere and refuses by construction.
        if len(kv) < 2 or not plausible_netbios_domain(kv):
            continue
        if _OPAQUE_LABEL_RE.fullmatch(kv):
            continue
        # Word-boundary check — case-insensitive so FINANCE-PC fires on
        # "finance-pc" and vice-versa.
        if re.search(r"(?<!\w)" + re.escape(kv) + r"(?!\w)", text, re.IGNORECASE):
            issues.append(f"residual learned value: {kv}")
    return issues


def redaction_summary(mapping: Mapping) -> dict[str, int]:
    """Return per-category redaction counts for the audit log.

    Never includes the actual values — only counts, safe to log.

    Example::

        {"IP": 3, "HOST": 1, "MAC": 2}
    """
    return dict(mapping.counters)


@dataclass(frozen=True)
class Replacement:
    """One redaction pair: the opaque label, the real value it replaced, and
    the sanitizer category (``IP``, ``HOST``, ``USER``, ``EMAIL``, ``MAC``)."""

    label: str
    value: str
    category: str


def redaction_replacements(mapping: Mapping) -> list[Replacement]:
    """Return every (label ↔ value) pair *mapping* has allocated, read-only.

    UNLIKE :func:`redaction_summary` this DOES carry the real values — use it
    only where the caller already sees the raw text (the admin-gated redaction
    previews, which return the original alongside the sanitized output).  The
    category is recovered from the label's ``{CATEGORY}_{NN}`` shape, so the
    result never depends on state beyond the mapping itself.
    """
    return [
        Replacement(label=label, value=value, category=label.rsplit("_", 1)[0])
        for value, label in mapping.forward.items()
    ]
