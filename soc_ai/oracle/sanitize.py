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
    ``evil.local-ai.com``; negative-lookbehind ``(?<![\\w@.])`` prevents
    matching the domain part of an email address.
    """
    parts: list[str] = []
    for suffix in suffixes:
        # Label quantifiers bounded to DNS limits (label ≤63, ≤127 labels) so a
        # long ``a-a-a…`` run cannot trigger catastrophic backtracking (ReDoS).
        parts.append(
            rf"(?<![\w@.])[A-Za-z0-9][\w-]{{0,62}}(?:\.[\w-]{{1,63}}){{0,126}}"
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
    """
    try:
        base = _settings_suffixes()
    except Exception:
        base = _DEFAULT_SUFFIXES
    return base + tuple(extra_suffixes)


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
    # avoid partial matches when one label is a prefix of another).
    pattern = re.compile(
        "|".join(re.escape(k) for k in sorted(mapping.reverse, key=len, reverse=True))
    )

    def _subst(text: str) -> str:
        return pattern.sub(lambda m: mapping.reverse[m.group(0)], text)

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


def unsafe_residue(
    text: str,
    *,
    allowlist: Iterable[str] = (),
    extra_suffixes: Iterable[str] = (),
    extra_hosts: Iterable[str] = (),
    known_values: Iterable[str] = (),
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
        host_parts.append(
            rf"(?<![\w@.])[A-Za-z0-9][\w-]{{0,62}}(?:\.[\w-]{{1,63}}){{0,126}}"
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
    # it never fires on a value the redacter already tokenised to a label.
    issues.extend(_residue_credentials(text, allow))

    return issues


_OPAQUE_LABEL_RE = re.compile(r"(?:USER|HOST|IP|MAC|EMAIL)_\d+")

# Independent (do-not-share-with-redact) NetBIOS/Windows bare-hostname patterns.
# Mirrors the conservative shape used by the redacter but is re-declared here so
# the two detection paths cannot fail together.  Same affix allow-set, same
# dot-disqualification (a dot ⇒ FQDN ⇒ suffix rules' job, not this net).
_RESIDUE_NETBIOS_PREFIX_RE = re.compile(
    r"(?<![\w.-])"
    r"(?:DESKTOP|LAPTOP|WIN|WORKSTATION|PC|WKS|SRV|DC)-[A-Z0-9-]*[A-Z0-9]"
    r"(?![\w.-])",
    re.IGNORECASE,
)
_RESIDUE_NETBIOS_SUFFIX_RE = re.compile(
    r"(?<![\w.-])"
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
_RESIDUE_CRED_KV_RE = re.compile(
    r"(?<![\w.])(?:samaccountname|username|user[_ -]?name|account|acct|logon|user|usr)"
    r"\s*[:=]\s*\"?"
    r"(?P<val>" + _RESIDUE_CRED_VALUE + r")(?![\w@-])",
    re.IGNORECASE,
)
# Separator is ``\\{1,2}``: the redacter operates on the single-backslash dict
# value, but this net runs on ``json.dumps`` output where the backslash is
# escaped to ``\\`` — match either so a missed logon name is still caught.
# Domain requires ≥2 chars (``[A-Za-z0-9]`` + ``{1,62}``) so a single-letter
# token (drive letter ``C\…``) is not mis-read as a NetBIOS domain — matches the
# redacter's _CRED_NETBIOS_RE so this net never fires on what the redacter skips.
_RESIDUE_CRED_NETBIOS_RE = re.compile(
    r"(?<![\w.\\])[A-Za-z0-9][A-Za-z0-9._-]{1,62}\\{1,2}"
    r"(?P<val>" + _RESIDUE_CRED_VALUE + r")(?![\w.\\@-])"
)
# Tokens that are not internal-identifying usernames (re-declared independently).
_RESIDUE_CRED_STOPSET: frozenset[str] = frozenset(
    {
        "true",
        "false",
        "null",
        "none",
        "nil",
        "yes",
        "no",
        "unknown",
        "na",
        "success",
        "successful",
        "failure",
        "failed",
        "fail",
        "denied",
        "allowed",
        "enabled",
        "disabled",
        "active",
        "inactive",
        "valid",
        "invalid",
        "error",
        "ok",
        "expired",
        "locked",
        "unlocked",
        "root",
        "system",
        "localsystem",
        "administrator",
        "admin",
        "guest",
        "nobody",
        "daemon",
        "bin",
        "sys",
        "sync",
        "lp",
        "mail",
        "news",
        "uucp",
        "proxy",
        "backup",
        "list",
        "irc",
        "gnats",
        "www-data",
        "sshd",
        "postfix",
        "anonymous",
        "ftp",
        "operator",
        "service",
        "localservice",
        "networkservice",
        "everyone",
        "self",
    }
)


def _residue_credentials(text: str, allow: set[str]) -> list[str]:
    """Flag credential-context usernames that survived the redacter.

    Independent of :mod:`redact` (own regex, own stopset).  Opaque labels,
    allowlisted tokens, built-in accounts, booleans/status words, and numeric
    ids are never flagged.
    """
    issues: list[str] = []
    seen: set[str] = set()
    for rx in (_RESIDUE_CRED_KV_RE, _RESIDUE_CRED_NETBIOS_RE):
        for mat in rx.finditer(text):
            val = mat.group("val")
            key = val.lower()
            if key in seen:
                continue
            seen.add(key)
            if _OPAQUE_LABEL_RE.fullmatch(val):
                continue
            if val in allow or key in allow:
                continue
            if key in _RESIDUE_CRED_STOPSET or val.isdigit():
                continue
            if not any(c.isalpha() for c in val):
                continue
            issues.append(f"residual credential username: {val}")
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
