"""Field-aware, learning redacter for structured SO/ECS case payloads.

:func:`sanitize_case` is the high-level entry point that replaces the plain
:func:`~soc_ai.oracle.sanitize.sanitize` call in :mod:`soc_ai.oracle.client`.
It performs a **two-pass** sweep over the structured dict:

**Pass 1 — field-aware harvest:**
Walk the dict path-aware.  For every ECS/SO field whose *role* is known
(HOST / USER / IP / DOMAIN), tokenize its value directly via
:meth:`~soc_ai.oracle.sanitize.Mapping.label_for`.  This *learns* the real
value into the mapping even when it has no detectable shape (bare hostnames
like ``FINANCE-PC``, bare usernames like ``jsmith``).

**Pass 2 — global scan:**
Walk every string in the dict.  For each one:
  (a) Replace any value learned in Pass 1 (from ``mapping.forward``) that
      appears as a word-boundary match — so a bare hostname learned from
      ``host.name`` is also redacted inside ``message`` / ``payload_printable``.
      Short learned values (≤3 chars) are NOT propagated globally to avoid
      corrupting public IOCs (e.g. a learned ``dc`` would corrupt
      ``dc.evil.com``).  They are still tokenised in their own structured field
      via Pass 1.
  (b) Apply the existing shape-based rules via the internal
      :func:`~soc_ai.oracle.sanitize._sanitize_str` logic (private IPs, MACs,
      suffix-FQDNs, internal emails, /home users).

Order matters: Pass 1 (learn) MUST complete before Pass 2 (replace) so
learned names propagate to free-text fields.

**Field policy:**

HOST (tokenised unconditionally):
  ``host.name``, ``hostname``, ``host_name``, ``agent.name``, ``agent_name``,
  ``observer.name``, ``observer_name``, ``beat.hostname``,
  ``related.hosts`` (list — each element),
  bare ``name`` leaf ONLY when its direct parent key is ``host``, ``agent``, or
  ``observer``.

USER (tokenised unconditionally):
  ``user.name``, ``user_name``, ``username``, ``related.user``,
  ``source.user.name``, ``destination.user.name``,
  bare ``name`` leaf ONLY when parent is ``user``.

IP (tokenised only when RFC-1918 / CGNAT / link-local / loopback — public passes):
  ``source.ip``, ``source_ip``, ``src_ip``,
  ``destination.ip``, ``destination_ip``, ``dest_ip``, ``dst_ip``,
  ``ip``, ``related.ip``, ``id.orig_h``, ``id.resp_h``.
  (``community_id`` / ``network.community_id`` is NOT an IP — left alone.)

DOMAIN (tokenised only when ending in an internal suffix — public passes):
  ``dns.question.name``, ``domain``, ``host.domain``.

DOMAIN_LIKE — Zeek protocol-identity fields (SNI / HTTP Host / DNS query):
  ``zeek_ssl_server_name``, ``zeek_http_host``, ``zeek_dns_query``,
  ``dns_query``, ``alert.zeek_ssl_server_name``, ``alert.zeek_http_host``,
  ``alert.dns_query``.
  These legitimately carry *public* values (external SNIs, public Host headers,
  public DNS queries) so they are NOT blanket-tokenised.  Instead, per-value
  gating applies:

  - Single-label value (no dot, e.g. ``PRINTSRV``, ``INTRANET``) → **tokenise**
    as HOST.  Public hostnames are FQDNs; a single-label SNI/Host/DNS query is
    internal (mDNS / LLMNR / NetBIOS).
  - Ends in a configured internal suffix (e.g. ``.lan``, ``.local``) →
    **tokenise** as HOST.
  - Dotted public FQDN (e.g. ``mail.google.com``, ``cdc.gov``) → **PASS**
    (Oracle needs it to reason about real threats).

  List-valued companions (``typed_zeek.sni_servers``, ``typed_zeek.http_hosts``,
  ``typed_zeek.dns_queries``) apply the same per-element gating.

Flat-dotted keys (``"source.ip"``) and nested dicts (``{"source": {"ip": ...}}``)
are handled identically — :func:`_harvest_pass` normalises both via a
path-aware walker.

**The flat SoAlert fields from** :class:`~soc_ai.so_client.models.SoAlert`
(``source_ip``, ``destination_ip``, ``host_name``, ``user_name``) use
underscore aliases that are included in the policy map and matched before any
nested walk, so the compact :func:`model_dump` representation used in the case
dict is fully covered.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from soc_ai.oracle._cred_data import CRED_KEYS, CRED_VALUE_STOPSET
from soc_ai.oracle.sanitize import (
    Mapping,
    _is_private_ipv4,
    _is_private_ipv6,
    _resolve_suffixes,
    _sanitize_str,
)

# ---------------------------------------------------------------------------
# Field policy  (category → set of dotted-path field names)
# ---------------------------------------------------------------------------

# HOST fields: tokenised unconditionally (bare names have no detectable shape).
_HOST_FIELDS: frozenset[str] = frozenset(
    {
        "host.name",
        "host.hostname",
        "host_hostname",
        "hostname",
        "host_name",
        "agent.name",
        "agent_name",
        "observer.name",
        "observer_name",
        "beat.hostname",
    }
)

# USER fields: tokenised unconditionally.
_USER_FIELDS: frozenset[str] = frozenset(
    {
        "user.name",
        "user_name",
        "username",
        "related.user",
        "source.user.name",
        "destination.user.name",
    }
)

# Winlog/EVTX credential LEAF keys — matched case-insensitively against the last
# path segment, wherever they nest (``winlog.event_data.TargetUserName``). These
# carry the account name verbatim and are not in ``_USER_FIELDS``. The credential
# stopset still applies, so a universal built-in (``SYSTEM`` / ``-`` / ``ANONYMOUS
# LOGON``) is not tokenised — matching the free-text credential rule's discipline.
_WINLOG_USER_LEAF_KEYS: frozenset[str] = frozenset(
    {"targetusername", "subjectusername", "samaccountname", "accountname"}
)

# IP fields: tokenised only when the value is a private/internal address.
_IP_FIELDS: frozenset[str] = frozenset(
    {
        "source.ip",
        "source_ip",
        "src_ip",
        "destination.ip",
        "destination_ip",
        "dest_ip",
        "dst_ip",
        "ip",
        "id.orig_h",
        "id.resp_h",
    }
)

# DOMAIN fields: tokenised only when the value ends in an internal suffix.
_DOMAIN_FIELDS: frozenset[str] = frozenset(
    {
        "dns.question.name",
        "domain",
        "host.domain",
    }
)

# List-valued HOST fields: every element of the list is tokenised.
_HOST_LIST_FIELDS: frozenset[str] = frozenset({"related.hosts"})

# List-valued IP fields: every element of the list is tokenised (if private).
_IP_LIST_FIELDS: frozenset[str] = frozenset({"related.ip", "host.ip"})

# DOMAIN_LIKE fields — Zeek protocol-identity fields (SNI / HTTP Host / DNS query).
# Gated per value: single-label → tokenise; internal suffix → tokenise; public FQDN → PASS.
# Covers both the flat SoAlert field names (from model_dump) and full nested paths.
_DOMAIN_LIKE_FIELDS: frozenset[str] = frozenset(
    {
        # Flat SoAlert field names (as produced by model_dump)
        "zeek_ssl_server_name",
        "zeek_http_host",
        "zeek_dns_query",
        "dns_query",
        # Nested alert.* paths (e.g. when the alert dict is wrapped under "alert")
        "alert.zeek_ssl_server_name",
        "alert.zeek_http_host",
        "alert.zeek_dns_query",
        "alert.dns_query",
    }
)

# List-valued DOMAIN_LIKE fields — typed_zeek collections; each element is gated.
_DOMAIN_LIKE_LIST_FIELDS: frozenset[str] = frozenset(
    {
        "typed_zeek.sni_servers",
        "typed_zeek.http_hosts",
        "typed_zeek.dns_queries",
        "sni_servers",
        "http_hosts",
        "dns_queries",
    }
)

# Parent keys that promote a bare "name" leaf into HOST/USER category.
_HOST_PARENT_KEYS: frozenset[str] = frozenset({"host", "agent", "observer"})
_USER_PARENT_KEYS: frozenset[str] = frozenset({"user"})


# ---------------------------------------------------------------------------
# Pattern-based bare-hostname detection (secondary; for free-text / message
# fields where no field role disambiguates the value).
# ---------------------------------------------------------------------------
#
# THE GAP this closes: a NetBIOS / Windows-style bare hostname (``DESKTOP-AB12``,
# ``WIN-7G3K9J2``, ``FINANCE-PC``) that appears ONLY inside a free-text field
# (``message``, ``payload_printable``, an alert title) and NOT in any structured
# host field is never learned by Pass 1, so it would egress verbatim.
#
# CONSERVATISM (privacy-vs-utility tradeoff — see module docstring + return):
# We deliberately match ONLY values that carry a *structural* Windows/NetBIOS
# computer-name signal, never an arbitrary uppercase token.  A value qualifies
# when its single label (no dot) is uppercase-alphanumeric-with-hyphens AND it
# bears one of the well-known auto-generated computer-name affixes:
#   prefix:  DESKTOP- / LAPTOP- / WIN- / WORKSTATION- / PC- / WKS- / SRV- / DC-
#   suffix:  -PC / -LAPTOP / -DESKTOP / -WKS / -WS / -WORKSTATION / -SRV / -PStn
# This keeps false positives near-zero: it will NOT fire on dictionary words,
# rule/signature names ("ET MALWARE …", "GPL ATTACK_RESPONSE"), product strings
# ("Windows", "PowerShell"), or public domains (which always contain a dot and
# never have a bare structural affix at a word boundary).
#
# A dot anywhere in the candidate disqualifies it (public FQDNs have dots; a
# real NetBIOS name never does), so ``DESKTOP-AB12.example.com`` is left wholly
# untouched here — its suffix-FQDN-ness is the suffix rules' job, not ours.

# Prefix form: AFFIX- then >=1 alnum char.  e.g. DESKTOP-AB12, WIN-7G3K9J2, PC-01.
_NETBIOS_PREFIX_RE = re.compile(
    r"(?<![\w.-])"
    r"(?:DESKTOP|LAPTOP|WIN|WORKSTATION|PC|WKS|SRV|DC)-[A-Z0-9-]*[A-Z0-9]"
    r"(?![\w.-])",
    re.IGNORECASE,
)

# Suffix form: BODY then -AFFIX.  e.g. FINANCE-PC, RECEPTION-LAPTOP, BUILD-SRV.
_NETBIOS_SUFFIX_RE = re.compile(
    r"(?<![\w.-])"
    r"[A-Z0-9][A-Z0-9-]*-(?:PC|LAPTOP|DESKTOP|WKS|WS|WORKSTATION|SRV)"
    r"(?![\w.-])",
    re.IGNORECASE,
)

# A handful of multi-word public/product strings that happen to contain a
# qualifying affix as a substring are NOT a concern: both patterns are anchored
# at non-word boundaries and require the affix to be hyphen-joined, so e.g.
# "ATTACK_RESPONSE" (underscore, not hyphen) and "Endpoint-Protection" (affix
# not in our allow-set) never match.


def _redact_netbios_hostnames(text: str, mapping: Mapping) -> str:
    """Tokenise NetBIOS/Windows-style bare hostnames found in free text.

    Each distinct match is registered via :meth:`Mapping.label_for` as a HOST,
    so it round-trips on :func:`desanitize` and becomes a known value for the
    residue gate.  Matching is case-insensitive but the original surface form is
    learned so rehydration restores the exact bytes.
    """

    def _sub(m: re.Match[str]) -> str:
        return mapping.label_for(m.group(0), "HOST")

    text = _NETBIOS_PREFIX_RE.sub(_sub, text)
    text = _NETBIOS_SUFFIX_RE.sub(_sub, text)
    return text


# ---------------------------------------------------------------------------
# Credential-context username detection (free-text fields)
# ---------------------------------------------------------------------------
#
# THE GAP this closes: a bare username that appears ONLY inside a free-text
# field in an unambiguous credential context — ``user=jdoe``, ``username: svc-bak``,
# ``ACMECORP\jdoe`` — and NEVER in a structured user field.  Pass 1 never learns
# it (no field role) and the shape rules (private-IP / MAC / suffix-FQDN) never
# fire on it, so it would egress verbatim to the cloud Oracle.
#
# CONSERVATISM: we anchor on the credential KEY (``user=`` / ``username:`` / …)
# or the NetBIOS ``DOMAIN\`` separator, so we never tokenise an arbitrary word —
# only the token a log line explicitly labels as an account.  Universal built-in
# accounts (``root``, ``SYSTEM``, ``Administrator``, ``guest`` …) and non-username
# tokens (booleans, status words, pure numbers) are left untouched: they carry no
# internal-identifying signal and the Oracle benefits from seeing them.  Public
# emails (``user=alice@gmail.com``) are left to the email rule via a trailing
# ``(?![\w@-])`` guard that refuses to match when an ``@`` follows the value.

# Credential keys — SHARED with the residue net via :mod:`soc_ai.oracle._cred_data`
# so the two independent regex engines cannot silently diverge (finding
# oracle-cred-twin-nets).  ``(?<![\w.])`` (applied where this alternation is
# embedded below) rejects the ``user`` inside ``superuser`` / ``a.user``.
_CRED_KEYS = CRED_KEYS

# A username value: starts and ends alphanumeric, inner ``. _ -`` allowed.  The
# trailing ``(?![\w@-])`` forces a maximal match AND rejects the whole match when
# an ``@`` follows (i.e. it's the local-part of an email — the email rule's job).
_CRED_VALUE = r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?"

# ``sep`` tolerates a closing quote BETWEEN key and the ``:``/``=`` separator, so
# the JSON rendering ``"TargetUserName": "<val>"`` is covered (the quote that
# closes the key previously defeated the match) as well as the ordinary
# ``key="value"`` opening-quote form.
_CRED_KV_RE = re.compile(
    r"(?P<key>(?<![\w.])(?:" + _CRED_KEYS + r"))"
    r"(?P<sep>\s*\"?\s*[:=]\s*\"?)"
    r"(?P<val>" + _CRED_VALUE + r")"
    r"(?![\w@-])",
    re.IGNORECASE,
)

# The literal 4624/4625 message rendering: ``Account Name:  <user>`` (the label is
# two space-joined words, matching no key alternation) and its domain sibling
# ``Account Domain:  <DOMAIN>``.  The value runs after the ``:`` + whitespace.
_CRED_ACCOUNT_NAME_RE = re.compile(
    r"(?P<key>Account Name\s*:\s+)(?P<val>" + _CRED_VALUE + r")(?![\w@-])",
    re.IGNORECASE,
)
_CRED_ACCOUNT_DOMAIN_RE = re.compile(
    r"(?P<key>Account Domain\s*:\s+)(?P<val>" + _CRED_VALUE + r")(?![\w@-])",
    re.IGNORECASE,
)

# NetBIOS / down-level logon name: ``DOMAIN\user``.  The leading ``(?<![\w.\\])``
# rejects a preceding backslash so Windows paths (``C:\Users\jdoe``, UNC
# ``\\srv\share``) are not mis-read as a NetBIOS domain.  ``dom`` requires ≥2 chars
# (``[A-Za-z0-9]`` + ``{1,62}``) so a single drive letter (``C\…``) is not taken as
# a domain; it accepts ``_``/``.`` so an already-tokenised ``HOST_01\jdoe`` still
# has its user component redacted.  The separator is ``\\{1,2}`` (captured and
# reproduced verbatim) because a winlog / nested-JSON message field carries the
# down-level name with TWO literal backslashes (``DOMAIN\\jdoe``); the single form
# is the common case.
_CRED_NETBIOS_RE = re.compile(
    r"(?<![\w.\\])(?P<dom>[A-Za-z0-9][A-Za-z0-9._-]{1,62})(?P<sep>\\{1,2})"
    r"(?P<usr>" + _CRED_VALUE + r")(?![\w.\\@-])"
)

# Tokens that are NOT internal-identifying usernames — never tokenise these.
# SHARED with the residue net via :mod:`soc_ai.oracle._cred_data` so a stopword
# added here cannot diverge from the net that would still flag it (finding
# oracle-cred-twin-nets).
_CRED_VALUE_STOPSET: frozenset[str] = CRED_VALUE_STOPSET

# NetBIOS authorities that are universal, not internal-identifying domains.  The
# bare ``nt`` covers the ``Account Domain:  NT AUTHORITY`` / ``NT SERVICE`` message
# rendering, where the value capture stops at the first space and yields only
# ``NT`` — the phrase forms never match a single captured token.
_NT_DOMAIN_STOPSET: frozenset[str] = frozenset(
    {"nt", "nt authority", "authority", "builtin", "nt service"}
)

# Registry hives (and the like) that a ``HIVE\Subkey`` path shares the
# ``TOKEN\TOKEN`` shape of a down-level logon name.  A path is NOT a credential;
# reject the NetBIOS match when the left token is one of these technical prefixes
# so ``HKLM\Software`` is left verbatim (multi-segment paths are already rejected
# by the trailing ``(?![\w.\\@-])`` — this covers the single-separator 2-segment
# case a structural constraint cannot distinguish from ``DOMAIN\user``).
_NONDOMAIN_PREFIXES: frozenset[str] = frozenset({"hklm", "hkcu", "hkcr", "hku", "hkcc"})

_OPAQUE_LABEL_FULL_RE = re.compile(r"(?:USER|HOST|IP|MAC|EMAIL)_\d+\Z")


def _is_nondomain_prefix(tok: str) -> bool:
    """True iff *tok* is a registry hive / non-domain technical prefix, so a
    ``tok\\segment`` match is a filesystem/registry PATH, not a NetBIOS logon."""
    low = tok.lower()
    return low in _NONDOMAIN_PREFIXES or low.startswith("hkey")


def _is_nonusername_token(val: str) -> bool:
    """True iff *val* must NOT be tokenised as a username.

    Skips opaque labels (already redacted), universal built-in accounts,
    booleans / status words, pure-numeric ids, and anything with no letter.
    """
    if _OPAQUE_LABEL_FULL_RE.match(val):
        return True
    if val.lower() in _CRED_VALUE_STOPSET:
        return True
    if val.isdigit():
        return True
    return not any(c.isalpha() for c in val)


def _redact_credentials(text: str, mapping: Mapping) -> str:
    """Tokenise usernames that appear in an explicit credential context.

    Handles ``key=value`` / ``key: value`` forms (``user``, ``username``,
    ``account``, ``logon``, ``samaccountname`` …) and NetBIOS ``DOMAIN\\user``
    logon names.  Each redacted value is learned via :meth:`Mapping.label_for`
    so it round-trips on :func:`desanitize` and is covered by the residue gate.

    Redaction is IN-PLACE only: unlike a structured host/user field, a value
    matched here is NOT globally propagated to other fields via ``_replace_learned``
    (we deliberately do not learn it in Pass 1).  A free-text ``user=<x>`` match is
    lower-confidence than a typed field, so propagating it could corrupt a public
    IOC that happens to follow ``user=`` (e.g. ``user=mimikatz`` → every
    ``mimikatz`` in the payload).  If the same internal username also appears bare
    elsewhere, the independent residue gate fails closed on it (safe) rather than
    risk corrupting the Oracle's view of public threat infrastructure.
    """

    def _kv_sub(m: re.Match[str]) -> str:
        val = m.group("val")
        if _is_nonusername_token(val):
            return m.group(0)
        return f"{m.group('key')}{m.group('sep')}{mapping.label_for(val, 'USER')}"

    text = _CRED_KV_RE.sub(_kv_sub, text)

    # 4624/4625 ``Account Name:`` (a USER) and ``Account Domain:`` (a HOST/NetBIOS
    # domain).  Both preserve the ``key`` prefix (label + separator) verbatim; the
    # ``key`` group already carries the ``:`` and trailing whitespace, so there is
    # no separate ``sep`` group here.
    def _acct_name_sub(m: re.Match[str]) -> str:
        val = m.group("val")
        if _is_nonusername_token(val):
            return m.group(0)
        return f"{m.group('key')}{mapping.label_for(val, 'USER')}"

    text = _CRED_ACCOUNT_NAME_RE.sub(_acct_name_sub, text)

    def _acct_domain_sub(m: re.Match[str]) -> str:
        val = m.group("val")
        if val.lower() in _NT_DOMAIN_STOPSET or _OPAQUE_LABEL_FULL_RE.match(val):
            return m.group(0)
        return f"{m.group('key')}{mapping.label_for(val, 'HOST')}"

    text = _CRED_ACCOUNT_DOMAIN_RE.sub(_acct_domain_sub, text)

    def _nb_sub(m: re.Match[str]) -> str:
        dom, usr = m.group("dom"), m.group("usr")
        # A registry-hive / drive-shaped left token means this is a PATH
        # (``HKLM\Software``), not a logon name — leave it wholly untouched.
        if _is_nondomain_prefix(dom):
            return m.group(0)
        out_dom = dom
        if dom.lower() not in _NT_DOMAIN_STOPSET and not _OPAQUE_LABEL_FULL_RE.match(dom):
            out_dom = mapping.label_for(dom, "HOST")
        out_usr = usr if _is_nonusername_token(usr) else mapping.label_for(usr, "USER")
        # Reproduce the ORIGINAL separator (one or two backslashes) so a doubled
        # winlog/nested-JSON down-level name round-trips byte-for-byte.
        return f"{out_dom}{m.group('sep')}{out_usr}"

    return _CRED_NETBIOS_RE.sub(_nb_sub, text)


# ---------------------------------------------------------------------------
# Domain-like gating logic (SNI / HTTP Host / DNS query fields)
# ---------------------------------------------------------------------------


def _is_internal_domain_like(value: str, suffixes: tuple[str, ...]) -> bool:
    """Return True iff *value* should be tokenised from a DOMAIN_LIKE field.

    A value is internal (and must be tokenised) when:
    - It has no dot (single-label: ``PRINTSRV``, ``INTRANET``, ``FILESERVER``).
      Public hostnames are always FQDNs; a single-label SNI/Host/DNS query is
      an internal NetBIOS/mDNS/LLMNR name.
    - It ends in a configured internal suffix (e.g. ``dc01.lan``, ``srv.local``).

    A dotted FQDN that does NOT end in an internal suffix is treated as public
    and passes through verbatim (the Oracle needs it).

    A trailing DNS root-zone dot (``PRINTSRV.``, ``dc01.lan.``) is stripped
    before the dot-membership test so the RFC-absolute-name form (also a known
    Host-header domain-filter evasion) cannot bypass the single-label branch.
    """
    v = value.strip().lower().rstrip(".")
    if not v:
        return False
    # Single-label (no dot) → internal by definition.
    if "." not in v:
        return True
    # Internal suffix match — compare against the FULL dotted suffix so the label
    # boundary is enforced (``.lan`` must not match ``…milan``).  ``_resolve_suffixes``
    # supplies each configured suffix with its leading dot.
    return any(v.endswith(s) for s in suffixes)


# ---------------------------------------------------------------------------
# Pass 1 — field-aware harvest
# ---------------------------------------------------------------------------


def _is_internal_ip(value: str) -> bool:
    """Return True iff *value* is a private/internal IPv4 or IPv6 address."""
    return _is_private_ipv4(value) or _is_private_ipv6(value)


def _harvest_pass(
    obj: Any,
    mapping: Mapping,
    *,
    suffixes: tuple[str, ...],
    no_propagate: set[str],
    _path: str = "",
    _parent_key: str = "",
) -> None:
    """Walk *obj* path-aware, tokenising values whose field role is known.

    *_path* is the dotted ECS path built as we descend into nested dicts
    (e.g. ``"alert_summary.source.ip"``).  *_parent_key* is the immediate
    parent key, used to promote a bare ``"name"`` leaf.

    *no_propagate* is a mutable set.  Values learned from DOMAIN_LIKE fields
    that are ≤3 chars are added here so ``sanitize_case`` can exclude them
    from the global-replace regex (Pass 2) to prevent short host tokens from
    corrupting public FQDNs containing the same substring.

    This function ONLY learns values into *mapping* — it does not modify *obj*.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            # Build the path for this key; the leaf suffix is just k for
            # top-level, or _path + "." + k for nested.
            leaf_path = f"{_path}.{k}" if _path else k
            # Also track the suffix (last two segments) for dotted-path lookup.
            # E.g. "alert_summary.source.ip" → suffix "source.ip".
            # We try both the full path AND the last-N-segment suffixes so that
            # nested dicts work regardless of the top-level wrapper key names.
            _harvest_pass(
                v,
                mapping,
                suffixes=suffixes,
                no_propagate=no_propagate,
                _path=leaf_path,
                _parent_key=k,
            )
    elif isinstance(obj, list):
        # When the parent key is a known list field, iterate and harvest each.
        # Otherwise recurse into each element with the same parent context.
        if _path in _HOST_LIST_FIELDS or _path.endswith(tuple(f".{f}" for f in _HOST_LIST_FIELDS)):
            for item in obj:
                if isinstance(item, str) and item:
                    mapping.label_for(item, "HOST")
        elif _path in _IP_LIST_FIELDS or _path.endswith(tuple(f".{f}" for f in _IP_LIST_FIELDS)):
            for item in obj:
                if isinstance(item, str) and item and _is_internal_ip(item):
                    mapping.label_for(item, "IP")
        elif _path in _DOMAIN_LIKE_LIST_FIELDS or _path.endswith(
            tuple(f".{f}" for f in _DOMAIN_LIKE_LIST_FIELDS)
        ):
            for item in obj:
                if isinstance(item, str) and item and _is_internal_domain_like(item, suffixes):
                    mapping.label_for(item, "HOST")
                    if len(item) <= 3:
                        no_propagate.add(item)
                        no_propagate.add(item.lower())
        else:
            for item in obj:
                _harvest_pass(
                    item,
                    mapping,
                    suffixes=suffixes,
                    no_propagate=no_propagate,
                    _path=_path,
                    _parent_key=_parent_key,
                )
    elif isinstance(obj, str) and obj:
        # Check if ANY suffix of the current path matches a known field.
        # E.g. full path "alert_summary.source.ip" → suffixes we test:
        #   "source.ip", "ip", "alert_summary.source.ip"
        _try_harvest_scalar(
            _path, _parent_key, obj, mapping, suffixes=suffixes, no_propagate=no_propagate
        )
    # Non-string scalars (int, float, bool, None): skip.


def _path_suffixes(path: str) -> list[str]:
    """Return all suffix sub-paths of *path* (longest first).

    E.g. ``"a.b.c.d"`` → ``["a.b.c.d", "b.c.d", "c.d", "d"]``.
    """
    parts = path.split(".")
    return [".".join(parts[i:]) for i in range(len(parts))]


def _try_harvest_scalar(
    path: str,
    parent_key: str,
    value: str,
    mapping: Mapping,
    *,
    suffixes: tuple[str, ...],
    no_propagate: set[str],
) -> None:
    """Decide which category (HOST/USER/IP/DOMAIN) a scalar string falls into
    based on its field path and parent key, then register it with *mapping*.

    For DOMAIN_LIKE fields, values that are ≤3 chars are also added to
    *no_propagate* to prevent them from corrupting public FQDNs in Pass 2.
    """
    suffixes_of_path = _path_suffixes(path)

    # HOST fields — unconditional.
    if any(s in _HOST_FIELDS for s in suffixes_of_path):
        mapping.label_for(value, "HOST")
        return

    # USER fields — unconditional.
    if any(s in _USER_FIELDS for s in suffixes_of_path):
        mapping.label_for(value, "USER")
        return

    # Winlog/EVTX credential leaf keys (TargetUserName / SubjectUserName /
    # SamAccountName / AccountName) — case-insensitive LEAF match, wherever they
    # nest.  Honour the credential stopset so a built-in (SYSTEM / "-") is left
    # verbatim rather than over-redacted.
    if path.rsplit(".", maxsplit=1)[-1].lower() in _WINLOG_USER_LEAF_KEYS:
        if not _is_nonusername_token(value):
            mapping.label_for(value, "USER")
        return

    # IP fields — private only.
    if any(s in _IP_FIELDS for s in suffixes_of_path):
        if _is_internal_ip(value):
            mapping.label_for(value, "IP")
        return

    # DOMAIN fields — internal suffix only.  Match the FULL dotted suffix so the
    # label boundary is enforced (``.lan`` must not match ``…milan``).
    if any(s in _DOMAIN_FIELDS for s in suffixes_of_path):
        v_lower = value.lower()
        if any(v_lower.endswith(s) for s in suffixes):
            mapping.label_for(value, "HOST")
        return

    # DOMAIN_LIKE fields (SNI / HTTP Host / DNS query) — per-value gating:
    # single-label or internal suffix → tokenise; public FQDN → PASS.
    if any(s in _DOMAIN_LIKE_FIELDS for s in suffixes_of_path):
        if _is_internal_domain_like(value, suffixes):
            mapping.label_for(value, "HOST")
            # Guard short values from corrupting public FQDNs in Pass 2.
            if len(value) <= 3:
                no_propagate.add(value)
                no_propagate.add(value.lower())
        return

    # Bare "name" leaf: category depends on parent key.
    leaf = path.rsplit(".", maxsplit=1)[-1]
    if leaf == "name":
        if parent_key in _HOST_PARENT_KEYS:
            mapping.label_for(value, "HOST")
            return
        if parent_key in _USER_PARENT_KEYS:
            mapping.label_for(value, "USER")
            return

    # Unrecognised field — do not harvest (let Pass 2 shape-based rules handle).


# ---------------------------------------------------------------------------
# Pass 2 — learned-value global replace + shape-based rules
# ---------------------------------------------------------------------------


def _build_learned_re(
    mapping: Mapping,
    *,
    no_propagate: frozenset[str] = frozenset(),
) -> re.Pattern[str] | None:
    """Compile a single alternation pattern for all learned real values.

    Matches only at word boundaries so ``jsmith`` does not match inside
    ``jsmith_backup``.  Returns ``None`` when the mapping is empty.

    Values in *no_propagate* are intentionally excluded from the global-replace
    pattern.  These are short (≤3 char) DOMAIN_LIKE values (e.g. ``dc``, ``ns``,
    ``ns1``) that were learned from protocol-identity fields but must NOT be
    propagated to free-text because they would corrupt public FQDNs containing
    the same substring (``dc.evil.com`` → ``HOST_01.evil.com``).  Such values
    are still tokenised in their own structured field via Pass 1 — they simply do
    not get a global-replace entry.
    """
    if not mapping.forward:
        return None
    # Filter out values that should not be globally propagated (short domain-like).
    propagatable = [real for real in mapping.forward if real not in no_propagate]
    if not propagatable:
        return None
    # Sort longest first to prevent a shorter value from consuming a prefix of a
    # longer one when they share a substring.
    escaped = [re.escape(real) for real in sorted(propagatable, key=len, reverse=True)]
    return re.compile(r"(?<!\w)(?:" + "|".join(escaped) + r")(?!\w)", re.IGNORECASE)


def _replace_learned(text: str, mapping: Mapping, learned_re: re.Pattern[str] | None) -> str:
    """Substitute learned real values in *text* with their opaque labels.

    Case-insensitive: ``learned_re`` matches occurrences regardless of casing,
    and the label is resolved via a case-folded index of ``mapping.forward``.
    This covers GENUINELY mixed-case originals (e.g. a ``WebSrv-Prod`` learned
    from ``host.name`` still redacts a ``websrv-prod`` / ``WEBSRV-PROD``
    occurrence in free text) — not only all-upper / all-lower forms.  An exact
    match is preferred first so byte-for-byte rehydration is unchanged when the
    original casing is present verbatim.
    """
    if learned_re is None or not mapping.forward:
        return text

    # Build the case-folded index once (earliest-learned label wins on a
    # case-collision, so the lowest-numbered label is preferred deterministically).
    folded: dict[str, str] = {}
    for real, label in mapping.forward.items():
        folded.setdefault(real.lower(), label)

    def _sub(m: re.Match[str]) -> str:
        matched = m.group(0)
        # Exact match first (preserves current byte-for-byte behaviour), then
        # fall back to the case-folded lookup for differently-cased occurrences.
        label = mapping.forward.get(matched)
        if label is None:
            label = folded.get(matched.lower())
        return label if label is not None else matched

    return learned_re.sub(_sub, text)


def _build_resweep_re(values: Iterable[str]) -> re.Pattern[str] | None:
    """Compile an alternation over *values* for the Pass-2 propagation re-sweep.

    Unlike :func:`_build_learned_re`, the boundaries reject a leading/trailing
    ``.`` or ``-`` as well as a word char.  A value learned during Pass 2 (from a
    free-text credential / NetBIOS context) is lower-confidence than a typed
    field, so it is propagated ONLY to standalone whole-word occurrences — never
    spliced into a compound token (a filename ``mimikatz.exe``, an FQDN
    ``FINANCE-PC.example.com``) where the same substring might be a public IOC.
    Values are sorted longest-first so a shorter value cannot consume a prefix of
    a longer one.  Returns ``None`` when *values* is empty.
    """
    vals = sorted({v for v in values if v}, key=len, reverse=True)
    if not vals:
        return None
    escaped = [re.escape(v) for v in vals]
    return re.compile(r"(?<![\w.-])(?:" + "|".join(escaped) + r")(?![\w.-])", re.IGNORECASE)


def _resweep_learned(obj: Any, mapping: Mapping, resweep_re: re.Pattern[str] | None) -> Any:
    """Walk *obj* replacing re-sweep matches with their opaque labels only.

    A learned-value replacement pass with no credential re-detection and no
    shape rules, so it is bounded: it cannot learn new values or touch
    already-labelled text (opaque labels never match ``resweep_re``).
    """
    if resweep_re is None:
        return obj
    if isinstance(obj, str):
        return _replace_learned(obj, mapping, resweep_re)
    if isinstance(obj, dict):
        return {
            _resweep_learned(k, mapping, resweep_re): _resweep_learned(v, mapping, resweep_re)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_resweep_learned(item, mapping, resweep_re) for item in obj]
    if isinstance(obj, tuple):
        return tuple(_resweep_learned(item, mapping, resweep_re) for item in obj)
    return obj


def _global_scan_pass(
    obj: Any,
    mapping: Mapping,
    *,
    suffixes: tuple[str, ...],
    extra_hosts: tuple[str, ...],
    orig_to_ph: dict[str, str],
    learned_re: re.Pattern[str] | None,
    direct_replace: frozenset[str] = frozenset(),
) -> Any:
    """Walk *obj* and apply both learned-value replacement and shape rules.

    *direct_replace* is a frozenset of real values that must be replaced as
    whole-string exact matches (not globally via regex).  These are short (≤3
    char) DOMAIN_LIKE values that were tokenised in Pass 1 but excluded from
    the global regex to prevent them corrupting public FQDNs.  When the entire
    string value equals a *direct_replace* entry, we substitute it directly via
    the mapping.
    """
    if isinstance(obj, str):
        # (a.1) Direct replacement for short DOMAIN_LIKE values: whole-string match.
        if direct_replace and obj in direct_replace:
            label = mapping.forward.get(obj) or mapping.forward.get(obj.lower())
            if label:
                return label
        # (a.2) Replace learned real values (word-boundary, case-insensitive).
        text = _replace_learned(obj, mapping, learned_re)
        # (a.3) Pattern-based NetBIOS/Windows bare-hostname catch — conservative;
        # only fires on structurally-shaped computer names in free text (a name
        # that appears here but in no structured host field would otherwise leak).
        text = _redact_netbios_hostnames(text, mapping)
        # (a.4) Credential-context usernames in free text (user=jdoe, DOMAIN\jdoe)
        # — anchored on the credential key, so only an explicitly-labelled account
        # token is tokenised, never an arbitrary word.  Redacted IN-PLACE only (not
        # learned in Pass 1 / not globally propagated) so a free-text match cannot
        # corrupt a public IOC; a bare re-occurrence fails closed at the residue gate.
        text = _redact_credentials(text, mapping)
        # (b) Shape-based rules (private IPs, MACs, suffix-FQDNs, emails, /home).
        text = _sanitize_str(
            text,
            mapping,
            suffixes=suffixes,
            extra_hosts=extra_hosts,
            orig_to_ph=orig_to_ph,
        )
        return text
    if isinstance(obj, dict):
        return {
            _global_scan_pass(
                k,
                mapping,
                suffixes=suffixes,
                extra_hosts=extra_hosts,
                orig_to_ph=orig_to_ph,
                learned_re=learned_re,
                direct_replace=direct_replace,
            ): _global_scan_pass(
                v,
                mapping,
                suffixes=suffixes,
                extra_hosts=extra_hosts,
                orig_to_ph=orig_to_ph,
                learned_re=learned_re,
                direct_replace=direct_replace,
            )
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [
            _global_scan_pass(
                item,
                mapping,
                suffixes=suffixes,
                extra_hosts=extra_hosts,
                orig_to_ph=orig_to_ph,
                learned_re=learned_re,
                direct_replace=direct_replace,
            )
            for item in obj
        ]
    if isinstance(obj, tuple):
        return tuple(
            _global_scan_pass(
                item,
                mapping,
                suffixes=suffixes,
                extra_hosts=extra_hosts,
                orig_to_ph=orig_to_ph,
                learned_re=learned_re,
                direct_replace=direct_replace,
            )
            for item in obj
        )
    return obj


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

# Re-export Mapping so callers only need to import from this module.
__all__ = ["Mapping", "sanitize_case"]


def sanitize_case(
    case: dict[str, Any],
    mapping: Mapping,
    *,
    allowlist: Iterable[str] = (),
    extra_hosts: Iterable[str] = (),
    extra_suffixes: Iterable[str] = (),
    no_propagate_out: set[str] | None = None,
) -> dict[str, Any]:
    """Field-aware, learning redacter for a structured SO/ECS case dict.

    Performs two passes:

    1. **Harvest pass** — walks the dict path-aware; for every ECS/SO field
       with a known role, tokenises its value into *mapping* (even bare names
       with no IP/suffix shape).
    2. **Global scan pass** — walks every string; replaces learned real values
       by word-boundary match AND applies shape-based rules
       (:func:`~soc_ai.oracle.sanitize._sanitize_str`).

    Args:
        case: The structured case payload dict (e.g. from
            :func:`~soc_ai.oracle.client._assemble_case_dict`).
        mapping: Per-case :class:`Mapping` instance — reuse the same instance
            across the adjudication cycle so labels stay consistent.
        allowlist: Tokens that MUST pass through verbatim.
        extra_hosts: Additional bare hostnames to redact (beyond suffix-detected
            ones and the policy-field-learned ones).
        extra_suffixes: Additional internal DNS suffixes beyond the settings
            default.
        no_propagate_out: Optional mutable set.  When provided, it is populated
            with the short (≤3 char) DOMAIN_LIKE values the harvest pass declined
            to propagate globally (to protect public FQDNs).  The caller (client)
            excludes these from ``known_values`` when running the residue gate —
            otherwise the gate flags the same substring inside a legitimate public
            FQDN and refuses by construction (finding oracle-refuse-by-design).

    Returns:
        A sanitized copy of *case* with the same structure.
    """
    suffixes: tuple[str, ...] = _resolve_suffixes(extra_suffixes)
    hosts: tuple[str, ...] = tuple(extra_hosts)

    # Build allowlist placeholder map (same mechanics as sanitize()).
    _ALLOW_PH = "\x00ALLOW{}\x00"
    allow_tokens = tuple(t for t in allowlist if t)
    orig_to_ph: dict[str, str] = {tok: _ALLOW_PH.format(i) for i, tok in enumerate(allow_tokens)}

    # ----- Pass 1: field-aware harvest -----
    # ``no_propagate`` collects short (≤3 char) DOMAIN_LIKE values that must
    # NOT be globally propagated in Pass 2 — they're tokenised in their own
    # structured field but would corrupt public FQDNs if globally replaced.
    no_propagate: set[str] = set()
    _harvest_pass(case, mapping, suffixes=suffixes, no_propagate=no_propagate)

    # ----- Pass 2: global scan + shape rules -----
    _np = frozenset(no_propagate)
    learned_re = _build_learned_re(mapping, no_propagate=_np)
    # Snapshot the values known BEFORE Pass 2 so we can tell which were learned
    # DURING it (credential-context / NetBIOS free-text values, redacted in place
    # only — they are not in ``learned_re``, which was compiled just above).
    pre_pass2_values = set(mapping.forward)
    # _global_scan_pass is typed Any→Any for generality; since we passed a
    # dict[str, Any] in, the return value is guaranteed to be dict[str, Any].
    result: dict[str, Any] = _global_scan_pass(
        case,
        mapping,
        suffixes=suffixes,
        extra_hosts=hosts,
        orig_to_ph=orig_to_ph,
        learned_re=learned_re,
        direct_replace=_np,
    )

    # ----- Pass 2b: propagate values learned DURING Pass 2 -----
    # A credential/NetBIOS value learned in place during Pass 2 that also appears
    # bare in ANOTHER field would survive to the wire and trip the independent
    # residue gate by construction (finding oracle-refuse-by-design). Rebuild a
    # learned regex from ONLY the newly-learned values — length ≥ 4 (short tokens
    # stay unpropagated, per the no_propagate rationale), still honouring
    # no_propagate and _is_nonusername_token — and sweep once more with a strict
    # boundary that will not corrupt a public IOC embedding the value.
    newly_learned = {
        real
        for real in mapping.forward
        if real not in pre_pass2_values
        and len(real) >= 4
        and real not in _np
        and not _is_nonusername_token(real)
    }
    resweep_re = _build_resweep_re(newly_learned)
    if resweep_re is not None:
        result = _resweep_learned(result, mapping, resweep_re)

    if no_propagate_out is not None:
        no_propagate_out.update(no_propagate)

    return result
