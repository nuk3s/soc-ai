"""Reversible sanitization of internal identifiers.

Adapted from an established redaction recipe for sending lab data to
the cloud oracle via the gateway, which soc-ai's eval harness needs to
mirror exactly. If you change the redaction rules here, keep them in
sync with that recipe (or DRY them into a shared package once both
need divergent behaviour).

Each replaced token is allocated a stable opaque label (e.g. `IP_07`,
`HOST_02`) so the remote model can reason about "the same machine"
across multiple references without learning anything about it. The
mapping is held by the caller and used to rehydrate the model's
output for local display.

Determinism: two calls with the same input + same Mapping yield the
same output and labels. This lets a multi-turn conversation reuse
labels established earlier in the session.

WHAT IS REDACTED
----------------
- IPv4 addresses inside RFC1918 / CGNAT / link-local / loopback /
  multicast / reserved ranges
- IPv6 addresses inside private / link-local / loopback ranges
- MAC addresses (always — they identify physical hardware)
- Hostnames ending in an internal suffix (`.lan`, `.local`,
  `.internal`, `.corp`) plus caller-supplied suffixes
- Bare single-label hostnames in the caller-supplied explicit list
  (no defaults — set per deployment via `ORACLE_EXTRA_HOSTS`)
- Email addresses whose domain matches an internal suffix
- `/home/<user>/` paths — username only, the rest of the path is
  preserved as useful context
- Caller-supplied bare usernames (typically from /etc/passwd scan)

WHAT PASSES THROUGH (LOAD-BEARING — do NOT redact)
--------------------------------------------------
The whole point of the oracle path is to give the oracle the
high-signal IOCs it needs to reason. These are intentionally NOT
redacted:

- **Public IPv4 / IPv6** (anything that isn't private / link-local
  / loopback / multicast / reserved). Adversary C2 IPs, sinkholes,
  resolver IPs, public scanner sources all pass through verbatim.
- **Public domains** (anything not ending in an internal suffix).
  Malware C2 domains, DGA candidates, suspicious FQDNs all pass.
- **URLs and URIs** are not parsed; the public host parts inside
  them pass through.
- **File hashes** (MD5, SHA-1, SHA-256, SHA-512). Bytes don't
  identify your network.
- **CVE / CWE / KEV / ATT&CK identifiers**, port numbers, ASNs,
  PIDs, line numbers — all bytes, all pass.
- **Public-domain emails** — only internal-domain emails are
  redacted.

If you need a particular token to bypass redaction (e.g. a private
IP that's actually a compromised internal host you want the oracle to
reason about as that exact IP), pass it via the `allowlist=`
parameter to `sanitize()`. Allowlist matches are wrapped in a word
boundary and short-circuit before any other redaction rule runs.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from re import Pattern

# --------------------------------------------------------------------
# Patterns
# --------------------------------------------------------------------

# IPv4 — captured separately from IPv6 because we treat private/public
# differently (only RFC1918/CGNAT/link-local need redaction).
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# IPv6 — match BOTH the full 8-group form and any compressed form so
# we can hand the whole address to ipaddress.IPv6Address() and decide
# private-vs-public on the whole thing. Without the compressed branch
# the regex would slice `::1` out of public `2606:4700::1` and redact
# only the loopback substring, breaking the public-passes-through
# guarantee. The (?<!...) / (?!...) lookarounds replace `\b`, which
# doesn't fire around `:`.
_IPV6_RE = re.compile(
    r"(?<![:\w.])"
    r"(?:"
    r"[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4}){7}"
    r"|(?:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4}){0,6})?::"
    r"(?:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4}){0,6})?"
    r")"
    r"(?![:\w.])"
)

_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")

# Email addresses with internal-looking domains. Public-domain emails
# (gmail.com, anthropic.com, etc.) are left alone — they aren't local
# inventory.
# Quantifiers are bounded to RFC limits (local-part ≤64, domain ≤255, TLD a DNS
# label ≤63) so a long ``a-a-a…`` run with no ``@`` cannot cause catastrophic
# backtracking (ReDoS) on attacker-controlled free text. No valid email exceeds
# these, so matching is unchanged for real input. Mirrors
# ``soc_ai.oracle.sanitize._EMAIL_RE``.
_EMAIL_RE = re.compile(r"\b[\w.+-]{1,64}@([\w.-]{1,255}\.[A-Za-z]{2,63})\b")

# Filesystem path containing a /home/<user>/ component. We redact the
# username only — the rest of the path is potentially useful context.
_HOMEPATH_RE = re.compile(r"(/home/)([A-Za-z_][A-Za-z0-9_-]{0,31})(/|\b)")

# Domains we treat as internal regardless of suffix list (helps the
# default config catch obvious cases). Caller can extend.
_DEFAULT_INTERNAL_SUFFIXES = (
    ".lan",
    ".local",
    ".internal",
    ".corp",
)

# Single-label internal hostnames the caller may provide explicitly.
# Detected as standalone tokens (word boundaries, not as part of a URL).
# EMPTY by default — the package ships no environment-specific hostnames.
# FQDN forms of internal hosts are still redacted by _DEFAULT_INTERNAL_SUFFIXES
# (e.g. ``host.lan``). Deployments add their bare single-label internal
# names via the ``oracle_extra_hosts`` / ``ORACLE_EXTRA_HOSTS`` setting.
_DEFAULT_INTERNAL_HOSTS: tuple[str, ...] = ()


# --------------------------------------------------------------------
# Mapping container
# --------------------------------------------------------------------


@dataclass
class Mapping:
    """Bidirectional, deterministic redaction map.

    `next_label` per category gives stable numbering (`IP_01`, `IP_02`)
    so a conversation can refer to the same address consistently. The
    map can be persisted (e.g. to claude_oracle_calls.metadata) so a
    follow-up turn picks up the same labels.
    """

    forward: dict[str, str] = field(default_factory=dict)  # original → label
    reverse: dict[str, str] = field(default_factory=dict)  # label → original
    counters: dict[str, int] = field(default_factory=dict)  # category → next idx

    def label_for(self, original: str, category: str) -> str:
        if original in self.forward:
            return self.forward[original]
        idx = self.counters.get(category, 0) + 1
        self.counters[category] = idx
        label = f"{category}_{idx:02d}"
        self.forward[original] = label
        self.reverse[label] = original
        return label

    def summary(self) -> dict[str, int]:
        """Per-category redaction counts, for the audit log."""
        return dict(self.counters)


# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------


_CGNAT_NETWORK = ipaddress.IPv4Network("100.64.0.0/10")


def _is_redactable_ipv4(addr: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(addr)
    except ValueError:
        return False
    # Python's `is_private` covers RFC1918 / link-local / loopback / etc
    # but does NOT include CGNAT (100.64.0.0/10) on 3.12. Check it
    # explicitly so addresses behind a carrier-grade NAT also get an
    # opaque label.
    if ip in _CGNAT_NETWORK:
        return True
    return ip.is_private or ip.is_link_local or ip.is_loopback or ip.is_multicast or ip.is_reserved


def _is_redactable_ipv6(addr: str) -> bool:
    try:
        ip = ipaddress.IPv6Address(addr)
    except ValueError:
        return False
    return ip.is_private or ip.is_link_local or ip.is_loopback


def _build_internal_host_re(
    suffixes: Iterable[str],
    explicit_hosts: Iterable[str],
) -> Pattern[str]:
    parts: list[str] = []
    for suffix in suffixes:
        # FQDNs ending in suffix; capture the full hostname.
        # Negative-lookbehind avoids matching inside an email; the
        # trailing `(?![\w-])` is load-bearing — without it the regex
        # would partial-match `evil.local` out of `evil.local-ai.com`
        # and over-redact a perfectly public domain.
        # Label quantifiers bounded to DNS limits (label ≤63, ≤127 labels) so a
        # long ``a-a-a…`` run cannot trigger catastrophic backtracking (ReDoS).
        # Mirrors ``soc_ai.oracle.sanitize._build_host_re``.
        parts.append(
            rf"(?<![\w@.])[A-Za-z0-9][\w-]{{0,62}}(?:\.[\w-]{{1,63}}){{0,126}}"
            rf"{re.escape(suffix)}(?![\w-])"
        )
    for host in explicit_hosts:
        parts.append(rf"(?<![\w@.]){re.escape(host)}(?![\w-])")
    return re.compile("|".join(parts), re.IGNORECASE)


# --------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------


def sanitize(
    text: str,
    *,
    mapping: Mapping | None = None,
    extra_hosts: Iterable[str] | None = None,
    extra_suffixes: Iterable[str] | None = None,
    extra_usernames: Iterable[str] | None = None,
    allowlist: Iterable[str] | None = None,
) -> tuple[str, Mapping]:
    """Replace internal identifiers with opaque labels.

    `extra_hosts`: caller-supplied single-label hostnames (e.g. inferred
    from Wazuh inventory). `extra_suffixes`: additional internal DNS
    suffixes beyond the defaults. `extra_usernames`: redacted as bare
    tokens via word-boundary match — used to scrub `/etc/passwd` UIDs.

    `allowlist`: tokens that MUST pass through verbatim even when they
    would otherwise be redacted. Useful when a private IP is actually
    a compromised internal host the analyst wants the oracle to reason
    about by its real identity, or when an internal-suffix domain has
    been confirmed adversary-hosted. Matched as bare tokens with word
    boundaries — case-sensitive.
    """
    m = mapping or Mapping()
    allowlist = tuple(allowlist or ())

    # Allowlist works by replacing each protected token with a placeholder
    # that none of the redaction rules would match, then restoring it at
    # the end. This is more reliable than trying to teach every rule to
    # short-circuit individually.
    _ALLOW_PLACEHOLDER = "\x00ALLOW{}\x00"
    allow_map: dict[str, str] = {}
    for i, token in enumerate(allowlist):
        if not token:
            continue
        ph = _ALLOW_PLACEHOLDER.format(i)
        # Replace bare-token occurrences with the placeholder.
        text = re.sub(rf"(?<!\w){re.escape(token)}(?!\w)", ph, text)
        allow_map[ph] = token

    # Order matters: redact more-specific patterns before less-specific
    # ones so an IP inside a URL doesn't get half-redacted by the host
    # rule first.

    # 1. IPv4 (only if private)
    def _v4(match: re.Match[str]) -> str:
        addr = match.group(0)
        if not _is_redactable_ipv4(addr):
            return addr
        return m.label_for(addr, "IP")

    text = _IPV4_RE.sub(_v4, text)

    # 2. IPv6 (only if private)
    def _v6(match: re.Match[str]) -> str:
        addr = match.group(0)
        if not _is_redactable_ipv6(addr):
            return addr
        return m.label_for(addr, "IP")

    text = _IPV6_RE.sub(_v6, text)

    # 3. MACs
    def _mac(match: re.Match[str]) -> str:
        return m.label_for(match.group(0).lower(), "MAC")

    text = _MAC_RE.sub(_mac, text)

    # 4. Internal hostnames
    suffixes = tuple(_DEFAULT_INTERNAL_SUFFIXES) + tuple(extra_suffixes or ())
    explicit = tuple(_DEFAULT_INTERNAL_HOSTS) + tuple(extra_hosts or ())
    host_re = _build_internal_host_re(suffixes, explicit)

    def _host(match: re.Match[str]) -> str:
        return m.label_for(match.group(0).lower(), "HOST")

    text = host_re.sub(_host, text)

    # 5. Internal email domains. Treat emails as internal if their
    # domain ends in one of our suffixes.
    def _email(match: re.Match[str]) -> str:
        domain = match.group(1).lower()
        if any(domain.endswith(s.lstrip(".")) for s in suffixes):
            return m.label_for(match.group(0).lower(), "EMAIL")
        return match.group(0)

    text = _EMAIL_RE.sub(_email, text)

    # 6. /home/<user>/ paths
    def _home(match: re.Match[str]) -> str:
        head, user, tail = match.group(1), match.group(2), match.group(3)
        return f"{head}{m.label_for(user, 'USER')}{tail}"

    text = _HOMEPATH_RE.sub(_home, text)

    # 7. Caller-supplied bare usernames (rarer; extra_usernames comes
    # from /etc/passwd scan in the caller).
    if extra_usernames:
        for u in extra_usernames:
            if not u or len(u) < 2:
                continue
            label = m.label_for(u, "USER")
            text = re.sub(rf"\b{re.escape(u)}\b", label, text)

    # 8. Restore allowlist placeholders.
    for ph, original in allow_map.items():
        text = text.replace(ph, original)

    return text, m


def desanitize(text: str, mapping: Mapping) -> str:
    """Replace labels with their original tokens. Used to rehydrate a
    remote model's response for local display."""
    if not mapping.reverse:
        return text
    pattern = re.compile(
        "|".join(re.escape(k) for k in sorted(mapping.reverse, key=len, reverse=True))
    )
    return pattern.sub(lambda m: mapping.reverse[m.group(0)], text)


def unsafe_residue(
    text: str,
    *,
    extra_suffixes: Iterable[str] | None = None,
    extra_usernames: Iterable[str] | None = None,
    allowlist: Iterable[str] | None = None,
) -> list[str]:
    """Final-pass sweep. Returns a list of remaining tokens that look
    like internal identifiers — caller should refuse to send if any.

    This catches drift between sanitize() and the cloud-bound payload
    (e.g. text added after sanitize ran, or a pattern we missed).

    `allowlist`: tokens that the caller deliberately pinned through
    sanitize() and that the residue check must NOT flag. Without this
    plumbing, an allowlisted private IP would always trip the check
    and prevent the call from going out.
    """
    issues: list[str] = []
    allow = set(allowlist or ())

    for m in _IPV4_RE.finditer(text):
        if _is_redactable_ipv4(m.group(0)) and m.group(0) not in allow:
            issues.append(f"residual private IPv4: {m.group(0)}")

    for m in _IPV6_RE.finditer(text):
        if _is_redactable_ipv6(m.group(0)) and m.group(0) not in allow:
            issues.append(f"residual private IPv6: {m.group(0)}")

    for m in _MAC_RE.finditer(text):
        if m.group(0) not in allow:
            issues.append(f"residual MAC: {m.group(0)}")

    suffixes = tuple(_DEFAULT_INTERNAL_SUFFIXES) + tuple(extra_suffixes or ())
    explicit = tuple(_DEFAULT_INTERNAL_HOSTS)
    host_re = _build_internal_host_re(suffixes, explicit)
    for m in host_re.finditer(text):
        if m.group(0) not in allow:
            issues.append(f"residual internal host: {m.group(0)}")

    for m in _HOMEPATH_RE.finditer(text):
        # The sanitiser replaces real usernames with labels like USER_01;
        # those labels are NOT real residue, just placeholder names. Skip
        # any /home/<label>/ where the name is a known opaque-label prefix.
        name = m.group(2)
        if re.match(r"^(USER|HOST|IP|MAC)_\d+$", name):
            continue
        issues.append(f"residual /home/<user>: {m.group(0)}")

    if extra_usernames:
        for u in extra_usernames:
            if u and u not in allow and re.search(rf"\b{re.escape(u)}\b", text):
                issues.append(f"residual username: {u}")

    return issues
